//! Strict, minimal CBOR (RFC 8949) codec for the WebAuthn/COSE subset used
//! by `splinter-core` attestation verification.
//!
//! Deliberately *strict* about what this gateway accepts:
//! * definite-length encoding only — indefinite-length items are rejected
//!   (the WebAuthn L2 conformance subset requires definite lengths);
//! * integers up to 64 bits; definite-length byte/text strings;
//! * no floats, no RFC 8949 tags — WebAuthn structures never contain them;
//! * map keys must be unique (duplicate keys are a malformed-attestation
//!   trap and are rejected at decode time);
//! * nesting depth is bounded (≤ 32) to bound recursive-descent stack use.
//!
//! The encoder mirrors the parser exactly on this subset. It exists so the
//! verifier and the test suite can build/synthesize attestation-shaped
//! structures without pulling a heavyweight generic CBOR dependency into
//! the crypto core (supply-chain minimization).

use std::collections::BTreeSet;

use thiserror::Error;

/// CBOR decoding errors. Offsets are recorded for auditability.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum CborError {
    /// Ran out of bytes mid-item.
    #[error("CBOR truncated at offset {0}")]
    Truncated(usize),
    /// Malformed header, indefinite-length encoding, or bounded-limit
    /// violation (depth / collection cardinality).
    #[error("CBOR invalid encoding at offset {0}")]
    InvalidEncoding(usize),
    /// Integer beyond 64 bits of usable value.
    #[error("CBOR integer too large at offset {0}")]
    IntegerOverflow(usize),
    /// Floats are not part of the accepted WebAuthn subset.
    #[error("CBOR floats are not supported in WebAuthn structures at offset {0}")]
    FloatRejected(usize),
    /// Tagged values (major type 6) are rejected.
    #[error("unexpected CBOR tag at offset {0}")]
    TagRejected(usize),
    /// Duplicate map key — strict decoding requirement.
    #[error("duplicate CBOR map key at offset {0}")]
    DuplicateMapKey(usize),
    /// Text string is not valid UTF-8.
    #[error("CBOR text string is not valid UTF-8 at offset {0}")]
    InvalidUtf8(usize),
}

/// A decoded CBOR value. The same tree shape is used for encoding, so a
/// `parse → encode → parse` round-trip is value-identical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cbor {
    /// Unsigned major type 0 (fitting in `i64`) or negative major type 1.
    Integer(i64),
    /// Major type 2, definite-length byte string.
    Bytes(Vec<u8>),
    /// Major type 3, definite-length UTF-8 text string.
    Text(String),
    /// Major type 4, definite-length array.
    Array(Vec<Cbor>),
    /// Major type 5, definite-length map. Key order is preserved; duplicates
    /// are rejected at decode time and must not be built by the encoder.
    Map(Vec<(Cbor, Cbor)>),
    /// Major type 7, simple values `false`/`true`.
    Bool(bool),
    /// Major type 7, `null` (simple value 22).
    Null,
}

impl Cbor {
    /// Shorthand: first entry whose `Integer` key equals `key`.
    pub fn map_int(&self, key: i64) -> Option<&Cbor> {
        match self {
            Cbor::Map(entries) => entries
                .iter()
                .find(|(k, _)| *k == Cbor::Integer(key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    /// Shorthand: first entry whose `Text` key equals `key`.
    pub fn map_text(&self, key: &str) -> Option<&Cbor> {
        match self {
            Cbor::Map(entries) => entries
                .iter()
                .find(|(k, _)| matches!(k, Cbor::Text(t) if t == key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    /// The payload if this value is a byte string.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Cbor::Bytes(b) => Some(b.as_slice()),
            _ => None,
        }
    }

    /// The item slice if this value is an array.
    pub fn as_array(&self) -> Option<&[Cbor]> {
        match self {
            Cbor::Array(items) => Some(items.as_slice()),
            _ => None,
        }
    }

    /// The string if this value is text.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Cbor::Text(t) => Some(t),
            _ => None,
        }
    }
}

const MAX_DEPTH: u8 = 32;
const MAX_COLLECTION_LEN: usize = 16_384;

/// Header read result: 3-bit major type, the argument value, and the total
/// header length in bytes (1 initial octet + long-form argument bytes).
struct Header {
    major: u8,
    argument: u64,
    total_len: usize,
}

/// Reads a CBOR header at `pos`.
fn read_header(input: &[u8], pos: usize) -> Result<Header, CborError> {
    if pos >= input.len() {
        return Err(CborError::Truncated(pos));
    }
    let first = input[pos];
    let major = first >> 5;
    let info = first & 0x1F;
    // Long-form encodings reserve 28..30; 31 marks indefinite length, which
    // is outside the accepted definite-length subset.
    let (argument, arg_len) = match info {
        0..=23 => (u64::from(info), 0),
        24 => {
            let byte = input.get(pos + 1).copied().ok_or(CborError::Truncated(pos))?;
            (u64::from(byte), 1)
        }
        25 => {
            let hi = input.get(pos + 1).copied().ok_or(CborError::Truncated(pos))?;
            let lo = input.get(pos + 2).copied().ok_or(CborError::Truncated(pos))?;
            (u64::from(u16::from_be_bytes([hi, lo])), 2)
        }
        26 => {
            if pos + 4 >= input.len() {
                return Err(CborError::Truncated(pos));
            }
            let raw = <[u8; 4]>::try_from(&input[pos + 1..pos + 5]).expect("exact 4 bytes");
            (u64::from(u32::from_be_bytes(raw)), 4)
        }
        27 => {
            if pos + 8 >= input.len() {
                return Err(CborError::Truncated(pos));
            }
            let raw = <[u8; 8]>::try_from(&input[pos + 1..pos + 9]).expect("exact 8 bytes");
            (u64::from_be_bytes(raw), 8)
        }
        _ => return Err(CborError::InvalidEncoding(pos)),
    };
    Ok(Header { major, argument, total_len: 1 + arg_len })
}

/// Maps a map key to a canonical comparable form for duplicate detection.
/// COSE keys are integers or text; anything else is encoded for comparison.
fn canonical_key_bytes(key: &Cbor) -> Vec<u8> {
    // The value tree contains no offsets or cycles, so re-encoding a decoded
    // key always succeeds.
    if let Ok(encoded) = encode(key) {
        encoded
    } else {
        // Deterministic, safe fallback for keys the encoder rejects.
        format!("{key:?}").into_bytes()
    }
}

/// Parses exactly one CBOR item at `pos`, returning the value and the end
/// offset of the item.
fn parse_item(input: &[u8], pos: usize, depth: u8) -> Result<(Cbor, usize), CborError> {
    if depth > MAX_DEPTH {
        return Err(CborError::InvalidEncoding(pos));
    }
    let Header { major, argument, total_len } = read_header(input, pos)?;
    let value_pos = pos + total_len;

    match major {
        0 => {
            if argument > i64::MAX as u64 {
                return Err(CborError::IntegerOverflow(pos));
            }
            Ok((Cbor::Integer(argument as i64), value_pos))
        }
        1 => {
            // Negative integer: value = -1 - argument (RFC 8949 §3.2.2).
            if argument > (i64::MAX as u64) {
                return Err(CborError::IntegerOverflow(pos));
            }
            let value = (-1i64)
                .checked_sub(argument as i64)
                .ok_or(CborError::IntegerOverflow(pos))?;
            Ok((Cbor::Integer(value), value_pos))
        }
        2 | 3 => {
            let len = usize::try_from(argument).map_err(|_| CborError::Truncated(pos))?;
            let end = value_pos
                .checked_add(len)
                .ok_or(CborError::Truncated(pos))?;
            let raw = input.get(value_pos..end).ok_or(CborError::Truncated(pos))?;
            if major == 2 {
                Ok((Cbor::Bytes(raw.to_vec()), end))
            } else {
                let text = std::str::from_utf8(raw)
                    .map_err(|_| CborError::InvalidUtf8(pos))?
                    .to_string();
                Ok((Cbor::Text(text), end))
            }
        }
        4 => {
            let len = usize::try_from(argument).map_err(|_| CborError::Truncated(pos))?;
            if len > MAX_COLLECTION_LEN {
                return Err(CborError::InvalidEncoding(pos));
            }
            let mut items = Vec::with_capacity(len.min(64));
            let mut cursor = value_pos;
            for _ in 0..len {
                let (item, next) = parse_item(input, cursor, depth + 1)?;
                items.push(item);
                cursor = next;
            }
            Ok((Cbor::Array(items), cursor))
        }
        5 => {
            let len = usize::try_from(argument).map_err(|_| CborError::Truncated(pos))?;
            if len > MAX_COLLECTION_LEN {
                return Err(CborError::InvalidEncoding(pos));
            }
            let mut entries = Vec::with_capacity(len.min(64));
            let mut seen_keys = BTreeSet::new();
            let mut cursor = value_pos;
            for _ in 0..len {
                let (key, next) = parse_item(input, cursor, depth + 1)?;
                let (value, next) = parse_item(input, next, depth + 1)?;
                if !seen_keys.insert(canonical_key_bytes(&key)) {
                    return Err(CborError::DuplicateMapKey(pos));
                }
                entries.push((key, value));
                cursor = next;
            }
            Ok((Cbor::Map(entries), cursor))
        }
        6 => Err(CborError::TagRejected(pos)),
        7 => match argument {
            20 => Ok((Cbor::Bool(false), value_pos)),
            21 => Ok((Cbor::Bool(true), value_pos)),
            22 | 23 => Ok((Cbor::Null, value_pos)),
            // 25..=27 are float encodings; ≥ 24 are unaccepted simple values.
            _ => Err(CborError::FloatRejected(pos)),
        },
        _ => unreachable!("3-bit major type is 0..=7"),
    }
}

impl std::fmt::Display for Cbor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cbor::Integer(i) => write!(f, "{i}"),
            Cbor::Bytes(b) => write!(f, "{} bytes", b.len()),
            Cbor::Text(t) => write!(f, "\"{t}\""),
            Cbor::Array(items) => write!(f, "array[{}]", items.len()),
            Cbor::Map(entries) => write!(f, "map[{}]", entries.len()),
            Cbor::Bool(b) => write!(f, "{b}"),
            Cbor::Null => write!(f, "null"),
        }
    }
}

/// Parses `input` as exactly one CBOR item, rejecting trailing bytes unless
/// `allow_tail` is set.
pub fn parse(input: &[u8], allow_tail: bool) -> Result<Cbor, CborError> {
    let (value, end) = parse_item(input, 0, 0)?;
    if !allow_tail && end != input.len() {
        return Err(CborError::InvalidEncoding(end));
    }
    Ok(value)
}

/// Encoder errors.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum CborWriteError {
    /// Numeric value cannot be represented (out-of-range argument).
    #[error("CBOR encoding failed: value out of representable range")]
    OutOfRange,
}

/// Encodes a [`Cbor`] value tree into definite-length CBOR bytes.
///
/// Semantics: unsigned major 0 for `Integer >= 0`, negative major 1 for
/// `Integer < 0` (following RFC 8949 the negative content is `-1 - value`).
pub fn encode(value: &Cbor) -> Result<Vec<u8>, CborWriteError> {
    let mut out = Vec::with_capacity(64);
    encode_into(value, &mut out)?;
    Ok(out)
}

fn write_header(out: &mut Vec<u8>, major: u8, argument: u64) {
    let initial = major << 5;
    let (info, extra): (u8, Vec<u8>) = if argument <= 23 {
        (argument as u8, Vec::new())
    } else if argument <= u::U8_MAX {
        (24, vec![argument as u8])
    } else if argument <= u::U16_MAX {
        (25, (argument as u16).to_be_bytes().to_vec())
    } else if argument <= u::U32_MAX {
        (26, (argument as u32).to_be_bytes().to_vec())
    } else {
        (27, argument.to_be_bytes().to_vec())
    };
    out.push(initial | info);
    out.extend_from_slice(&extra);
}

/// Numeric upper bounds kept as constants for `write_header` readability.
mod u {
    pub const U8_MAX: u64 = u8::MAX as u64;
    pub const U16_MAX: u64 = u16::MAX as u64;
    pub const U32_MAX: u64 = u32::MAX as u64;
}

fn encode_into(value: &Cbor, out: &mut Vec<u8>) -> Result<(), CborWriteError> {
    match value {
        Cbor::Integer(i) => {
            if *i >= 0 {
                write_header(out, 0, *i as u64);
            } else {
                // -1 - argument == i  ⇒  argument = -1 - i, computed
                // through i128 to absorb i64::MIN.
                let argument = (-1i128) - (*i as i128);
                if argument < 0 {
                    return Err(CborWriteError::OutOfRange);
                }
                write_header(out, 1, argument as u64);
            }
        }
        Cbor::Bytes(b) => {
            write_header(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Cbor::Text(t) => {
            write_header(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        }
        Cbor::Array(items) => {
            write_header(out, 4, items.len() as u64);
            for item in items {
                encode_into(item, out)?;
            }
        }
        Cbor::Map(entries) => {
            write_header(out, 5, entries.len() as u64);
            for (key, val) in entries {
                encode_into(key, out)?;
                encode_into(val, out)?;
            }
        }
        Cbor::Bool(b) => out.push(if *b { 0xF5 } else { 0xF4 }),
        Cbor::Null => out.push(0xF6),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_nested_attestation_like() {
        // {"fmt":"packed","attStmt":{"alg":-7,"sig":b"ff","x5c":[b"a"]},"authData":b"aaaa"}
        let value = Cbor::Map(vec![
            (Cbor::Text("fmt".into()), Cbor::Text("packed".into())),
            (
                Cbor::Text("attStmt".into()),
                Cbor::Map(vec![
                    (Cbor::Integer(3), Cbor::Integer(-7)),
                    (Cbor::Text("sig".into()), Cbor::Bytes(vec![0xFF; 2])),
                    (
                        Cbor::Text("x5c".into()),
                        Cbor::Array(vec![Cbor::Bytes(vec![0xAA])]),
                    ),
                ]),
            ),
            (
                Cbor::Text("authData".into()),
                Cbor::Bytes(vec![0xBB; 4]),
            ),
        ]);
        let encoded = encode(&value).expect("encode");
        let decoded = parse(&encoded, false).expect("parse");
        assert_eq!(decoded, value);
        // Structural checks on canonical encodings.
        assert_eq!(decoded.map_text("fmt").and_then(|v| v.as_text()), Some("packed"));
        assert_eq!(
            decoded
                .map_text("attStmt")
                .and_then(|a| a.map_int(3)),
            Some(&Cbor::Integer(-7))
        );
    }

    #[test]
    fn canonical_reference_encodings() {
        // RFC 8949 Appendix A fixtures relevant to this subset.
        assert_eq!(encode(&Cbor::Integer(0)).unwrap(), vec![0x00]);
        assert_eq!(encode(&Cbor::Integer(23)).unwrap(), vec![0x17]);
        assert_eq!(encode(&Cbor::Integer(24)).unwrap(), vec![0x18, 0x18]);
        assert_eq!(encode(&Cbor::Integer(500)).unwrap(), vec![0x19, 0x01, 0xF4]);
        assert_eq!(encode(&Cbor::Integer(-7)).unwrap(), vec![0x26]);
        let ietf = encode(&Cbor::Text("IETF".into())).unwrap();
        assert_eq!(ietf, vec![0x64, b'I', b'E', b'T', b'F']);
        let empty_map = encode(&Cbor::Map(vec![])).unwrap();
        assert_eq!(empty_map, vec![0xA0]);
        let bools = [encode(&Cbor::Bool(true)).unwrap(), encode(&Cbor::Bool(false)).unwrap()];
        assert_eq!(bools[0], vec![0xF5]);
        assert_eq!(bools[1], vec![0xF4]);
        // Negative zero boundary: i64::MIN must encode round-trip.
        let min = encode(&Cbor::Integer(i64::MIN)).unwrap();
        assert_eq!(parse(&min, false).unwrap(), Cbor::Integer(i64::MIN));
    }

    #[test]
    fn rejects_indefinite_length_truncation_and_garbage() {
        // Indefinite byte string (additional-info 31).
        assert_eq!(parse(&[0x5F], false), Err(CborError::InvalidEncoding(0)));
        // Reserved long-form info 30.
        assert_eq!(parse(&[0b000_11110], false), Err(CborError::InvalidEncoding(0)));
        // Truncated long-form argument.
        assert_eq!(parse(&[0x18], false), Err(CborError::Truncated(0)));
        // Byte string longer than the input.
        assert_eq!(parse(&[0x43, 1, 2], false), Err(CborError::Truncated(0)));
        // Trailing garbage rejected when tail is disallowed.
        assert!(parse(&[0x01, 0x02], false).is_err());
        assert!(parse(&[0x01, 0x02], true).is_ok());
    }

    #[test]
    fn negative_integer_boundary_round_trip() {
        for value in [-7i64, -1, -24, -25, -300, i64::MIN] {
            let encoded = encode(&Cbor::Integer(value)).unwrap();
            match parse(&encoded, false).unwrap() {
                Cbor::Integer(v) => assert_eq!(v, value, "value {value}"),
                other => panic!("expected integer, got {other:?}"),
            }
        }
    }

    #[test]
    fn floats_tags_duplicates_and_depth_are_rejected() {
        // Half-precision float (major 7, info 25).
        assert_eq!(parse(&[0xF9, 0x3C, 0x00], false), Err(CborError::FloatRejected(0)));
        // Tag (major 6) wrapping a uint.
        assert_eq!(parse(&[0xC1, 0x00], false), Err(CborError::TagRejected(0)));
        // Duplicate identical integer keys.
        let dup = [0xA2, 0x01, 0x00, 0x01, 0x00]; // {1:0, 1:0}
        assert_eq!(parse(&dup, false), Err(CborError::DuplicateMapKey(0)));
        // Flooded array cardinality (declares 65k items).
        assert_eq!(parse(&[0x9A, 0, 1, 0, 0], false), Err(CborError::InvalidEncoding(0)));
        // Deep nesting beyond the depth bound.
        let mut deep = vec![0xA1];
        for _ in 0..40 {
            deep.push(0x81);
        }
        deep.push(0x01);
        assert!(parse(&deep, false).is_err());
    }

    #[test]
    fn non_canonical_argument_length_is_still_definite() {
        // Long-form encoding of a small argument is legal RFC 8949 (it is
        // merely not canonical). Our decoder stays length-aware via the
        // header parse, so it must round-trip, not be misread.
        let mut non_canonical = vec![0x38]; // negative long-form header
        non_canonical.push(23); // argument 23 ⇒ value -24
        match parse(&non_canonical, false) {
            Ok(Cbor::Integer(-24)) => {}
            other => panic!("expected -24, got {other:?}"),
        }
    }
}
