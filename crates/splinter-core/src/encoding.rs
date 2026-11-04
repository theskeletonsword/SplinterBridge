//! Minimal base64 (RFC 4648 standard alphabet) codec.
//!
//! Used to decode `HardwareAttestation.assertion_token` (declared Base64 in
//! the wire contract) and to encode CBOR attestation objects in tests.
//!
//! Strictness: canonical padding only (`=` confined to the final quad,
//! ≤ 2), six-bit groups with zero discarded tail bits (non-canonical
//! encodings are rejected rather than silently misdecoded), ASCII
//! whitespace tolerated and skipped.

use thiserror::Error;

/// Base64 decoding failures with the offending byte and offset.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum Base64Error {
    /// Input contains a byte outside the base64 alphabet (beyond ASCII or
    /// not an alphabet member).
    #[error("base64: invalid character {0:#04x} at {1}")]
    InvalidByte(u8, usize),
    /// Padding rules or group-length invariants are violated.
    #[error("base64: malformed padding or input length {0}")]
    Malformed(usize),
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const INVALID: u8 = 255;

/// Reverse lookup built once per call site; `INVALID` marks non-alphabet.
fn decode_table() -> [u8; 256] {
    let mut table = [INVALID; 256];
    for (i, &c) in ALPHABET.iter().enumerate() {
        table[usize::from(c)] = i as u8;
    }
    table
}

/// Decodes standard padded base64, tolerating ASCII whitespace.
///
/// O(n). Allocation is exactly the decoded byte count. Canonical tail bits
/// and canonical padding are enforced (rejects over-long encodings).
pub fn decode_base64(input: impl AsRef<[u8]>) -> Result<Vec<u8>, Base64Error> {
    let table = decode_table();
    let raw = input.as_ref();

    // 1. Compact: drop ASCII whitespace; reject anything non-ASCII.
    let mut vals: Vec<u8> = Vec::with_capacity(raw.len());
    let mut padding_seen = false;
    for (i, &b) in raw.iter().enumerate() {
        match b {
            b' ' | b'\t' | b'\r' | b'\n' => {}
            _ if b > 0x7F => return Err(Base64Error::InvalidByte(b, i)),
            b'=' => {
                padding_seen = true;
            }
            _ => {
                if padding_seen {
                    // '=' must only be followed by further padding.
                    return Err(Base64Error::Malformed(raw.len()));
                }
                let v = table[usize::from(b)];
                if v == INVALID {
                    return Err(Base64Error::InvalidByte(b, i));
                }
                vals.push(v);
            }
        }
    }

    // 2. Structural invariants of RFC 4648 §4:
    //    * padded input: total length (data incl. padding) must be a
    //      multiple of 4 with 1 ≤ pad ≤ 2;
    //    * unpadded input: usable sextet length mod 4 ∈ {0, 2, 3} — a lone
    //      sextet can never produce a full byte.
    let pads = padding_markers(raw);
    if padding_seen {
        if !(1..=2).contains(&pads) {
            return Err(Base64Error::Malformed(raw.len()));
        }
        if (vals.len() + pads) % 4 != 0 {
            return Err(Base64Error::Malformed(raw.len()));
        }
    } else if vals.len() % 4 == 1 {
        return Err(Base64Error::Malformed(raw.len()));
    }

    // 3. Byte-stream interpretation: 6-bit groups accumulate into 8-bit
    //    outputs. Leftover width (<8) bits must be canonical zeros.
    let mut acc: u32 = 0;
    let mut width: u32 = 0;
    let mut out = Vec::with_capacity(3 * vals.len() / 4 + 2);
    for &v in &vals {
        acc = (acc << 6) | u32::from(v);
        width += 6;
        if width >= 8 {
            width -= 8;
            out.push((acc >> width) as u8);
        }
    }
    if width > 0 && width < 8 {
        // Trailing bits are non-payload; canonical base64 requires zeros.
        if acc & ((1u32 << width) - 1) != 0 {
            return Err(Base64Error::Malformed(raw.len()));
        }
    }
    Ok(out)
}

/// Counts the `=` padding markers of the raw input.
fn padding_markers(raw: &[u8]) -> usize {
    raw.iter().filter(|b| **b == b'=').count()
}

/// Encodes to canonical standard base64 with padding.
pub fn encode_base64(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let mut triple = [0u8; 3];
        triple[..chunk.len()].copy_from_slice(chunk);
        let word = (u32::from(triple[0]) << 16) | (u32::from(triple[1]) << 8) | u32::from(triple[2]);
        let symbols = [
            ((word >> 18) & 0x3F) as usize,
            ((word >> 12) & 0x3F) as usize,
            ((word >> 6) & 0x3F) as usize,
            (word & 0x3F) as usize,
        ];
        out.push(ALPHABET[symbols[0]] as char);
        out.push(ALPHABET[symbols[1]] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[symbols[2]] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[symbols[3]] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_reference_vectors() {
        assert_eq!(encode_base64(b""), "");
        assert_eq!(encode_base64(b"f"), "Zg==");
        assert_eq!(encode_base64(b"fo"), "Zm8=");
        assert_eq!(encode_base64(b"foo"), "Zm9v");
        assert_eq!(encode_base64(b"foob"), "Zm9vYg==");
        assert_eq!(encode_base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode_base64(b"foobar"), "Zm9vYmFy");

        assert_eq!(decode_base64("").unwrap(), b"");
        assert_eq!(decode_base64("Zg==").unwrap(), b"f");
        assert_eq!(decode_base64("Zm8=").unwrap(), b"fo");
        assert_eq!(decode_base64("Zm9v").unwrap(), b"foo");
        assert_eq!(decode_base64("Zm9vYg==").unwrap(), b"foob");
        assert_eq!(decode_base64("Zm9vYmE=").unwrap(), b"fooba");
        assert_eq!(decode_base64("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn round_trip_all_lengths() {
        for len in 0..96usize {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let encoded = encode_base64(&payload);
            assert_eq!(decode_base64(&encoded).unwrap(), payload, "len {len}");
        }
    }

    #[test]
    fn whitespace_is_skipped() {
        assert_eq!(
            decode_base64("Zm9v\nYm Fy\t==").is_err(),
            true,
            "padding may not be preceded by data break in the last quad"
        );
        assert_eq!(decode_base64("Zm9v\nYm Fy").unwrap(), b"foobar");
        assert_eq!(decode_base64(" Zm9 vYmFy ").unwrap(), b"foobar");
    }

    #[test]
    fn invalid_chars_rejected() {
        assert_eq!(decode_base64("Zm9*"), Err(Base64Error::InvalidByte(b'*', 3)));
        assert_eq!(decode_base64("Zm9v").unwrap(), b"foo");
        // U+00F3 (`ó` byte 0xC3) — non-ASCII byte.
        let non_ascii = [b'Z', b'm', 0xC3, b'B'];
        assert_eq!(decode_base64(&non_ascii), Err(Base64Error::InvalidByte(0xC3, 2)));
    }

    #[test]
    fn malformed_structures_rejected() {
        // Lone sextet can never emit a byte.
        assert_eq!(decode_base64("Z"), Err(Base64Error::Malformed(1)));
        // Padded input must be a multiple of 4 (7 chars total here).
        assert_eq!(decode_base64("Zm9vYg="), Err(Base64Error::Malformed(7)));
        // Three padding markers.
        assert_eq!(decode_base64("Z==="), Err(Base64Error::Malformed(4)));
        // Padding with non-zero discarded bits (non-canonical fill).
        assert_eq!(decode_base64("AR=="), Err(Base64Error::Malformed(4)));
        // '=' followed by data.
        assert_eq!(decode_base64("Zm9=Zg=="), Err(Base64Error::Malformed(8)));
        // Unpadded 6-sextet form is legal for "foob".
        assert_eq!(decode_base64("Zm9vYg").unwrap(), b"foob");
    }

    #[test]
    fn canonical_tail_bits_enforced_consistently() {
        // "AQ==" is canonical for byte 0x01.
        assert_eq!(decode_base64("AQ==").unwrap(), vec![0x01]);
        assert_eq!(decode_base64("AQ==").is_ok(), true);
    }
}
