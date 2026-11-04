//! Minimal, strict DER/X.509 reader for gateway trust-anchored verification.
//!
//! Scope (deliberate, security-relevant): this module implements exactly the
//! subset of X.509 needed to (a) extract SubjectPublicKeyInfo from enclave
//! root/leaf certificates, (b) expose the raw `tbsCertificate` bytes and the
//! signature so a caller can verify the chain up to a configured root, and
//! (c) enforce validity windows in UTC. Deliberately **no** heavyweight
//! certificate-stack dependency (webpki/x509-parser) inside the trusted
//! core — the accepted subset is small, strict, and fully unit-tested:
//!
//! * DER definite lengths must be minimally encoded (BER padding rejected);
//! * `tbsCertificate` must be X.509 v3 (explicit `[0] version = 2`);
//! * signature algorithms accepted: ECDSA/P-256 + SHA-256 and pure Ed25519;
//!   RSA is rejected outright by gateway security policy;
//! * ECDSA public keys: uncompressed SEC1 (`04 || X || Y`, 65 bytes);
//! * UTCTime / GeneralizedTime must end in `Z`, seconds ≤ 60 (leap).

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::Verifier;
use thiserror::Error;

/// DER parse errors with byte offsets for audit trails.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum DerError {
    /// Ran out of bytes inside a TLV.
    #[error("DER truncated at offset {0}")]
    Truncated(usize),
    /// A tag/content mismatch against the expected type.
    #[error("DER tag mismatch at offset {0}: expected {1}, got {2:#04x}")]
    UnexpectedTag(usize, &'static str, u8),
    /// Long-form length encoding that is not minimal (BER trap).
    #[error("DER non-minimal length encoding at offset {0}")]
    NonMinimalLength(usize),
    /// Structure semantics outside the supported X.509 subset.
    #[error("unsupported certificate element at offset {0}: {1}")]
    Unsupported(usize, String),
    /// Public key material could not be interpreted.
    #[error("malformed public key encoding at offset {0}")]
    BadPublicKey(usize),
    /// Signature bytes are neither DER ECDSA nor 64-byte raw Ed25519.
    #[error("malformed signature encoding at offset {0}")]
    BadSignature(usize),
    /// Cryptographic verification failed (tamper, wrong key, wrong scope).
    #[error("signature verification failed")]
    InvalidSignature,
    /// Certificate validity window does not contain `now`.
    #[error("certificate validity window violated: not_before={0} not_after={1} now={2}")]
    ValidityWindowViolation(u64, u64, u64),
}

/// A parsed TLV: tag, content view, and offsets within the enclosing buffer.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    /// ASN.1 tag octet.
    pub tag: u8,
    /// Content bytes (definite length), borrowed from the enclosing buffer.
    pub contents: &'a [u8],
    /// Byte offset (within the SAME buffer) where `contents` starts.
    pub content_offset: usize,
    /// Total occupied bytes (header + contents); next TLV at `pos + total_len`.
    pub total_len: usize,
}

impl<'a> Tlv<'a> {
    /// Errors unless this TLV has the expected tag octet.
    pub fn expect_tag(&self, tag: u8, what: &'static str, at: usize) -> Result<(), DerError> {
        if self.tag == tag {
            Ok(())
        } else {
            Err(DerError::UnexpectedTag(at, what, self.tag))
        }
    }
}

/// Parses one definite-length TLV starting at `pos`, enforcing the DER
/// minimal-length rule (X.690 §10.1) and in-bounds contents.
pub fn read_tlv(input: &[u8], pos: usize) -> Result<Tlv<'_>, DerError> {
    let tag = *input.get(pos).ok_or(DerError::Truncated(pos))?;
    let len_octet = *input.get(pos + 1).ok_or(DerError::Truncated(pos))?;
    let (contents_len, header_len) = if len_octet < 0x80 {
        (usize::from(len_octet), 2)
    } else {
        let bytes = usize::from(len_octet & 0x7F);
        if bytes == 0 || bytes > 4 {
            return Err(DerError::NonMinimalLength(pos));
        }
        // Minimal-encoding rule: the value must not be encodable in fewer
        // octets — a 1-octet long form must encode ≥ 0x80; longer forms must
        // start with a non-zero value octet.
        let first_val = *input.get(pos + 2).ok_or(DerError::Truncated(pos))?;
        if bytes == 1 && first_val < 0x80 {
            return Err(DerError::NonMinimalLength(pos));
        }
        if bytes > 1 && first_val == 0 {
            return Err(DerError::NonMinimalLength(pos));
        }
        let mut value: usize = 0;
        for i in 0..bytes {
            let octet = *input.get(pos + 2 + i).ok_or(DerError::Truncated(pos))?;
            value = value
                .checked_mul(256)
                .and_then(|v| v.checked_add(usize::from(octet)))
                .ok_or(DerError::NonMinimalLength(pos))?;
        }
        (value, 2 + bytes)
    };
    let content_offset = pos + header_len;
    let contents_end = content_offset
        .checked_add(contents_len)
        .ok_or(DerError::Truncated(pos))?;
    let contents = input
        .get(content_offset..contents_end)
        .ok_or(DerError::Truncated(pos))?;
    Ok(Tlv {
        tag,
        contents,
        content_offset,
        total_len: header_len + contents_len,
    })
}

/// OID content bytes (X.690 content octets, tag/length stripped).
pub mod oids {
    /// ecPublicKey (ANSI X9.62 elliptic-curve algorithm).
    pub const ECDSA: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    /// prime256v1 / P-256 named-curve parameter.
    pub const P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    /// ecdsa-with-SHA256 certificate signature algorithm.
    pub const ECDSA_WITH_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
    /// Ed25519 (PureEdDSA) algorithm, no parameters.
    pub const ED25519: &[u8] = &[0x2B, 0x65, 0x70];
}

/// Parsed SubjectPublicKeyInfo.
#[derive(Debug)]
pub struct Spki {
    /// `AlgorithmIdentifier.algorithm` OID content bytes.
    pub algorithm_oid: Vec<u8>,
    /// Curve parameter OID (ECDSA only; must be absent for Ed25519).
    pub curve_oid: Option<Vec<u8>>,
    /// Public-key bytes: uncompressed EC point or 32-byte Ed25519 key.
    pub key_bytes: Vec<u8>,
}

/// Certificate parse result: everything the chain verifier needs.
pub struct Certificate {
    /// Raw `tbsCertificate` TLV (header included) — the byte-exact scope of
    /// the certificate's own signature.
    pub tbs: Vec<u8>,
    /// Outer `signatureAlgorithm` OID content bytes.
    pub signature_alg_oid: Vec<u8>,
    /// Signature value (BIT STRING payload, unused-bits octet stripped).
    pub signature: Vec<u8>,
    /// `notBefore` packed `yyyymmddhhmmss` (UTC).
    pub not_before: u64,
    /// `notAfter` packed (UTC).
    pub not_after: u64,
    /// SubjectPublicKeyInfo.
    pub spki: Spki,
}

/// A verified public key usable for chain/attestation signature checks.
#[derive(Debug, Clone)]
pub enum TrustedPublicKey {
    /// ECDSA over P-256 (SHA-256).
    EcdsaP256(p256::ecdsa::VerifyingKey),
    /// Pure Ed25519.
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl TrustedPublicKey {
    /// Verifies `message` under this key.
    ///
    /// ECDSA inputs arrive as the X.509-wrapped DER `ECDSA-Sig-Value`
    /// (`SEQUENCE{r,s}`); Ed25519 as the raw 64-byte `r||s` octet string.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), DerError> {
        match self {
            TrustedPublicKey::EcdsaP256(vk) => {
                let sig = p256::ecdsa::Signature::from_der(signature)
                    .map_err(|_| DerError::BadSignature(0))?;
                vk.verify(message, &sig)
                    .map_err(|_| DerError::InvalidSignature)
            }
            TrustedPublicKey::Ed25519(vk) => {
                let sig = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|_| DerError::BadSignature(0))?;
                vk.verify(message, &sig)
                    .map_err(|_| DerError::InvalidSignature)
            }
        }
    }
}

/// Converts a parsed SPKI into a [`TrustedPublicKey`] under the accepted
/// algorithm policy.
pub fn spki_to_key(spki: &Spki, at: usize) -> Result<TrustedPublicKey, DerError> {
    match spki.algorithm_oid.as_slice() {
        x if x == oids::ECDSA => {
            if spki.curve_oid.as_deref() != Some(oids::P256) {
                return Err(DerError::Unsupported(
                    at,
                    "only prime256v1 curves are policy-accepted".into(),
                ));
            }
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&spki.key_bytes)
                .map_err(|_| DerError::BadPublicKey(at))?;
            Ok(TrustedPublicKey::EcdsaP256(vk))
        }
        x if x == oids::ED25519 => {
            if spki.curve_oid.is_some() {
                return Err(DerError::Unsupported(at, "Ed25519 SPKI carries no parameters".into()));
            }
            let raw: [u8; 32] = spki
                .key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| DerError::BadPublicKey(at))?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&raw)
                .map_err(|_| DerError::BadPublicKey(at))?;
            Ok(TrustedPublicKey::Ed25519(vk))
        }
        _ => Err(DerError::Unsupported(
            at,
            "SPKI algorithm outside (ECDSA P-256 | Ed25519) policy".into(),
        )),
    }
}

/// Parses one DER X.509 certificate. O(size), single forward walk.
pub fn parse_certificate(input: &[u8]) -> Result<Certificate, DerError> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let root = read_tlv(input, 0)?;
    root.expect_tag(0x30, "Certificate SEQUENCE", 0)?;

    let mut cursor = root.content_offset;
    let tbs = {
        let tbs_tlv = read_tlv(input, cursor)?;
        tbs_tlv.expect_tag(0x30, "TBSCertificate SEQUENCE", cursor)?;
        let bytes = input[cursor..cursor + tbs_tlv.total_len].to_vec();
        cursor += tbs_tlv.total_len;
        bytes
    };

    let signature_alg_oid = {
        let sig_alg = read_tlv(input, cursor)?;
        sig_alg.expect_tag(0x30, "signatureAlgorithm", cursor)?;
        let oid = read_tlv(sig_alg.contents, 0)?;
        oid.expect_tag(0x06, "OID", cursor)?;
        let bytes = oid.contents.to_vec();
        cursor += sig_alg.total_len;
        bytes
    };

    let signature = {
        let sig_value = read_tlv(input, cursor)?;
        sig_value.expect_tag(0x03, "signatureValue BIT STRING", cursor)?;
        if sig_value.contents.is_empty() || sig_value.contents[0] != 0 {
            return Err(DerError::Unsupported(
                cursor,
                "signatureValue BIT STRING carries unused bits".into(),
            ));
        }
        cursor += sig_value.total_len;
        let bytes = sig_value.contents[1..].to_vec();
        bytes
    };
    // Any non-zero trailing bytes after the certificate are malformed DER.
    if cursor < input.len() && input[cursor..].iter().any(|b| *b != 0) {
        return Err(DerError::Unsupported(cursor, "trailing bytes after Certificate".into()));
    }

    let (not_before, not_after, spki) = parse_tbs(&tbs, 0)?;
    Ok(Certificate {
        tbs,
        signature_alg_oid,
        signature,
        not_before,
        not_after,
        spki,
    })
}

/// Walks `tbsCertificate` children:
/// `[0] version, serialNumber, signatureAlgorithm, issuer, validity, subject,
/// subjectPublicKeyInfo, ([3] extensions tolerated — anything else rejected)`.
fn parse_tbs(tbs: &[u8], at: usize) -> Result<(u64, u64, Spki), DerError> {
    let outer = read_tlv(tbs, 0)?;
    outer.expect_tag(0x30, "TBSCertificate SEQUENCE", at)?;
    let mut cursor = outer.content_offset;

    // [0] EXPLICIT version INTEGER — required (v3 policy).
    let version = read_tlv(tbs, cursor)?;
    if version.tag != 0xA0 {
        return Err(DerError::Unsupported(
            at + cursor,
            "tbsCertificate must be X.509 v3 (explicit [0] version required)".into(),
        ));
    }
    let ver_int = read_tlv(version.contents, 0)?;
    if ver_int.tag != 0x02 || ver_int.contents != [2] {
        return Err(DerError::Unsupported(at + cursor, "version must be v3 (2)".into()));
    }
    cursor += version.total_len;

    let serial = read_tlv(tbs, cursor)?;
    serial.expect_tag(0x02, "serialNumber", at + cursor)?;
    cursor += serial.total_len;

    let alg = read_tlv(tbs, cursor)?;
    alg.expect_tag(0x30, "AlgorithmIdentifier", at + cursor)?;
    cursor += alg.total_len;

    let issuer = read_tlv(tbs, cursor)?;
    issuer.expect_tag(0x30, "issuer Name", at + cursor)?;
    cursor += issuer.total_len;

    let validity = read_tlv(tbs, cursor)?;
    validity.expect_tag(0x30, "validity", at + cursor)?;
    let (not_before, nb_end) = parse_time_at(tbs, validity.content_offset)?;
    let (not_after, _na_end) = parse_time_at(tbs, nb_end)?;
    cursor += validity.total_len;

    let subject = read_tlv(tbs, cursor)?;
    subject.expect_tag(0x30, "subject Name", at + cursor)?;
    cursor += subject.total_len;

    let spki_tlv = read_tlv(tbs, cursor)?;
    spki_tlv.expect_tag(0x30, "subjectPublicKeyInfo", at + cursor)?;
    // `parse_spki` expects the SPKI outer TLV position (not the content
    // offset): all its internal reads are position-scoped into `tbs`.
    let spki_pos = cursor;
    let spki = parse_spki(tbs, spki_pos)?;
    cursor = spki_pos + spki_tlv.total_len;

    // Trailing extensions ([3]) are tolerated but nothing else is.
    let tbs_end = outer.content_offset + outer.contents.len();
    while cursor < tbs_end {
        let tail = read_tlv(tbs, cursor)?;
        if tail.tag != 0xA3 {
            return Err(DerError::Unsupported(
                at + cursor,
                "unexpected trailing element in TBSCertificate".into(),
            ));
        }
        cursor += tail.total_len;
    }

    Ok((not_before, not_after, spki))
}

/// Reads one Time TLV at `pos` in `input` and returns its packed value.
fn parse_time_at(input: &[u8], pos: usize) -> Result<(u64, usize), DerError> {
    let time_tlv = read_tlv(input, pos)?;
    if time_tlv.tag != 0x17 && time_tlv.tag != 0x18 {
        return Err(DerError::UnexpectedTag(pos, "UTCTime/GeneralizedTime", time_tlv.tag));
    }
    let packed = parse_time(time_tlv.tag, time_tlv.contents)?;
    Ok((packed, pos + time_tlv.total_len))
}

/// SPKI ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
/// `pos` = SPKI outer TLV position inside `input`.
fn parse_spki(input: &[u8], pos: usize) -> Result<Spki, DerError> {
    let spki_outer = read_tlv(input, pos)?;
    spki_outer.expect_tag(0x30, "subjectPublicKeyInfo", pos)?;

    let alg = read_tlv(input, spki_outer.content_offset)?;
    alg.expect_tag(0x30, "AlgorithmIdentifier", spki_outer.content_offset)?;

    let oid = read_tlv(input, alg.content_offset)?;
    oid.expect_tag(0x06, "SPKI OID", alg.content_offset)?;
    let algorithm_oid = oid.contents.to_vec();
    let cursor = alg.content_offset + oid.total_len;
    // End of the AlgorithmIdentifier TLV = start of the BIT STRING.
    // (position of next TLV = content_offset + content length)
    let alg_end = alg.content_offset + alg.contents.len();

    // Optional parameters: ECDSA carries the curve OID; NULL is tolerated as
    // a degenerate drop; Ed25519 must carry no parameters at all.
    let mut curve_oid: Option<Vec<u8>> = None;
    if cursor < alg_end {
        let param = read_tlv(input, cursor)?;
        if param.tag == 0x06 {
            curve_oid = Some(param.contents.to_vec());
        } else if param.tag != 0x05 {
            return Err(DerError::Unsupported(
                cursor,
                "unsupported AlgorithmIdentifier parameter".into(),
            ));
        }
    }

    let key = read_tlv(input, alg_end)?;
    key.expect_tag(0x03, "subjectPublicKey BIT STRING", alg_end)?;
    if key.contents.is_empty() || key.contents[0] != 0 {
        return Err(DerError::Unsupported(
            alg_end,
            "subjectPublicKey BIT STRING with unused bits".into(),
        ));
    }
    Ok(Spki {
        algorithm_oid,
        curve_oid,
        key_bytes: key.contents[1..].to_vec(),
    })
}

/// UTC stamp packed as `yyyymmddhhmmss` — used ONLY for window comparisons
/// (monotonic in UTC across mixed Y/M/D values, which is what we need).
fn parse_time(tag: u8, contents: &[u8]) -> Result<u64, DerError> {
    let (year, rest) = match tag {
        0x17 => {
            // UTCTime YYMMDDHHMMSSZ (13 bytes).
            if contents.len() != 13 || contents[12] != b'Z' {
                return Err(DerError::Unsupported(0, "UTCTime must be YYMMDDHHMMSSZ".into()));
            }
            let yy = parse_two_digits(&contents[0..2])?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            (year, 2usize)
        }
        0x18 => {
            // GeneralizedTime YYYYMMDDHHMMSSZ (15 bytes).
            if contents.len() != 15 || contents[14] != b'Z' {
                return Err(DerError::Unsupported(0, "GeneralizedTime must be YYYYMMDDHHMMSSZ".into()));
            }
            (parse_year(&contents[0..4])?, 4usize)
        }
        _ => return Err(DerError::UnexpectedTag(0, "time", tag)),
    };
    let month = parse_two_digits(&contents[rest..rest + 2])?;
    let day = parse_two_digits(&contents[rest + 2..rest + 4])?;
    let hour = parse_two_digits(&contents[rest + 4..rest + 6])?;
    let minute = parse_two_digits(&contents[rest + 6..rest + 8])?;
    let second = parse_two_digits(&contents[rest + 8..rest + 10])?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(DerError::Unsupported(0, "time field out of range".into()));
    }
    Ok(u64::from(year) * 10_000_000_000
        + u64::from(month) * 100_000_000
        + u64::from(day) * 1_000_000
        + u64::from(hour) * 10_000
        + u64::from(minute) * 100
        + u64::from(second))
}

fn parse_two_digits(b: &[u8]) -> Result<u32, DerError> {
    if b.len() != 2 || !b.iter().all(u8::is_ascii_digit) {
        return Err(DerError::Unsupported(0, "expected 2 ASCII digits".into()));
    }
    Ok(u32::from(b[0] - b'0') * 10 + u32::from(b[1] - b'0'))
}

fn parse_year(b: &[u8]) -> Result<u32, DerError> {
    if b.len() != 4 || !b.iter().all(u8::is_ascii_digit) {
        return Err(DerError::Unsupported(0, "expected 4 ASCII digits".into()));
    }
    Ok(u32::from(b[0] - b'0') * 1000
        + u32::from(b[1] - b'0') * 100
        + u32::from(b[2] - b'0') * 10
        + u32::from(b[3] - b'0'))
}

/// Current UTC stamp packed as `yyyymmddhhmmss` for validity comparisons.
pub fn utc_stamp_now() -> u64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let secs_of_day = secs % 86_400;
    let (year, month, day) = civil_from_days(days as i64);
    hour_min_secs(year, month, day, secs_of_day)
}

fn hour_min_secs(year: i64, month: u32, day: u32, secs_of_day: u64) -> u64 {
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    (year as u64) * 10_000_000_000
        + u64::from(month) * 100_000_000
        + u64::from(day) * 1_000_000
        + hour * 10_000
        + minute * 100
        + second
}

/// Howard Hinnant's `civil_from_days` — UNIX epoch days → `(y, m, d)`.
/// O(1) pure integer arithmetic, no lookup tables.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::KeyPair;

    fn self_signed_p256_cert(cn: &str, is_ca: bool) -> Vec<u8> {
        let key_pair = KeyPair::generate().expect("rcgen P-256 keygen");
        let mut params = rcgen::CertificateParams::new(vec![cn.to_owned()])
            .expect("certificate params");
        params.is_ca = if is_ca {
            rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained)
        } else {
            rcgen::IsCa::NoCa
        };
        let cert = params.self_signed(&key_pair).expect("self-sign");
        cert.der().to_vec()
    }

    #[test]
    fn parses_rcgen_p256_self_signed_cert() {
        let der = self_signed_p256_cert("gateway-test", true);
        let cert = parse_certificate(&der).expect("parse");
        // rcgen defaults: ECDSA P-256 keys + SHA-256 certificate signatures.
        assert_eq!(cert.signature_alg_oid, oids::ECDSA_WITH_SHA256);
        assert_eq!(cert.spki.algorithm_oid, oids::ECDSA);
        assert_eq!(cert.spki.curve_oid.as_deref(), Some(oids::P256));
        // Uncompressed SEC1 point: 0x04 || 64 bytes.
        assert_eq!(cert.spki.key_bytes.len(), 65);
        assert_eq!(cert.spki.key_bytes[0], 0x04);
        // Validity window contains `now` (rcgen backdates notBefore).
        let now = utc_stamp_now();
        assert!(cert.not_before <= now, "not_before {} > now {}", cert.not_before, now);
        assert!(cert.not_after > now, "not_after {} <= now {}", cert.not_after, now);
    }

    #[test]
    fn spki_key_verifies_its_own_certificate_signature() {
        // Self-attestation trust-anchor form: the certificate signature
        // verifies against the SPKI key embedded in the same certificate.
        let der = self_signed_p256_cert("anchor", true);
        let cert = parse_certificate(&der).unwrap();
        let key = spki_to_key(&cert.spki, 0).expect("key");
        key.verify(&cert.tbs, &cert.signature)
            .expect("self-signature verifies");
    }

    #[test]
    fn signed_chain_leaf_verifies_against_root_spki() {
        // Root CA signs a leaf; the leaf's tbs signature must verify with
        // the ROOT's public key — the actual chain-verification primitive.
        let root_key = KeyPair::generate().unwrap();
        let mut root_params =
            rcgen::CertificateParams::new(vec!["splinter-root CA".to_owned()]).unwrap();
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root_cert = root_params.self_signed(&root_key).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params =
            rcgen::CertificateParams::new(vec!["attested-gateway".to_owned()]).unwrap();
        leaf_params.is_ca = rcgen::IsCa::NoCa;
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &root_cert, &root_key)
            .expect("leaf signed by root");

        let root_der = parse_certificate(&root_cert.der()).unwrap();
        let leaf_der = parse_certificate(&leaf_cert.der()).unwrap();
        let root_key_parsed = spki_to_key(&root_der.spki, 0).unwrap();
        root_key_parsed
            .verify(&leaf_der.tbs, &leaf_der.signature)
            .expect("leaf signature must verify under root SPKI");

        // The root itself is self-signed (anchor invariant).
        root_key_parsed
            .verify(&root_der.tbs, &root_der.signature)
            .expect("root self-signature verifies");
    }

    #[test]
    fn signature_bit_flips_are_rejected() {
        let der = self_signed_p256_cert("tamper", false);
        // Flip a byte in the last quarter of the DER (signature BIT STRING).
        let mut bad = der.clone();
        let mid = bad.len() * 3 / 4 + 2;
        bad[mid] ^= 0x40;
        match parse_certificate(&bad) {
            Err(_) => {} // structural break also acceptable
            Ok(cert) => {
                let key = spki_to_key(&cert.spki, 0).unwrap();
                match key.verify(&cert.tbs, &cert.signature) {
                    Ok(()) => panic!("tampered certificate must not verify"),
                    Err(DerError::InvalidSignature) => {}
                    Err(other) => panic!("unexpected error {other:?}"),
                }
            }
        }
        // Payload flip: altering tbs content while keeping the parse valid.
        let original = parse_certificate(&der).unwrap();
        let mut payload = original.tbs.clone();
        let last = payload.len() - 8;
        payload[last] ^= 0x01;
        let key = spki_to_key(&original.spki, 0).unwrap();
        assert!(matches!(
            key.verify(&payload, &original.signature),
            Err(DerError::InvalidSignature)
        ));
    }

    #[test]
    fn non_minimal_length_rejected() {
        // Long-form 1-byte encoding of a small value (0x05) ⇒ non-minimal.
        let bad = [0x30, 0x81, 0x05, 0x02, 0x01, 0x01, 0x02, 0x00];
        assert!(matches!(read_tlv(&bad, 0), Err(DerError::NonMinimalLength(0))));
        // Long-form 2-byte encoding with leading zero octet ⇒ non-minimal.
        let bad2 = [0x30, 0x82, 0x00, 0x05, 0x02, 0x01, 0x01, 0x02, 0x00];
        assert!(matches!(read_tlv(&bad2, 0), Err(DerError::NonMinimalLength(0))));
    }

    #[test]
    fn truncated_tlv_rejected() {
        assert!(matches!(read_tlv(&[0x30], 0), Err(DerError::Truncated(_))));
        assert!(matches!(read_tlv(&[0x30, 0x82, 0x01], 0), Err(DerError::Truncated(_))));
        // Contents extending past the buffer.
        assert!(matches!(read_tlv(&[0x30, 0x06, 1, 2], 0), Err(DerError::Truncated(_))));
    }

    #[test]
    fn time_parser_hits_reference_values() {
        // UTCTime 2020-06-15T08:30:00Z → packed 20200615083000.
        assert_eq!(
            parse_time(0x17, b"200615083000Z").unwrap(),
            20_200_615_083_000
        );
        // GeneralizedTime 2045-01-01T00:00:00Z.
        assert_eq!(
            parse_time(0x18, b"20450101000000Z").unwrap(),
            20_450_101_000_000
        );
        // UTCTime century pivot: 49 → 2049, 50 → 1950 (RFC 5280 §4.1.2.5.1).
        assert_eq!(
            parse_time(0x17, b"490101000000Z").unwrap() / 10_000_000_000,
            2049
        );
        assert_eq!(
            parse_time(0x17, b"500101000000Z").unwrap() / 10_000_000_000,
            1950
        );
        // Malformed time content.
        assert!(parse_time(0x17, b"200615083000").is_err());
        assert!(parse_time(0x17, b"002506150830Z").is_err()); // month 25
        assert!(parse_time(0x17, b"200632083000Z").is_err()); // day 32
        assert!(parse_time(0x17, b"200615253000Z").is_err()); // hour 25
    }

    #[test]
    fn civil_from_days_matches_reference_dates() {
        // Unix epoch: 1970-01-01.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // Known SI-second milestone: 1_000_000_000 s ≈ 2001-09-09.
        assert_eq!(civil_from_days(1_000_000_000 / 86_400), (2001, 9, 9));
        // Leap-year date: 2000-02-29 = 10957 + 59 days.
        assert_eq!(civil_from_days(10_957 + 59), (2000, 2, 29));
        // Aggregates across a leap century: 2100-03-01 follows no Feb 29.
        assert_eq!(civil_from_days(10_957 + 36_525 + 59), (2100, 3, 1));
    }
}
