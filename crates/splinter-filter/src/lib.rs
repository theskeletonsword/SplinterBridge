//! SplinterBridge Egress Pre-flight Interception Engine.
//!
//! Local destination-specific keyword matching against example catalogs.
//! Callers must invoke this check before dispatching events. Literal matches
//! do not establish legal compliance or perform semantic content classification.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use splinter_proto::{DropReasonCode, InteractionNotice, Jurisdiction};
use thiserror::Error;

/// Structured error returned when an outbound event violates sovereign boundary policies.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EgressFilterError {
    #[error("POLICY_KEYWORD")]
    CacViolation { drop_code: DropReasonCode },

    #[error("POLICY_KEYWORD")]
    RknViolation { drop_code: DropReasonCode },

    #[error("Unsupported or unspecified destination jurisdiction: {0:?}")]
    InvalidJurisdiction(Jurisdiction),

    #[error("DIRECT_PII_DETECTED")]
    DirectPiiDetected { drop_code: DropReasonCode },
}

impl EgressFilterError {
    /// Returns the canonical protocol buffer drop code.
    pub fn drop_reason_code(&self) -> DropReasonCode {
        match self {
            Self::CacViolation { drop_code, .. } => *drop_code,
            Self::RknViolation { drop_code, .. } => *drop_code,
            Self::DirectPiiDetected { drop_code, .. } => *drop_code,
            Self::InvalidJurisdiction(_) => DropReasonCode::DropReasonJurisdictionPolicyViolation,
        }
    }
}

/// UI notices are available even if text is rejected. Platforms should assess
/// the route before opening the composer, then recheck content at submission.
#[derive(Debug)]
pub struct InteractionAssessment {
    pub notices: Vec<InteractionNotice>,
    pub result: Result<(), EgressFilterError>,
}

/// Metadata associated with a compiled rule in the Aho-Corasick automaton.
#[derive(Debug, Clone)]
struct RuleMeta {
    term: &'static str,
}

/// High-throughput in-memory pre-flight filter for outbound federated events.
pub struct PreflightEgressFilter {
    cac_automaton: AhoCorasick,
    rkn_automaton: AhoCorasick,
}

impl Default for PreflightEgressFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl PreflightEgressFilter {
    /// Initializes and compiles in-memory Aho-Corasick search automata for sovereign egress rules.
    pub fn new() -> Self {
        // Illustrative local catalog; not an authoritative regulatory list.
        let cac_definitions: Vec<RuleMeta> = vec![
            RuleMeta { term: "8964" },
            RuleMeta { term: "tiananmen" },
            RuleMeta {
                term: "tiananmen square",
            },
            RuleMeta { term: "天安门" },
            RuleMeta { term: "六四" },
            RuleMeta { term: "6月4日" },
            RuleMeta { term: "june 4" },
            RuleMeta {
                term: "winnie the pooh",
            },
            RuleMeta {
                term: "小熊维尼"
            },
            RuleMeta { term: "维尼熊" },
            RuleMeta { term: "falun" },
            RuleMeta { term: "法轮" },
            RuleMeta { term: "法輪" },
            RuleMeta { term: "tank man" },
            RuleMeta { term: "王维林" },
        ];

        // Illustrative destination-specific catalog; not a legal classification.
        let rkn_definitions: Vec<RuleMeta> = vec![
            RuleMeta {
                term: "война против украины",
            },
            RuleMeta {
                term: "экстремистская организация",
            },
            RuleMeta {
                term: "дискредитация вс рф",
            },
            RuleMeta {
                term: "feygin live",
            },
            RuleMeta { term: "meduza" },
            RuleMeta { term: "fbk" },
            RuleMeta { term: "фбк" },
            RuleMeta {
                term: "штабы навального",
            },
        ];

        let cac_patterns: Vec<&str> = cac_definitions.iter().map(|r| r.term).collect();
        let cac_automaton = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostFirst)
            .build(&cac_patterns)
            .expect("Failed to build CAC Aho-Corasick automaton");

        let rkn_patterns: Vec<&str> = rkn_definitions.iter().map(|r| r.term).collect();
        let rkn_automaton = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostFirst)
            .build(&rkn_patterns)
            .expect("Failed to build RKN Aho-Corasick automaton");

        Self {
            cac_automaton,
            rkn_automaton,
        }
    }

    /// Evaluate both endpoint jurisdictions. China rules apply when either
    /// endpoint is China; two overseas endpoints do not inherit China rules.
    /// This function may also be used by domestic moderation before local commit.
    /// Route jurisdictions must come from trusted backend configuration.
    pub fn assess_interaction(
        &self,
        origin: Jurisdiction,
        destination: Jurisdiction,
        text: &str,
    ) -> InteractionAssessment {
        if origin == Jurisdiction::Unspecified || destination == Jurisdiction::Unspecified {
            return InteractionAssessment {
                notices: Vec::new(),
                result: Err(EgressFilterError::InvalidJurisdiction(
                    Jurisdiction::Unspecified,
                )),
            };
        }
        let origin_cn = origin == Jurisdiction::CnPiplCac;
        let destination_cn = destination == Jurisdiction::CnPiplCac;
        let notices = if origin_cn != destination_cn {
            vec![InteractionNotice::ChinaCrossBorderRules]
        } else {
            Vec::new()
        };
        let result = if origin_cn || destination_cn {
            self.check_text(Jurisdiction::CnPiplCac, text)
                .and_then(|()| self.check_text(destination, text))
        } else {
            self.check_text(destination, text)
        };
        InteractionAssessment { notices, result }
    }

    /// Scans text for directly identifying personal information (email, phone,
    /// IPv4 address, or national identifier). Returns an error when
    /// direct PII is detected so the export is blocked before crossing the
    /// border. Errors never echo the matched value.
    pub fn scan_direct_pii(&self, text: &str) -> Result<(), EgressFilterError> {
        if contains_email(text)
            || contains_phone(text)
            || contains_ipv4(text)
            || contains_national_id(text)
        {
            return Err(EgressFilterError::DirectPiiDetected {
                drop_code: DropReasonCode::DropReasonDirectPiiDetected,
            });
        }
        Ok(())
    }

    /// Evaluates text payload against the target destination jurisdiction in memory.
    /// Returns `Ok(())` when no catalog term matches, or `Err(EgressFilterError)`
    /// if the payload must be dropped before crossing borders.
    pub fn check_text(
        &self,
        destination: Jurisdiction,
        text: &str,
    ) -> Result<(), EgressFilterError> {
        let normalized = normalize_for_matching(text);
        match destination {
            Jurisdiction::CnPiplCac => {
                if self.cac_automaton.is_match(&normalized) {
                    return Err(EgressFilterError::CacViolation {
                        drop_code: DropReasonCode::DropReasonCacEgressRestrictedTerm,
                    });
                }
                Ok(())
            }
            Jurisdiction::Ru152Fz => {
                if self.rkn_automaton.is_match(&normalized) {
                    return Err(EgressFilterError::RknViolation {
                        drop_code: DropReasonCode::DropReasonRknEgressRestrictedTerm,
                    });
                }
                Ok(())
            }
            Jurisdiction::GlobalGdpr => {
                // Outbound towards Global GDPR: no sovereign egress restrictions applied here.
                Ok(())
            }
            Jurisdiction::Unspecified => Err(EgressFilterError::InvalidJurisdiction(destination)),
        }
    }
}

/// Matching copy only: lowercase, fold fullwidth ASCII, remove common invisible
/// format controls, and collapse whitespace. No rewrite of the local original.
/// This is NOT complete NFKC, confusable detection or semantic classification.
fn normalize_for_matching(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut whitespace = false;
    for ch in text.chars().flat_map(|c| {
        let c = if ('\u{ff01}'..='\u{ff5e}').contains(&c) {
            char::from_u32(c as u32 - 0xfee0).unwrap()
        } else {
            c
        };
        c.to_lowercase()
    }) {
        if matches!(ch, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
        {
            continue;
        }
        if ch.is_whitespace() {
            if !whitespace {
                result.push(' ');
            }
            whitespace = true;
        } else {
            result.push(ch);
            whitespace = false;
        }
    }
    result
}

/// Detects an email-like token (`local@domain.tld`). Value-free: never returns
/// the matched text.
fn contains_email(text: &str) -> bool {
    let Some(at) = text.find('@') else {
        return false;
    };
    let Some(domain) = text.get(at + 1..) else {
        return false;
    };
    domain.contains('.') && domain.len() >= 3
}

/// Detects a phone-like sequence of 7+ digits. Value-free: never returns the
/// matched text.
fn contains_phone(text: &str) -> bool {
    let digits: u32 = text.chars().filter(|c| c.is_ascii_digit()).count() as u32;
    digits >= 7
}

/// Detects a generic national identifier (digits with dot/space/dash separators
/// and a trailing check digit). Country-agnostic: matches common national-ID
/// formats worldwide without assuming any specific country. Value-free: never
/// returns the matched text.
fn contains_national_id(text: &str) -> bool {
    // Work on bytes: a match is all ASCII, and UTF-8 continuation bytes are never
    // ASCII, so this cannot split or misread a multi-byte character (CJK text).
    text.as_bytes().windows(12).any(is_national_id_shape)
}

/// Matches a 12-byte window against `dd s ddd s ddd s C`, where `s` is one of
/// `.`, space or `-`. The trailing check character is only required to be ASCII
/// alphanumeric: check-digit algorithms vary by country and cannot be validated
/// without knowing the issuer.
fn is_national_id_shape(window: &[u8]) -> bool {
    let separator = |b: u8| matches!(b, b'.' | b' ' | b'-');
    window[..2]
        .iter()
        .chain(&window[3..6])
        .chain(&window[7..10])
        .all(u8::is_ascii_digit)
        && separator(window[2])
        && separator(window[6])
        && separator(window[10])
        && window[11].is_ascii_alphanumeric()
}

/// Detects an IPv4 address with each octet in 0..=255. Value-free.
fn contains_ipv4(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() && try_ipv4_from(text, i).is_some() {
            return true;
        }
        i += 1;
    }
    false
}

/// Attempts to read four dot-separated octets starting at `start`.
/// Returns the position just after the last octet on success.
fn try_ipv4_from(text: &str, start: usize) -> Option<usize> {
    let mut pos = start;
    for octet_idx in 0..4 {
        let dig_start = pos;
        let mut dig_len = 0;
        while pos < text.len() && text.as_bytes()[pos].is_ascii_digit() && dig_len < 3 {
            dig_len += 1;
            pos += 1;
        }
        if dig_len == 0 {
            return None;
        }
        // Reject leading zeros (e.g. "01") except for "0" itself.
        if dig_len > 1 && text.as_bytes()[dig_start] == b'0' {
            return None;
        }
        // parse::<u8>() already rejects values above 255.
        let _octet: u8 = text[dig_start..pos].parse().ok()?;
        if octet_idx < 3 {
            if pos >= text.len() || text.as_bytes()[pos] != b'.' {
                return None;
            }
            pos += 1;
        }
    }
    Some(pos)
}

pub mod catalog;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_copy_normalizes_common_variants_and_errors_are_value_free() {
        let filter = PreflightEgressFilter::new();
        for text in [
            "ＴＩＡＮＡＮＭＥＮ",
            "Tian\u{200b}anmen",
            "Winnie\n\t the\u{a0}Pooh",
        ] {
            let error = filter
                .check_text(Jurisdiction::CnPiplCac, text)
                .unwrap_err();
            assert_eq!(error.to_string(), "POLICY_KEYWORD");
            let diagnostic = format!("{error:?}");
            assert!(!diagnostic.to_lowercase().contains("tiananmen"));
            assert!(!diagnostic.to_lowercase().contains("pooh"));
            assert!(filter
                .assess_interaction(Jurisdiction::GlobalGdpr, Jurisdiction::GlobalGdpr, text)
                .result
                .is_ok());
        }
    }

    #[test]
    fn interaction_matrix_is_symmetric_for_china_and_leaves_overseas_free() {
        let filter = PreflightEgressFilter::new();
        use Jurisdiction::{CnPiplCac as Cn, GlobalGdpr as Global};
        for text in ["Tiananmen", "Winnie the Pooh", "天安门", "小熊维尼"] {
            for (origin, destination, blocked, notice) in [
                (Global, Global, false, false),
                (Global, Cn, true, true),
                (Cn, Global, true, true),
                (Cn, Cn, true, false),
            ] {
                let assessment = filter.assess_interaction(origin, destination, text);
                assert_eq!(
                    assessment.result.is_err(),
                    blocked,
                    "{origin:?} -> {destination:?}: {text}"
                );
                assert_eq!(!assessment.notices.is_empty(), notice);
            }
        }
        for (origin, destination) in [(Global, Cn), (Cn, Global)] {
            let assessment = filter.assess_interaction(origin, destination, "Hello!");
            assert!(assessment.result.is_ok());
            assert_eq!(
                assessment.notices,
                vec![InteractionNotice::ChinaCrossBorderRules]
            );
        }
        assert!(filter
            .assess_interaction(Jurisdiction::Unspecified, Global, "hello")
            .result
            .is_err());
    }

    #[test]
    fn test_benign_content_passes_cac() {
        let filter = PreflightEgressFilter::new();
        let benign = "Exploring the beauty of Guilin mountains and traditional tea ceremonies!";
        assert!(filter.check_text(Jurisdiction::CnPiplCac, benign).is_ok());
    }

    #[test]
    fn test_cac_prohibited_terms_intercepted() {
        let filter = PreflightEgressFilter::new();

        let post_with_tiananmen = "Remembering what happened near Tiananmen back in the day.";
        let err1 = filter
            .check_text(Jurisdiction::CnPiplCac, post_with_tiananmen)
            .unwrap_err();
        assert_eq!(
            err1.drop_reason_code(),
            DropReasonCode::DropReasonCacEgressRestrictedTerm
        );

        let post_with_8964 = "Historical event 8964 discussion";
        let err2 = filter
            .check_text(Jurisdiction::CnPiplCac, post_with_8964)
            .unwrap_err();
        assert_eq!(
            err2.drop_reason_code(),
            DropReasonCode::DropReasonCacEgressRestrictedTerm
        );

        let post_with_pooh = "Look at this cute Winnie the Pooh costume!";
        let err3 = filter
            .check_text(Jurisdiction::CnPiplCac, post_with_pooh)
            .unwrap_err();
        assert_eq!(
            err3.drop_reason_code(),
            DropReasonCode::DropReasonCacEgressRestrictedTerm
        );
    }

    #[test]
    fn test_rkn_prohibited_terms_intercepted() {
        let filter = PreflightEgressFilter::new();

        let rkn_post = "Новый выпуск на канале ФБК уже в сети.";
        let err = filter
            .check_text(Jurisdiction::Ru152Fz, rkn_post)
            .unwrap_err();
        assert_eq!(
            err.drop_reason_code(),
            DropReasonCode::DropReasonRknEgressRestrictedTerm
        );
    }

    #[test]
    fn test_cyrillic_case_variants() {
        let filter = PreflightEgressFilter::new();
        for text in ["ФБК", "ФбК", "фбк"] {
            assert!(filter.check_text(Jurisdiction::Ru152Fz, text).is_err());
        }
        assert!(filter
            .check_text(Jurisdiction::Unspecified, "hello")
            .is_err());
    }

    #[test]
    fn test_cross_border_isolation() {
        let filter = PreflightEgressFilter::new();

        // A post containing 'Winnie the Pooh' sent towards Global/GDPR is unrestricted
        let text = "Winnie the Pooh meme for friends";
        assert!(filter.check_text(Jurisdiction::GlobalGdpr, text).is_ok());
    }

    #[test]
    fn scan_direct_pii_blocks_identifiers_without_echoing_them() {
        let filter = PreflightEgressFilter::new();
        for text in [
            "contact me at user@example.com",
            "call +56 9 8765 4321",
            "server at 192.168.1.100",
            "my national ID is 11.111.111-1",
        ] {
            let err = filter.scan_direct_pii(text).unwrap_err();
            let diag = format!("{err:?}");
            assert!(!diag.to_lowercase().contains("example.com"));
            assert!(!diag.to_lowercase().contains("192.168"));
            assert!(!diag.to_lowercase().contains("11.111"));
            assert_eq!(
                err.drop_reason_code(),
                DropReasonCode::DropReasonDirectPiiDetected
            );
        }
        assert!(filter
            .scan_direct_pii("just a normal post about music")
            .is_ok());
        // Any national-ID-shaped value must trigger (check-digit algorithms
        // vary by country and cannot be validated universally).
        assert!(filter
            .scan_direct_pii("my national ID is 11.111.111-9")
            .is_err());
    }

    #[test]
    fn scan_direct_pii_handles_multibyte_text_without_panicking() {
        // Regression: slicing &str by byte offsets panicked on CJK/Cyrillic text,
        // so any long Chinese post crashed both outbound and inbound checks.
        let filter = PreflightEgressFilter::new();
        for text in [
            "我今天在北京吃了很好吃的饺子，真开心",
            "Привет, как дела? Всё хорошо, спасибо",
            "混合 mixed текст 😀 with emoji and 中文",
        ] {
            assert!(filter.scan_direct_pii(text).is_ok(), "{text}");
        }
        // Identifiers embedded in multi-byte text are still detected.
        assert!(contains_national_id("身份证 11.111.111-1 号码"));
        assert!(contains_national_id("ID: 12 345 678 K"));
        assert!(!contains_national_id("11.111.111"));
        assert!(!contains_national_id("ab.cde.fgh-1x"));
        assert!(filter.scan_direct_pii("邮箱 user@example.com").is_err());
    }
}
