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
}

impl EgressFilterError {
    /// Returns the canonical protocol buffer drop code.
    pub fn drop_reason_code(&self) -> DropReasonCode {
        match self {
            Self::CacViolation { drop_code, .. } => *drop_code,
            Self::RknViolation { drop_code, .. } => *drop_code,
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
}
