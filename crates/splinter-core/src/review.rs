//! Origin-local privacy review. This API has no remote identity/database access.
use crate::{CrossBorderEventPayload, Jurisdiction, PublicProfileOptions};
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin, time::Duration};
use tokio::sync::Semaphore;

pub const REVIEW_POLICY_CODE: &str = "MINIMAL_EGRESS_V1";
pub const MAX_MODEL_RESPONSE_BYTES: usize = 8192;

/// Trusted local configuration, selected independently for each destination.
/// No route is enabled by default. Content needs a separate explicit opt-in.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExportRoutePolicy {
    pub allow_content: bool,
    pub profile_options: PublicProfileOptions,
}

/// Fixed field names prevent rejected values or arbitrary model text entering errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewField {
    Handle,
    DisplayName,
    PublicAvatarUrl,
    TextContent,
}

#[derive(Serialize)]
pub struct ReviewText {
    pub field: ReviewField,
    pub text: String,
}

/// Only approved candidate strings are exposed to the local classifier.
/// There are no account/event IDs, secrets, graphs or raw profile references.
#[derive(Serialize)]
pub struct ReviewInput {
    pub policy_code: &'static str,
    pub origin: i32,
    pub destination: i32,
    pub fields: Vec<ReviewText>,
}
impl std::fmt::Debug for ReviewInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReviewInput { [REDACTED] }")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SemanticDecision {
    Allow,
    ProhibitedPersonalData,
    UncertainPersonalData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldVerdict {
    pub field: ReviewField,
    pub decision: SemanticDecision,
    /// Adapter confidence, 0..=10_000. Must be calibrated on local evaluation data.
    /// An LLM's self-reported score is not a calibrated probability.
    pub confidence_bps: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticReport {
    pub fields: Vec<FieldVerdict>,
}

/// Only bounded, closed-schema JSON is accepted; parser messages never escape.
pub fn parse_semantic_report(bytes: &[u8]) -> Result<SemanticReport, ClassifierFailure> {
    if bytes.len() > MAX_MODEL_RESPONSE_BYTES {
        return Err(ClassifierFailure::InvalidResponse);
    }
    serde_json::from_slice(bytes).map_err(|_| ClassifierFailure::InvalidResponse)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassifierFailure {
    Unavailable,
    InvalidResponse,
}

pub type ClassificationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<SemanticReport, ClassifierFailure>> + Send + 'a>>;

/// Implement using a model hosted and authorized INSIDE the origin region.
/// Futures must be nonblocking and cancellation-safe: dropping one must cancel
/// inference/IO and release its resources. No detached work, remote DB queries,
/// cloud fallback, prompt logging, or identity/attribute inference is permitted.
/// This is a trusted adapter contract, not a network sandbox for arbitrary code.
pub trait SemanticClassifier: Send + Sync {
    fn classify(&self, input: ReviewInput) -> ClassificationFuture<'_>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PrivacyReviewError {
    #[error("PROHIBITED_FIELD")]
    ProhibitedField,
    #[error("UNCERTAIN_PERSONAL_DATA")]
    UncertainPersonalData { field: ReviewField },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("INVALID_REVIEW_CONFIGURATION")]
pub struct InvalidReviewConfiguration;

/// Share one gate across gateways using the same inference capacity. Saturation
/// sheds load immediately; it never queues or retains unreviewed user content.
pub struct SemanticReviewGate<'a> {
    classifier: &'a dyn SemanticClassifier,
    permits: Semaphore,
    deadline: Duration,
    min_confidence_bps: u16,
}

impl<'a> SemanticReviewGate<'a> {
    pub fn new(
        classifier: &'a dyn SemanticClassifier,
        max_in_flight: usize,
        deadline: Duration,
        min_confidence_bps: u16,
    ) -> Result<Self, InvalidReviewConfiguration> {
        if max_in_flight == 0
            || max_in_flight > 65536
            || deadline.is_zero()
            || deadline > Duration::from_secs(120)
            || !(1..=10000).contains(&min_confidence_bps)
        {
            return Err(InvalidReviewConfiguration);
        }
        Ok(Self {
            classifier,
            permits: Semaphore::new(max_in_flight),
            deadline,
            min_confidence_bps,
        })
    }

    pub(crate) async fn review(
        &self,
        origin: Jurisdiction,
        destination: Jurisdiction,
        event: &CrossBorderEventPayload,
    ) -> Result<(), PrivacyReviewError> {
        let uncertain = |field| PrivacyReviewError::UncertainPersonalData { field };
        // Acquire before cloning text: overload must not allocate inference jobs.
        let _permit = self
            .permits
            .try_acquire()
            .map_err(|_| uncertain(ReviewField::Handle))?;
        let author = event.author.as_ref().expect("validated author");
        let mut fields = vec![
            ReviewText {
                field: ReviewField::Handle,
                text: author.handle.clone(),
            },
            ReviewText {
                field: ReviewField::DisplayName,
                text: author.display_name.clone(),
            },
        ];
        if !author.public_avatar_url.is_empty() {
            fields.push(ReviewText {
                field: ReviewField::PublicAvatarUrl,
                text: author.public_avatar_url.clone(),
            });
        }
        if !event.text_content.is_empty() {
            fields.push(ReviewText {
                field: ReviewField::TextContent,
                text: event.text_content.clone(),
            });
        }
        let expected: Vec<_> = fields.iter().map(|f| f.field).collect();
        let input = ReviewInput {
            policy_code: REVIEW_POLICY_CODE,
            origin: origin as i32,
            destination: destination as i32,
            fields,
        };
        let report = tokio::time::timeout(self.deadline, self.classifier.classify(input))
            .await
            .map_err(|_| uncertain(expected[0]))?
            .map_err(|_| uncertain(expected[0]))?;
        // Missing, duplicate or unexpected fields must never turn into approval.
        if report.fields.len() != expected.len()
            || report.fields.iter().any(|v| !expected.contains(&v.field))
        {
            return Err(uncertain(expected[0]));
        }
        for field in &expected {
            if report.fields.iter().filter(|v| v.field == *field).count() != 1 {
                return Err(uncertain(*field));
            }
        }
        for verdict in report.fields {
            if verdict.confidence_bps > 10000 || verdict.confidence_bps < self.min_confidence_bps {
                return Err(uncertain(verdict.field));
            }
            match verdict.decision {
                SemanticDecision::Allow => (),
                SemanticDecision::ProhibitedPersonalData => {
                    return Err(PrivacyReviewError::ProhibitedField)
                }
                SemanticDecision::UncertainPersonalData => return Err(uncertain(verdict.field)),
            }
        }
        Ok(())
    }
}
