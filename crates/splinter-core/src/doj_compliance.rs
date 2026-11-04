//! DOJ / CFIUS compliance layer (28 CFR Part 202, EO 14117, PAFACA).
//!
//! This module provides minimal trait interfaces so operators can restrict the
//! wire protocol to **public expressive material only** and reject any payload
//! that could qualify as "bulk sensitive personal data" under the DOJ Data
//! Security Program. It does not implement a DOJ ruling or an advisory opinion;
//! those are legal processes the operator must pursue with DOJ NSD.

use splinter_proto::Jurisdiction;
use thiserror::Error;

/// Errors from DOJ compliance checks.
#[derive(Debug, Error)]
pub enum DojComplianceError {
    #[error("DOJ compliance unavailable")]
    Unavailable,
    #[error("content is not classified as public expressive material")]
    NotExpressiveMaterial,
    #[error("payload contains bulk sensitive personal data")]
    BulkSensitiveData,
    #[error("operational relationship prohibited by PAFACA")]
    OperationalRelationshipProhibited,
}

/// Classification of outbound payload under DOJ 28 CFR Part 202.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentClassification {
    /// Public expressive material (video, comment, audio, opinion). Permitted
    /// under the Berman Amendment / 28 CFR § 202 expressive-materials exemption.
    PublicExpressive,
    /// Bulk sensitive personal data (telemetry, behavior signals, biometrics,
    /// private social graph). Prohibited for cross-border transfer.
    BulkSensitive,
    /// Unclassified; default to blocking.
    Unclassified,
}

/// Trait for classifying whether a candidate payload is public expressive
/// material or bulk sensitive personal data.
///
/// Implementations must:
/// - Inspect only wire-visible fields (text, media hashes, public profile).
/// - Never inspect internal IDs, telemetry, or behavior signals.
/// - Return `Unclassified` (block) when uncertain — fail-closed.
pub trait ContentClassifier: Send + Sync {
    /// Classifies `content` for cross-border egress under DOJ rules.
    fn classify(
        &self,
        content: &CandidateContent,
    ) -> Result<ContentClassification, DojComplianceError>;
}

/// Minimal representation of a candidate outbound payload for DOJ review.
#[derive(Debug, Clone)]
pub struct CandidateContent {
    /// Public text content (post, comment, caption).
    pub text: String,
    /// Public media perceptual hashes only (no raw media, no telemetry).
    pub media_hash_count: usize,
    /// Whether the payload carries any behavioral/telemetry signal.
    pub has_behavioral_signal: bool,
    /// Whether the payload carries a private social graph or follower list.
    pub has_private_graph: bool,
}

/// Default classifier: blocks everything unless explicitly allowed.
pub struct DenyAllClassifier;

impl ContentClassifier for DenyAllClassifier {
    fn classify(
        &self,
        _content: &CandidateContent,
    ) -> Result<ContentClassification, DojComplianceError> {
        Err(DojComplianceError::NotExpressiveMaterial)
    }
}

impl Default for DenyAllClassifier {
    fn default() -> Self {
        Self
    }
}

/// Permissive classifier for development only. Production must replace with a
/// DOJ-reviewed classifier that verifies expressive-material status.
pub struct AllowExpressiveClassifier;

impl ContentClassifier for AllowExpressiveClassifier {
    fn classify(
        &self,
        content: &CandidateContent,
    ) -> Result<ContentClassification, DojComplianceError> {
        if content.has_behavioral_signal || content.has_private_graph {
            return Err(DojComplianceError::BulkSensitiveData);
        }
        Ok(ContentClassification::PublicExpressive)
    }
}

/// Enforces PAFACA operational-relationship separation: content federation is
/// permitted, algorithmic / recommendation feed synchronization is prohibited.
pub trait PaFacadeChecker: Send + Sync {
    /// Returns `Ok(())` if the route is a content-only syndication (RSS-like)
    /// and not a recommendation-algorithm sharing relationship.
    fn check_route_relationship(
        &self,
        origin: Jurisdiction,
        destination: Jurisdiction,
    ) -> Result<(), DojComplianceError>;
}

/// Default PAFACA checker: denies all cross-border routes until explicitly
/// configured by the operator's legal team.
pub struct DenyAllPaFacade;

impl PaFacadeChecker for DenyAllPaFacade {
    fn check_route_relationship(
        &self,
        _origin: Jurisdiction,
        _destination: Jurisdiction,
    ) -> Result<(), DojComplianceError> {
        Err(DojComplianceError::OperationalRelationshipProhibited)
    }
}

impl Default for DenyAllPaFacade {
    fn default() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_all_classifier_blocks_everything() {
        let classifier = DenyAllClassifier;
        let content = CandidateContent {
            text: "hello".into(),
            media_hash_count: 0,
            has_behavioral_signal: false,
            has_private_graph: false,
        };
        assert!(classifier.classify(&content).is_err());
    }

    #[test]
    fn allow_expressive_blocks_behavioral_signals() {
        let classifier = AllowExpressiveClassifier;
        let bad = CandidateContent {
            text: "hello".into(),
            media_hash_count: 1,
            has_behavioral_signal: true,
            has_private_graph: false,
        };
        assert!(matches!(
            classifier.classify(&bad),
            Err(DojComplianceError::BulkSensitiveData)
        ));
        let good = CandidateContent {
            text: "public opinion".into(),
            media_hash_count: 1,
            has_behavioral_signal: false,
            has_private_graph: false,
        };
        assert_eq!(
            classifier.classify(&good).unwrap(),
            ContentClassification::PublicExpressive
        );
    }

    #[test]
    fn deny_all_pafacda_blocks_all_routes() {
        let checker = DenyAllPaFacade;
        use splinter_proto::Jurisdiction;
        assert!(checker
            .check_route_relationship(Jurisdiction::GlobalGdpr, Jurisdiction::CnPiplCac)
            .is_err());
    }
}
