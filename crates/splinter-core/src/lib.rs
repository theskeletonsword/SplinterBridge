//! SplinterBridge Core Gateway Engine.
//!
//! Provides the primary orchestration engine for server-to-server (S2S)
//! cross-border federation between isolated sovereign social networks.

pub mod attestation;
pub mod audit_log;
pub mod boundary;
pub mod differential_privacy;
pub mod doj_compliance;
pub mod ephemeral;
pub mod hsm;
pub mod identity;
pub mod inbound;
pub mod killswitch;
pub mod merkle;
pub mod outbound;
pub mod outbox;
pub mod rate_limit;
pub mod replay;
pub mod review;
pub use review::*;
#[cfg(unix)]
pub mod local_classifier;
#[cfg(unix)]
pub use local_classifier::UnixGrpcClassifier;

pub use boundary::{
    derive_federated_reference, BoundaryError, LocalEventDraft, LocalEventTarget, MAX_EVENT_BYTES,
};
pub use inbound::{AcceptedEvent, InboundError, InboundGateway, TrustedGateway};
pub use outbound::{OutboundError, OutboundGateway, OutboundRejection};

pub use attestation::{
    AttestationError, AttestationReport, AttestationVerifier, DenyAllAttestation, EnclaveType,
};
pub use audit_log::{AuditLog, AuditLogError, AuditRecord, NoopAuditLog};
pub use differential_privacy::{
    gaussian_noise, k_anonymous_bucket, laplace_noise, noisy_count, DifferentialPrivacyError,
};
pub use doj_compliance::{
    ContentClassification, ContentClassifier, DenyAllClassifier, DenyAllPaFacade,
    DojComplianceError, PaFacadeChecker,
};
pub use ephemeral::{
    derive_ephemeral_did, valid_ephemeral_did, EphemeralPepper, EphemeralSession, EphemeralVault,
    DEFAULT_EPOCH_SECONDS,
};
pub use hsm::{HsmError, HsmSigner, SoftwareHsm};
pub use identity::{
    derive_federated_did, project_blind_profile, project_blind_profile_with_options, GatewaySigner,
    GatewayVerifier, IdentityError, PublicProfileOptions, RawInternalUserProfile, RegionalPepper,
};
pub use killswitch::{DefaultKillSwitch, KillSwitch, KillSwitchError, KillSwitchStatus};
pub use outbox::{Inbox, NoopInbox, NoopOutbox, Outbox, OutboxError};
pub use rate_limit::{NoopRateLimiter, RateLimitError, RateLimitVerdict, RateLimiter, TokenBucket};
pub use replay::{
    ReplayCache, ReplayCacheError, SlidingWindowReplayCache, DEFAULT_REPLAY_WINDOW_SECONDS,
};
pub use splinter_filter::{EgressFilterError, InteractionAssessment, PreflightEgressFilter};
pub use splinter_proto::*;
pub use splinter_safety::{PdqHash, StopNciiEngine, StopNciiError, DEFAULT_PDQ_HAMMING_THRESHOLD};

#[cfg(test)]
mod boundary_tests;

/// Suggested English client disclaimer; adapters decide placement and localization.
pub fn interaction_notice_en(notice: InteractionNotice) -> Option<&'static str> {
    match notice {
        InteractionNotice::ChinaCrossBorderRules => Some(
            "This interaction connects an overseas service with a service in mainland China. \
             China-route content restrictions apply, and some messages may be rejected. \
             Conversations exclusively between overseas users do not use this China-specific filter.",
        ),
        _ => None,
    }
}
