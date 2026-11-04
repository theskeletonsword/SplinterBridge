//! SplinterBridge Core Gateway Engine.
//!
//! Provides the primary orchestration engine for server-to-server (S2S)
//! cross-border federation between isolated sovereign social networks.

pub mod boundary;
pub mod identity;
pub mod inbound;
pub mod outbound;

pub use boundary::{
    derive_federated_reference, BoundaryError, LocalEventDraft, LocalEventTarget, MAX_EVENT_BYTES,
};
pub use inbound::{AcceptedEvent, InboundError, InboundGateway, TrustedGateway};
pub use outbound::{OutboundError, OutboundGateway, OutboundRejection};

pub use identity::{
    derive_federated_did, project_blind_profile, project_blind_profile_with_options, GatewaySigner,
    GatewayVerifier, IdentityError, PublicProfileOptions, RawInternalUserProfile, RegionalPepper,
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
