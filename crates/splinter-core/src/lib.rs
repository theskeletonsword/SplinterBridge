//! SplinterBridge Core Gateway Engine.
//!
//! Provides the primary orchestration engine for server-to-server (S2S)
//! cross-border federation between isolated sovereign social networks.

pub mod identity;

pub use identity::{
    derive_federated_did, project_blind_profile, GatewaySigner, GatewayVerifier, IdentityError,
    RawInternalUserProfile, RegionalPepper,
};
pub use splinter_filter::{EgressFilterError, PreflightEgressFilter};
pub use splinter_proto::*;
pub use splinter_safety::{PdqHash, StopNciiEngine, StopNciiError, DEFAULT_PDQ_HAMMING_THRESHOLD};
