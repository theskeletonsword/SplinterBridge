//! Receive approved projections using locally configured gateway trust, never remote DB lookups.
use crate::*;
use prost::Message;
use thiserror::Error;

/// Configure locally. Never construct this from envelope-supplied identity or key data.
pub struct TrustedGateway {
    pub key_id: String,
    pub origin: Jurisdiction,
    pub public_key: [u8; 32],
}

#[derive(Debug, Error)]
pub enum InboundError {
    #[error("Untrusted peer, wrong destination, or invalid route")]
    UntrustedRoute,
    #[error("Envelope exceeds size limits or uses a non-canonical/unknown payload")]
    InvalidPayload,
    #[error("Hardware attestations require a verifier not implemented here")]
    UnsupportedAttestation,
    #[error(transparent)]
    Signature(#[from] IdentityError),
    #[error(transparent)]
    Content(#[from] OutboundError),
    #[error("Missing or unexpected route notices")]
    InvalidNotices,
    #[error("Optional public profile fields were not approved by this receiver")]
    UnapprovedProfileFields,
}

#[derive(Debug)]
pub struct AcceptedEvent {
    pub payload: CrossBorderEventPayload,
    pub notices: Vec<InteractionNotice>,
}

/// Verifies projections only. Callers must still enforce replay protection,
/// authenticated transport, local storage authorization and UI display.
pub struct InboundGateway<'a> {
    local: Jurisdiction,
    filter: &'a PreflightEgressFilter,
    safety: &'a StopNciiEngine,
    profile_options: PublicProfileOptions,
}
impl<'a> InboundGateway<'a> {
    pub fn new(
        local: Jurisdiction,
        filter: &'a PreflightEgressFilter,
        safety: &'a StopNciiEngine,
    ) -> Result<Self, InboundError> {
        if local == Jurisdiction::Unspecified {
            return Err(InboundError::UntrustedRoute);
        }
        Ok(Self {
            local,
            filter,
            safety,
            profile_options: PublicProfileOptions::default(),
        })
    }

    /// Opt in locally to public extras; the sender cannot choose this setting.
    pub fn with_profile_options(mut self, options: PublicProfileOptions) -> Self {
        self.profile_options = options;
        self
    }

    pub fn accept(
        &self,
        envelope: &FederatedEventEnvelope,
        trusted: &TrustedGateway,
    ) -> Result<AcceptedEvent, InboundError> {
        if envelope.encoded_len() > MAX_EVENT_BYTES + 4096 {
            return Err(InboundError::InvalidPayload);
        }
        if trusted.origin == Jurisdiction::Unspecified
            || trusted.key_id.trim().is_empty()
            || envelope.origin_gateway_key_id != trusted.key_id
            || envelope.origin_jurisdiction != trusted.origin as i32
            || envelope.destination_jurisdiction != self.local as i32
        {
            return Err(InboundError::UntrustedRoute);
        }
        GatewayVerifier::verify_envelope(&trusted.public_key, envelope)?;
        if envelope.humanity_attestation.is_some() {
            return Err(InboundError::UnsupportedAttestation);
        }
        let event = CrossBorderEventPayload::decode(envelope.payload_bytes.as_slice())
            .map_err(|_| InboundError::InvalidPayload)?;
        // Reject unknown/duplicate fields instead of silently forwarding hidden data.
        if event.encode_to_vec() != envelope.payload_bytes {
            return Err(InboundError::InvalidPayload);
        }
        let notices = crate::outbound::check_export(
            trusted.origin,
            self.local,
            &event,
            self.filter,
            self.safety,
        )?;
        if envelope.policy_notices != notices.iter().map(|n| *n as i32).collect::<Vec<_>>() {
            return Err(InboundError::InvalidNotices);
        }
        let author = event.author.as_ref().expect("validated author");
        if (!self.profile_options.avatar && !author.public_avatar_url.is_empty())
            || (!self.profile_options.following_count && author.following_count != 0)
            || (!self.profile_options.badges && !author.badges.is_empty())
        {
            return Err(InboundError::UnapprovedProfileFields);
        }
        Ok(AcceptedEvent {
            payload: event,
            notices,
        })
    }
}
