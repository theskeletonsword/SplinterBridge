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
    #[error("No replay cache configured; refusing to accept envelopes")]
    ReplayProtectionNotConfigured,
    #[error(transparent)]
    Replay(#[from] ReplayCacheError),
    #[error("Peer rate limit exceeded; retry after {retry_after_ms} ms")]
    RateLimited { retry_after_ms: u64 },
    #[error("Rate limiter unavailable")]
    RateLimiterUnavailable,
    #[error("Kill switch tripped")]
    KillSwitchTripped,
    #[error("Audit log unavailable")]
    AuditUnavailable,
}

impl InboundError {
    /// Value-free rejection code, also used in audit records.
    pub fn code(&self) -> &'static str {
        match self {
            InboundError::UntrustedRoute => "UNTRUSTED_ROUTE",
            InboundError::InvalidPayload => "INVALID_PAYLOAD",
            InboundError::UnsupportedAttestation => "UNSUPPORTED_ATTESTATION",
            InboundError::Signature(_) => "INVALID_SIGNATURE",
            InboundError::Content(e) => e.code(),
            InboundError::InvalidNotices => "INVALID_NOTICES",
            InboundError::UnapprovedProfileFields => "UNKNOWN_FIELD",
            InboundError::ReplayProtectionNotConfigured => "REPLAY_PROTECTION_NOT_CONFIGURED",
            InboundError::Replay(ReplayCacheError::ReplayDetected) => "REPLAY_DETECTED",
            InboundError::Replay(ReplayCacheError::StaleTimestamp) => "STALE_TIMESTAMP",
            InboundError::Replay(_) => "REPLAY_CACHE_UNAVAILABLE",
            InboundError::RateLimited { .. } => "RATE_LIMITED",
            InboundError::RateLimiterUnavailable => "RATE_LIMITER_UNAVAILABLE",
            InboundError::KillSwitchTripped => "KILL_SWITCH_TRIPPED",
            InboundError::AuditUnavailable => "AUDIT_UNAVAILABLE",
        }
    }

    /// Wire drop reason for a `FederatedEventResponse`.
    pub fn drop_reason_code(&self) -> DropReasonCode {
        match self {
            InboundError::Signature(_) => DropReasonCode::DropReasonInvalidOriginSignature,
            InboundError::UnsupportedAttestation => {
                DropReasonCode::DropReasonAttestationVerificationFailed
            }
            InboundError::Replay(_) => DropReasonCode::DropReasonReplayDetected,
            InboundError::Content(e) => e.drop_reason_code(),
            _ => DropReasonCode::DropReasonJurisdictionPolicyViolation,
        }
    }
}

#[derive(Debug)]
pub struct AcceptedEvent {
    pub payload: CrossBorderEventPayload,
    pub notices: Vec<InteractionNotice>,
}

/// Verifies projections and rejects replays. A replay cache is required:
/// `accept` fails closed without one. Callers must still provide authenticated
/// transport, local storage authorization and UI display.
pub struct InboundGateway<'a> {
    local: Jurisdiction,
    filter: &'a PreflightEgressFilter,
    safety: &'a StopNciiEngine,
    profile_options: PublicProfileOptions,
    replay: Option<&'a dyn ReplayCache>,
    rate_limiter: Option<&'a dyn RateLimiter>,
    audit: Option<&'a dyn AuditLog>,
    kill_switch: Option<&'a dyn KillSwitch>,
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
            replay: None,
            rate_limiter: None,
            audit: None,
            kill_switch: None,
        })
    }

    /// Opt in locally to public extras; the sender cannot choose this setting.
    pub fn with_profile_options(mut self, options: PublicProfileOptions) -> Self {
        self.profile_options = options;
        self
    }

    /// Required. Every gateway instance accepting the same route must share it.
    pub fn with_replay_cache(mut self, replay: &'a dyn ReplayCache) -> Self {
        self.replay = Some(replay);
        self
    }

    /// Limits accepted envelopes per trusted peer key. The check runs after the
    /// signature is verified, so unauthenticated traffic cannot drain a peer's
    /// quota; unauthenticated floods belong at the transport or network edge.
    pub fn with_rate_limiter(mut self, limiter: &'a dyn RateLimiter) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Records every accept decision (codes only, never content). If an append
    /// fails, the envelope is rejected.
    pub fn with_audit_log(mut self, audit: &'a dyn AuditLog) -> Self {
        self.audit = Some(audit);
        self
    }

    /// While the switch is tripped every envelope is rejected before any work.
    pub fn with_kill_switch(mut self, kill_switch: &'a dyn KillSwitch) -> Self {
        self.kill_switch = Some(kill_switch);
        self
    }

    pub fn accept(
        &self,
        envelope: &FederatedEventEnvelope,
        trusted: &TrustedGateway,
    ) -> Result<AcceptedEvent, InboundError> {
        let result = self.accept_unaudited(envelope, trusted);
        let Some(log) = self.audit else {
            return result;
        };
        let (outcome, reason) = match &result {
            Ok(_) => ("allowed", None),
            Err(e) => ("rejected", Some(e.code())),
        };
        let record = AuditRecord::new(
            "envelope_accept",
            trusted.origin as u32,
            self.local as u32,
            &trusted.key_id,
            outcome,
            reason,
        );
        match (log.append(&record), result) {
            (Ok(_), result) => result,
            (Err(_), Ok(_)) => Err(InboundError::AuditUnavailable),
            (Err(_), Err(e)) => Err(e),
        }
    }

    fn accept_unaudited(
        &self,
        envelope: &FederatedEventEnvelope,
        trusted: &TrustedGateway,
    ) -> Result<AcceptedEvent, InboundError> {
        if matches!(self.kill_switch, Some(ks) if ks.status() != KillSwitchStatus::Armed) {
            return Err(InboundError::KillSwitchTripped);
        }
        let replay = self
            .replay
            .ok_or(InboundError::ReplayProtectionNotConfigured)?;
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
        if let Some(limiter) = self.rate_limiter {
            match limiter.check(&trusted.key_id) {
                Ok(RateLimitVerdict::Allow) => {}
                Ok(RateLimitVerdict::RetryAfter { retry_after_ms }) => {
                    return Err(InboundError::RateLimited { retry_after_ms });
                }
                Err(_) => return Err(InboundError::RateLimiterUnavailable),
            }
        }
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
        // Last step: only fully valid envelopes consume a nonce. Nonce and
        // timestamp are inside the signed payload, so they cannot be swapped.
        replay.check_and_record(
            trusted.origin as u32,
            self.local as u32,
            event.nonce,
            event.timestamp_epoch_ms,
        )?;
        Ok(AcceptedEvent {
            payload: event,
            notices,
        })
    }
}
