//! Data-only export preparation; no remote backend or database interface.
use crate::*;
use prost::Message;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OutboundRejection {
    #[error(transparent)]
    Policy(#[from] EgressFilterError),
    #[error(transparent)]
    Projection(#[from] BoundaryError),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Media(#[from] StopNciiError),
    #[error("Origin jurisdiction and gateway key ID must be configured")]
    InvalidOrigin,
    #[error("A populated local fingerprint catalog is required for media exports")]
    EmptySafetyCatalog,
    #[error("TMK video matching is not implemented; refusing this export")]
    UnsupportedVideoHash,
}

/// Notices accompany every preparation rejection on a restricted cross-region route.
#[derive(Debug, Error)]
#[error("{reason}")]
pub struct OutboundError {
    pub reason: OutboundRejection,
    pub notices: Vec<InteractionNotice>,
}
impl OutboundError {
    pub fn policy_notices(&self) -> &[InteractionNotice] {
        &self.notices
    }
    pub fn drop_reason_code(&self) -> DropReasonCode {
        match &self.reason {
            OutboundRejection::Policy(e) => e.drop_reason_code(),
            OutboundRejection::Media(e) => e.drop_reason_code(),
            _ => DropReasonCode::DropReasonJurisdictionPolicyViolation,
        }
    }
}

pub(crate) fn check_export(
    origin: Jurisdiction,
    destination: Jurisdiction,
    event: &CrossBorderEventPayload,
    filter: &PreflightEgressFilter,
    safety: &StopNciiEngine,
) -> Result<Vec<InteractionNotice>, OutboundError> {
    let assessment = filter.assess_interaction(origin, destination, &event.text_content);
    let notices = assessment.notices;
    let check = || -> Result<(), OutboundRejection> {
        assessment.result?;
        crate::boundary::validate_event(event, origin)?;
        let author = event.author.as_ref().expect("validated author");
        // Names and optionally approved avatars must not bypass text policy.
        for text in [
            &author.handle,
            &author.display_name,
            &author.public_avatar_url,
        ] {
            filter
                .assess_interaction(origin, destination, text)
                .result?;
        }
        for media in &event.media_hashes {
            if !media.tmk_hash.is_empty() {
                return Err(OutboundRejection::UnsupportedVideoHash);
            }
            if safety.is_empty() {
                return Err(OutboundRejection::EmptySafetyCatalog);
            }
            safety.evaluate_raw_bytes(&media.pdq_hash)?;
        }
        Ok(())
    };
    check().map_err(|reason| OutboundError {
        reason,
        notices: notices.clone(),
    })?;
    Ok(notices)
}

/// Call after domestic acceptance. Errors never mutate or delete a domestic event.
/// This type owns no database connection and makes no network requests.
pub struct OutboundGateway<'a> {
    origin: Jurisdiction,
    key_id: String,
    signer: &'a GatewaySigner,
    filter: &'a PreflightEgressFilter,
    safety: &'a StopNciiEngine,
}
impl<'a> OutboundGateway<'a> {
    pub fn new(
        origin: Jurisdiction,
        key_id: String,
        signer: &'a GatewaySigner,
        filter: &'a PreflightEgressFilter,
        safety: &'a StopNciiEngine,
    ) -> Result<Self, OutboundError> {
        if origin == Jurisdiction::Unspecified || key_id.trim().is_empty() || key_id.len() > 256 {
            return Err(OutboundError {
                reason: OutboundRejection::InvalidOrigin,
                notices: vec![],
            });
        }
        Ok(Self {
            origin,
            key_id,
            signer,
            filter,
            safety,
        })
    }

    /// Recommended boundary: construct the approved minimal profile and opaque IDs
    /// locally. Neither raw profiles nor local ID mappings are returned to the peer.
    pub fn prepare_local(
        &self,
        destination: Jurisdiction,
        raw: &RawInternalUserProfile,
        pepper: &RegionalPepper,
        draft: &LocalEventDraft,
    ) -> Result<FederatedEventEnvelope, OutboundError> {
        let event =
            crate::boundary::project_local_event(raw, self.origin, pepper, draft).map_err(|e| {
                OutboundError {
                    reason: OutboundRejection::Identity(e),
                    notices: self
                        .filter
                        .assess_interaction(self.origin, destination, "")
                        .notices,
                }
            })?;
        self.prepare(destination, &event)
    }

    /// Advanced API for already approved projections. It validates shape, routing,
    /// policy and media, but cannot detect every sensitive value inside arbitrary text.
    pub fn prepare(
        &self,
        destination: Jurisdiction,
        event: &CrossBorderEventPayload,
    ) -> Result<FederatedEventEnvelope, OutboundError> {
        let notices = check_export(self.origin, destination, event, self.filter, self.safety)?;
        let mut envelope = FederatedEventEnvelope {
            payload_bytes: event.encode_to_vec(),
            origin_jurisdiction: self.origin as i32,
            destination_jurisdiction: destination as i32,
            origin_gateway_key_id: self.key_id.clone(),
            policy_notices: notices.iter().map(|n| *n as i32).collect(),
            ..Default::default()
        };
        self.signer.sign_envelope(&mut envelope);
        Ok(envelope)
    }
}
