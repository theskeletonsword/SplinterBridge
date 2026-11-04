//! Data-only export preparation; no remote backend or database interface.
use crate::*;
use prost::Message;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OutboundRejection {
    #[error("ROUTE_NOT_ALLOWED")]
    RouteNotAllowed,
    #[error("CONTENT_NOT_ALLOWED")]
    ContentNotAllowed,
    #[error("UNKNOWN_FIELD")]
    UnapprovedProfileFields,
    #[error(transparent)]
    Privacy(#[from] PrivacyReviewError),
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
    #[error("DIRECT_PII_DETECTED")]
    DirectPii(EgressFilterError),
}

/// Notices accompany every preparation rejection on a restricted cross-region route.
#[derive(Debug, Error)]
#[error("{reason}")]
pub struct OutboundError {
    pub reason: OutboundRejection,
    pub notices: Vec<InteractionNotice>,
}
impl OutboundError {
    /// Value-free review response, suitable for adapter JSON errors. Never send
    /// arbitrary Debug/Display output, model responses or the local input record.
    pub fn review_json(&self) -> serde_json::Value {
        use OutboundRejection::*;
        let code = match &self.reason {
            Privacy(PrivacyReviewError::UncertainPersonalData { field }) => {
                return serde_json::json!({"code": "UNCERTAIN_PERSONAL_DATA", "field": field});
            }
            Privacy(PrivacyReviewError::ProhibitedField) => "PROHIBITED_FIELD",
            Policy(
                EgressFilterError::CacViolation { .. } | EgressFilterError::RknViolation { .. },
            ) => "POLICY_KEYWORD",
            Projection(BoundaryError::PrivateContent) => "PRIVATE_ACCOUNT",
            RouteNotAllowed => "ROUTE_NOT_ALLOWED",
            ContentNotAllowed => "CONTENT_NOT_ALLOWED",
            UnapprovedProfileFields => "UNKNOWN_FIELD",
            DirectPii(_) => "DIRECT_PII_DETECTED",
            Media(_) | EmptySafetyCatalog | UnsupportedVideoHash => "MEDIA_POLICY",
            _ => "INVALID_PROJECTION",
        };
        serde_json::json!({"code": code})
    }
    pub fn policy_notices(&self) -> &[InteractionNotice] {
        &self.notices
    }
    pub fn drop_reason_code(&self) -> DropReasonCode {
        match &self.reason {
            OutboundRejection::Policy(e) => e.drop_reason_code(),
            OutboundRejection::Media(e) => e.drop_reason_code(),
            OutboundRejection::DirectPii(e) => e.drop_reason_code(),
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
    // Validate the route and bounded shapes before inspecting user content.
    let assessment = filter.assess_interaction(origin, destination, "");
    let notices = assessment.notices;
    let check = || -> Result<(), OutboundRejection> {
        assessment.result?;
        crate::boundary::validate_event(event, origin)?;
        // PII-direct scan: block any authored content or public handle/name that
        // carries directly identifying information before it crosses the border.
        let author = event.author.as_ref().expect("validated author");
        for text in [
            &event.text_content,
            &author.handle,
            &author.display_name,
            &author.public_avatar_url,
        ] {
            filter.scan_direct_pii(text).map_err(OutboundRejection::DirectPii)?;
        }
        filter
            .assess_interaction(origin, destination, &event.text_content)
            .result?;
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
/// This type owns no database connection. Its classifier must remain local.
/// New gateways deny all routes until explicitly configured and require review.
pub struct OutboundGateway<'a> {
    origin: Jurisdiction,
    key_id: String,
    signer: &'a GatewaySigner,
    filter: &'a PreflightEgressFilter,
    safety: &'a StopNciiEngine,
    routes: HashMap<Jurisdiction, ExportRoutePolicy>,
    review: Option<&'a SemanticReviewGate<'a>>,
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
            routes: HashMap::new(),
            review: None,
        })
    }

    pub fn with_route_policy(
        mut self,
        destination: Jurisdiction,
        policy: ExportRoutePolicy,
    ) -> Self {
        self.routes.insert(destination, policy);
        self
    }

    pub fn with_semantic_review(mut self, review: &'a SemanticReviewGate<'a>) -> Self {
        self.review = Some(review);
        self
    }

    fn rejection(&self, destination: Jurisdiction, reason: OutboundRejection) -> OutboundError {
        OutboundError {
            reason,
            notices: self
                .filter
                .assess_interaction(self.origin, destination, "")
                .notices,
        }
    }

    fn route_policy(&self, destination: Jurisdiction) -> Result<ExportRoutePolicy, OutboundError> {
        let route = self.filter.assess_interaction(self.origin, destination, "");
        route
            .result
            .map_err(|e| self.rejection(destination, e.into()))?;
        self.routes
            .get(&destination)
            .copied()
            .ok_or_else(|| self.rejection(destination, OutboundRejection::RouteNotAllowed))
    }

    /// Recommended boundary: construct the approved minimal profile and opaque IDs
    /// locally. Neither raw profiles nor local ID mappings are returned to the peer.
    pub async fn prepare_local(
        &self,
        destination: Jurisdiction,
        raw: &RawInternalUserProfile,
        pepper: &RegionalPepper,
        draft: &LocalEventDraft,
    ) -> Result<FederatedEventEnvelope, OutboundError> {
        let policy = self.route_policy(destination)?;
        let event = crate::boundary::project_local_event(
            raw,
            self.origin,
            pepper,
            draft,
            policy.profile_options,
        )
        .map_err(|e| OutboundError {
            reason: OutboundRejection::Identity(e),
            notices: self
                .filter
                .assess_interaction(self.origin, destination, "")
                .notices,
        })?;
        self.prepare(destination, &event).await
    }

    /// Advanced API for already approved projections. It validates shape, routing,
    /// policy and media, but cannot detect every sensitive value inside arbitrary text.
    pub async fn prepare(
        &self,
        destination: Jurisdiction,
        event: &CrossBorderEventPayload,
    ) -> Result<FederatedEventEnvelope, OutboundError> {
        let policy = self.route_policy(destination)?;
        let notices = check_export(self.origin, destination, event, self.filter, self.safety)?;
        let author = event.author.as_ref().expect("validated author");
        if event.event_type != FederatedEventType::EventTypeProfileSync as i32
            && !policy.allow_content
        {
            return Err(self.rejection(destination, OutboundRejection::ContentNotAllowed));
        }
        if (!policy.profile_options.avatar && !author.public_avatar_url.is_empty())
            || (!policy.profile_options.following_count && author.following_count != 0)
            || (!policy.profile_options.badges && !author.badges.is_empty())
        {
            return Err(self.rejection(destination, OutboundRejection::UnapprovedProfileFields));
        }
        let review = self.review.ok_or_else(|| {
            self.rejection(
                destination,
                PrivacyReviewError::UncertainPersonalData {
                    field: ReviewField::Handle,
                }
                .into(),
            )
        })?;
        review
            .review(self.origin, destination, event)
            .await
            .map_err(|e| self.rejection(destination, e.into()))?;
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

    /// JSON-only review interface. Success includes business allowlist fields
    /// and the policy code; protocol pseudonyms/routing stay in the envelope API.
    /// A rejection or pending review never contains a partial candidate export.
    pub async fn review_local_json(
        &self,
        destination: Jurisdiction,
        raw: &RawInternalUserProfile,
        pepper: &RegionalPepper,
        draft: &LocalEventDraft,
    ) -> serde_json::Value {
        match self.prepare_local(destination, raw, pepper, draft).await {
            Err(error) => error.review_json(),
            Ok(envelope) => {
                let event = CrossBorderEventPayload::decode(envelope.payload_bytes.as_slice())
                    .expect("self-encoded event");
                let profile = event.author.expect("validated author");
                let mut value = serde_json::json!({
                    "policy_code": REVIEW_POLICY_CODE,
                    "handle": profile.handle,
                    "display_name": profile.display_name,
                    "followers_count": profile.followers_count,
                    "is_private": profile.is_private,
                });
                let options = self.routes[&destination].profile_options;
                if options.avatar {
                    value["public_avatar_url"] = profile.public_avatar_url.into();
                }
                if options.following_count {
                    value["following_count"] = profile.following_count.into();
                }
                if options.badges {
                    value["badges"] = serde_json::json!(profile.badges);
                }
                if !event.text_content.is_empty() {
                    value["text_content"] = event.text_content.into();
                }
                value
            }
        }
    }
}
