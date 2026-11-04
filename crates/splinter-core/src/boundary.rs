//! Data-only boundary: local IDs are projected, never looked up across regions.
use crate::*;
use thiserror::Error;

pub const MAX_EVENT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum BoundaryError {
    #[error("Invalid public projection, opaque reference, event type or size")]
    InvalidProjection,
    #[error("Private-account content export is disabled; only the public profile may be shared")]
    PrivateContent,
}

fn region(j: Jurisdiction) -> Option<&'static str> {
    match j {
        Jurisdiction::GlobalGdpr => Some("global"),
        Jurisdiction::CnPiplCac => Some("cn"),
        Jurisdiction::Ru152Fz => Some("ru"),
        Jurisdiction::Unspecified => None,
    }
}

fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn valid_did(did: &str, origin: Jurisdiction) -> bool {
    region(origin).is_some_and(|r| {
        did.strip_prefix(&format!("did:splinter:{r}:"))
            .is_some_and(hex_digest)
    })
}

pub(crate) fn valid_reference(value: &str, kind: &str, origin: Option<Jurisdiction>) -> bool {
    [
        Jurisdiction::GlobalGdpr,
        Jurisdiction::CnPiplCac,
        Jurisdiction::Ru152Fz,
    ]
    .into_iter()
    .filter(|j| origin.is_none_or(|o| o == *j))
    .any(|j| {
        value
            .strip_prefix(&format!("urn:splinter:{kind}:{}:", region(j).unwrap()))
            .is_some_and(hex_digest)
    })
}

/// Derive a domain-separated opaque event or resource reference from a local ID.
/// Only the owning region needs the secret; the receiver never resolves local IDs.
pub fn derive_federated_reference(
    local_id: &str,
    origin: Jurisdiction,
    pepper: &RegionalPepper,
    resource: bool,
) -> Result<String, IdentityError> {
    let kind = if resource { "resource" } else { "event" };
    let r = region(origin).ok_or(IdentityError::UnsupportedJurisdiction(origin))?;
    let digest = pepper.reference_digest(kind, r, local_id)?;
    Ok(format!("urn:splinter:{kind}:{r}:{digest}"))
}

/// IDs below are local inputs only. This struct is deliberately not serializable.
pub struct LocalEventDraft {
    pub local_event_id: String,
    pub local_resource_id: Option<String>,
    pub event_type: FederatedEventType,
    pub timestamp_epoch_ms: i64,
    pub nonce: u64,
    pub text_content: String,
    pub media_hashes: Vec<MediaPerceptualHash>,
    pub target: LocalEventTarget,
}

pub enum LocalEventTarget {
    None,
    LocalResource(String),
    FederatedResource(String),
}

pub(crate) fn project_local_event(
    raw: &RawInternalUserProfile,
    origin: Jurisdiction,
    pepper: &RegionalPepper,
    draft: &LocalEventDraft,
    options: PublicProfileOptions,
) -> Result<CrossBorderEventPayload, IdentityError> {
    Ok(CrossBorderEventPayload {
        event_id: derive_federated_reference(&draft.local_event_id, origin, pepper, false)?,
        event_type: draft.event_type as i32,
        resource_id: draft
            .local_resource_id
            .as_ref()
            .map(|id| derive_federated_reference(id, origin, pepper, true))
            .transpose()?
            .unwrap_or_default(),
        timestamp_epoch_ms: draft.timestamp_epoch_ms,
        nonce: draft.nonce,
        author: Some(project_blind_profile_with_options(
            raw, origin, pepper, options,
        )?),
        text_content: draft.text_content.clone(),
        media_hashes: draft.media_hashes.clone(),
        target_resource_id: match &draft.target {
            LocalEventTarget::None => String::new(),
            LocalEventTarget::LocalResource(id) => {
                derive_federated_reference(id, origin, pepper, true)?
            }
            LocalEventTarget::FederatedResource(id) => id.clone(),
        },
    })
}

pub(crate) fn validate_event(
    event: &CrossBorderEventPayload,
    origin: Jurisdiction,
) -> Result<(), BoundaryError> {
    use prost::Message;
    let author = event
        .author
        .as_ref()
        .ok_or(BoundaryError::InvalidProjection)?;
    let event_type = FederatedEventType::try_from(event.event_type)
        .map_err(|_| BoundaryError::InvalidProjection)?;
    if event.encoded_len() > MAX_EVENT_BYTES
        || !valid_reference(&event.event_id, "event", Some(origin))
        || (!event.target_resource_id.is_empty()
            && !valid_reference(&event.target_resource_id, "resource", None))
        || (!event.resource_id.is_empty()
            && !valid_reference(&event.resource_id, "resource", Some(origin)))
        || author.origin_jurisdiction != origin as i32
        || !valid_did(&author.federated_did, origin)
        || author.handle.len() > 128
        || author.display_name.len() > 256
        || author.public_avatar_url.len() > 2048
        || event.text_content.len() > 65536
        // MIME metadata is a closed enum-like list, never an unchecked text channel.
        || event.media_hashes.iter().any(|m| !matches!(m.mime_type.as_str(),
            "" | "image/jpeg" | "image/png" | "image/webp" | "image/gif" |
            "image/avif" | "video/mp4" | "video/webm"))
        || author.handle.chars().any(char::is_control)
        || author.display_name.chars().any(char::is_control)
        || author
            .badges
            .iter()
            .any(|b| VerifiedBadgeType::try_from(*b).is_err())
        || event_type == FederatedEventType::EventTypeUnspecified
    {
        return Err(BoundaryError::InvalidProjection);
    }
    if event_type == FederatedEventType::EventTypeProfileSync {
        if !event.text_content.is_empty()
            || !event.media_hashes.is_empty()
            || !event.target_resource_id.is_empty()
            || !event.resource_id.is_empty()
        {
            return Err(BoundaryError::InvalidProjection);
        }
    } else if author.is_private {
        return Err(BoundaryError::PrivateContent);
    }
    if event_type == FederatedEventType::EventTypeEngagementInteraction
        && (!event.text_content.is_empty() || !event.media_hashes.is_empty())
    {
        return Err(BoundaryError::InvalidProjection);
    }
    if matches!(
        event_type,
        FederatedEventType::EventTypePostPublish | FederatedEventType::EventTypeCommentPublish
    ) && event.resource_id.is_empty()
    {
        return Err(BoundaryError::InvalidProjection);
    }
    if matches!(
        event_type,
        FederatedEventType::EventTypeCommentPublish
            | FederatedEventType::EventTypeEngagementInteraction
    ) && event.target_resource_id.is_empty()
    {
        return Err(BoundaryError::InvalidProjection);
    }
    Ok(())
}
