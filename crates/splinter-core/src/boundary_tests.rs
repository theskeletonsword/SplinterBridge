use crate::*;
use ed25519_dalek::SigningKey;
use prost::Message;

struct Fixture {
    signer: GatewaySigner,
    filter: PreflightEgressFilter,
    safety: StopNciiEngine,
    pepper: RegionalPepper,
}
impl Fixture {
    fn new() -> Self {
        Self {
            signer: GatewaySigner::new(SigningKey::from_bytes(&[7; 32])),
            filter: PreflightEgressFilter::new(),
            safety: StopNciiEngine::default(),
            pepper: RegionalPepper::new(&[9; 32]),
        }
    }
    fn outbound(&self, origin: Jurisdiction) -> OutboundGateway<'_> {
        OutboundGateway::new(
            origin,
            "regional-key".into(),
            &self.signer,
            &self.filter,
            &self.safety,
        )
        .unwrap()
    }
    fn peer(&self, origin: Jurisdiction) -> TrustedGateway {
        TrustedGateway {
            key_id: "regional-key".into(),
            origin,
            public_key: self.signer.verifying_key().to_bytes(),
        }
    }
    fn inbound(&self, destination: Jurisdiction) -> InboundGateway<'_> {
        InboundGateway::new(destination, &self.filter, &self.safety).unwrap()
    }
}
fn raw(private: bool) -> RawInternalUserProfile {
    RawInternalUserProfile {
        internal_user_id: "SECRET-internal-user".into(),
        national_id_hash: Some("SECRET-national-id".into()),
        email: Some("SECRET-email@example.invalid".into()),
        phone: Some("SECRET-phone".into()),
        internal_ip_address: Some("SECRET-internal-ip".into()),
        handle: "@nickname".into(),
        display_name: "Public name".into(),
        avatar_url: "https://private.invalid/SECRET-avatar".into(),
        followers_count: 123,
        following_count: 456,
        is_private: private,
        badges: vec![VerifiedBadgeType::VerifiedBadgeOfficialOrganization],
    }
}
fn draft(kind: FederatedEventType, text: &str) -> LocalEventDraft {
    LocalEventDraft {
        local_event_id: "SECRET-internal-event".into(),
        local_resource_id: if kind == Profile {
            None
        } else {
            Some("SECRET-own-resource".into())
        },
        event_type: kind,
        timestamp_epoch_ms: 1_000,
        nonce: 1,
        text_content: text.into(),
        media_hashes: vec![],
        target: if kind == FederatedEventType::EventTypeProfileSync {
            LocalEventTarget::None
        } else {
            LocalEventTarget::LocalResource("SECRET-internal-resource".into())
        },
    }
}
fn decode(e: &FederatedEventEnvelope) -> CrossBorderEventPayload {
    CrossBorderEventPayload::decode(e.payload_bytes.as_slice()).unwrap()
}
fn resign(f: &Fixture, e: &mut FederatedEventEnvelope, event: CrossBorderEventPayload) {
    e.payload_bytes = event.encode_to_vec();
    f.signer.sign_envelope(e);
}
use FederatedEventType::{EventTypeCommentPublish as Comment, EventTypeProfileSync as Profile};
use Jurisdiction::{CnPiplCac as China, GlobalGdpr as Global};

#[test]
fn public_fields_roundtrip_in_both_directions_for_public_and_private_accounts() {
    let f = Fixture::new();
    for (origin, destination) in [(China, Global), (Global, China)] {
        for private in [true, false] {
            let local = raw(private);
            let e = f
                .outbound(origin)
                .prepare_local(destination, &local, &f.pepper, &draft(Profile, ""))
                .unwrap();
            let accepted = f.inbound(destination).accept(&e, &f.peer(origin)).unwrap();
            let a = accepted.payload.author.unwrap();
            assert_eq!(a.handle, local.handle);
            assert_eq!(a.display_name, local.display_name);
            assert_eq!(a.followers_count, local.followers_count);
            assert_eq!(a.is_private, private);
            assert!(a.public_avatar_url.is_empty());
            assert_eq!(a.following_count, 0);
            assert!(a.badges.is_empty());
            assert_eq!(
                accepted.notices,
                vec![InteractionNotice::ChinaCrossBorderRules]
            );
            assert!(!String::from_utf8_lossy(&e.payload_bytes).contains("SECRET-"));
        }
    }
}

#[test]
fn all_four_routes_enforce_policy_and_leave_the_local_event_intact() {
    let f = Fixture::new();
    for text in ["Tiananmen", "Winnie the Pooh", "天安门", "小熊维尼"] {
        let d = draft(Comment, text);
        for (origin, destination, allowed) in [
            (Global, Global, true),
            (Global, China, false),
            (China, Global, false),
            (China, China, false),
        ] {
            let result = f
                .outbound(origin)
                .prepare_local(destination, &raw(false), &f.pepper, &d);
            assert_eq!(result.is_ok(), allowed, "{origin:?} -> {destination:?}");
            if let Err(e) = result {
                assert_eq!(!e.policy_notices().is_empty(), origin != destination);
            }
        }
        assert_eq!(d.text_content, text);
        // A failed China export cannot suppress another overseas destination.
        let e = f
            .outbound(Global)
            .prepare_local(Global, &raw(false), &f.pepper, &d)
            .unwrap();
        f.inbound(Global).accept(&e, &f.peer(Global)).unwrap();
    }
}

#[test]
fn opaque_references_are_stable_scoped_and_do_not_disclose_local_ids() {
    let f = Fixture::new();
    let a = derive_federated_reference("local-id", Global, &f.pepper, false).unwrap();
    assert_eq!(
        a,
        derive_federated_reference("local-id", Global, &f.pepper, false).unwrap()
    );
    let b = derive_federated_reference("local-id", Global, &f.pepper, true).unwrap();
    let c = derive_federated_reference("local-id", China, &f.pepper, false).unwrap();
    assert_ne!(a.rsplit(':').next(), b.rsplit(':').next());
    assert_ne!(a.rsplit(':').next(), c.rsplit(':').next());
    let account = derive_federated_did("local-id", Global, &f.pepper).unwrap();
    assert_ne!(a.rsplit(':').next(), account.rsplit(':').next());
    assert!(!a.contains("local-id"));
    assert!(derive_federated_reference(" ", Global, &f.pepper, false).is_err());
}

#[test]
fn optional_public_fields_require_explicit_opt_in() {
    let f = Fixture::new();
    let r = raw(false);
    let p = project_blind_profile_with_options(
        &r,
        China,
        &f.pepper,
        PublicProfileOptions {
            avatar: true,
            following_count: true,
            badges: true,
        },
    )
    .unwrap();
    assert_eq!(p.public_avatar_url, r.avatar_url);
    assert_eq!(p.following_count, 456);
    assert_eq!(p.badges.len(), 1);
    assert!(!format!("{r:?}").contains("SECRET-"));
}

#[test]
fn private_posts_and_disguised_profile_content_are_rejected() {
    let f = Fixture::new();
    for (origin, destination) in [(Global, China), (China, Global)] {
        let err = f
            .outbound(origin)
            .prepare_local(destination, &raw(true), &f.pepper, &draft(Comment, "hello"))
            .unwrap_err();
        assert!(matches!(
            err.reason,
            OutboundRejection::Projection(BoundaryError::PrivateContent)
        ));
        assert_eq!(
            err.policy_notices(),
            &[InteractionNotice::ChinaCrossBorderRules]
        );
        let err = f
            .outbound(origin)
            .prepare_local(
                destination,
                &raw(true),
                &f.pepper,
                &draft(Profile, "private post"),
            )
            .unwrap_err();
        assert!(matches!(err.reason, OutboundRejection::Projection(_)));
    }
}

#[test]
fn receiver_rechecks_content_and_both_endpoints_even_for_a_valid_signer() {
    let f = Fixture::new();
    for (origin, destination) in [(Global, China), (China, Global), (China, China)] {
        let mut e = f
            .outbound(origin)
            .prepare_local(
                destination,
                &raw(false),
                &f.pepper,
                &draft(Comment, "hello"),
            )
            .unwrap();
        let mut event = decode(&e);
        event.text_content = "Tiananmen".into();
        resign(&f, &mut e, event);
        assert!(matches!(
            f.inbound(destination).accept(&e, &f.peer(origin)),
            Err(InboundError::Content(_))
        ));
    }
}

#[test]
fn profile_fields_cannot_bypass_route_policy() {
    let f = Fixture::new();
    let mut r = raw(false);
    r.display_name = "Winnie the Pooh".into();
    assert!(f
        .outbound(Global)
        .prepare_local(China, &r, &f.pepper, &draft(Profile, ""))
        .is_err());
    assert!(f
        .outbound(Global)
        .prepare_local(Global, &r, &f.pepper, &draft(Profile, ""))
        .is_ok());
}

#[test]
fn receiver_binds_trust_to_origin_destination_and_key() {
    let f = Fixture::new();
    let e = f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &draft(Comment, "hello"))
        .unwrap();
    assert!(f.inbound(Global).accept(&e, &f.peer(Global)).is_err());
    assert!(f.inbound(China).accept(&e, &f.peer(China)).is_err());
    let mut peer = f.peer(Global);
    peer.key_id = "wrong".into();
    assert!(f.inbound(China).accept(&e, &peer).is_err());
    peer = f.peer(Global);
    peer.public_key = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
    assert!(matches!(
        f.inbound(China).accept(&e, &peer),
        Err(InboundError::Signature(_))
    ));
}

#[test]
fn receiver_rejects_removed_or_forged_notices_even_when_resigned() {
    let f = Fixture::new();
    for (origin, destination) in [(Global, China), (China, Global), (Global, Global)] {
        let mut e = f
            .outbound(origin)
            .prepare_local(
                destination,
                &raw(false),
                &f.pepper,
                &draft(Comment, "hello"),
            )
            .unwrap();
        e.policy_notices = if origin == destination {
            vec![1]
        } else {
            vec![]
        };
        f.signer.sign_envelope(&mut e);
        assert!(matches!(
            f.inbound(destination).accept(&e, &f.peer(origin)),
            Err(InboundError::InvalidNotices)
        ));
    }
}

#[test]
fn receiver_rejects_internal_ids_invalid_author_and_private_content() {
    let f = Fixture::new();
    let base = f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &draft(Comment, "hello"))
        .unwrap();
    for field in 0..7 {
        let mut e = base.clone();
        let mut p = decode(&e);
        match field {
            0 => p.event_id = "internal-db-row-42".into(),
            1 => p.target_resource_id = "internal-db-row-99".into(),
            2 => p.author.as_mut().unwrap().federated_did = "raw-user-id".into(),
            3 => p.author.as_mut().unwrap().origin_jurisdiction = China as i32,
            4 => p.author.as_mut().unwrap().is_private = true,
            5 => p.resource_id = "internal-post-id".into(),
            _ => p.event_type = 999,
        }
        resign(&f, &mut e, p);
        assert!(matches!(
            f.inbound(China).accept(&e, &f.peer(Global)),
            Err(InboundError::Content(_))
        ));
    }
}

#[test]
fn receiver_rejects_hidden_unknown_payload_fields_and_oversize() {
    let f = Fixture::new();
    let mut e = f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &draft(Comment, "hello"))
        .unwrap();
    // Unknown protobuf field 15, length-delimited, containing a secret.
    e.payload_bytes
        .extend_from_slice(&[0x7a, 3, b'p', b'i', b'i']);
    f.signer.sign_envelope(&mut e);
    assert!(matches!(
        f.inbound(China).accept(&e, &f.peer(Global)),
        Err(InboundError::InvalidPayload)
    ));
    e.payload_bytes = vec![0; MAX_EVENT_BYTES + 4097];
    assert!(matches!(
        f.inbound(China).accept(&e, &f.peer(Global)),
        Err(InboundError::InvalidPayload)
    ));
}

#[test]
fn media_validation_and_notices_apply_to_all_failures() {
    let f = Fixture::new();
    let mut d = draft(Comment, "hello");
    d.media_hashes.push(MediaPerceptualHash {
        pdq_hash: vec![0xff; 32],
        ..Default::default()
    });
    let error = f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &d)
        .unwrap_err();
    assert!(matches!(
        error.reason,
        OutboundRejection::EmptySafetyCatalog
    ));
    assert_eq!(
        error.policy_notices(),
        &[InteractionNotice::ChinaCrossBorderRules]
    );
    f.safety.register_signature(PdqHash([0; 4]));
    let e = f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &d)
        .unwrap();
    f.inbound(China).accept(&e, &f.peer(Global)).unwrap();
    d.media_hashes[0].pdq_hash = vec![0; 32];
    assert!(f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &d)
        .is_err());
    d.media_hashes[0].pdq_hash = vec![0; 31];
    assert!(f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &d)
        .is_err());
    d.media_hashes[0].tmk_hash = vec![0; 32];
    assert!(f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &d)
        .is_err());
}

#[test]
fn unsupported_hardware_assertions_are_not_silently_trusted() {
    let f = Fixture::new();
    let mut e = f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &draft(Profile, ""))
        .unwrap();
    e.humanity_attestation = Some(HardwareAttestation::default());
    f.signer.sign_envelope(&mut e);
    assert!(matches!(
        f.inbound(China).accept(&e, &f.peer(Global)),
        Err(InboundError::UnsupportedAttestation)
    ));
    assert!(
        interaction_notice_en(InteractionNotice::ChinaCrossBorderRules)
            .unwrap()
            .contains("overseas")
    );
}

#[test]
fn receiver_must_explicitly_approve_optional_public_fields() {
    let f = Fixture::new();
    let mut e = f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &draft(Profile, ""))
        .unwrap();
    let mut event = decode(&e);
    event.author.as_mut().unwrap().following_count = 7;
    resign(&f, &mut e, event);
    assert!(matches!(
        f.inbound(China).accept(&e, &f.peer(Global)),
        Err(InboundError::UnapprovedProfileFields)
    ));
    let received = f
        .inbound(China)
        .with_profile_options(PublicProfileOptions {
            following_count: true,
            ..Default::default()
        })
        .accept(&e, &f.peer(Global))
        .unwrap();
    assert_eq!(received.payload.author.unwrap().following_count, 7);
}

#[test]
fn replies_resolve_federated_resources_without_shared_ids_or_keys() {
    let global = Fixture::new();
    let mut china = Fixture::new();
    china.signer = GatewaySigner::new(SigningKey::from_bytes(&[8; 32]));
    china.pepper = RegionalPepper::new(&[10; 32]);
    let mut post = draft(FederatedEventType::EventTypePostPublish, "hello");
    post.target = LocalEventTarget::None;
    let export = global
        .outbound(Global)
        .prepare_local(China, &raw(false), &global.pepper, &post)
        .unwrap();
    let imported = china
        .inbound(China)
        .accept(&export, &global.peer(Global))
        .unwrap();
    let public_post_id = imported.payload.resource_id;
    assert!(!public_post_id.contains("SECRET-"));
    let mut reply = draft(Comment, "nice video");
    reply.target = LocalEventTarget::FederatedResource(public_post_id.clone());
    let export = china
        .outbound(China)
        .prepare_local(Global, &raw(false), &china.pepper, &reply)
        .unwrap();
    let imported_reply = global
        .inbound(Global)
        .accept(&export, &china.peer(China))
        .unwrap();
    assert_eq!(imported_reply.payload.target_resource_id, public_post_id);
    assert_ne!(
        imported_reply.payload.resource_id,
        imported_reply.payload.target_resource_id
    );
}
