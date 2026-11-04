// Fixture-only deterministic reviewer; it is NOT a semantic classifier.
struct FixtureReviewer;
impl SemanticClassifier for FixtureReviewer {
    fn classify(&self, input: ReviewInput) -> ClassificationFuture<'_> {
        Box::pin(async move {
            Ok(SemanticReport {
                fields: input
                    .fields
                    .into_iter()
                    .map(|f| FieldVerdict {
                        field: f.field,
                        decision: SemanticDecision::Allow,
                        confidence_bps: 10000,
                    })
                    .collect(),
            })
        })
    }
}
use crate::*;
use ed25519_dalek::SigningKey;
use prost::Message;

struct Fixture {
    signer: GatewaySigner,
    filter: PreflightEgressFilter,
    safety: StopNciiEngine,
    pepper: RegionalPepper,
    review: SemanticReviewGate<'static>,
}
impl Fixture {
    fn new() -> Self {
        Self {
            signer: GatewaySigner::new(SigningKey::from_bytes(&[7; 32])),
            filter: PreflightEgressFilter::new(),
            safety: StopNciiEngine::default(),
            pepper: RegionalPepper::new(&[9; 32]),
            review: SemanticReviewGate::new(
                &FixtureReviewer,
                8,
                std::time::Duration::from_secs(1),
                9000,
            )
            .unwrap(),
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
        .with_route_policy(
            Global,
            ExportRoutePolicy {
                allow_content: true,
                ..Default::default()
            },
        )
        .with_route_policy(
            China,
            ExportRoutePolicy {
                allow_content: true,
                ..Default::default()
            },
        )
        .with_semantic_review(&self.review)
    }
    fn peer(&self, origin: Jurisdiction) -> TrustedGateway {
        TrustedGateway {
            key_id: "regional-key".into(),
            origin,
            public_key: self.signer.verifying_key().to_bytes(),
        }
    }
    /// Each call gets its own replay cache (leaked: test-only) on the fixture clock.
    fn inbound(&self, destination: Jurisdiction) -> InboundGateway<'_> {
        let replay: &'static SlidingWindowReplayCache = Box::leak(Box::new(fixture_replay()));
        self.inbound_without_replay(destination)
            .with_replay_cache(replay)
    }
    fn inbound_without_replay(&self, destination: Jurisdiction) -> InboundGateway<'_> {
        InboundGateway::new(destination, &self.filter, &self.safety).unwrap()
    }
}
/// Fixture drafts are stamped at t = 1000 ms; the replay clock agrees.
const FIXTURE_NOW_MS: i64 = 1_000;
fn fixture_replay() -> SlidingWindowReplayCache {
    SlidingWindowReplayCache::with_clock(300, 1024, || FIXTURE_NOW_MS)
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
        actor_public_key: None,
        commitment_hash: None,
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
        timestamp_epoch_ms: FIXTURE_NOW_MS,
        nonce: 1,
        text_content: text.into(),
        media_hashes: vec![],
        target: if kind == FederatedEventType::EventTypeProfileSync {
            LocalEventTarget::None
        } else {
            LocalEventTarget::LocalResource("SECRET-internal-resource".into())
        },
        content_signature: None,
        actor_public_key: None,
        zk_proof_reference: None,
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

#[tokio::test]
async fn public_fields_roundtrip_in_both_directions_for_public_and_private_accounts() {
    let f = Fixture::new();
    for (origin, destination) in [(China, Global), (Global, China)] {
        for private in [true, false] {
            let local = raw(private);
            let e = f
                .outbound(origin)
                .prepare_local(destination, &local, &f.pepper, &draft(Profile, ""))
                .await
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

#[tokio::test]
async fn all_four_routes_enforce_policy_and_leave_the_local_event_intact() {
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
                .prepare_local(destination, &raw(false), &f.pepper, &d)
                .await;
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
            .await
            .unwrap();
        f.inbound(Global).accept(&e, &f.peer(Global)).unwrap();
    }
}

#[tokio::test]
async fn opaque_references_are_stable_scoped_and_do_not_disclose_local_ids() {
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

#[tokio::test]
async fn optional_public_fields_require_explicit_opt_in() {
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

#[tokio::test]
async fn private_posts_and_disguised_profile_content_are_rejected() {
    let f = Fixture::new();
    for (origin, destination) in [(Global, China), (China, Global)] {
        let err = f
            .outbound(origin)
            .prepare_local(destination, &raw(true), &f.pepper, &draft(Comment, "hello"))
            .await
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
            .await
            .unwrap_err();
        assert!(matches!(err.reason, OutboundRejection::Projection(_)));
    }
}

#[tokio::test]
async fn receiver_rechecks_content_and_both_endpoints_even_for_a_valid_signer() {
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
            .await
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

#[tokio::test]
async fn profile_fields_cannot_bypass_route_policy() {
    let f = Fixture::new();
    let mut r = raw(false);
    r.display_name = "Winnie the Pooh".into();
    assert!(f
        .outbound(Global)
        .prepare_local(China, &r, &f.pepper, &draft(Profile, ""))
        .await
        .is_err());
    assert!(f
        .outbound(Global)
        .prepare_local(Global, &r, &f.pepper, &draft(Profile, ""))
        .await
        .is_ok());
}

#[tokio::test]
async fn receiver_binds_trust_to_origin_destination_and_key() {
    let f = Fixture::new();
    let e = f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &draft(Comment, "hello"))
        .await
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

#[tokio::test]
async fn receiver_rejects_removed_or_forged_notices_even_when_resigned() {
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
            .await
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

#[tokio::test]
async fn receiver_rejects_internal_ids_invalid_author_and_private_content() {
    let f = Fixture::new();
    let base = f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &draft(Comment, "hello"))
        .await
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

#[tokio::test]
async fn receiver_rejects_hidden_unknown_payload_fields_and_oversize() {
    let f = Fixture::new();
    let mut e = f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &draft(Comment, "hello"))
        .await
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

#[tokio::test]
async fn media_validation_and_notices_apply_to_all_failures() {
    let f = Fixture::new();
    let mut d = draft(Comment, "hello");
    d.media_hashes.push(MediaPerceptualHash {
        pdq_hash: vec![0xff; 32],
        ..Default::default()
    });
    let error = f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &d)
        .await
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
        .await
        .unwrap();
    f.inbound(China).accept(&e, &f.peer(Global)).unwrap();
    d.media_hashes[0].pdq_hash = vec![0; 32];
    assert!(f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &d)
        .await
        .is_err());
    d.media_hashes[0].pdq_hash = vec![0; 31];
    assert!(f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &d)
        .await
        .is_err());
    d.media_hashes[0].tmk_hash = vec![0; 32];
    assert!(f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &d)
        .await
        .is_err());
}

#[tokio::test]
async fn unsupported_hardware_assertions_are_not_silently_trusted() {
    let f = Fixture::new();
    let mut e = f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &draft(Profile, ""))
        .await
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

#[tokio::test]
async fn receiver_must_explicitly_approve_optional_public_fields() {
    let f = Fixture::new();
    let mut e = f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &draft(Profile, ""))
        .await
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

#[tokio::test]
async fn replies_resolve_federated_resources_without_shared_ids_or_keys() {
    let global = Fixture::new();
    let mut china = Fixture::new();
    china.signer = GatewaySigner::new(SigningKey::from_bytes(&[8; 32]));
    china.pepper = RegionalPepper::new(&[10; 32]);
    let mut post = draft(FederatedEventType::EventTypePostPublish, "hello");
    post.target = LocalEventTarget::None;
    let export = global
        .outbound(Global)
        .prepare_local(China, &raw(false), &global.pepper, &post)
        .await
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
        .await
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

struct CapturingReviewer {
    seen: std::sync::Mutex<Vec<String>>,
    mode: u8,
}
impl CapturingReviewer {
    fn new(mode: u8) -> Self {
        Self {
            seen: Default::default(),
            mode,
        }
    }
}
impl SemanticClassifier for CapturingReviewer {
    fn classify(&self, input: ReviewInput) -> ClassificationFuture<'_> {
        self.seen
            .lock()
            .unwrap()
            .push(serde_json::to_string(&input).unwrap());
        Box::pin(async move {
            if self.mode == 1 {
                return Err(ClassifierFailure::Unavailable);
            }
            if self.mode == 2 {
                return std::future::pending().await;
            }
            let mut report = FixtureReviewer.classify(input).await?;
            match self.mode {
                3 => report.fields[0].confidence_bps = 8999,
                4 => report.fields[0].confidence_bps = 10001,
                5 => report.fields[0].decision = SemanticDecision::UncertainPersonalData,
                6 => report.fields[0].decision = SemanticDecision::ProhibitedPersonalData,
                7 => {
                    report.fields.pop();
                }
                8 => report.fields[1] = report.fields[0].clone(),
                9 => report.fields[0].field = ReviewField::PublicAvatarUrl,
                _ => (),
            }
            Ok(report)
        })
    }
}

#[tokio::test]
async fn default_gateway_requires_route_then_classifier() {
    let f = Fixture::new();
    let gateway =
        OutboundGateway::new(Global, "key".into(), &f.signer, &f.filter, &f.safety).unwrap();
    let result = gateway
        .review_local_json(China, &raw(false), &f.pepper, &draft(Profile, ""))
        .await;
    assert_eq!(result, serde_json::json!({"code":"ROUTE_NOT_ALLOWED"}));
    let gateway = gateway.with_route_policy(China, ExportRoutePolicy::default());
    let result = gateway
        .review_local_json(China, &raw(false), &f.pepper, &draft(Profile, ""))
        .await;
    assert_eq!(
        result,
        serde_json::json!({"code":"UNCERTAIN_PERSONAL_DATA", "field":"handle"})
    );
}

#[tokio::test]
async fn reviewer_receives_only_candidate_text_and_json_output_has_closed_allowlist() {
    let f = Fixture::new();
    let classifier = CapturingReviewer::new(0);
    let gate =
        SemanticReviewGate::new(&classifier, 1, std::time::Duration::from_secs(1), 9000).unwrap();
    let gateway = f.outbound(Global).with_semantic_review(&gate);
    let result = gateway
        .review_local_json(China, &raw(true), &f.pepper, &draft(Profile, ""))
        .await;
    assert_eq!(
        result,
        serde_json::json!({
            "policy_code":"MINIMAL_EGRESS_V1", "handle":"@nickname", "display_name":"Public name", "followers_count":123, "is_private":true
        })
    );
    let seen = classifier.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    for forbidden in [
        "SECRET-",
        "federated_did",
        "event_id",
        "email",
        "followers_count",
        "is_private",
    ] {
        assert!(!seen[0].contains(forbidden));
    }
    assert!(seen[0].contains("@nickname"));
}

#[tokio::test]
async fn invalid_private_unapproved_or_keyword_blocked_events_never_reach_model() {
    let f = Fixture::new();
    let classifier = CapturingReviewer::new(0);
    let gate =
        SemanticReviewGate::new(&classifier, 1, std::time::Duration::from_secs(1), 9000).unwrap();
    let gateway = f
        .outbound(Global)
        .with_semantic_review(&gate)
        .with_route_policy(Global, ExportRoutePolicy::default());
    for (destination, private, kind, text, code) in [
        (Global, false, Comment, "hello", "CONTENT_NOT_ALLOWED"),
        (China, true, Comment, "private content", "PRIVATE_ACCOUNT"),
        (China, false, Comment, "Tiananmen", "POLICY_KEYWORD"),
        (
            Jurisdiction::Ru152Fz,
            false,
            Profile,
            "",
            "ROUTE_NOT_ALLOWED",
        ),
        (
            Jurisdiction::Unspecified,
            false,
            Profile,
            "",
            "INVALID_PROJECTION",
        ),
    ] {
        let result = gateway
            .review_local_json(destination, &raw(private), &f.pepper, &draft(kind, text))
            .await;
        assert_eq!(result["code"], code);
    }
    let mut event = crate::boundary::project_local_event(
        &raw(false),
        Global,
        &f.pepper,
        &draft(Profile, ""),
        PublicProfileOptions::default(),
    )
    .unwrap();
    event.author.as_mut().unwrap().following_count = 1;
    assert_eq!(
        gateway
            .prepare(China, &event)
            .await
            .unwrap_err()
            .review_json()["code"],
        "UNKNOWN_FIELD"
    );
    assert!(classifier.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn uncertainty_errors_low_confidence_and_malformed_reports_never_sign() {
    let f = Fixture::new();
    for mode in 1..=9 {
        let classifier = CapturingReviewer::new(mode);
        let gate =
            SemanticReviewGate::new(&classifier, 1, std::time::Duration::from_millis(10), 9000)
                .unwrap();
        let gateway = f.outbound(Global).with_semantic_review(&gate);
        let result = gateway
            .review_local_json(China, &raw(false), &f.pepper, &draft(Profile, ""))
            .await;
        assert_eq!(
            result["code"],
            if mode == 6 {
                "PROHIBITED_FIELD"
            } else {
                "UNCERTAIN_PERSONAL_DATA"
            }
        );
        assert!(!result.to_string().contains("@nickname"));
        assert!(!result.to_string().contains("SECRET-"));
    }
}

#[tokio::test]
async fn optional_fields_and_content_permissions_are_scoped_to_destination() {
    let f = Fixture::new();
    let gateway = f.outbound(Global).with_route_policy(
        China,
        ExportRoutePolicy {
            allow_content: false,
            profile_options: PublicProfileOptions {
                following_count: true,
                ..Default::default()
            },
        },
    );
    let cn = gateway
        .review_local_json(China, &raw(false), &f.pepper, &draft(Profile, ""))
        .await;
    assert_eq!(cn["following_count"], 456);
    let overseas = gateway
        .review_local_json(Global, &raw(false), &f.pepper, &draft(Profile, ""))
        .await;
    assert!(overseas.get("following_count").is_none());
    assert_eq!(
        gateway
            .review_local_json(China, &raw(false), &f.pepper, &draft(Comment, "hello"))
            .await["code"],
        "CONTENT_NOT_ALLOWED"
    );
    assert_eq!(
        gateway
            .review_local_json(Global, &raw(false), &f.pepper, &draft(Comment, "hello"))
            .await["text_content"],
        "hello"
    );
}

#[test]
fn model_parser_rejects_unknown_keys_duplicate_keys_and_values_without_echo() {
    for body in [
        r#"{"fields":[],"explanation":"SECRET"}"#,
        r#"{"fields":[],"fields":[]}"#,
        r#"{"fields":[{"field":"email","decision":"ALLOW","confidence_bps":10000}]}"#,
        r#"{"fields":[{"field":"handle","decision":"ALLOW","confidence_bps":-1}]}"#,
        r#"{"fields":[{"field":"handle","decision":"ALLOW","confidence_bps":10000,"value":"SECRET"}]}"#,
    ] {
        let error = parse_semantic_report(body.as_bytes()).unwrap_err();
        assert_eq!(error, ClassifierFailure::InvalidResponse);
        assert!(!format!("{error:?}").contains("SECRET"));
    }
    assert!(parse_semantic_report(&vec![b' '; MAX_MODEL_RESPONSE_BYTES + 1]).is_err());
}

#[tokio::test]
async fn concurrency_is_bounded_and_timeout_releases_capacity() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct BlockingReviewer {
        calls: AtomicUsize,
        started: tokio::sync::Notify,
    }
    impl SemanticClassifier for BlockingReviewer {
        fn classify(&self, input: ReviewInput) -> ClassificationFuture<'_> {
            Box::pin(async move {
                if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    self.started.notify_one();
                    std::future::pending::<()>().await;
                }
                FixtureReviewer.classify(input).await
            })
        }
    }
    let f = Fixture::new();
    let classifier = BlockingReviewer {
        calls: AtomicUsize::new(0),
        started: tokio::sync::Notify::new(),
    };
    let gate = SemanticReviewGate::new(&classifier, 1, std::time::Duration::from_millis(50), 9000)
        .unwrap();
    let gateway = f.outbound(Global).with_semantic_review(&gate);
    let local = raw(false);
    let d = draft(Profile, "");
    let first = gateway.prepare_local(China, &local, &f.pepper, &d);
    let second = async {
        classifier.started.notified().await;
        let error = gateway
            .prepare_local(China, &local, &f.pepper, &d)
            .await
            .unwrap_err();
        assert_eq!(error.review_json()["code"], "UNCERTAIN_PERSONAL_DATA");
        assert_eq!(classifier.calls.load(Ordering::SeqCst), 1);
    };
    let (first, ()) = tokio::join!(first, second);
    assert!(first.is_err());
    assert!(gateway
        .prepare_local(China, &local, &f.pepper, &d)
        .await
        .is_ok());
    assert_eq!(classifier.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn media_metadata_and_engagement_events_cannot_be_hidden_text_channels() {
    let f = Fixture::new();
    let classifier = CapturingReviewer::new(0);
    let gate =
        SemanticReviewGate::new(&classifier, 1, std::time::Duration::from_secs(1), 9000).unwrap();
    let gateway = f.outbound(Global).with_semantic_review(&gate);
    let mut d = draft(Comment, "hello");
    d.media_hashes.push(MediaPerceptualHash {
        mime_type: "SECRET-email@example.invalid".into(),
        pdq_hash: vec![0xff; 32],
        ..Default::default()
    });
    assert_eq!(
        gateway
            .review_local_json(China, &raw(false), &f.pepper, &d)
            .await["code"],
        "INVALID_PROJECTION"
    );
    let d = draft(
        FederatedEventType::EventTypeEngagementInteraction,
        "SECRET-embedded-text",
    );
    assert_eq!(
        gateway
            .review_local_json(China, &raw(false), &f.pepper, &d)
            .await["code"],
        "INVALID_PROJECTION"
    );
    assert!(classifier.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn receiver_requires_replay_protection_and_rejects_replays() {
    let f = Fixture::new();
    let e = f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &draft(Comment, "hello"))
        .await
        .unwrap();
    // Fail closed: no replay cache, no acceptance.
    assert!(matches!(
        f.inbound_without_replay(China).accept(&e, &f.peer(Global)),
        Err(InboundError::ReplayProtectionNotConfigured)
    ));
    let replay = fixture_replay();
    let inbound = f.inbound_without_replay(China).with_replay_cache(&replay);
    inbound.accept(&e, &f.peer(Global)).unwrap();
    let replayed = inbound.accept(&e, &f.peer(Global)).unwrap_err();
    assert!(matches!(
        replayed,
        InboundError::Replay(ReplayCacheError::ReplayDetected)
    ));
    assert_eq!(replayed.code(), "REPLAY_DETECTED");
    assert_eq!(
        replayed.drop_reason_code(),
        DropReasonCode::DropReasonReplayDetected
    );
    // A fresh nonce from the same sender is accepted.
    let mut next = draft(Comment, "hello again");
    next.nonce = 2;
    let e2 = f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &next)
        .await
        .unwrap();
    inbound.accept(&e2, &f.peer(Global)).unwrap();
}

#[tokio::test]
async fn receiver_rejects_stale_timestamps_and_unset_nonces() {
    let f = Fixture::new();
    let e = f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &draft(Comment, "hello"))
        .await
        .unwrap();
    // Receiver clock one hour after the event: outside the 5 minute window.
    let late = SlidingWindowReplayCache::with_clock(300, 16, || FIXTURE_NOW_MS + 3_600_000);
    assert!(matches!(
        f.inbound_without_replay(China)
            .with_replay_cache(&late)
            .accept(&e, &f.peer(Global)),
        Err(InboundError::Replay(ReplayCacheError::StaleTimestamp))
    ));
    // Unset nonce/timestamp are invalid on both sides, even when re-signed.
    for (nonce, timestamp) in [(0, FIXTURE_NOW_MS), (1, 0)] {
        let mut d = draft(Comment, "hello");
        d.nonce = nonce;
        d.timestamp_epoch_ms = timestamp;
        assert!(f
            .outbound(Global)
            .prepare_local(China, &raw(false), &f.pepper, &d)
            .await
            .is_err());
        let mut forged = e.clone();
        let mut event = decode(&forged);
        event.nonce = nonce;
        event.timestamp_epoch_ms = timestamp;
        resign(&f, &mut forged, event);
        assert!(matches!(
            f.inbound(China).accept(&forged, &f.peer(Global)),
            Err(InboundError::Content(_))
        ));
    }
}

#[tokio::test]
async fn receiver_rate_limits_each_trusted_peer_after_signature_checks() {
    let f = Fixture::new();
    let limiter = TokenBucket::new(1, 1);
    let replay = fixture_replay();
    let inbound = f
        .inbound_without_replay(China)
        .with_replay_cache(&replay)
        .with_rate_limiter(&limiter);
    let mut envelopes = vec![];
    for nonce in [1, 2] {
        let mut d = draft(Comment, "hello");
        d.nonce = nonce;
        envelopes.push(
            f.outbound(Global)
                .prepare_local(China, &raw(false), &f.pepper, &d)
                .await
                .unwrap(),
        );
    }
    // A forged envelope fails the signature check without spending quota.
    let mut forged = envelopes[0].clone();
    forged.ed25519_signature[0] ^= 1;
    assert!(matches!(
        inbound.accept(&forged, &f.peer(Global)),
        Err(InboundError::Signature(_))
    ));
    inbound.accept(&envelopes[0], &f.peer(Global)).unwrap();
    assert!(matches!(
        inbound.accept(&envelopes[1], &f.peer(Global)),
        Err(InboundError::RateLimited { .. })
    ));
}

#[tokio::test]
async fn audit_log_records_value_free_decisions_on_both_gateways() {
    let f = Fixture::new();
    let log = HashChainedAuditLog::new();
    let outbound = f.outbound(Global).with_audit_log(&log);
    let e = outbound
        .prepare_local(China, &raw(false), &f.pepper, &draft(Comment, "hello"))
        .await
        .unwrap();
    assert!(outbound
        .prepare_local(China, &raw(false), &f.pepper, &draft(Comment, "Tiananmen"))
        .await
        .is_err());
    let replay = fixture_replay();
    let inbound = f
        .inbound_without_replay(China)
        .with_replay_cache(&replay)
        .with_audit_log(&log);
    inbound.accept(&e, &f.peer(Global)).unwrap();
    assert!(inbound.accept(&e, &f.peer(Global)).is_err());

    let records = log.records();
    let summary: Vec<_> = records
        .iter()
        .map(|r| {
            (
                r.event_type.as_str(),
                r.outcome.as_str(),
                r.reason.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            ("envelope_export", "allowed", None),
            ("envelope_export", "rejected", Some("POLICY_KEYWORD")),
            ("envelope_accept", "allowed", None),
            ("envelope_accept", "rejected", Some("REPLAY_DETECTED")),
        ]
    );
    for r in &records {
        assert_eq!((r.origin, r.destination), (Global as u32, China as u32));
        assert_eq!(r.actor_key_id, "regional-key");
    }
    // Records carry codes only: no content, handles, names or local identifiers.
    let dump = format!("{records:?}").to_lowercase();
    for secret in ["tiananmen", "hello", "nickname", "public name", "secret"] {
        assert!(!dump.contains(secret), "{secret}");
    }
    assert!(verify_records(&records, None).is_ok());
    assert!(log.verify_chain(1, 4).unwrap());
}

#[tokio::test]
async fn audit_failures_fail_closed() {
    let f = Fixture::new();
    let full = HashChainedAuditLog::with_max_records(1);
    let outbound = f.outbound(Global).with_audit_log(&full);
    outbound
        .prepare_local(China, &raw(false), &f.pepper, &draft(Comment, "hello"))
        .await
        .unwrap();
    // The log is full: a valid export is refused instead of leaving unrecorded.
    let err = outbound
        .prepare_local(China, &raw(false), &f.pepper, &draft(Comment, "hello"))
        .await
        .unwrap_err();
    assert!(matches!(err.reason, OutboundRejection::AuditUnavailable));
    assert_eq!(
        err.review_json(),
        serde_json::json!({"code": "AUDIT_UNAVAILABLE"})
    );

    let e = f
        .outbound(Global)
        .prepare_local(China, &raw(false), &f.pepper, &draft(Comment, "hello"))
        .await
        .unwrap();
    assert!(matches!(
        f.inbound(China)
            .with_audit_log(&full)
            .accept(&e, &f.peer(Global)),
        Err(InboundError::AuditUnavailable)
    ));
}

#[tokio::test]
async fn kill_switch_stops_both_gateways_until_the_auditor_rearms() {
    let f = Fixture::new();
    let ks = AtomicKillSwitch::from_token("auditor-token");
    let outbound = f.outbound(Global).with_kill_switch(&ks);
    let e = outbound
        .prepare_local(China, &raw(false), &f.pepper, &draft(Comment, "hello"))
        .await
        .unwrap();
    ks.trip().unwrap();
    let err = outbound
        .prepare_local(China, &raw(false), &f.pepper, &draft(Comment, "hello"))
        .await
        .unwrap_err();
    assert!(matches!(err.reason, OutboundRejection::KillSwitchTripped));
    assert!(!err.policy_notices().is_empty());
    assert!(outbound.prepare(China, &decode(&e)).await.is_err());
    let replay = fixture_replay();
    let inbound = f
        .inbound_without_replay(China)
        .with_replay_cache(&replay)
        .with_kill_switch(&ks);
    assert!(matches!(
        inbound.accept(&e, &f.peer(Global)),
        Err(InboundError::KillSwitchTripped)
    ));
    assert!(ks.rearm("wrong").is_err());
    ks.rearm("auditor-token").unwrap();
    inbound.accept(&e, &f.peer(Global)).unwrap();
    assert!(outbound.prepare(China, &decode(&e)).await.is_ok());
}
