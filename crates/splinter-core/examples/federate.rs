//! Local, data-only round trip. No database or network connection is opened.
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};
use splinter_core::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let review = SemanticReviewGate::new(
        &SyntheticFixtureReviewer,
        1,
        std::time::Duration::from_secs(1),
        10000,
    )?;
    for (origin, destination) in [
        (Jurisdiction::GlobalGdpr, Jurisdiction::CnPiplCac),
        (Jurisdiction::CnPiplCac, Jurisdiction::GlobalGdpr),
    ] {
        let signer = GatewaySigner::new(SigningKey::generate(&mut OsRng));
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let pepper = RegionalPepper::new(&secret);
        zeroize::Zeroize::zeroize(&mut secret);
        let filter = PreflightEgressFilter::new();
        let safety = StopNciiEngine::default();
        let raw = RawInternalUserProfile {
            internal_user_id: "local-account-id".into(),
            national_id_hash: None,
            email: Some("local-only@example.invalid".into()),
            phone: None,
            internal_ip_address: None,
            handle: "@example".into(),
            display_name: "Example".into(),
            avatar_url: String::new(),
            followers_count: 42,
            following_count: 10,
            is_private: true,
            badges: vec![],
            actor_public_key: None,
            commitment_hash: None,
        };
        let draft = LocalEventDraft {
            local_event_id: "local-profile-update-id".into(),
            local_resource_id: None,
            event_type: FederatedEventType::EventTypeProfileSync,
            timestamp_epoch_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis()
                .try_into()?,
            nonce: OsRng.next_u64(),
            text_content: String::new(),
            media_hashes: vec![],
            target: LocalEventTarget::None,
            content_signature: None,
            actor_public_key: None,
            zk_proof_reference: None,
        };
        let outbound = OutboundGateway::new(
            origin,
            "configured-gateway".into(),
            &signer,
            &filter,
            &safety,
        )?
        .with_route_policy(destination, ExportRoutePolicy::default())
        .with_semantic_review(&review);
        let envelope = outbound
            .prepare_local(destination, &raw, &pepper, &draft)
            .await?;
        // In a real deployment this key binding is provisioned locally, never taken from a received message.
        let trusted = TrustedGateway {
            key_id: "configured-gateway".into(),
            origin,
            public_key: signer.verifying_key().to_bytes(),
        };
        let received =
            InboundGateway::new(destination, &filter, &safety)?.accept(&envelope, &trusted)?;
        for notice in received.notices {
            if let Some(text) = interaction_notice_en(notice) {
                println!("{text}");
            }
        }
        let profile = received.payload.author.ok_or("missing public profile")?;
        println!(
            "{origin:?} -> {destination:?}: {} | {} | {} followers | private={}",
            profile.handle, profile.display_name, profile.followers_count, profile.is_private
        );
    }
    Ok(())
}

// Synthetic data demonstration ONLY. Production must supply a locally evaluated model.
struct SyntheticFixtureReviewer;
impl SemanticClassifier for SyntheticFixtureReviewer {
    fn classify(&self, input: ReviewInput) -> ClassificationFuture<'_> {
        Box::pin(async move {
            if input.fields.len() != 2
                || input.fields[0].text != "@example"
                || input.fields[1].text != "Example"
            {
                return Err(ClassifierFailure::Unavailable);
            }
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
