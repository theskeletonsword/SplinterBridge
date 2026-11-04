//! Local, data-only round trip. No database or network connection is opened.
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};
use splinter_core::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
        };
        let outbound = OutboundGateway::new(
            origin,
            "configured-gateway".into(),
            &signer,
            &filter,
            &safety,
        )?;
        let envelope = outbound.prepare_local(destination, &raw, &pepper, &draft)?;
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
