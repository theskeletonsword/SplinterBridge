# Unreleased

Working controls behind the 0.9.0 interfaces, a crash fix and green CI:
- **Fix (security):** `scan_direct_pii` sliced `&str` at byte offsets and
  panicked on any CJK/Cyrillic text longer than 12 bytes. It runs on both the
  outbound and inbound paths, so a peer could crash a receiving gateway with
  ordinary Chinese text. It now scans byte windows; regression test added.
- `SlidingWindowReplayCache` and `TokenBucket` were stubs that always allowed.
  They are now real, bounded, single-process implementations with tests
  (atomic check-and-record, clock-step-back protection, fail closed when full).
- New `HashChainedAuditLog` with `compute_record_hash`/`verify_records`: SHA-256
  hash-chained, value-free decision records that auditors can verify from an
  export. `NoopAuditLog::verify_chain` now returns an error instead of `true`.
- New `AtomicKillSwitch`: trips immediately, rearms only with the auditor token
  (stored as SHA-256). `DefaultKillSwitch`, which could never trip, is deprecated.
- Gateways: `InboundGateway::with_replay_cache` (required), `with_rate_limiter`,
  and `with_audit_log`/`with_kill_switch` on both gateways. A failed audit append
  refuses the operation. New value-free `OutboundError::code()`,
  `InboundError::code()` and `InboundError::drop_reason_code()`.
- Removed `der.rs`, `cbor.rs`, `engine.rs`, `mih.rs` and `pdq.rs`: they were never
  declared as modules, never compiled, and needed undeclared dependencies.
- rustfmt and clippy fixes; CI had been failing since the 0.7.0 commit.

Migration:
- `InboundGateway::accept` returns `ReplayProtectionNotConfigured` until
  `with_replay_cache` is set. Share one `ReplayCache` per receiving route.
- Events with `nonce == 0` or `timestamp_epoch_ms <= 0` are now rejected by both
  gateways. Senders must use a random, non-zero nonce per event.
- Envelopes older than the replay window (default 5 minutes) are rejected as
  stale; retries beyond the window need a newly prepared event.
- New `OutboundRejection` and `InboundError` variants; exhaustive matches need
  updating.

Not changed: no proto field-number or signature-format changes. None of this
establishes DOJ, CFIUS, CAC or other regulatory approval.

# 0.9.0

Production-ready interfaces and known gaps (CAC / PIPL Art. 73 and NIST SP 800-188), 2026-11-04:
- New module `splinter_core::replay`: anti-replay sliding-window nonce cache trait
  (`ReplayCache`, `SlidingWindowReplayCache`) for distributed replay protection.
- New module `splinter_core::rate_limit`: rate limiter trait (`RateLimiter`,
  `NoopRateLimiter`, `TokenBucket`) for distributed backpressure and admission control.
- New module `splinter_core::hsm`: HSM abstraction trait (`HsmSigner`,
  `SoftwareHsm`) so operators can plug FIPS 140-3 / OSCCA GM/T HSMs via PKCS#11.
- New module `splinter_core::outbox`: durable outbox/inbox interface traits
  (`Outbox`, `Inbox`, `NoopOutbox`, `NoopInbox`) for Kafka/Pulsar/Raft-backed
  durable delivery and idempotent receipt.
- New module `splinter_filter::catalog`: hot-reloadable regulatory catalog trait
  (`RegulatoryCatalog`, `AllowAllCatalog`) for zero-downtime catalog updates.
- New doc `docs/PRODUCTION_REALITY.md`: five production barriers (durable delivery,
  replay/backpressure, hardware sovereignty, false-negative legal liability,
  CAC/PAFACA/CFIUS/TIA bureaucracy) with what the library provides vs. what
  production requires.
- Version bump to 0.9.0; no proto field-number or signature-format changes.

# 0.8.0

Formally homologable anonymization (CAC / PIPL Art. 73 and NIST SP 800-188), 2026-11-04:
- Proto contract extended without breaking compatibility (fields appended at the
  end): `SanitizedPublicProfile` adds `generalized_followers_count` (k-anonymity
  bucket, NIST SP 800-188), `actor_public_key` (Ed25519 of the Autonomous Public
  Actor) and `commitment_hash` (civil commitment anchored locally).
  `CrossBorderEventPayload` adds `content_signature` (actor authorship
  signature), `actor_public_key` and `zk_proof_reference` (locally-retained ZK
  proof reference).
- New module `splinter_core::merkle`: Merkle commitment tree; only the root
  crosses the border, civil opening under local threshold custody.
- New module `splinter_core::differential_privacy::generalize_followers_count`
  for k-anonymized bucketization of followers.
- `splinter_filter::PreflightEgressFilter::scan_direct_pii`: direct PII
  detection (email, phone, IPv4, generic national ID) blocking export with
  `DropReasonCode::DropReasonDirectPiiDetected`; integrated into
  `OutboundGateway::check_export` over text, handle, display name and avatar.
- `splinter_core::identity`: `project_blind_profile_with_options` derives the
  generalized follower count and exposes the actor public key and commitment.
- `docs/CAC_NIST_HOMOLOGATION.md`: four-layer architecture to homologate
  anonymization before the CAC (China) and NIST/FTC (U.S.), while preserving
  the exact end-user experience (nickname, display name, followers, posts).
- New `OutboundRejection::DirectPii`. Version bump to 0.8.0.

# 0.7.0

Anonymization and pseudonymization (PIPL Art. 73 / GDPR Recital 26), 2026-11-04:
- New module `splinter_core::ephemeral`: ephemeral identifiers with rotating
  master seed per epoch, `derive_ephemeral_did` unlinkable across epochs,
  `EphemeralSession` with crypto-shredding (zeroize) of the nonce on drop, and
  `EphemeralVault` with rotation of epoch keys destroyed in memory. Response to
  the problem that `derive_federated_did` is reversible by the origin operator
  with the local pepper (pseudonymization, not anonymization).
- New module `splinter_core::differential_privacy`: Laplace and Gaussian noise,
  differential epsilon counting and k-anonymity gate for metrics/telemetry
  aggregates without individual trace.
- New guide docs/ANONYMIZATION.md: distinguishes pseudonymization from
  anonymization under PIPL Art. 73 and GDPR Recital 26, describes the three
  technical paths and the realistic transfer route (CAC assessment / standard
  contracts).
- Documents in `identity.rs` that `derive_federated_did` is deterministic and
  origin-reversible; refers to `ephemeral` for unlinkable identifiers.
- Version bump to 0.7.0. No changes to proto fields, field numbers or signature
  formats.

Documentation revision, 2026-11-04:
- Update README and the informational NOTICE sections with source-linked legal
  applicability guidance for mainland China, the EU/EEA and selected U.S. regimes.
- Correct assumptions about anonymity, HSM/enclave/TMK implementation, signatures,
  regulator contracts, content-filter immunity and automatic transfer compliance.
- Add docs/LEGAL_DEPLOYMENT.md with applicable mechanisms, primary sources and an
  operator-evidence matrix. Preserve blind-backend separation and the Apache
  license/attributions. No Rust, protobuf, dependency or runtime changes.


- Require per-destination route/content/extra-field opt-ins and asynchronous
  origin-local semantic review on both outbound preparation APIs before signing.
- Add a bounded, non-queuing review gate with timeouts, confidence thresholds,
  closed verdicts and fail-closed handling of missing, duplicate or invalid results.
- Add a real gRPC client over Unix sockets with server UID validation, request
  deadlines, bounded messages and no TCP/DNS or external inference fallback.
  This is a model integration interface, not a bundled trained classifier.
- Add a JSON business-projection review API: allowlisted fields + policy code on
  success, fixed codes on rejection, field-only uncertainty with no value echo.
- Remove matched terms and categories from keyword errors, normalize common
  fullwidth/invisible/whitespace variants, and preserve route-local originals.
- Close unchecked MIME metadata and engagement-content text channels.
- Keep backends/DBs mutually blind; document model ownership and missing production
  components for large social platforms. The local RPC is separate from federation.
- Breaking source API migration is documented in README.md and docs/REGIONAL_REVIEW.md.
  Existing federation protobuf fields and signature formats are unchanged.

Validation results and the environment's Unix-socket limitation are recorded in
VALIDATION.txt. No model accuracy or production throughput claim is made.

# 0.5.0

- Standardize documentation, policy guidance, client notice text and example
  output on English for independent platform implementers and technical review.
- Rename `interaction_notice_es` to `interaction_notice_en`; update tests and
  the runnable example. This is a source API change, not a wire-format change.
- Translate and rename the interaction policy to INTERACTION_POLICY.md.
- Preserve Chinese and Russian catalog entries and test fixtures as matching data.
- Preserve the four-route policy, reciprocal public fields, mutually blind
  backend architecture and all existing implementation limitations.

Validated with 31 passing unit tests, passing doc-tests, formatting checks,
strict Clippy, release compilation and the English bidirectional example.
Full command output is recorded in VALIDATION.txt.

# 0.4.0

- Add `prepare_local` to construct minimal reciprocal public profiles from local
  records; avatars, following counts and badges now require explicit opt-in.
- Add opaque regional event/resource references and validate all boundary IDs.
  Payload field 9 (`resource_id`) lets replies target locally indexed projections
  without querying a remote backend. Peers must upgrade together.
- Redact private raw profile Debug output and keep raw records/drafts off the wire.
- Add inbound peer-key/region/destination verification, size limits, canonical
  payload checks, route re-evaluation and mandatory notice consistency.
- Reject unsupported hardware assertions and private-account content. Public
  profile synchronization works for public and private accounts in both directions.
- Filter public profile text as well as event text; notices survive identity,
  projection, policy and media preparation failures on restricted routes.
- Add a runnable reciprocal local example and adversarial round-trip tests.
- Breaking API changes and deployment limitations are described in README.md.

Validated on Linux x86_64 with Rust 1.99.1: 31 unit tests and doc-tests passed;
format checks, strict Clippy, release compilation and the local example passed.
Full command output is recorded in VALIDATION.txt. No live network, database or
platform integration was exercised.

# 0.3.0

- Apply an explicit endpoint matrix: Overseas → Overseas has no China filter;
  Overseas → China, China → Overseas and China → China use the China catalog.
- Add `assess_interaction` for route notices and content checks, usable before
  composing and in domestic adapters before local acceptance.
- Make outbound preparation enforce both endpoint jurisdictions.
- Return notices for policy rejections and bind accepted notice codes into
  envelope signatures. Add notice fields to envelope and response schemas.
- Add matrix coverage for English/Chinese terms, allowed cross-region messages,
  China-origin exports, rejected-message notices and notice tampering.
- Preserve independent domestic storage and unrelated overseas interactions.
- New local validation: 20 unit tests; formatting, strict Clippy and release build.
  See VALIDATION.txt. Frontend display and live transport remain adapter work.

# 0.2.0

- Make platform-neutral scope and independent domestic databases explicit.
- Add `OutboundGateway::prepare`: independently check a destination's text/media
  policy and sign permitted exports without mutating the domestic event.
- Refuse media exports with empty catalogs or unsupported TMK hashes in that helper.
- Add regression tests for blocked China export while preserving the original
  comment and permitting an independent export to another destination.
- Fix Prost jurisdiction enum names that prevented the workspace from compiling.
- Protect every public-profile field, with a shared v2 serialization and strict
  Ed25519 verification. This intentionally invalidates old profile signatures.
- Add full-envelope signatures that bind payload, origin, destination, key ID
  and optional attestation; no replay protection is implied.
- Clear owned regional pepper buffers on drop and reject short peppers/empty IDs.
- Correct uppercase/mixed-case Cyrillic keyword matching.
- Add vendored protoc fallback, a dependency lockfile and CI checks.
- Add regressions for avatar/badge/payload/routing/attestation tampering,
  incorrect keys/signature lengths, identity validation, Cyrillic case handling,
  hash lengths and the 31/32-bit media matching boundary.
- Replace unverified architecture guarantees with documented implementation limits.

## Validation

Validated on Linux x86_64 with Rust 1.99.1:

- `cargo fmt --all -- --check`: passed.
- `cargo test --workspace --locked`: 18 unit tests passed; doc-tests passed.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed.
  The upstream generated Tonic module has a scoped `result_large_err` allowance;
  handwritten code has no blanket lint suppression.
- `cargo build --release --locked`: passed.

Full command output is included in VALIDATION.txt. CI configuration is included
but has not been executed on GitHub. No live service or platform integration was
exercised, because neither is implemented.
