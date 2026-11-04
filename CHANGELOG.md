# 0.8.0

Anonimización formalmente homologable (CAC / PIPL Art. 73 y NIST SP 800-188), 2026-11-04:
- Contrato proto extendido sin romper compatibilidad (campos al final): 
  `SanitizedPublicProfile` añade `generalized_followers_count` (bucket k-anónimo,
  NIST SP 800-188), `actor_public_key` (Ed25519 del Actor Público Autónomo) y
  `commitment_hash` (vínculo civil anclado localmente). `CrossBorderEventPayload`
  añade `content_signature` (firma de autoría del actor), `actor_public_key` y
  `zk_proof_reference` (referencia a prueba ZK retenida localmente).
- Nuevo módulo `splinter_core::merkle`: árbol de commitments Merkle; solo la raíz
  cruza la frontera, la apertura civil queda bajo custodia local de umbral.
- Nuevo módulo `splinter_core::differential_privacy::generalize_followers_count`
  para bucketización k-anónima de seguidores.
- `splinter_filter::PreflightEgressFilter::scan_direct_pii`: detección de PII
  directa (email, teléfono, IPv4, RUT chileno) que bloquea la exportación con
  `DropReasonCode::DropReasonDirectPiiDetected`; integrado en
  `OutboundGateway::check_export` sobre texto, handle, display name y avatar.
- `splinter_core::identity`: `project_blind_profile_with_options` deriva el
  follower count generalizado y expone la clave pública y commitment del actor.
- `docs/HOMOLOGACION_CAC_NIST.md`: arquitectura de cuatro capas para homologar
  la anonimización ante la CAC (China) y el NIST/FTC (EE. UU.), manteniendo
  exactamente la experiencia de usuario (nickname, display name, seguidores,
  posts).
- Nuevo `OutboundRejection::DirectPii`. Bump de versión a 0.8.0.

# 0.7.0

Anonimización y seudonimización (PIPL art. 73 / GDPR Considerando 26), 2026-11-04:
- Nuevo módulo `splinter_core::ephemeral`: identificadores efímeros con semilla
  maestra rotatoria por época, `derive_ephemeral_did` no vinculable entre
  épocas, `EphemeralSession` con crypto-shredding (zeroize) del nonce al
  dropear y `EphemeralVault` con rotación de claves de época destruidas en
  memoria. Respuesta al problema de que `derive_federated_did` es reversible
  por el origen operator con el pepper local (seudonimización, no anonimización).
- Nuevo módulo `splinter_core::differential_privacy`: ruido laplaciano y
  gaussiano, conteo diferencial (epsilon) y puerta k-anónima para agregados
  de métricas/telemetría sin traza individual.
- Nueva guía docs/ANONYMIZATION.md: distingue seudonimización de anonimización
  bajo PIPL art. 73 y GDPR Considerando 26, describe los tres caminos técnicos
  y el camino realista de transferencia (evaluación CAC / contratos estándar).
- Documenta en `identity.rs` que `derive_federated_did` es determinista y
  reversible por el origen; remite a `ephemeral` para identificadores
  no vinculables.
- Bump de versión a 0.7.0. Ningún cambio en campos de proto, números de campo
  ni formatos de firma.

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
