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
