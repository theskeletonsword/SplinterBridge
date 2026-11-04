# Repository guidance

Read README.md and CHANGELOG.md for current scope and migration notes.

## Commands

```bash
cargo build --release --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

- Build uses vendored `protoc` unless `PROTOC` is set.
- `clippy`/`rustfmt` may not be installed in every environment; if a command is missing, skip it rather than installing.
- `cargo test --workspace --locked` is the single verification step; run it after any code change.

## Workspace

- Four crates: `splinter-proto`, `splinter-filter`, `splinter-safety`, `splinter-core`.
- `splinter-core` is the facade; it re-exports the other crates' public APIs.
- Dependencies declared in root `Cargo.toml` (workspace 0.9.0, edition 2021) and inherited by members.
- Tests live alongside source in `#[cfg(test)]` modules. Run one crate: `cargo test -p splinter-core --locked`.

## Source of truth

- `proto/splinter_bridge.proto` and `proto/local_review.proto` are the wire contract. Prost strips the `Jurisdiction` prefix from jurisdiction enum variants; `DropReasonCode` and `VerifiedBadgeType` keep their `DropReason`/`VerifiedBadge` prefixes.
- Do not reuse or remove protobuf field numbers. Append-only changes only; signature formats (profile v2, envelope v1) require coordinated migration + tampering tests if changed.
- `crates/splinter-proto/build.rs` compiles both protos with `tonic-build`.

## Architecture

- `splinter-core` modules: `boundary`, `differential_privacy`, `ephemeral`, `hsm`, `identity`, `inbound`, `killswitch`, `merkle`, `outbound`, `outbox`, `rate_limit`, `replay`, `review`, plus `audit_log`, `attestation`, `doj_compliance` (DOJ/CFIUS compliance interfaces).
- `splinter-filter` modules: `catalog` (hot-reloadable regulatory catalog).
- Backends must remain mutually blind: no direct DB access, shared credentials, replication, or cross-region joins. Gateways exchange signed, policy-checked projections only.
- `OutboundGateway::prepare_local` / `prepare` are async, require explicit destination route + semantic reviewer, reject sender extras without per-route opt-in. Neither modifies the domestic event.
- `InboundGateway::accept` verifies peer key/region/destination, canonical payload, route notice consistency. No remote DB lookup.

## Invariants (do not break)

- Dedicated private profile fields stay out of profile projection.
- Regional HMAC secrets stay local; route policy checked at origin. China rules apply when either endpoint is China.
- Media comparison is local; no external media requests in the matching path.
- Errors must not carry matched text or matched values.
- Do not claim the libraries guarantee anonymity or legal compliance.
- `doj_compliance` and `attestation` default to **deny** and are trait interfaces only. `replay`, `rate_limit`, `audit_log` and `killswitch` have single-process implementations wired into the gateways; production needs shared/durable backends.
- `InboundGateway::accept` fails closed without `with_replay_cache`. Audit records carry value-free codes only; a failed append rejects the operation.

## Notable gotchas

- CI enforces `cargo fmt --check` and `clippy -D warnings`; run both before pushing. If they are missing, say so instead of running install steps.
- `OutboundError::review_json()` returns fixed codes only — never echo matched text.
- Media catalog starts empty; `OutboundGateway::prepare` rejects media exports until a catalog is loaded. Default PDQ Hamming threshold is 31 (inclusive).
- `DropReasonDirectPiiDetected` blocks direct PII (email, phone, IPv4, national ID pattern) before crossing the border.
