# AGENTS.md

Guidance for AI coding agents working in this repository. See `README.md` for the design/threat model and `CLAUDE.md` for a longer architecture walkthrough.

SplinterBridge (Rust 2021 workspace, ref impl of a zero-trust S2S federation gateway between social backends under incompatible regulatory regimes: Global/GDPR, China CAC/PIPL, Russia RKN). Code changes must preserve four invariants: no PII in cross-border payloads; identities cross borders only as blind HMAC-based `federated_did`s; egress text is filtered against the *destination* jurisdiction's catalog at the origin; media is checked against StopNCII PDQ hashes in memory (Hamming ≤ 31), never via third-party calls.

## Commands

- `protoc` (`protobuf-compiler`) must be on PATH — `splinter-proto/build.rs` regenerates stubs via `tonic-build` on every build of that crate. Without it, `cargo check`/`build` fails fast with `Could not find \`protoc\``; fix with `apt-get install protobuf-compiler` (Debian) or by pointing the `PROTOC` env var at an existing protoc binary.
- `cargo build --release` and `cargo test --workspace` are the README quickstart; there is no CI config in-repo, so local cargo is the only verification.
- One crate: `cargo test -p splinter-filter`. One test by name filter: `cargo test -p splinter-core test_signature`.
- Lint/format: `cargo clippy --workspace --all-targets`, `cargo fmt --all`.
- Tests are inline `#[cfg(test)] mod tests` in each source file; there is no `tests/` directory.

## Architecture

- Dependency direction: `splinter-proto` ← (`splinter-filter`, `splinter-safety`) ← `splinter-core`. `splinter-core/src/lib.rs` is a facade re-exporting every other crate's public API — downstream code should depend only on `splinter-core`.
- `proto/splinter_bridge.proto` (`splinterbridge.v1`) is the single source of truth for wire types and the gRPC service; `splinter-proto` only includes/re-exports the generated stubs.
- Dependency versions are pinned once in the root `Cargo.toml` `[workspace.dependencies]`; member crates reference them with `foo.workspace = true`. Add new deps at the root first.

## Gotchas

- **Prost enum naming:** generated variants keep the enum prefix, CamelCased (`JURISDICTION_CN_PIPL_CAC` → `Jurisdiction::JurisdictionCnPiplCac`), and enum / repeated-enum message fields are stored as `i32` (hence the `as i32` casts in `identity.rs`).
- **Signatures do not cover everything.** `sign_profile`/`verify_profile` sign a serde_json `CanonicalProfilePayload` (not protobuf bytes) that intentionally omits `public_avatar_url` and `badges` — those fields are not tamper-protected. Signer and verifier each build that struct separately; any change must be mirrored in both places or verification breaks silently.
- **Filter rule alignment:** `PreflightEgressFilter` builds one ASCII-case-insensitive `LeftmostFirst` Aho-Corasick automaton per destination jurisdiction from hard-coded `RuleMeta` lists in `new()`; match indices index into that same `Vec<RuleMeta>`, so the vec is the single source for both. Destination `JurisdictionGlobalGdpr` is unfiltered; `JurisdictionUnspecified` returns an error.
- **`RegionalPepper::new_test()` is `#[cfg(test)]` only** — unavailable outside tests.
- Error convention: `thiserror` enums; filter/safety errors expose `drop_reason_code()` → proto `DropReasonCode`, the value callers put in `FederatedEventResponse.drop_reason`.

## Design intent vs. implemented reality

The README describes more than exists: there is no gRPC server/client, no mTLS setup, no envelope signature over `payload_bytes`, no replay/nonce/timestamp-window checks, no hardware-attestation verification, no TMK video hashing. `tokio`, `tonic` transport, `rustls`, `aws-lc-rs`, and `tracing-subscriber` are declared but largely unused. Treat the README as design intent, not current behavior.

## Environment

The repo lives on a WSL filesystem — run cargo from inside WSL/Linux, not from Windows against the UNC path.
