# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project context

SplinterBridge is a reference implementation (v0.1.0, Apache-2.0, author TheSkeletonSword / `perex`) of a server-to-server federation gateway between social-network backends that live under incompatible legal regimes: Global/GDPR, Mainland China (PIPL/CAC) and Russia (152-FZ/RKN). The example use case in the README is federating TikTok Global with Douyin so creators can interact across borders, while each side keeps its own data and content rules.

The design rests on four invariants. Code changes should preserve them:

1. **Zero-PII crossing.** No raw user ID, email, phone, IP or real-name/national-ID data is ever serialized into a cross-border payload. Western users prove they're human with hardware attestations (FIDO2/WebAuthn, Secure Enclave, StrongBox) instead of uploading IDs. Chinese real-name (Shimingzhi) data stays on domestic servers.
2. **Blind identity mapping.** Users appear abroad only as `federated_did` = HMAC-SHA256(regional pepper, internal ID), plus a public handle, display name, avatar URL, aggregate follower/following counts, a private flag and badges. Peppers never leave the origin region's HSM/KMS.
3. **Egress filtering at the origin.** Before an event is sent, its text is checked in memory against the *destination* jurisdiction's banned-term catalog (CAC or RKN). A match drops the event with a `DropReasonCode`. The content stays visible in the origin's domestic feed and simply isn't exported.
4. **Local media-safety matching.** Media is checked against StopNCII/CSAM perceptual hashes (PDQ 256-bit; TMK for video is planned) by Hamming distance ≤ 31, entirely in memory, with no calls to third parties.

Planned transport (see README threat model): gRPC over mutual TLS 1.3, Ed25519 signatures on every envelope, and replay protection through a 60 s timestamp window, UUIDv4 event IDs and nonces.

## Commands

Requires Rust 1.75+ and `protoc` (protobuf-compiler) on PATH — `splinter-proto/build.rs` invokes it via `tonic-build` on every build.

```bash
cargo build --release                         # build whole workspace
cargo test --workspace                        # all tests
cargo test -p splinter-filter                 # one crate
cargo test -p splinter-core test_signature    # single test by name filter
cargo clippy --workspace --all-targets
cargo fmt --all
```

The repo lives on a WSL filesystem (`\\wsl.localhost\Debian\...`); run cargo from inside WSL rather than from Windows against the UNC path.

## Architecture

Cargo workspace (edition 2021, resolver 2). All dependency versions are pinned once in the root `Cargo.toml` `[workspace.dependencies]`; member crates reference them with `foo.workspace = true`. Add new deps at the root first.

Dependency graph: `splinter-proto` ← `splinter-filter`, `splinter-safety` ← `splinter-core`.

- **`proto/splinter_bridge.proto`** (`splinterbridge.v1`) is the single source of truth for wire types and the `SplinterBridgeService` gRPC service. `splinter-proto` just does `tonic::include_proto!` and re-exports `v1::*`. Prost renames enum variants to CamelCase with the enum prefix kept (e.g. `JURISDICTION_CN_PIPL_CAC` → `Jurisdiction::JurisdictionCnPiplCac`), and enum/repeated-enum fields in messages are stored as `i32` (hence `as i32` casts in `identity.rs`).
- **`splinter-core`** — `identity.rs` holds the blind-identity layer: `derive_federated_did` (HMAC-SHA256 keyed by `RegionalPepper` over `"<jur_code>:<internal_id>"`, output `did:splinter:<global|cn|ru>:<hex>`), `project_blind_profile` (maps `RawInternalUserProfile` → proto `SanitizedPublicProfile`, dropping email/phone/IP/national ID), and `GatewaySigner`/`GatewayVerifier` (Ed25519). `lib.rs` is a facade that re-exports the public API of all other crates — downstream code is expected to depend only on `splinter-core`.
- **`splinter-filter`** — `PreflightEgressFilter`: one Aho-Corasick automaton per destination jurisdiction (ASCII-case-insensitive, `LeftmostFirst`), built from hard-coded `RuleMeta` term lists in `new()`. `check_text(destination, text)` returns `EgressFilterError` carrying a proto `DropReasonCode`. Rule index in the `Vec<RuleMeta>` must stay aligned with the pattern index in the automaton. Destination `GlobalGdpr` is unfiltered; `Unspecified` is an error.
- **`splinter-safety`** — `StopNciiEngine`: `RwLock<Vec<PdqHash>>` linear scan, matching when Hamming distance ≤ threshold (`DEFAULT_PDQ_HAMMING_THRESHOLD = 31`). `PdqHash` is `[u64; 4]` built from 32 bytes little-endian.

Error convention across crates: `thiserror` enums, and filter/safety errors expose `drop_reason_code()` so callers can fill `FederatedEventResponse.drop_reason`.

### Things that aren't obvious

- **Signatures cover a JSON canonical form, not protobuf bytes.** `sign_profile`/`verify_profile` serialize a private `CanonicalProfilePayload` struct with `serde_json`. It intentionally (or not) omits `public_avatar_url` and `badges`, so those fields are *not* tamper-protected. Signer and verifier each build the struct separately — any change must be made in both places identically or verification breaks.
- **README describes more than is implemented.** There is no gRPC server/client implementation, no mTLS setup, no envelope signing over `payload_bytes`, no replay/nonce/timestamp-window checks, no attestation verification, and no TMK video matching. `tokio`, `tonic` transport, `rustls`, `aws-lc-rs`, `tracing-subscriber` are declared but largely unused. Treat the README as the design intent.
- `RegionalPepper::new_test()` is `#[cfg(test)]` only.
- Tests are inline `#[cfg(test)] mod tests` in each source file; there is no `tests/` directory.
