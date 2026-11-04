# Repository guidance

Read README.md and CHANGELOG.md for current scope and migration notes.

## Invariants

- Dedicated private profile fields must stay out of profile projection.
- Regional HMAC secrets stay local; route policy is checked at origin. China rules apply when either endpoint is
  China; two global endpoints do not inherit them. Cross-region China interactions
  return notices on acceptance and policy rejection.
- Media comparison is local; no external media requests in the matching path.
- Do not claim these libraries guarantee anonymity or legal compliance.

## Architecture

The facade is `splinter-core`; it depends on `splinter-proto`, `splinter-filter`
and `splinter-safety`. The `.proto` contract is the wire source of truth.
Dependencies are declared in root Cargo.toml and inherited by members.
Tests live alongside source in `#[cfg(test)]` modules.

## Commands

```bash
cargo build --release --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

The build uses vendored protoc unless PROTOC is set. Prost strips the
`Jurisdiction` prefix from jurisdiction values, but `DropReasonCode` and
`VerifiedBadgeType` values retain `DropReason` and `VerifiedBadge` prefixes.

Profile signature v2 includes every current profile field via one shared
serializer and a versioned domain prefix. Envelope signatures bind all known
fields except the signature itself. Changes to either format require coordinated
migration and tampering tests. `OutboundGateway::prepare_local` projects local records and signs approved exports.
The advanced `prepare` validates pre-built projections. Neither modifies the domestic
event. Call it per destination after committing the local event. Platform adapters
and regional databases remain independent. There is no
replay protection, hardware validation or transport security implementation.
Filter matching uses lowercased Unicode text with literal example catalogs.
The media catalog starts empty; matching uses an inclusive default threshold 31.

`InboundGateway::accept` verifies locally configured peer key/region/destination,
canonical bounded payloads, private-account policy and route notice consistency.
No remote database lookup is performed. Raw profiles redact Debug output; profile
extras require explicit opt-in. See the migration section for reference formats.
