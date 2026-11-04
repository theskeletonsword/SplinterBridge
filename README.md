# SplinterBridge

Rust libraries and a Protocol Buffers contract for server-to-server federation
between independently operated social backends. Version 0.6.0, Apache-2.0.
The protocol is platform-neutral: TikTok/Douyin, Meta products and other networks
are possible integration examples, not dependencies or existing partnerships.

Copyright 2026 TheSkeletonSword (perex). See LICENSE and NOTICE.

This is a reference implementation. It does not connect to TikTok or Douyin,
and does not guarantee regulatory compliance, anonymity, or absence of personal data.

## Implemented components

| Crate | Function |
| --- | --- |
| `splinter-proto` | Protocol messages and generated gRPC client/server interfaces |
| `splinter-core` | Minimal projection, route opt-in, async semantic review gate, host-local gRPC classifier client, inbound verification, Ed25519 signatures |
| `splinter-filter` | Route-specific literal matching with lowercase, fullwidth ASCII and common invisible/whitespace normalization |
| `splinter-safety` | Local Hamming-distance comparison of supplied 256-bit fingerprints |

The facade crate `splinter-core` re-exports the other crates' APIs.

## Mutually blind backends and independent regional stores

SplinterBridge is an open protocol for any social network. TikTok/Douyin, Meta
products and other services are possible examples; the protocol is not tied to
ByteDance or any other operator.

**China and overseas application backends must remain mutually blind.** Neither
backend may directly call, query, administer or inspect the other backend or its
databases. They must not share database credentials, tables, replication streams,
internal identity directories, private social graphs or a cross-region database
join. Each region operates its own storage, identity verification, authentication,
moderation and feed. An integration must not use the bridge as a tunnel into a
remote backend or as an arbitrary database-query interface.

Only dedicated regional gateways exchange explicitly authorized protocol events.
Each gateway obtains an approved projection from its own local adapter, applies
the route policy and signs the export. The receiving gateway validates it and
hands an accepted projection to its own local adapter. Neither application
backend receives direct access to the other. Any permitted cross-region network
path must terminate at these gateways, not at domestic databases or internal
application services. Deployment network controls and authorization must enforce
this separation; the Rust libraries alone cannot establish it.

In this architecture, **blind** means no visibility into the opposite backend's
private state, original account identifiers, database layout or internal service
interfaces. The peer sees only the fields explicitly approved for federation,
together with the gateway identity and routing metadata needed by the protocol.
A gateway connection necessarily reveals its own endpoint; this is not a claim
that communication itself is invisible or that the peers exchange no information.

Regional HMAC secrets, identity-verification records, credentials and mappings
from federated pseudonyms to internal accounts must remain local. Shared profile
and event fields must be minimized and reviewed by the local adapter. Public
handles, names, avatar URLs and content can still identify people. Blind backend
separation is not a cryptographic anonymity or zero-knowledge guarantee, and the
review gate requires a configured classifier for candidate free-form fields, but no
trained model is bundled and this cannot prove the absence of sensitive information.

The destination stores an accepted projection independently. It must not resolve
a federated identifier by looking up the origin's database. Any local mapping
and any later export decision remain under the owning regional backend's control.

### Public profile visible across regions

Public-profile visibility is reciprocal: an overseas user may see the following
approved projection of a Chinese account, and a Chinese user may see the same
fields of an overseas account. Backend blindness does not require hiding these
public profiles.

| Visible information | Protocol field | Meaning |
| --- | --- | --- |
| Nickname / public handle | `handle` | Public account nickname, not its internal database ID |
| Display name | `display_name` | Name published on the profile, not a transfer of the domestic verification record |
| Follower count | `followers_count` | Aggregate number of followers, without the private follower graph |
| Account visibility | `is_private` | `true`: private account; `false`: public account |

These fields exist in `SanitizedPublicProfile` and are populated by
`project_blind_profile`, in either direction. Avatar, following count and badges
are omitted by default. `project_blind_profile_with_options` requires explicit
per-field opt-in for those extras. The receiving gateway also rejects extras
unless its local `with_profile_options` configuration explicitly approves them. They are visible alongside the federated pseudonym;
neither backend needs to query the other backend to display them.
A public display name can itself identify a person, so this is an approved public
projection rather than an anonymity guarantee. The schema also supports avatar,
following count and verification badges; adapters must explicitly decide which
additional fields are permitted and visible.

The public/private flag describes account visibility. Publishing that flag or
its follower count does not grant access to private posts, private relationships
or domestic identity records. The Rust boundary rejects content events from private accounts and only permits
content-free profile synchronization for them. It does not implement access grants
for authorized followers; platforms must integrate that separately before enabling
private-content federation.

### Local publication and route-specific export

The domestic event is evaluated under its local rules and committed locally.
`OutboundGateway::prepare` then checks each origin/destination pair independently
and either returns a signed export envelope or an export error. It receives the
event by immutable reference and has no database handle, deletion operation or
domestic visibility operation. Domestic China-to-China interactions must also be
assessed before local acceptance, as described in the matrix below.

For example, an overseas comment containing `Tiananmen` can remain on its
originating platform and visible in an overseas-to-overseas interaction while
its export to China is refused. Refusing that export must not remove the original
comment or suppress an independently permitted overseas interaction. China-to-
overseas interactions are checked as well; this is not a destination-only rule.
The same separation applies to every integrating social network.

### Regulatory purpose and implementation scope

The separation is intended to avoid direct cross-region backend and database
coupling and support independent regional governance. A deployment involving
China, the United States or Europe must assess its actual data flows, access
rights and applicable requirements separately. This project does not conclude
that a particular architecture necessarily triggers or avoids fines or sanctions
for ByteDance, Meta or another operator. Mutually blind backends and content
filters are architectural requirements of this design, not regulatory approval.

There is no backend/database connection code in this reference implementation.
Transport and network isolation remain deployment work. The Rust boundary now
projects local records, validates exported fields and verifies received events
against a locally provisioned peer key and region. Provisioning trust and deciding
which public values are approved remain responsibilities of each local adapter.

## Interaction policy matrix

The participating backend jurisdictions determine the rule, not the users'
nationality, language, device locale or a client-supplied flag.

| Origin | Recipient | China keyword filter | Cross-region notice |
| --- | --- | --- | --- |
| Overseas | Overseas | No | No |
| Overseas | China | Yes | Yes |
| China | Overseas | Yes | Yes |
| China | China | Yes | No cross-region notice needed |

Here Overseas means the `GlobalGdpr` backend profile. Other destination policies,
such as the existing Russia example catalog, remain independent.

`assess_interaction(origin, destination, text)` applies this matrix and returns
both notice codes and the content result. Use it before opening the composer
(with empty text) and again at submission. In particular **China → Overseas**
is restricted just like **Overseas → China**; checking only the destination
would incorrectly allow the former. Domestic China → China adapters must call
this assessment before accepting a local interaction, since the export helper
cannot change or enforce a domestic database's moderation policy.

`OutboundGateway::prepare` uses this assessment. Accepted envelopes carry
`policy_notices`, included in their signature. Policy rejections expose the same
codes through `OutboundError::policy_notices()`. The response schema also has a
notice field for future service implementations. There is no frontend in this
repository: adapters must localize and display notices on both sides before the
interaction; notice codes alone cannot force a third-party app to display UI.
The English interaction policy and suggested disclaimer are in INTERACTION_POLICY.md.

This route policy leaves the overseas original event intact. It must not be
used to retroactively filter unrelated Overseas → Overseas conversations.

## Executable local boundary

Use `OutboundGateway::prepare_local(destination, raw_profile, pepper, draft).await`
to construct a minimal public profile from local records. Raw profiles and drafts
are not serializable wire messages. The method derives opaque event/resource
references instead of copying local database IDs. `resource_id` identifies the
published post/comment projection separately from its event ID; receivers index
it locally. `target_resource_id` identifies the parent of a reply or interaction.
A reply can therefore point at an imported projection without a remote DB query. Target references can be either
a local resource to project or an already federated resource. Regional HMAC
secrets remain at the origin, and no remote lookup is required by the receiver. Reference digests use HMAC-SHA256
with the domain `splinterbridge:reference:v1\0` and length-prefixed kind, region
and local ID, separate from the account DID derivation.

`prepare(...).await` remains an advanced API for candidate projections. Both methods
require an explicitly configured destination route and semantic review gate. They
reject unapproved optional fields; neither can bypass the reviewer. Both methods
validate event type, regional DID shape, opaque reference shapes, profile field
limits, private-account restrictions, route policy and media fingerprints.
They filter profile text as well as event text. Notices accompany all preparation
errors on a recognized China cross-region route, including identity/media errors.

`InboundGateway::accept` requires a `TrustedGateway` configured locally with key
ID, public key and origin jurisdiction. It checks the receiving jurisdiction,
verifies the envelope signature, decodes a bounded payload, rejects non-canonical
or unknown payload fields and repeats the content checks. Notice codes must match
the route, even for a valid signer. Unsupported hardware assertions are rejected,
not accepted as verified. Accepted data is a public event projection, with no
remote database handle or internal ID mapping.

Run the local, data-only demonstration:

```bash
cargo run -p splinter-core --example federate --locked
```

It demonstrates reciprocal public-profile visibility for private accounts without
exporting their posts. It generates ephemeral keys, uses an exact synthetic-fixture reviewer (not a
semantic model), and does not open a network connection. `interaction_notice_en` supplies suggested English notice copy for
adapters; actual UI presentation still belongs to the platform.

The reviewer integration does not supply a model or establish its accuracy on arbitrary text,
whether a trusted origin's public claims are truthful, or whether an operator has
configured network rules correctly. It is not a running federation service.

## Origin-local semantic review

Every outbound preparation now requires an asynchronous `SemanticReviewGate`.
It bounds concurrency, applies a deadline, validates a closed per-field verdict
schema and withholds exports on uncertainty, missing responses, overload or errors.
`UnixGrpcClassifier` connects only to an origin-host Unix socket and verifies the
worker OS UID; it exposes no TCP/DNS or cross-region inference endpoint. The worker
must also be isolated from network egress and backend credentials by deployment.

SplinterBridge supplies the gate and integration contract. The integrating
platform deploys and evaluates its regional model and runs human review. No model
weights, training pipeline or inference server are included. This is infrastructure
for a classifier, not a claim that substring matching has become semantic AI.

`review_local_json(...).await` returns the four allowlisted profile fields plus
`policy_code`, optional fields explicitly enabled for the route, and permitted
public text. Errors contain only fixed reason codes; uncertainty adds a fixed
field name. No raw values are included in errors. Model input excludes internal
IDs, opaque protocol references, credentials and dedicated private profile fields.

Read [REGIONAL_REVIEW.md](docs/REGIONAL_REVIEW.md) for the enforced flow, local worker
contract, model responsibilities, blind-backend topology and large-scale deployment
requirements. The libraries are not a production federation service.

## Build and verify

Use a current stable Rust toolchain with a native linker/C compiler. The included
Cargo.lock records the tested dependency resolution. Rust 1.99.1 was used locally;
older Rust versions have not been verified.

```bash
cargo build --release --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

The build uses `protoc-bin-vendored` when `PROTOC` is unset. Set `PROTOC` to an
explicit compiler path to override it. Initial builds need access to Cargo's
registry. No system-wide protobuf compiler installation is required on supported
vendored platforms.

## Identity and signatures

`derive_federated_did` computes HMAC-SHA256 over
`jurisdiction_code || ":" || internal_user_id`, using a regional secret, and
returns `did:splinter:<region>:<hex_digest>`. It rejects empty IDs, unspecified
jurisdictions and secrets shorter than 32 bytes. Use cryptographically random
secrets: length checks do not establish entropy. Secret buffers owned by
`RegionalPepper` are cleared on drop via `zeroize`; caller-owned source buffers
remain the caller's responsibility. This implementation stores keys in process
memory, not an HSM.

`project_blind_profile` omits dedicated email, phone, internal IP, national-ID
and internal-ID fields. Public names, handles, avatar URLs and arbitrary event
text may still identify people or contain sensitive data. A pseudonym can be
linked across events. Apply consent, field validation, retention rules and data
minimization in the integrating backend.

`sign_profile` and `verify_profile` share a single canonical serializer. All
current profile fields are covered, including avatar and verification badges.
The signature input is the byte prefix `splinterbridge:profile:v2\0` (ending in
one NUL byte) followed by compact serde_json output of the canonical struct.
Field order is fixed by that struct; this is not a general JSON canonicalization
standard. Verifiers use Ed25519 strict verification.

`sign_envelope` and `verify_envelope` cover the entire known envelope, including
payload, routing, gateway key ID and attestation. The signature input is
`splinterbridge:envelope:v1\0` followed by Prost encoding of a cloned envelope
with `ed25519_signature` cleared. Re-encoding known fields defines the format;
unknown protobuf fields are not preserved. Schema evolution needs a coordinated
signature-format review. Verification authenticates the key's statement; it
does not prove the signer is authorized or a hardware assertion is valid.
Resolve the key ID through a trusted registry and enforce local destination,
size limits and validation separately.

### Migration from earlier releases

0.6.0 makes outbound preparation async and deny-by-default: configure each route
with `with_route_policy`, configure `with_semantic_review`, and add `.await`.
The advanced API enforces optional sender fields as well. Keyword errors no longer
carry matched terms or categories. The new local classifier protocol is separate
from federation: no existing federation field numbers or signing formats changed.
See [regional review and production integration](docs/REGIONAL_REVIEW.md) for
migration, the model responsibility split and remaining deployment requirements.

In 0.5.0, `interaction_notice_es` is renamed to `interaction_notice_en`, and its
message is English. Update API call sites. The policy document is now
`INTERACTION_POLICY.md`. Policy matching terms and non-English test fixtures
remain unchanged because they are protocol data, not documentation or UI copy.
No wire field numbers or signature formats change between 0.4.0 and 0.5.0.

Old profile signatures are deliberately incompatible with v2. Upgrade both peers
and re-sign profiles; do not fall back to accepting signatures that omit badges
and avatars. Existing protobuf field numbers are unchanged; 0.3.0 adds `policy_notices` to
envelopes (field 7) and responses (field 6). Upgrade peers together: signatures
include envelope notices, which older generated schemas do not retain.
In 0.4.0 `OutboundError` is a struct with `reason: OutboundRejection` and
`notices`; `policy_notices()` and `drop_reason_code()` remain available.
`project_blind_profile` now defaults to the minimal public fields; callers needing
extras must opt in. The boundary requires HMAC-shaped regional DIDs and opaque
`urn:splinter:event:<region>:<hex>` / `urn:splinter:resource:<region>:<hex>`
references. Use `prepare_local` to derive them from local IDs. 0.4.0 also adds payload field 9, `resource_id`, and requires it for posts/comments;
profile syncs cannot carry it or content. Comment/engagement targets must be valid
federated resource references. This schema addition changes envelope signing bytes,
so peers must upgrade together. Existing arbitrary
IDs must be migrated locally; the remote backend is not queried to resolve them.
Envelope signing
now uses the full-envelope format above instead of the old payload-only design.
The generated Rust jurisdiction variants are `GlobalGdpr`, `CnPiplCac`,
`Ru152Fz` and `Unspecified`; `DropReasonCode` and `VerifiedBadgeType` keep their
existing value prefixes.

## Filtering and media safety

The existing example CAC/RKN keyword catalogs are retained. The low-level `check_text` checks one jurisdiction's catalog. The higher-level
`assess_interaction` also applies China rules when China is the origin, and
returns an error when either endpoint jurisdiction is unspecified.
Matching normalizes lowercase (including Cyrillic), fullwidth ASCII, common invisible
format controls and whitespace on a copy. It remains a literal substring filter:
false positives, confusables, alternative spellings and omissions remain possible.
The separate mandatory semantic gate reviews privacy; it cannot override literal
policy matches. Model deployment and accuracy evaluation belong to the platform. The example lists are not
complete or authoritative regulatory catalogs. Domestic visibility is controlled
by the integrating backend, not this library.

`StopNciiEngine` starts with an empty local catalog. Populate it from a trusted,
authorized source before relying on it; `is_empty()` can enforce that policy.
The low-level engine permits every correctly sized hash with an empty catalog;
`OutboundGateway::prepare` instead rejects media exports until a catalog is loaded. The engine compares supplied
fingerprints in a linear scan, using a default distance threshold of 31 inclusive.
It does not calculate PDQ from images, implement TMK, obtain StopNCII/CSAM feeds,
or establish that a caller-supplied hash belongs to the media. A real integration
must derive hashes from the actual media in a trusted path. Local comparison is
not a cryptographic zero-knowledge proof. There is no measured latency guarantee.

## Integration work still required

There is a host-local gRPC classifier client, but no model/inference server and no
running federation gRPC service, mTLS configuration, transport dispatch loop,
replay cache or timestamp-window enforcement, hardware-attestation verifier,
persistent storage, rate limiting or connection to existing social platforms.
Signatures alone do not prevent replay. These components must be implemented
and reviewed before production deployment. Use `OutboundGateway::prepare_local` (or the advanced `prepare`) to apply the
current projection, text and media checks before signing. Calling the lower-level signer alone bypasses those checks. The helper
rejects missing authors, inconsistent author jurisdictions, unspecified destinations,
invalid fingerprints, media exports with an empty catalog and unsupported TMK
hashes. It checks field shapes and catalog terms but cannot establish that
free-form profile values contain no sensitive data, or that a policy decision
matches every rule a regulator might impose. The example keyword lists remain
incomplete; arbitrary disallowed content cannot be identified by those lists alone.

For detailed engineering guidance on cross-border data transfer mechanisms, 
statutory threshold baselines (CAC 2024/2026, GDPR/EDPB 01/2020, US PAFACA/DOJ 28 CFR Part 202), 
and operator deployment responsibilities, see [LEGAL_APPLICABILITY.md](docs/LEGAL_APPLICABILITY.md).

See CHANGELOG.md for the changes and validation record.
