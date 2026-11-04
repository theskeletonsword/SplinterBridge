# Anonymization, pseudonymization and SplinterBridge

PIPL Art. 73 (China) and GDPR Recital 26 (EU/EEA). Reviewed 2026-11-04.

This document is engineering guidance, not a legal opinion or compliance
certification. The operator must evaluate, with qualified counsel, its entities,
data, purposes and scale.

## 1. The core problem: the HMAC-SHA256-derived DID is pseudonymization

SplinterBridge's current federated identifier is:

```
did:splinter:<region>:<hex(HMAC-SHA256(pepper, region_code ":" user_id))>
```

It is deterministic. The origin backend retains the original `user_id` in its
local database and the regional pepper in its HSM/memory. If a court or police
present the Chinese node with a `user_id` and ask it to apply the function and
confirm whether a DID belongs to that person, the answer is immediate and
deterministic.

That is **origin-reversible pseudonymization**, not anonymization:

- **PIPL Art. 73**: anonymization requires that information be processed so that
  a natural person cannot be identified by any reasonable means, and that the
  process be technically irreversible, including for the originator. An HMAC
  with a pepper known to the origin fails this test.
- **GDPR Recital 26**: identical requirement; if re-identification is possible by
  reasonable means, it remains personal data.

Conclusion: `project_blind_profile` and the opaque DIDs are
**state-of-the-art pseudonymization**. They protect against automated mass
surveillance and prevent backends from synchronizing civil-identity databases,
but they do not eliminate the emitting node's ability to re-identify.

## 2. The three viable technical paths

### 2.1 K-anonymity + differential privacy (metrics, trends, telemetry)

If what crosses the border is not an individual profile but aggregates
(interactions, music trends, views):

- **Differential privacy (ε, δ):** inject Gaussian or Laplace noise at the
  gateway into counts before emitting them. New module:
  `splinter_core::differential_privacy` (`noisy_count`, `laplace_noise`,
  `gaussian_noise`).
- **K-anonymity / L-diversity:** the gateway emits only aggregated blocks where
  each event is indistinguishably mixed with at least k users (k ≥ 100). New
  module: `splinter_core::differential_privacy::k_anonymous_bucket`.

Legal outcome: with no individual trace and no unique identifier, it ceases to
be personal data for the PIPL and the GDPR. It loses utility for profiles,
followers or individual reputation.

### 2.2 Stateless, memoryless ephemeral identities

If interaction is required (comments, content visible abroad) but the platform
deliberately renounces the concept of a "unified persistent profile":

- Each interaction or thread generates a temporary identifier derived from an
  ephemeral secret that rotates daily or per post.
- Correspondence table destroyed in RAM via crypto-shredding
  (`zeroize` / `blkdiscard`).
- Registration-free proof of humanity: blind FIDO2/WebAuthn assertion or
  anonymous credentials (Privacy Pass / BBS+), with cryptographic verifiability
  but impossible linkability between signatures (unlinkability).

New module: `splinter_core::ephemeral`
(`derive_ephemeral_did`, `EphemeralSession`, `EphemeralPepper`,
`EphemeralVault`). Ephemeral DIDs have the format
`did:splinter:eph:<region>:<digest>`, derived from an epoch key that is
zeroized after rotation. Two interactions by the same account in different
epochs are mathematically unlinkable without the destroyed seed.

Legal outcome: neither sender nor receiver can trace the author or link their
posts to each other; reversibility is zero.

### 2.3 Total zero knowledge (ZKP: SNARKs / Groth16)

Validating permissions and attributes without sending a single identifying
datum:

- the author is a valid account registered for more than 30 days,
- age of majority without revealing date of birth,
- not on the list of accounts suspended for security violations.

The receiver verifies the proof against a public verification key. No DID, no
handle, no IP, no persistent metadata.

Legal outcome: absolute impossibility of re-identification. Meets PIPL Art. 73,
but involves high cryptographic complexity and no implementation exists in this
repository.

## 3. The real social network dilemma

If the user publishes a video with their face or voice and assigns a persistent
identifier so their followers can recognize them (@example, video and comment
history), it is ontologically impossible to speak of absolute legal anonymization:
there will always be the capacity to link the content to a physical person.

That is why SplinterBridge's current design (`MINIMAL_EGRESS_V1`,
`project_blind_profile`, opaque DIDs, mutually blind backends) does not aim to be
"ghost anonymity", but rather **data minimization and state-of-the-art
pseudonymization**.

## 4. The realistic industry path (China ↔ West)

For the flow to be legal, there is no point pretending to anonymization that
would destroy the social network. The realistic path is to homologate this
shielded pseudonymization within formal transfer mechanisms:

- **China:** formal CAC assessment or standard contract deposit (PIPL Arts.
  55-56, 2024 measures and January 2026 FAQ), with impact assessment, data
  classification, cybersecurity and content duties. See docs/LEGAL_DEPLOYMENT.md.
- **EU/EEA:** Art. 46 GDPR mechanism (SCCs or BCRs) plus EDPB 01/2020-style
  contextual assessment; a filter, pseudonym or Ed25519 signature is not by
  itself a transfer instrument or proof of Schrems II compliance.

## 5. What this version provides (0.7.0)

| Module | Purpose | Legal guarantee |
|---|---|---|
| `identity::derive_federated_did` | Stable regional pseudonymous DID | Origin-reversible pseudonymization; not anonymization |
| `ephemeral::derive_ephemeral_did` | Ephemeral per-epoch DID, zeroized seed | Unlinkable across epochs; zero reversibility after shredding |
| `differential_privacy` | Noisy and k-anonymous counts for aggregates | Output without individual trace (metrics/telemetry) |

The ephemeral DIDs of `ephemeral` are an independent building block in this
version: they are not yet accepted by `boundary::validate_event` nor wired into
`OutboundGateway::prepare_local`. That integration (extending `valid_did`)
remains adapter work.

## 6. Declared limitations

- No bundled trained language model; semantic review is origin-local, bounded
  and fail-closed.
- Replay protection covers a single process only (`SlidingWindowReplayCache`);
  no hardware validation, transport security or complete federation service.
- The code does not guarantee anonymity or legal compliance; it declares no safe
  harbor. See AGENTS.md (invariants) and docs/LEGAL_DEPLOYMENT.md.
