# CAC (China, PIPL Art. 73) and NIST/FTC (U.S.) anonymization homologation

SplinterBridge v0.8.0. Reviewed 2026-11-04.

This document describes a four-layer architecture so that a public profile
keeps showing **exactly what the user sees today** (nickname, display name,
follower count and posts) while technically approaching the **anonymization**
definition required by PIPL Art. 73 (China) and NIST SP 800-188 / IR 8053
(U.S.).

This is engineering guidance, **not a legal opinion or compliance
certification**. The operator must evaluate, with qualified counsel, its
entities, data, purposes, scale and the measures in force in each jurisdiction.

---

## 1. Core problem: the visible profile is still "personal information"

A profile with a name and posts is considered personal information when there is
a reasonable technical or legal path to link it to a natural person
(*Shimingzhi*, passport, IP, bank card, etc.). SplinterBridge's current
`federated_did` (`HMAC-SHA256(pepper, internal_user_id)`) is deterministic and
reversible by the origin operator holding the pepper and the local `user_id`: it
is **pseudonymization**, not anonymization.

Cutting that link in a mathematically demonstrable way converts the profile from
"de-identified personal information" into a **fully anonymized autonomous
pseudonymous identity**, for which neither the receiving cluster nor an attacker
in transit can deduce the civil document behind.

---

## 2. Four-layer design

### Layer 1 — Identifier: Autonomous Public Actor with ZK anchoring

Instead of deriving the identifier from the civil ID, the user generates an
ephemeral key pair specific to the federation (`SK_actor`, `PK_actor`).

```
[ Local Civil Backend ]                              [ Remote Federated Network ]
┌─────────────────────────┐                          ┌─────────────────────────┐
│ Civil ID (Shimingzhi)   │                          │ handle: @example          │
│ National ID / Passport  │                          │ display_name: Agustín   │
│ FIDO2 / Secure Enclave  │                          │ followers_count: 14.8K  │
└────────────┬────────────┘                          │ public_key: Ed25519_pub │
             │ ZKP (zk-SNARK)                        └────────────▲────────────┘
             ▼                                                    │
┌─────────────────────────┐  Proves without revealing the civil ID: │
│ Ephemeral profile key   │  1. Valid civil account at origin        │
│ generator               │  2. Authorization to use this handle     │
│ (SK_actor, PK_actor)    │  3. No active sanctions                  │
└─────────────────────────┘                                         │
                                                                    │
             Merkle commitment (root only)                         │
             civil<->actor retained under local custody             │
```

- For the remote cluster, `@example` is a verified, live entity, but **no
  mathematical function or relational table** allows deducing the document
  number, phone or email that originated the account.
- The full ZK proof is retained **within the origin jurisdiction**; only a
  reference (commitment hash) crosses the border.

### Layer 2 — CAC homologation: *Shimingzhi* without exporting PII

The CAC requires that no one be anonymous before the law in the event of
serious crimes or national security risks (CSL Art. 24). The design meets this
**without exporting PII**:

- Real-name verification (*Shimingzhi*) is performed and retained **100% within
  the emitting backend's territory**.
- A **cryptographic commitment** of the civil ↔ actor link is generated.
- The ability to open that commitment is split into Shamir $(t, n)$ fragments
  under **local threshold custody** (for example, internal legal compliance +
  a key custodian audited by the national authority).

> Defense before the CAC: *"The user publishing abroad complies with real-name
> registration in Chinese territory under CSL Art. 24. To comply with PIPL Art.
> 73 and avoid cross-border leakage of Chinese citizens' data, exported data is
> anonymized through cryptographic proofs of validity. Upon a motivated local
> judicial order, the link can be audited exclusively within the borders of the
> People's Republic of China."*

### Layer 3 — NIST homologation: metadata anonymization (SP 800-188)

NIST warns that visible attributes can become **quasi-identifiers (QIDs)**
allowing user re-identification when combined with external sources.

#### A. Follower count: k-anonymity without visual loss

An exact number (`14.892`) is a fingerprint. The Protobuf contract forces
generalization at wire level:

```protobuf
message SanitizedPublicProfile {
  string handle = 1;
  string display_name = 2;
  // Bucketized (k-anonymous) value, not the exact integer.
  uint64 generalized_followers_count = 10;  // e.g. 14800 instead of 14892
  ...
}
```

The application keeps showing the formatted value (`14.8K`), but the value on
the wire belongs to an equivalence class with $k \ge 50$, nullifying unique
correlation attacks.

#### B. Names and posts: direct PII detection (simplified NER)

The local `SemanticReviewGate` runs a named-entity scan before authorizing
export:

- If the post includes a national ID / passport number, phone, IP or email, the
  gateway blocks the export (`DropReasonCode::DropReasonDirectPiiDetected`).
- If the content is an opinion, video or standard social comment, it travels
  intact.

Under NIST SP 800-188, public expressive content without direct identifiers is
classified as **low-risk / de-identified data**, fit for open publication.

### Layer 4 — Post verification model

Each post carries an authorship signature generated by the actor's private key:

$$\sigma_{\text{post}} = \text{Sign}_{SK_{\text{actor}}}(\text{content\_hash} \parallel \text{timestamp})$$

The receiving gateway validates the signature against the profile's `PK_actor`
and the ZK attestation, and stores the post in its local cluster associated
with the handle. **It does not query any API or database in the origin country**
to render the profile with its posts.

---

## 3. Comparison: current version vs. homologable model

| Element | Current version (0.6.0) | CAC/NIST homologable model | Visual impact on app |
|---|---|---|---|
| Internal identifier | `did:splinter:<region>:<hmac>` (origin-reversible pseudonym) | Autonomous Actor public key + humanity ZK proof | None (internal routing ID) |
| Nickname / Handle | Plain text (`@handle`) | Federated namespace validated by origin signature | Identical (`@example`) |
| Display name | Plain text | Plain text + direct PII filter | Identical |
| Followers | Raw exact integer (`14892`) | k-anonymized bucketized value (`14800`) | Imperceptible (UI shows `14.8K`) |
| Posts and content | Literal catalog filter | Authorship signature + semantic PII filter | Identical |
| Civil link | Local pepper + user_id in DB | Merkle commitment under local threshold custody | Not visible |
| Legal status | **Pseudonymized** (subject to PIPL/GDPR export restrictions) | **Anonymized with conditional cryptographic attribution** | Meets PIPL Art. 73 and NIST SP 800-188 |

---

## 4. What this version provides (0.8.0)

| Block | File | Purpose |
|---|---|---|
| Extended proto contract | `proto/splinter_bridge.proto` | `generalized_followers_count`, `actor_public_key`, `commitment_hash` (profile); `content_signature`, `zk_proof_reference` (event). Fields appended at the end, no compatibility break. |
| Merkle commitment | `crates/splinter-core/src/merkle.rs` | Lightweight tree; only the root crosses the border. Civil opening under local custody. |
| Follower k-anonymity | `crates/splinter-core/src/differential_privacy.rs` | `generalize_followers_count(count, k)` → bucket. |
| Direct PII | `crates/splinter-filter/src/lib.rs` | `scan_direct_pii` (email, phone, IPv4, generic national ID) with `DropReasonDirectPiiDetected`. |
| Identity and signature | `crates/splinter-core/src/identity.rs` | `project_blind_profile_with_options` derives generalized follower count and exposes actor key/commitment. |

---

## 5. Declared limitations

- No bundled trained language model; semantic review is origin-local, bounded
  and fail-closed.
- The full ZK proof (zk-SNARK / Groth16) of "valid civil account without
  sanctions" is the **next integration phase** and is not bundled in this
  version; `zk_proof_reference` is the hook for it.
- Replay protection covers a single process only (`SlidingWindowReplayCache`);
  no transport security (mTLS) or complete federation service.
- The code does not guarantee anonymity or legal compliance; it declares no
  safe harbor. See AGENTS.md (invariants), docs/LEGAL_DEPLOYMENT.md and
  docs/ANONYMIZATION.md.

---

## 6. Roadmap to real homologation

1. Client generates `(SK_actor, PK_actor)` and registers them in the origin
   backend linked to the civil ID (local, under threshold custody).
2. Origin generates the Merkle commitment and exposes only `commitment_hash`.
3. `SK_actor` signs each post; the receiver verifies with `PK_actor`.
4. Integrate a real ZK library (e.g. Halo2 / Bellman) for the "valid
   personhood" proof and replace `zk_proof_reference` with verification of the
   proof against a public verification key.
5. Formalize the transfer contract before the CAC (assessment or standard
   contract) and an Art. 46 GDPR mechanism (SCCs/BCRs) with contextual
   assessment.
