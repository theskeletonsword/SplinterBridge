# SplinterBridge — Production Reality and Known Gaps

SplinterBridge v0.9.0. Reviewed 2026-11-04.

This document describes the **production-grade engineering and operational gaps**
that must be closed before the library can be audited and operated at the scale
of massive social infrastructures (e.g. TikTok Global / Douyin-class clusters).
It is engineering guidance, not a legal opinion.

The Rust crates, Protobuf contracts, and in-memory filters solve the **transport
layer and cryptographic invariant computation**. They do **not** implement the
distributed systems, hardware security, or legal-operational machinery required
for production cross-border federation between two sovereign backends.

---

## 1. The library vs. production cluster abyss

A reference implementation defines how a node evaluates a packet in memory; it
does not implement the machinery required to sustain hundreds of millions of
concurrent requests per second across a global network.

### 1.1 Durable delivery (outbox/inbox with partition tolerance)

Cross-border federation traverses submarine cables and trans-Pacific links that
suffer congestion, BGP route drops, and intermittent cuts. If the origin gateway
signs an event and the mTLS connection fails mid-handshake, the system needs
durable message queues (Kafka, Pulsar, or Raft-based architectures) with
**at-least-once delivery** and **strict idempotency** at the receiver.

Without a persistent, locally replicated event bus, feeds drift out of sync or
lose interactions forever.

**What the library provides:** `CrossBorderEventPayload.nonce` and
`FederatedEventResponse.remote_event_ack_id` fields exist in the contract, and
`InboundGateway` rejects duplicate nonces through a required single-process
`ReplayCache`. There is **no durable outbox, no inbox and no persistent
idempotency store** in the Rust code.

**What production needs:**
- Local durable outbox per destination route (write-ahead log before signing).
- Idempotency key store with TTL sliding window (nonce + timestamp dedup).
- Retry with exponential backoff and dead-letter queue for rejected envelopes.
- Exactly-once application semantics at the receiving adapter.

### 1.2 Global state and deletion propagation (tombstones vs. replay)

If a user deletes a comment or closes their account in the West, that revocation
order must cross the bridge and replicate into the remote cluster immediately.
Without a distributed anti-replay cache with strict time synchronization
(Spanner TrueTime or hardware PTP), a malicious actor or network error could
re-inject old signed packets, resurrecting deleted posts or forging deactivated
profiles.

**What the library provides:** Signed nonce and timestamp in
`CrossBorderEventPayload` (nonce 0 and unset timestamps are invalid).
`InboundGateway::accept` refuses to run without a `ReplayCache` and maps
rejections to `DROP_REASON_REPLAY_DETECTED`. `SlidingWindowReplayCache` enforces
a bounded per-route window in one process, survives local clock steps backwards,
and fails closed when full. It is not shared across instances or restarts, and
there is no tombstone or revocation protocol.

**What production needs:**
- Anti-replay sliding window (nonce + origin + timestamp) with sub-second clock
  sync (PTP or TrueTime).
- Tombstone propagation protocol: signed deletion events that the receiver
  applies to its imported projection without querying the origin DB.
- Revocation list distribution between gateways.

### 1.3 Concurrency control and backpressure

A single viral video on Douyin can generate tens of thousands of comments per
second toward a federated Western profile. The local classifier and the Rust
gateway need distributed rate limiting (sliding-window) and priority-based
controlled discard. Without this surrounding infrastructure, a traffic surge
from the remote side can crash the local gateway via file-descriptor exhaustion
or memory saturation in the Unix socket queue.

**What the library provides:** `SemanticReviewGate` bounds concurrency with a
semaphore, deadline, and fail-closed overload shedding. `InboundGateway` can
apply a per-peer `TokenBucket` after signature verification. Both are
single-process. No network-level rate limiting, no adaptive backpressure, no
priority queues.

**What production needs:**
- Distributed rate limiter per origin/destination/route (token bucket or
  sliding window, shared across gateway instances).
- Adaptive backpressure signals (HTTP 429 / gRPC RESOURCE_EXHAUSTED) propagated
  to the sending adapter.
- Priority queues: profile sync > comment > engagement > telemetry.

---

## 2. Cryptographic compute and inference bottleneck at mass scale

The "zero knowledge" and "secure-enclave humanity attestation" promise imposes
brutal computational penalties that destroy economies of scale unless
orchestrated with dedicated silicon.

### 2.1 Enclave latency and ZK proofs

Verifying Ed25519 signatures is fast on modern CPUs, but verifying zk-SNARKs or
Bulletproofs for anonymous identity attestation, or computing VOPRF operations
over elliptic curves, requires GPU or dedicated cryptographic accelerators
(ASICs/FPGAs). Multiplied by tens of thousands of concurrent interactions, this
adds hundreds of milliseconds of latency to publishing a single comment,
degrading the immediacy the feed requires.

**What the library provides:** Ed25519 signing/verification via `ed25519-dalek`;
`HardwareAttestation` proto message; inbound rejection of unsupported
attestations. No ZKP library, no GPU path, no hardware acceleration.

**What production needs:**
- zk-SNARK verification library (e.g. Halo2, Bellman) integrated behind the
  `zk_proof_reference` hook.
- Batched signature verification on GPU/ASIC for high-throughput paths.
- Asynchronous proof generation off the critical network path.

### 2.2 Computational cost of local semantic analysis

The design delegates PII detection and moderation to a local gRPC worker over
Unix socket (`UnixGrpcClassifier`). Passing free text through language models or
NER classifiers to ensure no civil data leaks covertly requires massive local
inference clusters. If the classifier takes 50 ms per text and 100,000 outgoing
comments are queued, gateway memory collapses unless dedicated inference farms
process egress traffic exclusively.

**What the library provides:** `SemanticReviewGate` with timeout, confidence
thresholds, closed verdicts, fail-closed handling. No model weights, no
inference server, no NER bundle.

**What production needs:**
- Local model farm per region (CPU/GPU) behind the Unix socket classifier.
- Batching and model quantization for throughput.
- Fallback to deterministic rules (Aho-Corasick + NER regex) when model
  capacity is saturated.

### 2.3 Catalog cache and divergence

The Aho-Corasick filter runs in memory with O(n) lookups, but regulatory
catalogs (CAC, RKN guidelines) are not static: they mutate daily, adding
neologisms, coded slang, deliberate homophones, and metaphors to evade filters.
Keeping automata synchronized across hundreds of gateway instances without
restarting the service or causing packet-processing pauses requires dynamic
zero-downtime hot-reloading of state graphs.

**What the library provides:** Static `PreflightEgressFilter` built at
construction; example catalogs only. No hot reload, no distributed catalog
sync.

**What production needs:**
- Hot-reloadable catalog distribution (config service -> gateway instances).
- Versioned catalogs with atomic swap; rollback on bad signature.
- Per-region catalog sovereignty (China catalog never leaves China).

---

## 3. Hardware sovereignty trap (HSMs and physical enclaves)

The current code stores seeds and keys (`pepper`) in process memory and
zeroizes them on `zeroize::Zeroizing` drop. For industrial and government
cybersecurity standards, this is unacceptable for production.

### 3.1 Hardware Security Module (HSM) isolation

Both FIPS 140-3 in the West and commercial cryptography schemes (Guomi / GM/T)
certified by China's Office of State Commercial Cryptography Administration
(OSCCA) require master keys to reside in tamper-resistant physical modules.
Integrating the Rust pipeline with PKCS#11 or proprietary high-performance HSM
APIs introduces synchronous I/O locks and severe transaction throughput
restrictions.

**What the library provides:** `RegionalPepper` in `zeroize::Zeroizing<Vec<u8>>`
in process memory; not an HSM. Documented as a limitation in AGENTS.md and
README.

**What production needs:**
- PKCS#11 or vendor HSM abstraction behind `RegionalPepper` / `GatewaySigner`.
- FIPS 140-3 Level 3 (West) and OSCCA GM/T (China) certified modules.
- Key rotation and recovery ceremonies per jurisdiction.

### 3.2 Mobile enclave interoperability gap

SplinterBridge assumes user devices can deliver trustworthy hardware assertions
(FIDO2, Apple Secure Enclave, Android StrongBox). In practice, the mobile
hardware ecosystem in China is fragmented: millions of devices run Android
forks (HarmonyOS, HyperOS, ColorOS) with security modules based on local
standards and without Google Play Services or standard WebAuthn. Building a
universal attestation engine that verifies silicon authenticity without
collecting hardware identifiers (IMEI, serial numbers that violate no-PII) is
an enormous compatibility challenge.

**What the library provides:** `EnclaveType` enum; inbound rejection of
unsupported attestations. No FIDO2/WebAuthn verifier, no StrongBox path, no
HarmonyOS enclave path.

**What production needs:**
- Pluggable attestation verifier per enclave type (FIDO2, SE, StrongBox, local
  Guomi enclave).
- Attestation verification without hardware identifier leakage.

---

## 4. Editorial legal responsibility and the "false negative" risk

For software engineers, a system works if it passes unit tests with a low
statistical error margin. For regulators and courts, failure tolerance is zero.

### 4.1 Strict result liability in China

Under PRC Cybersecurity Law and CAC guidelines, platform operator liability for
published content is strict. If a semantic classifier in the West or in the
gateway commits a false negative and lets through a wordplay satirizing a
political leader or endangering national security interests, the regulator does
not sanction the algorithm: it administratively sanctions the legal
representative and the corporate entity in Beijing, with risk of million-dollar
fines, service disconnection, or imprisonment for local executives. No legal
team approves opening an automated gate without absolute guarantee or a massive
contingent of thousands of human moderators auditing queues in real time.

### 4.2 Asymmetric incentives between platforms

The emitting cluster has no legal incentive to exhaustively censor what leaves
its borders, because that content is legal in its own territory; the receiving
cluster assumes 100% of the civil and criminal liability of what enters. This
asymmetry forces the receiver to distrust by default any validation made by the
emitter, duplicating processing and imposing redundant audits that annul the
speed advantages of federation.

**What the library provides:** Route policy, literal filter, semantic gate,
Ed25519 signatures, notice codes, and a hash-chained decision log
(`HashChainedAuditLog`) whose exports either party can verify with
`verify_records`. No human moderation queue integration, no appeals workflow,
no durable shared log store, no shared liability model.

**What production needs:**
- Human moderation queue with SLA per region.
- Shared audit log (append-only, tamper-evident) accessible to both parties'
  compliance teams.
- Escalation path for false negatives/positives.

---

## 5. The bureaucratic labyrinth and formal interconnection treaties

Although the code downloads and compiles in one minute with `cargo build
--release`, deploying it requires a legal and corporate process that usually
takes 12 to 24 months of formal processing.

### 5.1 CAC Data Export Security Assessment (Order 16)

For massive platforms exceeding one million users, ByteDance is legally obliged
to submit the detailed technical design to the Cyberspace Administration of
China (CAC) before transmitting the first byte. Government inspectors audit
source code, physical datacenter topology, cryptographic algorithms, and
metadata destination. If the protocol uses Western cryptographic primitives not
homologated by Chinese standards (e.g. Ed25519 instead of SM2 elliptic curves
and SM3 hash functions), homologation is rejected for non-compliance with
commercial cryptography laws.

### 5.2 National Security Oversight and Judicial Mandates in the West (PAFACA / CFIUS)

In the United States, under the federal *Protecting Americans from Foreign
Adversary Controlled Applications Act*, any data interconnection, joint
recommendation, or operational relationship with a foreign-adversary-controlled
entity is prohibited without qualified divestiture or explicit Executive
authorization. Opening a direct mTLS channel between servers in Virginia or
Ireland and servers in Beijing would immediately violate standing national
security mitigation agreements (such as code and infrastructure audits
monitored by Oracle under Project Texas), exposing the company to immediate
judicial blocking orders in Western app stores.

### 5.3 Inter-corporate legal contracts (bilateral SCCs and TIA)

The European Union requires exhaustive Transfer Impact Assessments (TIA) under
the *Schrems II* standard. Legal teams must documentarily demonstrate that no
foreign law allows an intelligence agency to compel the local operator to
compromise gateway keys or decrypt metadata in transit — a burden of proof no
European court has granted lightly regarding transfers to third countries
without adequacy decisions.

**What the library provides:** Technical controls (`MINIMAL_EGRESS_V1`,
signatures, filters). No legal-evidence verifier, no consent ledger, no
regulatory-volume counter, no activation service.

**What production needs:**
- Region-local activation service binding routes to legal entities, purposes,
  allowed event/field sets, and current authorization evidence.
- CAC assessment filing package; SCC execution; TIA documentation.
- Legal review before enabling each route; route inactivation when evidence
  expires.

---

## 6. Summary table: what exists vs. what production requires

| Area | Library (unreleased) | Production requirement | Owner |
|---|---|---|---|
| Durable delivery | None (in-memory only) | Replicated outbox/inbox, idempotency store | Platform infra |
| Replay protection | Required single-process sliding-window cache | Shared nonce cache across instances + clock sync | Platform infra |
| Backpressure | Semaphore gate; per-peer token bucket (single process) | Distributed rate limiter + adaptive signals | Platform infra |
| HSM / key custody | Process memory, zeroize | PKCS#11 / FIPS 140-3 / OSCCA GM/T HSM | Security team |
| ZKP verification | None | Halo2/Bellman integration + GPU batching | Crypto team |
| Semantic inference | Gate contract only | Local model farm per region | ML team |
| Catalog sync | Static at build | Hot-reload, versioned, per-region | Ops team |
| Mobile enclaves | Reject unsupported | Pluggable verifier per enclave type | Client team |
| Legal activation | None | Region-local activation service + CAC/SCC/TIA | Legal team |
| Human moderation | None | Queue + appeals + shared audit log | Trust & Safety |
| Audit trail | In-memory hash-chained decision log + verifier | WORM storage, external head-hash anchoring, retention | Compliance team |
| Kill switch | `AtomicKillSwitch` on both gateways | Authenticated auditor control plane | Security team |

---

## 7. Conclusion

Implementing SplinterBridge is not simply starting a web service: it is
building a zero-failure mission-critical infrastructure where ultra-low-latency
distributed systems engineering, hardware-accelerated cryptography, and
international regulatory diplomacy converge. The Rust library lays the
mathematical and architectural foundations, but putting it into operation
requires raising the monumental network of compute, moderation, legal support,
and sovereign enclaves that sustain that bridge over the geopolitical abyss.

The library has **not** been independently audited. It can serve as a
reviewable **reference implementation**; it is **not** a production federation
service, and nothing in it establishes DOJ, CFIUS, CAC or other regulatory
approval. Any operator adopting it must treat items in the "Production
requirement" column as mandatory pre-deployment work.
