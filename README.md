# SplinterBridge

> **Zero-Trust Server-to-Server (S2S) Partitioned Federation Engine for Sovereign Social Backends**  
> *Connecting TikTok Global, Douyin China, and Sovereign Digital Realms without Cross-Border PII Leakage.*

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Language](https://img.shields.io/badge/Language-Rust%202021-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/Status-Core%20Engine%20Reference-green.svg)]()

---

## Copyright & License Notice

```text
Copyright 2026 TheSkeletonSword (perex)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

## 1. Executive Architecture Overview

Modern social network architectures face an existential dilemma: the global internet has fractured into incompatible regulatory regimes (the *Splinternet*):
* **Western / Global (GDPR, CCPA, DSA):** Enforces rigorous privacy protections, prohibits unconstrained biometric and identity surveillance, and resists foreign state access.
* **Mainland China (PIPL, Data Security Law, CAC):** Mandates strict localized real-name registration (*Shimingzhi*), domestic data localization, and strict ideological content governance.
* **Russian Federation (152-FZ, RKN):** Imposes localized data storage and bans unauthorized external narratives.

**SplinterBridge** is an open-source, high-concurrency S2S gateway protocol implemented in Rust. It enables mutual discovery, content federation, and social engagement between distinct sovereign backends (such as **TikTok Global** and **Douyin**) without violating any jurisdiction's legal mandates.

```
┌─────────────────────────────────┐                       ┌─────────────────────────────────┐
│     Global / GDPR Cluster       │                       │      China / CAC Cluster        │
│     (e.g., TikTok Global)       │                       │         (e.g., Douyin)          │
│                                 │                       │                                 │
│  [User DB: Pseudonymous Graph]  │                       │ [User DB: Shimingzhi Real-Name] │
│                 │               │                       │                 │               │
│                 ▼               │                       │                 ▼               │
│     [Pre-flight Egress Filter]  │                       │     [Pre-flight Egress Filter]  │
│      - CAC / RKN In-Memory Trie │                       │      - GDPR In-Memory Checks    │
│      - StopNCII PDQ Popcnt      │                       │      - StopNCII PDQ Popcnt      │
│                 │               │                       │                 │               │
│                 ▼               │     Mutual TLS 1.3    │                 ▼               │
│    [Origin Gateway Signer]      │◄═════════════════════►│   [Destination Gateway Verifier]│
│      - Ed25519 Payload Sig      │   Zero-PII Envelope   │      - Ed25519 Validation       │
│      - Regional Pepper HMAC     │   gRPC Protocol Buffers│     - Local Blind Mapping      │
└─────────────────────────────────┘                       └─────────────────────────────────┘
```

---

## 2. Core Architectural Invariants

### 1. Zero-PII Overseas Verification
* **Western Users:** Never upload government IDs, passports, or biometrics to foreign clusters. Proof-of-humanity relies on hardware-backed cryptographic enclave assertions (**FIDO2 / WebAuthn, Apple Secure Enclave, Android StrongBox**) or established reputation graph metrics.
* **Chinese Users:** Mandatory real-name identity verification (*Shimingzhi*) remains strictly confined to domestic Mainland servers. No real-name data, national identification numbers, phone numbers, or resident identity records ever cross the gateway.

### 2. Blind Identity Projection (Blind Mapping)
Internal database identifiers are transformed into irreversible pseudonymous decentralized identifiers via HMAC-SHA256 initialized with regional secret peppers:
$$\text{federated\_did} = \text{"did:splinter:"} \parallel \text{jurisdiction} \parallel \text{":"} \parallel \text{HMAC-SHA256}(\text{pepper}_{\text{region}}, \text{internal\_user\_id})$$
The receiving cluster only observes:
* `federated_did` (e.g., `did:splinter:global:e3b0c442...`)
* Public handle (e.g., `@theskeletonsword`)
* Display name (e.g., `perex`)
* Aggregated followers and following counters
* Visibility flags (`is_private`)
* Cryptographic trust flags (`VerifiedBadgeType`)

### 3. Pre-flight Egress Interception (In-Memory)
Before any cross-border packet touches the outbound network interface:
* An in-memory Aho-Corasick automaton checks textual content against destination-specific regulatory catalogs (e.g., Cyberspace Administration of China historical and political sensitivities; Roskomnadzor banned extremist entities).
* If a prohibited token is detected, the event is immediately aborted at the origin egress gateway with an explicit `DropReasonCode`.
* **Sovereign Safety Guarantee:** The prohibited content remains fully accessible within the domestic global feed, but never crosses the border, protecting domestic users and preventing legal jeopardy for destination recipients.

### 4. Zero-Knowledge Digital Safety (StopNCII / CSAM)
* Every media attachment is evaluated locally via perceptual hashing (**PDQ 256-bit** for images and **TMK** for video).
* Autonomous in-memory Hamming distance matching uses hardware-accelerated bitwise population counts (`popcnt`).
* Any media with $\text{HammingDistance}(\text{candidate}, \text{known}) \le 31$ is dropped in hot path before dispatch.
* No raw images, personal media, or cross-border telemetry queries are sent to external third parties.

---

## 3. Threat Model & Mitigations

| Threat Vector | Attack Scenario | SplinterBridge Mitigation |
| :--- | :--- | :--- |
| **Cross-Border PII Exfiltration** | Foreign cluster queries or subpoena requests user identity documents. | **Cryptographic Impossibility.** Raw IDs, emails, phone numbers, and IPs are never serialized into protobuf payloads. Regional HMAC peppers never leave sovereign HSM boundaries. |
| **Man-in-the-Middle (MitM) & Spoofing** | Adversary intercepts cross-border federation line or injects forged posts. | **mTLS 1.3 + Ed25519 Payload Signatures.** Every event payload is digitally signed by the origin gateway private key and verified against public keys by the destination gateway. |
| **Destination Legal Liability** | Western user posts content illegal in destination (e.g., 8964 in China). | **In-Memory Egress Pre-flight Interception.** Origin gateway filters and drops non-compliant egress traffic before border crossing, shielding remote recipients. |
| **Replay & Sybil Attacks** | Malicious actor replays valid cross-border messages to spam clusters. | **Timestamp Windows & Monotonic Nonces.** Envelopes enforce a 60-second validity window, unique UUIDv4 event IDs, and nonces. |
| **Child Sexual Abuse & NCII Distribution** | Bad actor attempts to cross-federate abusive media across sovereign borders. | **Zero-Knowledge PDQ Popcnt Matching.** Local StopNCII perceptual hash blocks intercept abusive media variations in <10 microseconds. |

---

## 4. Bilateral Benefits (ByteDance: TikTok Global vs. Douyin)

| Dimension | Status Quo (Hard Partition / Silos) | With SplinterBridge Federation Engine |
| :--- | :--- | :--- |
| **Regulatory Compliance (US/EU)** | Constant scrutiny regarding potential Chinese access to Western PII. | **Verifiable Zero-PII Guarantee.** Code audits prove zero PII leaves Western data centers. Hardware attestations replace ID requirements. |
| **Regulatory Compliance (China CAC/PIPL)** | Fear that foreign unfiltered political dissent will permeate domestic Douyin. | **Automated Pre-Flight Sovereign Egress.** Origin gateways filter non-compliant political content in RAM prior to cross-border dispatch. |
| **Network Effects & Global Reach** | Cross-border cultural exchange is completely severed; creators cannot reach each other. | **Unified Global Culture Engine.** A creator in Milan or New York can federate viral trends, music, and comments with creators in Shanghai seamlessly. |
| **Commercial & E-Commerce Upside** | Cross-border live-stream shopping and brand sponsorship fragmented across apps. | **Sovereign-Sanitized Merchant Handles.** Global and Chinese creators can interact and co-host federated spaces with localized checkout gateways. |
| **Infrastructure Overhead** | Maintaining completely independent, duplicated product and discovery features. | **Standardized Protobuf & gRPC Backbone.** Shared, open-source S2S protocol reduces bespoke bridging engineering costs. |

---

## 5. Repository Structure

```text
SplinterBridge/
├── Cargo.toml                      # Workspace manifest
├── README.md                       # Comprehensive architecture & threat model
├── proto/
│   └── splinter_bridge.proto       # Protocol Buffers v3 contract
└── crates/
    ├── splinter-proto/             # Tonic/Prost compiled stubs & build.rs
    ├── splinter-filter/            # CAC & RKN in-memory Egress Pre-flight engine
    ├── splinter-safety/            # StopNCII 256-bit PDQ Hamming popcnt engine
    └── splinter-core/              # Blind DID (HMAC-SHA256) & Ed25519 signer
```

---

## 6. Quickstart & Building

### Prerequisites
* Rust 1.75+ (Cargo)
* `protobuf-compiler` (`protoc`)

```bash
# Clone the repository
git clone https://github.com/TheSkeletonSword/SplinterBridge.git
cd SplinterBridge

# Compile the entire workspace in release mode
cargo build --release

# Run the comprehensive cryptographic and safety test suite
cargo test --workspace
```

---

## 7. Authors & Attribution

Designed and architected by **TheSkeletonSword** (`perex`). Released under the Apache 2.0 open-source license.
Contributions, security audits, and formal enterprise integration whitepapers are welcomed.
