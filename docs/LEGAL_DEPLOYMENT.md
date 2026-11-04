# Legal applicability and deployment requirements

Documentation review: 2026-11-04. Scope: mainland China, EU/EEA, and selected
United States federal regimes. This is engineering guidance for deployment
review, not a legal opinion, certification, exhaustive legal inventory, or a
finding about any named company's current regulatory status. Operators need
qualified counsel to assess their entities, services, data and applicable orders.

## Design does not establish permission to deploy

SplinterBridge separates regional backends and minimizes gateway exports. That
can support a compliance program; it does not make every implementation or
transfer lawful. Open-source licensing is distinct from permission to process,
export, receive or retain data. Neither sharing a database nor avoiding one,
by itself, determines the legal outcome.

Only authorized gateway projections may cross the regional boundary. Application
backends, databases, identity records, secrets and internal-account mappings stay
independent. Each gateway uses its own local adapter; no remote database queries,
shared credentials, replication, identity resolution or cross-region joins are
part of the design. Deployment network controls must enforce this topology.
Even this restricted exchange can constitute a regulated disclosure or transfer.

`GlobalGdpr`, `CnPiplCac` and `Ru152Fz` are technical policy labels, not a complete
legal applicability engine. The literal filter uses the configured origin and
destination. Legal review additionally needs the actual countries, legal entities,
roles, ownership/control, purposes, affected populations and onward recipients.
Language, interface locale and an unsupported inference about nationality do not
supply those facts. Public visibility is not blanket permission to export.

`MINIMAL_EGRESS_V1`, a successful classifier result, and an Ed25519 signature mean
that specific software checks passed. None is a regulatory approval, consent
record, transfer-impact assessment or proof that contractual obligations are met.

## What the implementation actually provides

| Mechanism | Version 0.6.0 | What it does not establish |
| --- | --- | --- |
| Regional HMAC references | Deterministic pseudonyms; pepper in process memory with owned-buffer zeroization | Anonymity, unlinkability, HSM custody, or impossibility of reidentification |
| Ed25519 | Signed profiles/envelopes and configured-peer verification | Content confidentiality, transport encryption, replay prevention or lawful transfer |
| Local review | Route opt-ins, minimized fields, private-content rejection, literal matching, bounded semantic-review interface | An authoritative legal catalog, a bundled trained model, perfect detection or operator immunity |
| Local classifier transport | gRPC over a Unix socket with server UID checks | Federation mTLS, a deployed inference service, or proof a worker never relays data |
| Hardware assertions | Protocol fields; unsupported inbound assertions rejected | Implemented FIDO2/StrongBox/Secure Enclave verification or verified human identity |
| Media fingerprints | Local comparison of supplied 256-bit fingerprints against a caller-populated catalog | PDQ extraction, TMK support, authoritative CSAM/StopNCII feeds, or statutory reporting compliance |
| Distributed operation | Protocol and library boundaries | A durable outbox/inbox, deletion propagation, rate limits, platform connectors, or production readiness |

HMAC has no decryption or “inversion key.” An origin with its key and local IDs
can recompute references; a stable DID links events, and public handles/names may
identify people independently. An HSM integration could reduce key-extraction risk
but would not remove authorized-operation abuse or identifying public content.
Its design, implementation and deployment attestation remain future work.

## Mainland China

PIPL distinguishes de-identification from anonymization (Articles 4 and 73).
Treat the current named public-profile projection as personal information unless
a documented, context-specific assessment establishes otherwise. Determine a lawful
processing basis, required notices/consents, recipient safeguards and individual
rights. Overseas provision triggers the impact-assessment requirements in Articles
55–56; assess Article 39's notice and separate-consent obligations under the
applicable legal basis and exceptions. The model is not responsible for deciding
these legal questions. [CN1]

The available transfer route is not simply “CAC assessment or SCC.” The March
2024 cross-border rules include assessment, standard contract/certification routes
and exemptions. Subject to their specific exclusions and exemptions:

| Situation | Baseline route under the 2024 provisions |
| --- | --- |
| CIIO exporting personal information or important data; non-CIIO exporting important data | CAC security assessment |
| Non-CIIO exporting non-sensitive personal information of at least 1,000,000 individuals, or sensitive information of at least 10,000, cumulatively since January 1 | CAC security assessment |
| Non-CIIO exporting non-sensitive information of 100,000 to fewer than 1,000,000 individuals, or sensitive information below 10,000 | Standard contract or certification |
| Non-CIIO below 100,000 individuals, with no sensitive information or important data | Exemption from those transfer mechanisms, not from all PIPL duties |

These are individual/data-category thresholds, not counts of gateway messages.
Other statutory situations, free-trade-zone rules and sector classifications can
change the analysis. Do not split processing to evade an applicable threshold.
The January 2026 CAC FAQ confirms reassessment when the applicable scale changes.
The library does not measure these regulatory populations or determine CIIO or
important-data status. [CN2][CN3]

A Chinese standard contract is between the domestic personal-information processor
and the overseas recipient, not a contract “with the CAC in Beijing.” Under the
standard-contract measures, file the contract and PIPIA with the competent
provincial cyberspace authority within 10 working days after effectiveness.
Read the older measures together with the later 2024 rules. [CN4]
The outbound personal-information certification measures took effect on
2026-01-01; certification is an independent route subject to its conditions,
not something this software or an HSM audit grants. [CN5]

Data-security classification and important/core-data controls can apply beyond
personal information. The Data Security Law requires organizational and technical
controls, risk handling and relevant assessments; absence of email or national-ID
fields is not an exemption. [CN6]
Use the Cybersecurity Law as amended in 2025, effective 2026-01-01, and the Network
Data Security Management Regulations effective 2025-01-01. Review MLPS, relevant
localization, security monitoring, incident handling, supplier and content duties.
The amended law's Article 23 includes required network-log retention; do not
confuse minimizing gateway error messages with deleting all legally required local
security records. Isolate such records and keep excluded values out of bridge
errors, explanations and logs. [CN7][CN8]

A keyword filter can prevent a matched export, but it neither guarantees that
unlawful content never reaches China nor exempts an operator from liability.
The supplied catalogs are project examples, not an official legal blacklist.
Domestic moderation and local obligations remain independent. An overseas export
rejection must not automatically delete the originating domestic event.

## European Union / EEA

Separate the lawful basis for processing from the legal mechanism for a third-
country transfer. GDPR obligations include transparency, rights, minimization,
security proportionate to risk and, where required, a DPIA. A transfer mechanism
does not replace these duties. Pseudonymization is a possible safeguard, not by
itself an Article 46 transfer instrument. [EU1]

China is not on the Commission's adequacy list reviewed for this document. Assess
an applicable Article 46 mechanism, such as suitable SCCs or approved binding
corporate rules; Article 49 derogations are limited, not a default basis for
continuous large-scale federation. [EU2][EU4]
EU SCCs are concluded by exporter and importer using the applicable module, not
signed with the Commission or a data-protection authority. Complete the required
annexes and assess destination laws/practices and onward transfers. [EU3]

EDPB Recommendations 01/2020 require a contextual assessment of supplementary
measures. Keeping a pepper local does not neutralize cleartext names or content
available to the importer. Ed25519 is not encryption; even transport/storage
cryptography may be inadequate against importer-side access where the importer
can read the data. Suspend a transfer when effective protection cannot be achieved.
No combination of these library features is declared automatically sufficient
under Schrems II. [EU4]

Avoid the absolute statement “personal whenever anyone, anywhere can identify.”
In C-413/23 P (2025), concerning Regulation 2018/1725, the Court recognized that
pseudonymized information need not be personal data for every recipient in every
circumstance, while preserving the controller's collection-stage transparency
analysis. This does not establish that SplinterBridge's named profiles are
anonymous or remove the origin's obligations. Use a documented assessment of the
relevant actor, purpose and reasonably available identification means. [EU5]

For large social platforms, assess NIS2 applicability under relevant national
implementation, including risk management, supply-chain controls and significant-
incident reporting. Social-networking services are within its sectoral coverage
subject to the applicable scope criteria. [EU6]
Separately assess DSA service obligations. Designated VLOPs/VLOSEs have systemic-
risk, mitigation and independent-audit requirements; introducing cross-border
content/recommendation functionality can require review before launch. A privacy
filter does not discharge these platform-level duties. [EU7]

## United States

PAFACA addresses covered foreign-adversary-controlled applications and specified
distribution/hosting activities; it is not a general rule satisfied by local DB
storage. Its qualified-divestiture definition addresses operational relationships,
including recommendation-algorithm cooperation and data-sharing agreements with
specified formerly affiliated entities. A blind gateway may still be relevant to
that analysis. Review the statute and currently applicable company-specific
determinations, orders and agreements; this repository makes no conclusion about
any particular operator's compliance or enforcement status. [US1]

CFIUS is a separate investment-review regime concerning covered transactions,
including certain non-controlling investments. Do not describe it as a generic
permission service for every federation link. Evaluate applicable mitigation
agreements and ownership/control constraints independently. [US2]

Also evaluate the DOJ Data Security Program, 28 CFR Part 202, under EO 14117.
It regulates specified transactions involving U.S. government-related data or bulk
U.S. sensitive personal data and countries of concern/covered persons. Applicability
depends on data, thresholds, access, parties, transaction type and exceptions;
“social federation” is not an automatic classification. [US3]
Pseudonymized, de-identified or encrypted data is not categorically outside its
bulk-sensitive-data definition. Conversely, the rules exclude qualifying
expressive information/materials and certain associated metadata; do not treat
every public post as a prohibited transaction. Evaluate the actual projection,
not just the presence of an HMAC. [US4]
Restricted transactions can require the CISA security controls and other program
obligations; technical controls do not turn a prohibited transaction into a
permitted one. Establish due diligence, auditing, records and reporting where
applicable. [US5]

This is not an exhaustive inventory of U.S. state privacy, consumer-protection,
children's privacy, biometric, sectoral, sanctions or other federal obligations.
The same is true for Chinese sector rules and EU/national requirements outside
this document's scope. Do not infer authorization from silence here.

## Deployment evidence and local activation controls

The following is a proposed operator control design, not implemented legal
verification or a claim that every listed item is mandatory in every jurisdiction.
Keep the evidence in each region's own compliance systems; the peer must not gain
database access to inspect it.

| Control | Evidence before enabling a route | Current software boundary |
| --- | --- | --- |
| Legal scope and purpose | Named entities/roles, countries, ownership, recipients, purposes and data inventory | Not derived from jurisdiction enums |
| Transfer authorization | Applicable basis/mechanism, assessment/filing/certification or reasoned exemption; scope, owner and review date | No legal-evidence verifier |
| Individual controls | Required notices and consent/lawful-basis records; rights, minors and retention workflows | A public/private flag does not prove permission |
| Separation and access | Regional identities, firewall tests, independent credentials, approved gateway-only routes, local-only model | Library cannot enforce cluster topology |
| Confidentiality and integrity | mTLS peer validation, at-rest protection, key lifecycle/HSM design where chosen, rotation and incident recovery | Signatures implemented; federation transport/HSM absent |
| Reliable delivery | Local outbox/inbox, replay defense, idempotency, revocation and deletion/retention handling | Single-process replay cache only; no outbox, inbox, revocation or deletion handling |
| Moderation and model governance | Approved versioned policy, evaluated languages, local review/appeals and incident procedures | Example catalogs and a classifier interface only |
| Monitoring | Aggregate value-free metrics; separate access-controlled statutory records and retention schedule | In-memory hash-chained decision log only; no durable record store, retention or access control |

Use a region-local activation service to bind an approved route to its legal
entities, purposes, allowed event/field set and current authorization evidence.
Only that trusted configuration path should enable `with_route_policy`; a model,
client flag or remote gateway must not authorize its own export. Keep routes
inactive when evidence is missing, expires or no longer covers the intended use.
Recheck queued dispatch after relevant policy, recipient or authorization changes.
This activation service is not supplied in version 0.6.0.

A later erasure/retention workflow must exchange only authorized protocol events
between gateways and apply them to each recipient's own imported projection.
It must not query an origin database to resolve a pseudonym. Pending/rejected
candidate content stays in the origin region's authorized local review system.
Do not duplicate excluded values in rejection payloads, model rationales or logs.

## Primary sources consulted

These sources support the legal distinctions above, not a certification of the
implementation. Recheck official texts and operator-specific measures at deployment.

[CN1]: https://www.cac.gov.cn/2021-08/20/c_1631050028355286.htm
[CN2]: https://www.cac.gov.cn/2024-03/22/c_1712776611775634.htm
[CN3]: https://www.cac.gov.cn/2026-01/30/c_1771505108953002.htm
[CN4]: https://www.cac.gov.cn/2023-02/24/c_1678884830036813.htm
[CN5]: https://www.cac.gov.cn/2025-10/17/c_1762449728720008.htm
[CN6]: https://www.samr.gov.cn/zw/zfxxgk/fdzdgknr/bgt/art/2023/art_33654085364e45e2a878c70a06934414.html
[CN7]: https://www.gjbmj.gov.cn/n1/2026/0421/c409088-40705863.html
[CN8]: https://www.cac.gov.cn/2024-09/30/c_1729384452307680.htm
[EU1]: https://eur-lex.europa.eu/legal-content/es/ALL/?uri=CELEX%3A32016R0679
[EU2]: https://commission.europa.eu/law/law-topic/data-protection/international-dimension-data-protection/adequacy-decisions_en
[EU3]: https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=celex%3A32021D0914
[EU4]: https://www.edpb.europa.eu/system/files/documents/2021-06/edpb_recommendations_202001vo.2.0_supplementarymeasurestransferstools_en.pdf
[EU5]: https://curia.europa.eu/site/upload/docs/application/pdf/2025-09/cp250107en.pdf
[EU6]: https://digital-strategy.ec.europa.eu/en/policies/nis2-directive
[EU7]: https://digital-strategy.ec.europa.eu/en/faqs/qa-risk-assessment-reports-audit-reports-and-audit-implementation-reports-under-dsa
[US1]: https://www.congress.gov/118/plaws/publ50/PLAW-118publ50.pdf
[US2]: https://www.cfius.gov/resources/faqs/
[US3]: https://www.justice.gov/nsd/data-security
[US4]: https://justice.gov/nsd/media/1415006/dl
[US5]: https://www.justice.gov/opa/media/1396356/dl

- [CN1] PIPL, particularly Articles 4, 13, 38–40, 55–56 and 73.
- [CN2] CAC Order 16 (2024), especially Articles 3–8, 10–11 and 13.
- [CN3] CAC cross-border data policy FAQ, January 2026.
- [CN4] CAC standard-contract measures (2023), especially Articles 5–8;
  read the eligibility provisions with the subsequent 2024 rules.
- [CN5] Outbound personal-information certification measures, effective 2026-01-01.
- [CN6] PRC Data Security Law, notably Articles 21 and 27–31.
- [CN7] PRC Cybersecurity Law, 2025 amendment; [CN8] Network Data Security
  Management Regulations.
- [EU1] GDPR; [EU2] Commission adequacy list; [EU3] Decision (EU) 2021/914 SCCs.
- [EU4] EDPB Recommendations 01/2020, final version, especially Annex 2 use cases
  2, 6 and 7. [EU5] Court press release on C-413/23 P, 2025-09-04, an explanatory
  summary of the judgment, not the binding judgment text.
- [EU6] Commission NIS2 guidance; [EU7] Commission DSA risk/audit guidance.
- [US1] Public Law 118-50, Division H, particularly section 2(a) and 2(g)(6).
- [US2] CFIUS jurisdiction FAQ. [US3] DOJ Data Security Program resources, updated
  2026-10-08; [US4] DOJ FAQ, particularly questions 22 and 71–72;
  [US5] DOJ compliance guide.
