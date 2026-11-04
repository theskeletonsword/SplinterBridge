# SplinterBridge Interaction Policy

This open protocol is independent of the company operating each social network.
TikTok, Douyin, and Meta products are possible integration examples. This
repository does not provide official integrations with those platforms.

## Endpoint policy matrix

| Sender | Recipient | Tiananmen / Winnie the Pooh under the example catalog | China cross-region notice |
| --- | --- | --- | --- |
| Overseas | Overseas | Allowed by this policy | No |
| Overseas | China | Rejected | Yes |
| China | Overseas | Rejected | Yes |
| China | China | Rejected | No cross-region notice required |

The China-to-overseas route is explicitly evaluated. Checking only the
destination would be insufficient: China rules apply whenever either endpoint
uses the China jurisdiction profile. A user's nationality, language, or appearance
does not determine the route. Trusted backend configuration determines each
endpoint's regional profile.

## Suggested notice for both cross-region directions

> This interaction connects an overseas service with a service in mainland China.
> China-route content restrictions apply, and some messages may be rejected.
> Conversations exclusively between overseas users do not use this China-specific filter.

Platforms must display the notice to both participants before interaction,
including when a submission is rejected. The Rust enum value is
`InteractionNotice::ChinaCrossBorderRules`; the protobuf value is
`INTERACTION_NOTICE_CHINA_CROSS_BORDER_RULES`. Each interface handles presentation
and any additional localization. `interaction_notice_en` provides the English
copy above. The notice is separate from user-authored content.

## Reciprocal public-profile visibility

An overseas user may see a Chinese account's public nickname, display name,
aggregate follower count, and public/private status. A Chinese user may see the
same fields of an overseas account. These map to `handle`, `display_name`,
`followers_count`, and `is_private` in the public profile projection.

The default local projection omits avatars, following counts, and badges. Optional
extras require explicit sender opt-in and independent receiver approval. A public
profile may be shared for a private account, but the Rust boundary rejects its
content events. Private-content access grants are not implemented.

## Visibility and backend separation

A comment accepted on an overseas service may remain visible in its local feed
even if export to China is refused. That refusal must not suppress an unrelated
overseas-to-overseas interaction. Each route receives an independent decision.

Domestic China-to-China interactions must pass `assess_interaction` before local
acceptance. The protocol does not control a platform's database or UI: local
adapters must integrate the check and display the applicable notices.

Regional backends and databases remain independent and mutually blind to private
internal state. Dedicated gateways exchange approved event projections; they do
not link databases or expose the other backend's tables or internal APIs.
Receivers use opaque resource references to associate replies with their locally
stored projections, without querying the originating database.

The catalog is an illustrative keyword list. It does not cover all possible
restrictions, perform semantic classification, or guarantee regulatory approval.
Each platform's other policies remain independent. Transport security, shared
(multi-instance) replay protection, network isolation, local storage permissions, and UI integration
require deployment work.


## Mandatory origin-local privacy review

Outbound routes are disabled until explicitly configured. Content and profile
extras need independent per-destination opt-ins. Both outbound APIs require async
semantic review before signing. Missing models, invalid/uncertain responses,
timeouts or saturation withhold the export for local human review without sending
candidate values to the peer. Literal keyword failures cannot be overridden by a
model. No trained classifier is bundled; each platform must supply and evaluate
one inside its origin region. See docs/REGIONAL_REVIEW.md for the contract.
