# Network Risk v2 — implemented shadow candidate

This source candidate is not deployed. BASELINE_B0, its feature extractor, weights,
thresholds, mandatory MFA, revocation and generation decisions are unchanged.
`RISK_NETWORK_V2_MODE` defaults to `DISABLED`; the only other mode is `SHADOW`.
No enforcement mode, decision threshold or response-field replacement exists.

## Trusted history and privacy

The authorized Risk caller supplies the existing server-derived subject and peer IP.
The observer never reads HTTP forwarding headers. The existing trusted ingress and
Keycloak peer-IP configuration remain prerequisites; browser/user JWTs cannot call
the evaluate or success endpoints. Native Keycloak `LOGIN` (without error) optionally
forwards the server auth-note evaluation UUID. The success payload supplies no network
or GeoIP claims. SSO without a matching fresh evaluation, refresh, denied evaluations,
LOGIN_ERROR, duplicate events and mismatched subjects/clients do not establish history.
Real 26.8.2 integration found that required actions can replace event details. The
listener therefore uses the matching server authentication session (exact user/client,
not an SSO shortcut) before falling back to native event details when no context exists.
No browser header, cookie value or user-session claim supplies a Risk evaluation ID.

The Risk observer correlates its own captured GeoIP observation to that UUID, exact
subject/client and a committed existing authentication-success row. Before learning,
an independent transaction locks the existing trust-generation row, requires the same
generation and no pending reset, and leaves trust/revocation state unchanged. An FK
requires the parent success event. The matching cache is one-use, bounded to 4096
entries and expires after 10 minutes. No old network context is invented/backfilled.

New state uses scoped HMAC-SHA-256 subject and normalized-address identifiers with the
existing private history pepper. It retains country, ASN, quality, city accuracy radius
and timestamps, without raw IP, user-agent, city, password or token. There is no new
history-read API. Query and calculator both isolate subject/client; history is limited
to 128 verified complete samples in 30 days, recorded before the evaluation.

## Deterministic candidate rules (`NETWORK_CONTEXT_V2_SHADOW:1`)

At least three complete samples across two UTC dates are needed. Otherwise the score
is **null / COLD_START**, never zero. An address is an exact normalized-address HMAC,
not an ASN reputation, subnet reputation or geographic travel model.

| Independent contribution | Points |
| --- | --- |
| ASN previously seen for this subject/client / unfamiliar | 0 / 20 |
| Country unchanged | 0 |
| Country changes within 6h: known return / unseen | 10 / 20 |
| Country changes after 6h: known return / unseen | 5 / 10 |
| Address context unchanged / known return / unseen | 0 / 5 / 10 |

Total is 0–50, uncalibrated and **not** a B0 Network Risk replacement. Novel country
or ASN is context novelty, not proof of attack. No country lists are introduced.
Private/NAT/documentation/transition addresses and disabled/unavailable/unmatched
GeoIP are explicitly UNAVAILABLE; missing country/ASN is PARTIAL. These scores are
null, never fabricated low risk. City radius >500km is COARSE_LOCATION; absent radius
is UNKNOWN_ACCURACY. Radius describes city accuracy, not country/ASN confidence, and
does not add points. Dataset freshness remains the existing external dataset guard;
this observer does not claim to independently attest dataset age or IP attribution.

## Isolation, observation and deployment boundary

A single FIFO background worker and bounded 128-task queue prevent shadow DB/GeoIP
work from blocking login. Queue overflow, cache loss/expiry, failed telemetry/write
or restart drops learning; it never retries into trusted history after an unknown
commit. A lost sample therefore causes less confidence/cold start, not fake trust.
SQL/query work is bounded to two-second queries. Dedicated structured logs use
`ZEROTRUST_NETWORK_V2_SHADOW`, evaluation UUID, B0 outcome, candidate points/reasons,
sample counts and evidence quality/radius. They exclude subject/address hashes and
country/ASN identifiers. Micrometer exposes `risk.network.v2.shadow.dropped` and
`risk.network.v2.shadow.queue.depth` through the existing management configuration;
no management endpoint or port is opened.

V6 is additive; V7 adds the retention index. The candidate passed Flyway V1–V7 on
fresh synthetic MySQL 8.0.46, checksum 661092940 for V5, schema transfer and validation
on 8.4.13 (the actual active runtime version). Neither migration is applied to active.
The new build requires the schema even with mode disabled. Existing success ingestion
is the trusted native-event contract, not independent proof of final token redemption.

Physical retention is implemented separately from the query window. It defaults to
**disabled** and can only be enabled with SHADOW. `retention-days=30` must be at least
`history-days`; `retention-batch-size=200` is capped at 1000. Each hourly job deletes
at most one batch where BOTH authenticated_at and recorded_at are strictly older
than the cutoff. A V7 index bounds the candidate scan; queries time out after 2s and
the transaction after 5s. Freshly recorded or recent-auth context is retained. No
parent authentication success, generation, pending operation, trust or audit row is
deleted. Failures emit a static status and never change authentication. Approve a
retention/collection duration and backlog monitoring before enabling it in a rollout.
Actual scheduled MySQL acceptance used a test batch of two; production defaults remain
disabled and the test configuration was returned to disabled afterwards.

Real integration receipts: `target/network-v2-integration-20261112/`. They cover strict
TLS/CRL/service JWT, native OTP/PKCE/LOGIN UUID, async MySQL persistence, SSO/refresh/
replay/error isolation, generation/pending/revocation fences, deterministic scoring,
queue overflow, physical retention and old-Risk/V7 wire/schema compatibility without
database restore. The positive public-address network input is an explicit test-only
service simulator, not a public browser peer. The normal private-browser path rejects
forged forwarded headers and does not create public network history. Historical UTC
dates are isolated synthetic fixtures, not asserted historical browser logins. The
simulator/maintenance identity is absent from application images and active state.
Keycloak audit/event DB remains enabled; the isolated logging configuration suppresses
the native raw-IP WARN event logger while retaining structured SPI traces.

Candidate builds and isolated integration were owner-authorized and completed. A
separately reviewed active maintenance/migration/promotion with exact new pins and
controller-compatible restore/rollback plan is still required. Never repoint an old descriptor to this
source or run V6 on the active DB implicitly. Start with shadow collection; live
enforcement requires a separate security-policy decision and calibration evidence.
D-10 remains separate, D-17 PENDING, G8 INTERNET_NO_GO.

## Source map

Under `src/main/java/com/zerotrust/risk/`:

- `config/NetworkRiskV2Properties.java`: defaults and bounded configuration.
- `networkv2/NetworkObservation.java`, `NetworkHistorySample.java`,
  `NetworkRiskV2Assessment.java`: evidence and independent result types.
- `networkv2/NetworkAddressScope.java`, `NetworkRiskV2Calculator.java`: scope and scoring.
- `networkv2/NetworkRiskV2WorkQueue.java`, `PendingNetworkObservations.java`: nonblocking,
  bounded work and one-use correlation.
- `networkv2/NetworkAuthenticationContextEntity.java`, `NetworkContextRepository.java`,
  `NetworkContextWriter.java`: isolated verified-history persistence and generation fence.
- `networkv2/NetworkRiskV2Retention.java`, `NetworkRiskV2RetentionSchedule.java`:
  disabled-by-default, bounded physical shadow-context retention.
- `networkv2/NetworkRiskV2Shadow.java`, `NetworkRiskV2Trace.java`: observer and structured trace.
- `controller/RiskEvaluationController.java`, `AuthenticationSuccessController.java`,
  `dto/request/AuthenticationSuccessRequest.java`: backwards-compatible API integration.

`src/main/resources/application.properties` adds the default-disabled flag;
`src/main/resources/db/migration/V6__network_risk_v2_shadow_history.sql` adds the table.
`src/main/resources/db/migration/V7__network_risk_v2_retention_index.sql` adds the cleanup index.
In `keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/`, only
`listener/RiskEventListener.java` and `dto/AuthenticationSuccessRequest.java` change
the optional native-event correlation contract. No authenticator/flow is changed.
New tests are in Risk `src/test/java/com/zerotrust/risk/networkv2/`; two existing MVC
security slices add an observer mock. SPI listener and success DTO/wire tests cover
the caller side.
