[Mục lục tài liệu](../README.md) · [Trang dự án](../../README.md)

> Báo cáo tại thời điểm ghi trong tài liệu; không thay thế kiểm chứng trạng thái hiện tại.

# Adaptive authentication review — 2026-10-02

## Verified in this run

- `verify-project.ps1`: PASS. Portal 187, Risk 128, extension 71 Java tests; no failures/errors. Frontend ESLint and TypeScript PASS.
- Tests use H2/mocks; these results do not establish browser-flow or real Keycloak MFA correctness.
- Docker's selected desktop-linux context was unavailable. Explicit default context reached healthy MySQL/Redis and running Keycloak without changing the global context.
- Keycloak realm discovery responded. Installed provider SHA256: `54d210af036a28cbda05d3e0c3b01e5e0f40df2d32b8d4260bf0fdf9798b6f56` (matches the provider deployed in the preceding login fix).
- Started Risk with run-risk-local.ps1. It started successfully on 8081 and health returned UP.
- Live Risk DB contains 8 TRUSTED devices, 36 successful-login records across 4 subjects, and zero pending resets. Historical records establish persisted telemetry, not successful end-to-end execution in this review.
- Frontend 3000 and Portal 8080 were not listening when probed. No test-account credentials/MFA were supplied. Browser login, OTP, recovery and Portal reset were NOT executed in this review.

## Completion assessment

The implementation is an integrated prototype with real persistence and policy code. It is not yet an end-to-end acceptance-tested deployment. No numerical completion percentage is assigned because the acceptance criteria and live scenario results are incomplete.

## Findings, highest priority first

1. **Reset does not immediately invalidate already issued Portal access tokens.** SecurityConfig validates JWT issuer/time/audience and roles, without a per-subject invalidation boundary. Add a reset/security epoch or another verified revocation mechanism and test old tokens after reset. Validate SSO paths independently.
2. **Admin reset has no fresh-MFA check.** UserServiceImpl checks ADMIN but does not enforce verified authentication strength and recency. Define the Keycloak authentication context and enforce it server-side before reset.
3. **Reset deployment is incomplete/unverified.** The root .env has no PORTAL_RISK_* entries. External process configuration may provide them, but was not verified. Without dedicated client credentials/configuration the client fails closed. Provision the separate caller and verify both authorized revoke and denied unrelated routes.
4. **In-flight reset/login race remains beyond device trust.** Generation checks reject stale device registration, but TrustedDeviceRegistrationAuthenticator deliberately permits the current login after a registration 409. This prevents restoring trust, not necessarily issuing a token for an authentication started before reset. Define and test whether reset must cancel those logins; enforce at authentication completion and resource access as required.
5. **Real IP and network policy are not acceptance-tested.** Context extraction uses Keycloak remote address. Prove canonical client IP through the actual network path. Current CIDR policy includes documentation/test ranges and empty country lists. Do not treat a default score as measured location anomaly.
6. **Evaluation audit is absent from the scoring path.** Persist evaluation ID, factor scores, data availability, decision/reasons and policy version with privacy-aware retention. Reset audit is separate.
7. **Telemetry loss is not represented in scoring.** Listener failures are swallowed; Redis may remain available with incomplete counters. Add delivery monitoring, freshness/completeness signals and a durable retry strategy if required.
8. **Behavior model and policy need validation.** Weights 0.25 and thresholds 40/75 remain TBD; five events alone do not establish representative temporal behavior. Measure results on controlled scenarios and separate held-out evaluation data.
9. **Device recognition is cookie-based.** User-Agent is collected but unused in scoring; there is no verified device posture. Fingerprint can be an additional untrusted signal, not automatic device trust.
10. **Deployment compatibility needs a gate.** The earlier old-provider/new-Risk mismatch caused INVALID_RESPONSE. Pin and record artifact versions; add a real provider/API contract test and coordinated rollout procedure.

## Required live acceptance matrix

All rows below are pending for this review; do not infer PASS from unit tests.

| Scenario | Expected evidence |
|---|---|
| New browser, valid password | Risk evaluates; MFA required; token only after successful required steps |
| Invalid password/OTP | Login denied; intended failure counter increments without double counting |
| MFA enrollment and later MFA login | No premature device trust; subsequent MFA establishes trust |
| Familiar device and sufficient normal history | Explainable low-risk ALLOW when policy permits |
| Recovery code | Accepted once; reuse rejected; expected trust behavior |
| Device expiry, reset and security revoke | Correct step-up/rotation versus hard-deny distinctions |
| Risk/Redis/Geo-IP unavailable | Configured failure policy, clear availability reason, no silent low-risk result |
| Admin reset partial failure and retry | Honest admin error, pending state, deterministic recovery |
| Reset during in-flight MFA | Stale registration rejected; explicitly verify whether token issuance is blocked |
| Old access token and existing SSO after reset | Demonstrate the chosen invalidation policy at Portal and Keycloak |
| Public client IP through proxy | Correct IP source and no spoofed forwarding-header trust |

## Next work

Finish the live matrix with a dedicated test account first. Then address token/session invalidation and fresh admin MFA, followed by evaluation audit and signal validation. Add fingerprint only after current signals and enforcement are verified.
