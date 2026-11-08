# PD-02-04 — Authentication, JWT & B0 security invariant hardening

Evidence **EV-PD-02-04-01**, ngày **06/11/2026, GMT+7**. Canonical repository,
branch `zerotrust-v4-risk-scoring`, base HEAD `c401e17029d64f9a96738d845b8c0ad0f03fc164`.
Source/config/tests vẫn chưa commit. **CONTROLLED OFFLINE / synthetic loopback**, không live Lab,
Keycloak engine, Staging hoặc Production. Tiến độ chỉ ở [Master Roadmap](../PUBLIC_DEMO_ROADMAP.md).

**Task PASS trong phạm vi source/security regression.** PR-012/PR-017 vẫn OPEN, G3 PARTIAL;
D-10/D-15/D-16 pending và Public Demo NO-GO. Những giới hạn delivery/realm/runtime bên dưới
không được chuyển thành FIXED bằng kết quả unit tests.

## 1. Source security baseline

Đối chiếu checkpoint PD-R4, task/acceptance PD-02-04, Security Audit PR-012/017/G3,
evidence PD-02-01/02/03, ARCHITECTURE, LOGIN_FLOW, MFA_RESET_LIFECYCLE, RISK_API_SECURITY,
source/factories/configuration/test của Portal/Gateway/Risk/SPI và SPA adapter/API calls.
Quyết định owner về B0/read-only có hiệu lực mới hơn đoạn lịch sử “numeric policy chưa chốt”.

Baseline có **665 tracked/untracked nonignored files**, HEAD như trên, branch ahead3 theo local
tracking ref. 10 Lab containers đều exited theo selected metadata. Không reset/rebase/stash,
checkout/stage/push/commit; không đọc Lab secrets/database hoặc private realm/config export.
Dependency candidate giữ Boot3.5.16/Cloud2025.0.3, JDK17, SPI/server26.7.0 và Node24.22.2.
Không giải quyết D-15/D-16 bằng thay platform/server trong task.

## 2. JWT/OIDC trust-boundary inventory

| Boundary | Contract source | Fresh verification và giới hạn |
|---|---|---|
| SPA → Keycloak | Public client, Code flow/PKCE S256; adapter tokens trong memory; client fixture direct grant false, access-only API audience mapper | Execute actual keycloak.ts với adapter mock: init S256/check-sso/singleton/no client secret. Fixture/SDK source review không thay live PKCE/code exchange/state/redirect validation |
| SPA → Portal/Gateway | Refresh trước request, dùng access token hiện tại; ghi đè Authorization do caller truyền; credentials omit |7 Node tests mới execute actual api.ts/keycloak.ts: bounded401 retry, refresh failure/clear, concurrent single-flight;9 PortalRoute tests gồm logout/clear/redirect vẫn PASS |
| Gateway JWT → Backend | Signature/JWKS, RS256 mặc định, iss/aud/exp/nbf; ADMIN/STUDENT route roles; preserve original API bearer, strip bearer/cookie khỏi SPA route | Real signed JWT/JWKS/upstream loopback, unsigned/RS384/RS512/PS256/HS256/future nbf rejected; no upstream call khi denied. Không actual Keycloak issuance |
| Portal JWT → application | Signature/JWKS, issuer, required exp, timestamps/audience; realm-role converter, method/path RBAC, owner từ JWT sub |12 decoder tests (signed fixtures); MockMvc role/ownership tests và90 PD-02-01 tests vẫn PASS. JWT request postprocessor trong MVC tests không tự chứng minh signature |
| SPI/listener → Risk | Service Client Credentials, audience Risk, azp risk-caller + dedicated evaluate/device-write/events-write roles |19 RiskApiSecurityTests có signed JWT; wrong issuer/aud/expiry/nbf/signature/caller/role denied, RSA/PSS/HMAC unsupported rejected, caller-supplied score/decision không thay server result |
| Portal → Risk reset | Separate portal-risk-admin + risk:device:revoke; revoke/completion gắn subject/operation/requester | Existing signed/security/lifecycle/orchestration tests PASS; không trộn provisioner/browser/risk-caller identities |
| Portal → Keycloak admin | Separate admin client; reset OTP/recovery, enrollment required action và logout sau Risk revoke | Existing gateway/client/user-service tests PASS; external actions mocked, không reset người thật |

Ba decoders hiện dùng RS256 mặc định; không thay allowed algorithms hoặc token TTL để làm test xanh.
Tham chiếu [Spring Security6.5 JWT contract](https://docs.spring.io/spring-security/reference/6.5/servlet/oauth2/resource-server/jwt.html).
SPI cache token tới refresh window, invalidate/retry401 một lần; không retry vô hạn timeout/5xx.
API audiences/service grants được kiểm ở source/test, chưa readback realm thật.

**Phân biệt lifecycle:** access JWT là bearer có thể dùng lại khi signature/claims/thời hạn còn hợp lệ.
SPA clear/logout, Keycloak session/refresh invalidation, và Risk device revocation là các trạng thái khác nhau.
Resource servers không introspect/blacklist mỗi request hoặc mặc định kiểm auth_time/acr cho reset.
Không có lời hứa logout/reset làm mọi JWT đã phát mất hiệu lực tức thì. SSO cookie/refresh có thể không
chạy password/Risk Browser Flow theo thiết kế; cần test/đo cửa sổ token/session ở04/06, theo D-10.
[Keycloak adapter guidance](https://www.keycloak.org/securing-apps/javascript-adapter) không thay browser acceptance.

## 3. SPI/Risk integration và source fixes

Password/OTP do Keycloak; SPI extract context server-side → authenticated Risk HTTP → validated response
→ enforcement notes/ALLOW/STEP_UP/DENY. Risk sở hữu scoring; không đưa công thức/trọng số/ngưỡng vào SPI.
Không lấy score/decision từ browser: request DTO không có các trường đó, injection test vẫn nhận server DENY.

Response hardening:

- Evaluation chỉ nhận HTTP200 + bounded JSON/content type; check subject và root:tab correlation giữ nguyên.
- `RiskResponseContract` kiểm decision/level/dataStatus tương thích, score hiện diện cho COMPLETE và
  null cho unscored status, range0–100/precision≤2, nonblank identifiers, nonnegative generation nếu có.
  LOW/ALLOW phải COMPLETE; mandatory MFA có thể MEDIUM với score25; incomplete MFA và unscored
  priority DENY được giữ. SPI không tính lại score hoặc diễn giải reason để thay Risk policy.
- SPI sinh UUID mới **mỗi HTTP attempt** trong `X-ZeroTrust-Risk-Request`. Risk kiểm/echo sau JWT/caller
  authorization; SPI đòi đúng một echo khớp. Reply cũ của cùng subject/root:tab không thỏa attempt mới.
  Nonce không là permission, scoring input, bearer anti-replay hay exactly-once. Evaluation ID/correlation
  hiện có không đổi. Server compromised/cached-body-with-rebased-header không được giải quyết chỉ bằng nonce.
- Risk giữ legacy requests không có header; SPI mới fail-closed nếu Risk cũ không echo. Cần paired RC
  artifacts và staging acceptance; không rollout một phía hoặc áp vào Lab trong task.
- ObjectReader riêng cho Risk/token responses từ chối trailing JSON/garbage, duplicate keys và numeric
  enum decision. Token response bị reject không được cache. Không mutate global Keycloak ObjectMapper;
  decimal expiry validation/refresh policy giữ nguyên. Parser cause có thể chứa payload bị bỏ khỏi lỗi.

DEFAULT failureMode DENY vẫn DENY cho HTTP/timeout/parsing/correlation failures. Configured fallback
STEP_UP_MFA của code cũ được giữ như contract riêng, không tạo trust eligibility/generation từ outage.
Public Demo cần pin/readback DENY trên realm thật; task không đổi live flow hoặc failureMode để tăng availability.

## 4. B0 invariants

Giữ nguyên `R = round_HALF_UP_2((D+N+T+H)/4)`, D/N/T/H25% mỗi nhóm, LOW<40,
MEDIUM40≤R<75, HIGH≥75. Không sửa scoring calculators, weights/default thresholds, mandatory/priority
logic hoặc migrations. `PublicDemoB0Contract` bổ sung vào strict startup path PD-02-03:
chỉ BASELINE_B0/.25×4/40/75; equivalent decimal representations hợp lệ; B1 hoặc override bị reject.
General Lab/research policy vẫn cho cấu hình B1/weight sum hợp lệ, không deploy B1 Public Demo.

| Fresh test | Result |
|---|---|
|39.994/39.995/40|39.99 LOW ALLOW /40.00 MEDIUM MFA /40.00 MEDIUM MFA|
|74.994/74.995/75|74.99 MEDIUM MFA /75.00 HIGH DENY /75.00 HIGH DENY|
|0.004/0.005/99.995|0.00/0.01/100.00, HALF_UP hai chữ số|
|Unequal factors|D0.01/0.02/100, ba nhóm còn lại0 →0.00/0.01/25.00|
|LOW + mandatory|score25 vẫn MFA; HIGH + mandatory vẫn DENY|
|Priority violation|short-circuit features; DENY/HIGH, score=null, NOT_EVALUATED; không gọi scored HIGH|
|Incomplete data|fallback factors0 không thành LOW/ALLOW; STEP_UP_MFA, score=null|
|Public Demo configuration|12 tests: B1/override rejection, valid-sum alternate weights rejected, decimal equivalents accepted; general Lab research policy không bị khóa|

17 B0 decision tests bind **actual application properties** rồi dùng production scoring/evaluation classes;
không copy một công thức giả vào test để làm oracle. Runtime feature policy/readback vẫn cần acceptance.

## 5. MFA và Trusted Device lifecycle

Source gap được sửa: eligibility flag một mình không chứng minh MFA. Handler nay bind eligibility với
evaluated subject và root:tab. Registration consume notes trước side effects, từ chối subject/tab mismatch,
và chỉ trust khi actual execution-status map có SUCCESS cho native OTP hoặc recovery authenticator.
CHALLENGED/ATTEMPTED/FAILED/SKIPPED/SETUP_REQUIRED không là MFA proof. Required CONFIGURE_TOTP
vẫn defer enrollment theo logic đã có; registration bỏ qua, không issue trust cookie trước enrollment.

20 registration-authenticator tests +8 actual factory/HTTP wiring tests kiểm OTP/recovery success marker,
missing proof, account/session mismatch, one-use notes, rotation, pending enrollment, missing generation,
registration outage/409 và only-after-204 cookie. HTTP harness dùng **mock Keycloak models/status**, không
xác minh một OTP code thật hoặc chạy Keycloak authentication engine.

Risk registration giữ subject lock/generation đến commit. Reset tăng generation/mark pending/revoke trước
IdP reset, completion đúng operation/requester mới kết thúc; old generation/new ID không khôi phục trust.
Explicit security revoke DENY; expired30days/MFA_RESET yêu cầu reauth/rotation. HMAC subject/device scoping,
normalization, timestamp và V5 semantics giữ nguyên. Full Risk lifecycle/JPA/H2 concurrency tests vẫn PASS;
không lấy H2 làm MySQL locking/real engine proof. Cookie entropy/path/HttpOnly/Secure/SameSite source/tests
giữ, không thêm bỏ OTP cho demo. Mapping execution SUCCESS được đối chiếu
[Keycloak26.7.0 source](https://github.com/keycloak/keycloak/blob/26.7.0/services/src/main/java/org/keycloak/authentication/DefaultAuthenticationFlow.java),
không thay live Browser Flow acceptance.

## 6. Security event delivery — PR-017

LOGIN_ERROR chỉ credential/user-not-found errors của monitored client; unknown subject có thể chỉ ghi IP.
LOGIN ghi successful authentication time gốc/client/subject. Expired-code/temporary-lockout/logout/unrelated
clients không tự tăng counters. Client chỉ role events-write; user/provisioner/revoke identity không thay thế.

**Đã sửa:** nếu native event thiếu ID, gán UUID một lần vào Event dưới synchronized block trước delivery.
Cùng object callback, concurrent callbacks hoặc clone **sau khi đã gán ID** giữ idempotency key. Distinct
events cùng subject/millisecond vẫn có ID riêng; không gộp các password failures hợp lệ bằng fingerprint.
Retry401 giữ serialized payload; redelivery sau unknown remote commit giữ ID. Chỉ metadata UUID, không log token.

**Chưa giải quyết:** synchronous best-effort, failed delivery/process loss không có durable replay. Wire test
503 chứng minh chỉ một attempt và phục hồi endpoint không tự phát lại event. Counter healthy/zero không
cho Risk biết một producer event đã mất; H có thể thấp hơn lịch sử thực. Same object ID fix không bảo đảm
clones trước assignment, process replay, loss-before-storage hoặc retry sau Redis dedup TTL. Không exactly-once.
Redis Lua/counter TTL/HMAC và MySQL unique event ID không bị sửa; fresh real Redis/MySQL test chưa chạy.
Subject counters tách account; source-IP counter được dùng chung theo thiết kế, không nhầm thành trust
cross-account. Trật tự event/commit và canonical IP còn cần acceptance thực tế.

**PR-017 OPEN:** cần bounded delivery latency/loss metrics + alert/receiver ở06/07, explicit consistency/recovery
contract. Nếu cần durable delivery, review producer-assigned persisted IDs/outbox/ack/retry/age bounds và
Keycloak transaction lifecycle bằng nhiệm vụ riêng; không tự thêm broker, đổi auth failureMode hoặc giả rollback.

## 7. Verified findings và remediation scope

Các ID F dưới đây là evidence subrecords, map về PR gốc; không tạo tracker hoặc đếm thành thêm PR findings.
Severity định tính theo điều kiện source; không có exploit live hoặc CVSS giả.

| ID / severity | Trigger đã tái hiện | Fix / fresh result | Remaining boundary |
|---|---|---|---|
|PD04-F01 / Medium, PR-012|Public Demo chưa pin approved B0, có thể nhận B1/valid-sum alternative policy|Strict startup B0 contract;12 tests PASS|Actual policy readback/realm/candidate chưa verified|
|PD04-F02 / High under malformed trusted-response precondition, PR-012|HTTP200 ALLOW với INCOMPLETE/HIGH/MEDIUM hoặc score shape sai vẫn được trả cho caller|Wire contract validation;14 negative cases +valid mandatory/incomplete/priority cases PASS|Không phải unauthenticated client tự sửa response TLS; SPI không tự scoring|
|PD04-F03 / Medium, PR-012|Old reply cùng subject/session đủ qua correlation cũ|Per-attempt nonce/echo +duplicate/missing rejection PASS|Paired Risk/SPI release, TLS/proxy/runtime proof chưa có|
|PD04-F04 / High under stale/misordered server-flow-state precondition, PR-012|Eligible flag/no MFA success hoặc evaluated account khác vẫn gọi trust registration|MFA execution proof +subject/root:tab binding +consume notes; tests PASS|Chưa chứng minh live Browser Flow exploit; native OTP/recovery/required actions cần04/06|
|PD04-F05 / Medium, PR-017|Event thiếu ID nhận ID khác ở repeated callback/unknown-commit retry|Assign-once event ID; repeated/concurrent/distinct-event tests PASS|Delivery loss/durability/bounded dedup chưa FIXED|
|PD04-F06 / Medium, PR-012|Trailing JSON, duplicate decision/score/token/expiry fields, numeric decision được chấp nhận|Local strict readers, sensitive parser cause suppression, invalid token not cached;10 negative cases PASS|Không thay parser global/server, không claim token issuer/runtime patched|

Pre-fix tests chạy thật: SPI31 tests/18 failures (response/event), Risk10/7 failures (early startup guard
harness), trust10/2 failures, strict JSON48/10 failures. Đây là **expected red reproduction**, không cộng
failures vào final results hoặc gọi mỗi failure là exploit. Các isolated early property contexts chưa bind
toàn bộ policy validation; valid-sum override/Lab binding được kiểm bổ sung trong final12 tests để không
nhầm invalid weight sum đã có guard với production bypass. Một lỗi Mockito nested stubbing trong test
duplicate-header đã sửa ở harness; giữ nguyên security assertions, final verify chạy lại SPI đạt.

## 8. Source fixes và regression inputs

Production: Risk B0 startup validator/correlation filter, SPI response/token readers/wire validator,
HTTP attempt nonce, MFA subject/session notes/proof guard và assign-once event ID. JWT decoders/callers,
authorization policy, calculators, generation/migrations/realm/Browser Flow không đổi policy.
Source/test manifest ở cuối xác định đúng inputs; không giả HEAD đã chứa dirty-tree changes.

Test fixtures chỉ được làm đúng contract: HTTP stubs echo nonce; STEP_UP response có MEDIUM/score50;
eligible-MFA fixtures có native SUCCESS và bound subject/session. Không giảm requirement/disable assertion.
Các guarded historical audit tests không được bật để giả live acceptance. Một số historical characterizations
(ID-less ID đổi mỗi callback, permissive trailing JSON) mô tả hành vi cũ và không dùng làm release evidence mới;
normal regression tests mới kiểm hành vi đã sửa. Không sửa các assertion lịch sử đó để “xanh” toàn audit.

## 9. Commands đã chạy

Process-local Temurin **17.0.21+9**, Maven Wrapper3.9.16. Không đổi global toolchain, không clean/xóa artifacts.

```powershell
$env:JAVA_HOME=(Resolve-Path 'target\pd-02-02\toolchain\jdk\jdk-17.0.21+9').Path
$env:Path="$env:JAVA_HOME\bin;$env:Path"
# Red reproductions trước từng source fix:
.\mvnw.cmd --batch-mode --no-transfer-progress -f keycloak-risk-extension\pom.xml '-Dtest=RiskResponseInvariantTest,RiskEventListenerTest' test
.\mvnw.cmd --batch-mode --no-transfer-progress -f risk-scoring-service\pom.xml '-Dtest=PublicDemoB0ContractTest' test
.\mvnw.cmd --batch-mode --no-transfer-progress -f keycloak-risk-extension\pom.xml '-Dtest=TrustedDeviceRegistrationAuthenticatorTest' test
.\mvnw.cmd --batch-mode --no-transfer-progress -f keycloak-risk-extension\pom.xml '-Dtest=RiskResponseInvariantTest,ClientCredentialsTokenProviderTest' test
# Targeted regression sau sửa; rồi final full verify:
.\mvnw.cmd --batch-mode --no-transfer-progress -f keycloak-risk-extension\pom.xml '-Dtest=RiskResponseInvariantTest,RiskEventListenerTest,HttpRiskScoringClientTest,RiskAuthenticatorTest,RiskDecisionHandlerTest,TrustedDeviceRegistrationAuthenticatorTest' test
.\mvnw.cmd --batch-mode --no-transfer-progress -f risk-scoring-service\pom.xml '-Dtest=PublicDemoB0ContractTest,PublicDemoStartupConfigurationTest,RiskApiSecurityTests' test
.\mvnw.cmd --batch-mode --no-transfer-progress -f risk-scoring-service\pom.xml '-Dtest=PublicDemoB0ContractTest,PublicDemoB0DecisionTest,PublicDemoStartupConfigurationTest,RiskApiSecurityTests' test
.\mvnw.cmd --batch-mode --no-transfer-progress -f pom.xml verify
.\mvnw.cmd --batch-mode --no-transfer-progress -f risk-scoring-service\pom.xml verify
.\mvnw.cmd --batch-mode --no-transfer-progress -f gateway\pom.xml verify
.\mvnw.cmd --batch-mode --no-transfer-progress -f keycloak-risk-extension\pom.xml verify
& '.\target\pd-02-02\toolchain\node\node-v24.22.2-win-x64\node.exe' --test frontend/tests/authentication-contract.test.mjs frontend/tests/portal-route.test.mjs frontend/tests/student-score-dashboard.test.mjs
python -X utf8 -m unittest discover -s scripts/public_demo -p 'test_*.py' -v
```

Targeted runs ở `target/pd-02-04`: SPI69 PASS; Risk98 PASS rồi expanded123 PASS, SPI default245total/27skip
trước strict parser addition. Không cộng trùng các lượt này vào final unique suite totals.
Local logs/XML/results là artifacts kiểm thử, không là CI/release/SBOM/provenance hoặc progress tracker khác.

## 10. Final regression results

| Suite | Total | PASS | Failures / errors | SKIPPED | Finish GMT+7 |
|---|---:|---:|---:|---:|---|
|Portal,48 classes|521|521|0 / 0|0|15:44:50|
|Risk,67 classes|824|728|0 / 0|96|15:44:59|
|Gateway,3 classes|25|25|0 / 0|0|15:44:20|
|SPI,28 classes|259|232|0 / 0|27|15:54:35|
|**Java tổng**|**1.629**|**1.506**|**0 / 0**|**123**|06/11/2026|
|Frontend Node (actual modules/components + mocks)|22|22|0 / 0|0|06/11/2026|
|Public Demo deployment config Python|10|10|0 / 0|0|06/11/2026|

**107 Java +7 Node tests mới**, đã bao gồm trong totals.90 PD-02-01 read-only,169 PD-02-03 config/grants
tests,3 PD-02-02 headers và V5checksum test1 vẫn PASS. Class totals chỉ lấy XML thuộc `Running` trong final
logs, không lấy stale ControlledStudyExperiment XML hoặc cộng các red/targeted runs.

123 skipped: Risk qa.http.audit43, qa.mysql.audit4, qa.redis.audit30, postfix03a.gateB3,
postfix03b.native16; SPI guarded qa.spi.audit27. SPI audit là loopback/mock historical harness,
không tự là live test; skipped không tính PASS. Không bật external/native DB/Redis QA hoặc dùng secrets Lab.
New normal SPI factory/HTTP tests cung cấp fresh verification cho scope đã sửa, không lấy skipped probes
làm bằng chứng. Frontend build/lint/image/dependency scan/remote CI không chạy lại vì không đổi runtime
frontend/dependencies/build inputs; Node tests chạy mới. Actual browser/issuer vẫn chưa verified.

V5 checksum **661092940 PASS**; bốn compiled V5/helper SHA-256 giống PD-02-02. B0 calculators/default
properties, SQL/Java migrations/helper/version guard/history giữ nguyên. Không sửa applied history hoặc engine.

## 11. D-10 reset policy — recommendations only

Current `POST /api/admin/users/{id}/mfa/reset`: path/service ADMIN, UUID input validation, active target;
STUDENT/anonymous denied. ADMIN có valid token vẫn reset được theo policy hiện tại, không yêu cầu fresh
auth_time/acr. Public Demo academic read-only không tự khóa SECURITY_STATE reset; role ADMIN demo vì thế
có thể ảnh hưởng MFA của các tài khoản demo khác. Tests mới malformed targets/anonymous cùng current
ADMIN/STUDENT tests và orchestration failure cases PASS. Không tự thay public identity admin policy.

**PROPOSED — NOT APPROVED:** public ADMIN chỉ trải nghiệm read-only; reset/enrollment/recovery do operator
trên private surface/network với danh tính riêng và fresh MFA được owner duyệt. Có target/requester/operation
audit, subject-generation fencing, pending/completion reconciliation, giới hạn delivery và hướng dẫn khôi phục.
Chốt TTL/session/old-token window và phương thức cấp riêng credentials trước implementation. Không mở endpoint
mới, không tự thêm fresh-MFA claim policy hoặc reset Lab. D-10 vẫn PENDING; D-15/D-16 giữ nguyên.

## 12. Limits và downstream acceptance

- Không live OIDC/code/PKCE/redirect/cookie/logout/session/key rotation/grants readback hoặc native OTP/recovery
  verification; mock SUCCESS không là OTP verified. Cần đúng realm/SPI/domain/paired artifacts ở04/06.
- No distributed atomicity guarantee giữa Risk snapshot/evaluation và concurrent reset/Keycloak token issuance; generation proof chỉ fence trust registration. Cần race acceptance đúng candidate, không suy instant revocation.
- No real MySQL/Redis TLS/grants/locking/TTL/AOF/dedup/durability/load/failure recovery; H2/mock không thay proof.
- PR-017 loss và H consistency vẫn là blocker cần xử lý/decision riêng; no exactly-once hoặc durable replay.
- PD-02-02 PARTIAL, dependency/server/support blockers và D-15/D-16 không thay bằng unit tests.
- D-10 policy/operator workflow chưa approved. G3 PARTIAL; PR-012/PR-017 OPEN, không actual Production GO.
- PD-02-08 cần review/retire historical opt-in expectations và tích hợp107 Java/7Node mới vào release checks trước freeze; không biến historical probes thành current PASS.
- Task kế tiếp đủ dependency là **PD-02-05**. Không thực hiện PD-02-05–08 trong task này.

## 13. Preservation verification và source manifest

Manifest và selected metadata đối chiếu với baseline PD-R4; final verification record bên dưới.
Không tạo worktree/clone/source copy, image/Staging/Production runtime, không start/restart/recreate Lab,
đọc/ghi Lab DB/Redis/realm/secrets, commit/push hoặc xóa backup/artifacts. Chỉ Java/Node/Python test harness
và synthetic loopback servers. HEAD/branch và10 Lab exited IDs/images/sorted mounts/networks giữ nguyên.

PD-02-01 inputs tại checkpoint PD-R4 và evidence giữ nguyên; toàn bộ13 dependency/build/test inputs của
PD-02-02 cùng evidence giữ nguyên.15/16 inputs PD-02-03 giữ nguyên; Risk startup initializer được mở rộng
có chủ đích để pin B0, không bỏ DB/TLS/grants checks,169 tests vẫn PASS. Historical audit/evidence giữ byte;
roadmap được cập nhật duy nhất. Native Browser Flow/realm/keys/CA/volumes không đổi.

SHA-256 dưới đây là source/config/test inputs đã kiểm, không là release SHA/digest:

| Source/config/test file | SHA-256 |
|---|---|
| [docs/security/RISK_API_SECURITY.md](../../../docs/security/RISK_API_SECURITY.md) | `f96d8994e91d3739872d6eae7db1e7f5ed6f97083ba01a0bc9c5878b354c8e82` |
| [frontend/tests/authentication-contract.test.mjs](../../../frontend/tests/authentication-contract.test.mjs) | `6257968f0a9fbddd2b23ab612b9458919ce217d44ec374db2f0210735bee350a` |
| [gateway/src/test/java/com/zerotrust/gateway/GatewaySecurityTests.java](../../../gateway/src/test/java/com/zerotrust/gateway/GatewaySecurityTests.java) | `9d3d93ad92bba0b11f703d9d4c9a76eca035b6fab885d08bcad7f0389004a611` |
| [keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/authenticator/TrustedDeviceRegistrationAuthenticator.java](../../../keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/authenticator/TrustedDeviceRegistrationAuthenticator.java) | `00cfe64364d946e53084ec5e434060d3c377b99bc9b696ac91e394f2d90414ba` |
| [keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/client/ClientCredentialsTokenProvider.java](../../../keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/client/ClientCredentialsTokenProvider.java) | `a0aae0aefc554e1a5da5a3057159bdcf89f436747b84e219eaf58b1bd8a90584` |
| [keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/client/HttpRiskScoringClient.java](../../../keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/client/HttpRiskScoringClient.java) | `2611c29ce57a29ef684cf97632e8d4bca8993226c2bab59eeee8072234deca6e` |
| [keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/client/RiskResponseContract.java](../../../keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/client/RiskResponseContract.java) | `4fddf03393213e1bd2f2d5cac14e98adce52f8f067f37ce288d9c02259bba842` |
| [keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/listener/RiskEventListener.java](../../../keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/listener/RiskEventListener.java) | `11b7fa2a24566d794cc443725f467f57e60ee996e5a52a4d95b3aa3feba66727` |
| [keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/policy/RiskAuthenticationNotes.java](../../../keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/policy/RiskAuthenticationNotes.java) | `68f938fd425aa93e241322d971c8c5dff9e3a9a2420de2d4a8ce1a82c12edc95` |
| [keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/policy/RiskDecisionHandler.java](../../../keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/policy/RiskDecisionHandler.java) | `d03343ea5519faf40c1c629632715a70b41d7ce8dc7faaec4b3e176f54c4880b` |
| [keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/audit/PublicDemoAdaptiveContractTest.java](../../../keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/audit/PublicDemoAdaptiveContractTest.java) | `a6b188432474cf58df061927851a944aeba835ce709196b18132deacf0244b2e` |
| [keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/audit/SpiAuditFixture.java](../../../keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/audit/SpiAuditFixture.java) | `36d7ae2bcdf0c180ac85140d2665de8d6fa1dfb8b117a50d22e4bfeae52f336d` |
| [keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/authenticator/TrustedDeviceRegistrationAuthenticatorTest.java](../../../keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/authenticator/TrustedDeviceRegistrationAuthenticatorTest.java) | `6ba010ab88f91cc4e22845168089ebe7c39d332782714593621e395d8e22d623` |
| [keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/client/ClientCredentialsTokenProviderTest.java](../../../keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/client/ClientCredentialsTokenProviderTest.java) | `9104af856fa8b82f4fa5b8d76838e5be109a21f562ef66bb660304fe323ac12d` |
| [keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/client/HttpRiskScoringClientTest.java](../../../keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/client/HttpRiskScoringClientTest.java) | `6ceff36bb600ac6c94a2a00d7c75228e9e2873bcae8bc2908a0cfad2fd5ff04e` |
| [keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/client/RiskResponseInvariantTest.java](../../../keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/client/RiskResponseInvariantTest.java) | `0dcb5a2b95a5c526d88ff651bc664e030697cd65439f8d30f7953cdc5204800e` |
| [keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/listener/RiskEventListenerTest.java](../../../keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/listener/RiskEventListenerTest.java) | `2141263f278f1529a5308911236273d3cf5e6e0dbf36b515208fd9123cc9d0f6` |
| [risk-scoring-service/src/main/java/com/zerotrust/risk/config/PublicDemoB0Contract.java](../../../risk-scoring-service/src/main/java/com/zerotrust/risk/config/PublicDemoB0Contract.java) | `4bf60f375bb28645fe2fe914e88b6b34b3c9e9bb98b5ee305d9cf1477755c3f4` |
| [risk-scoring-service/src/main/java/com/zerotrust/risk/config/PublicDemoStartupInitializer.java](../../../risk-scoring-service/src/main/java/com/zerotrust/risk/config/PublicDemoStartupInitializer.java) | `0723eb37c49cb557e63451fc9c0b42815f9b77b0372009dcebd42a05edee69d2` |
| [risk-scoring-service/src/main/java/com/zerotrust/risk/config/RiskApiSecurityConfig.java](../../../risk-scoring-service/src/main/java/com/zerotrust/risk/config/RiskApiSecurityConfig.java) | `9cb97e72d57d41f5e9331de35da6f84a8205356392f2582aabbf37c7308ca3aa` |
| [risk-scoring-service/src/main/java/com/zerotrust/risk/security/RiskEvaluationCorrelationFilter.java](../../../risk-scoring-service/src/main/java/com/zerotrust/risk/security/RiskEvaluationCorrelationFilter.java) | `beb62a2080a8596c5ce43cedf927a1378565f1800d6b265999a62c87589f95e2` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/config/PublicDemoB0ContractTest.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/config/PublicDemoB0ContractTest.java) | `6507a46f8ca8f3d3b30299db870a15c35a1a313e3dae7ce484521616e1386a44` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/config/PublicDemoB0DecisionTest.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/config/PublicDemoB0DecisionTest.java) | `f4ae836d888e81d4a48dd6b6311f0eddd07f2ba84a438bad98ba2a4462a58b27` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/security/RiskApiSecurityTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/security/RiskApiSecurityTests.java) | `3fee57cd956bc8772a412edabf13d451bf85057b630760058043c90592e50ab3` |
| [src/test/java/com/zerotrust/zerotrust/config/PortalJwtDecoderTest.java](../../../src/test/java/com/zerotrust/zerotrust/config/PortalJwtDecoderTest.java) | `e5fdbef0676416848fdbc35861eb1a66ececae7c51032ac849a05f12b74a529b` |
| [src/test/java/com/zerotrust/zerotrust/controller/AdminControllerSecurityTest.java](../../../src/test/java/com/zerotrust/zerotrust/controller/AdminControllerSecurityTest.java) | `30446da25657717c41e0bc7f0a27b1efc209e83068c22a1475bccd4e8bea7269` |

V5 compiled-bytecode preservation (so với EV-PD-02-02-01):

| Class | SHA-256 |
|---|---|
| `risk-scoring-service/target/classes/db/migration/V5__isolate_subject_identity.class` | `24449acbaab162df24350998c0e8c889140ddc404594738f2f8d8dc2713d77a1` |
| `risk-scoring-service/target/classes/com/zerotrust/risk/migration/SubjectIdentityMigrationPreflight$Plan.class` | `dfa6f251de3d6579fafc7378e5a311b0f68fd271c43ee2d07903551be62f3e0f` |
| `risk-scoring-service/target/classes/com/zerotrust/risk/migration/SubjectIdentityMigrationPreflight$Snapshot.class` | `307f931418b9254194f219eaf3f62dbc81164029e3f18b92fe8973d5840bc711` |
| `risk-scoring-service/target/classes/com/zerotrust/risk/migration/SubjectIdentityMigrationPreflight.class` | `6005aeeeba2cdefc09e4a2c2daf950b5448497fa8be8111efbe40d0d3cf8b74e` |

**Final preservation/document QA PASS:**646/665 files có trước giữ nguyên SHA-256;19 existing files
thay đổi đúng scope (18 source/test/contract inputs +roadmap),9 files mới (8 inputs +report),0 removed.
43 historical audit/evidence files,12 PD-02-01 inputs tại PD-R4,13 PD-02-02 inputs và15/16 PD-02-03 inputs
bảo toàn; chỉ Risk startup initializer được mở rộng B0 có chủ đích. HEAD/branch và10 Lab containers
IDs/images/sorted mounts/networks/exited giữ nguyên.26 source input hashes khớp;50unique tasks/16fields,
8PASS/36TODO/1PARTIAL/5BLOCKED,18OPEN findings,16pending/15approved decisions,dependency DAG acyclic,
92 local links đã kiểm. No live/native/CI/release acceptance được suy từ QA này.
