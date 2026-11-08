# PD-02-05 — Abuse limits & trusted proxy security hardening

Evidence ID: **EV-PD-02-05-01**. Ngày06/11/2026, Asia/Saigon; checkpoint **PD-R6**.
**PASS — source/configuration/isolated HTTP testing**, không phải Production acceptance.
Canonical repo `<repo-root>`, branch `zerotrust-v4-risk-scoring`,
HEAD `c401e17029d64f9a96738d845b8c0ad0f03fc164`; local upstream ahead3, toàn bộ thay đổi chưa commit.
SSOT duy nhất: [PUBLIC_DEMO_ROADMAP.md](../PUBLIC_DEMO_ROADMAP.md).

## 1. HTTP attack surface inventory

| Host / endpoint group | Luồng Internet dự kiến | Controls / coverage |
|---|---|---|
| Portal `/`, `/students`, `/admin`, Next/static assets | Ingress → Gateway → frontend | Static rate/body/connection limits tại cả ingress/Gateway; frontend không nhận bearer/cookie từ Gateway; UI không là authorization boundary |
| `/api`, `/api/**` | Ingress → Gateway → Portal backend | Broad per-IP ingress guard; signed issuer+subject Gateway quota; JWT/RBAC/ownership; actual body count; public academic writes vẫn bị Backend403 theo PD-02-01 |
| ADMIN/STUDENT public read APIs | Cùng API route trên | Profile/grade/catalog reads giữ role/ownership. Gateway không mở thêm route hoặc quyền |
| `/api/admin/users/{id}/mfa/reset` | API route hiện có | Security-state write khác academic write. Giữ current ADMIN policy; D-10 chưa duyệt private reset policy, không thay trong task này |
| Auth `/realms/<realm>/.well-known/openid-configuration`, certs | Ingress → Keycloak trực tiếp | Realm/auth zone + TLS/body/connection bounds; không đi qua Gateway |
| OIDC auth/logout/session/account/broker dưới `/realms/<realm>/` | Ingress → Keycloak trực tiếp | Separate auth zone; fixed canonical host/HTTPS forwarding; native Keycloak policy giữ |
| `/realms/<realm>/protocol/openid-connect/token` và trailing slash | Ingress → Keycloak trực tiếp | Exact token locations cùng zone riêng; không bypass quota bằng slash; POST body cap; bearer/basic credentials không bị đổi |
| `/realms/<realm>/login-actions/**` password/OTP/enrollment/recovery | Ingress → Keycloak trực tiếp | Auth quota/burst/body/connection/timeout; không coi mỗi IP là một người; không sửa Browser Flow/MFA |
| Auth `/resources/**` | Ingress → Keycloak trực tiếp | Static zone/body bounds; không tiêu auth/token zone |
| Auth `/admin`, `/realms/master`, `/health`, `/metrics`, `/management`, unknown paths | Không route public |404; unknown/admin hostname421. Portal `/admin` SPA là route khác với Keycloak Admin |
| Portal `/internal`, `/actuator`, `/health`, `/metrics`, `/management`, `/realms`, `/resources` | Không route public |404 trong generated ingress; không chuyển sang Risk hoặc management |
| Risk evaluations/trusted-device/event/revocation/completion APIs | Chỉ internal service graph | Không có public ingress/Gateway route tới Risk. JWT issuer/aud/azp/role + DTO validation giữ; private network/firewall proof downstream |
| Direct Portal backend, Keycloak listener, DB/Redis/Observatory/management | Chỉ private interfaces/networks | Final manifest phải không publish public ports. Gateway có source peer403; unit/mock không chứng minh firewall hoặc direct socket isolation trên host thật |

NGINX routing tests kiểm Portal/API/Next, discovery/auth/token/login-actions/resources, unknown/admin
hosts/master/management/internal. Keycloak traffic **bypass Gateway** được kiểm bằng counters của hai
HTTPS upstream stubs riêng; không dùng Gateway limiter để tuyên bố bảo vệ Keycloak.

## 2. Baseline security assessment

Đã đọc PD-R5, dependency PD-01-05 PASS, PR-003/004, G2/G3/G5 và evidence PD-02-01–04;
đối chiếu routes/security, Risk normalizer/CIDR/Network/History, SPI context/event IP và Lab config sources.
Trước sửa: Gateway có canonical path/header sanitization, RS256/JWT/RBAC, connect/response timeout;
**không có request admission/body-stream cap**. Codec1MiB không phải upstream body enforcement.
Chưa có public ingress contract hoặc auth/token quotas. X-Real-IP/identity aliases chưa được strip đầy đủ.
Lab không cấu hình public proxy trust; không tự bật trust hoặc sửa generator/realm.

| Subfinding trong scope | Sửa/verification | Finding gốc |
|---|---|---|
| PD05-S1 thiếu bounded admission/actual body count | New Gateway filter/table + real Netty413/429/header431; cancellation/deadline/config tests | PR-004 OPEN |
| PD05-S2 chưa có single-ingress trusted peer/IP contract | Socket CIDR allowlist + single literal XFF; native NGINX overwrite/TLS/route tests; Portal/Risk disable automatic forwarding | PR-003 OPEN |
| PD05-S3 Keycloak bypass Gateway chưa có edge bounds | Auth/token/static zones độc lập + native NGINX413/429/concurrency; Keycloak hostname/proxy fragment | PR-003/004 OPEN |

Không có exploit trên Lab hoặc runtime được tuyên bố. No changes to calculators/weights/thresholds,
priority DENY/mandatory MFA/incomplete/failureMode, JWT cryptographic contract, HTTP attempt nonce,
strict response JSON, trust generation/MFA proof hoặc Event ID semantics từ PD-02-04.

## 3. Rate limiting design

Toàn bộ số dưới đây **PROPOSED — NOT APPROVED**, chờ **D-06**; không là workload/SLA đã chốt.

| Layer/group | Rate / burst | Key | Concurrency |
|---|---|---|---|
| Ingress API |100/s +200 excess | TCP client IP | Global128, per-IP64 active |
| Ingress Portal/static/Keycloak resources |100/s +200 excess | TCP client IP | Cùng global/per-IP bounds |
| Ingress auth/login/OTP/realm |10/s +60 excess | TCP client IP | Cùng bounds; không ban/lock cả NAT |
| Ingress token |5/s +30 excess | TCP client IP | Zone riêng, không tiêu auth zone |
| Gateway API |10/s, capacity20 | SHA-256(verified issuer + NUL + subject) | Global32, subject4 |
| Gateway static |100/s, capacity200 | SHA-256(canonical client IP) | Cùng global32, IP16 |

Ingress NGINX leaky bucket nodelay; `burst` là excess, khác Gateway token capacity bao gồm request đầu.
Bốn fixed1MiB request zones +hai1MiB connection zones; zone exhaustion/admission fail closed429.
Gateway dùng synchronized map + monotonic clock, tối đa4096 keys, idle TTL60s, không có admission queue.
Atomic acquire/refill/release trong một process, release idempotent sau complete/error/cancel.
Không evict active keys; full table429 Retry-After1. TTL được validate ≥full refill interval, tránh
key expiry cho quota mới sớm. Keys chỉ lưu digest, không thêm raw IP/subject persistence.

Không dùng Redis limiter: **không namespace/Redis TTL/Lua/write mới**, không đụng History Risk counters.
Ingress/Gateway denials không được ghi thành failed authentication/security event giả. Gateway counters
ephemeral/local, reset khi restart; nhiều replicas nhân quota, chưa có distributed coordination.
Memory bounded theo số keys và admitted bodies: mặc định32×64KiB=2MiB retained byte arrays, thêm join/copy
transients/headers/Netty/TLS/client buffers/object overhead; không phải measured heap/RSS limit.

NAT: test hai JWT subjects cùng IP có quotas riêng; đổi XFF không reset subject quota. Native ingress
cho8 synthetic logins cùng127.0.0.1 với proposed auth burst60. Edge guards vẫn chia sẻ IP/global dưới
saturation, không hứa fairness/capacity. Không hard ban, không username/unsigned claims làm quota identity.
D-06 phải đo class/cohort, auth/refresh/static/API mix trước khi chốt hoặc chỉnh limits; giữ MFA/guards.

## 4. Request/body/time limits

| Control | Gateway proposed | Ingress proposed |
|---|---|---|
| Body | API65536, static8192 actual bytes trước upstream | API65536, static8192, auth/token32768; request buffering on |
| Headers | Native total16384bytes; HTTP431 test | Initial4KiB, two8KiB large buffers; single header quá8KiB HTTP400 test |
| Body deadline |2s absolute từ filtered body subscription;408 nếu chưa commit |5s body idle/progress timeout; không là absolute duration |
| Exchange/response |15s filtered exchange;5s upstream response |5s upstream read/send idle;10s client send idle |
| Connect/pool |2s connect; FIXED32/acquire2s; idle15s/lifetime60s |2s upstream connect; no retry to another upstream |
| Server idle/connection |15s idle, keepalive100 requests; global32 admitted |15s keepalive/100 requests; worker512 connections; global128/perIP64 active requests |

Gateway dùng bounded `DataBufferUtils.join` và kiểm actual byte count, không chỉ declared Content-Length.
Chunked/no Content-Length vẫn bị413; valid chunks được gửi nguyên bytes, Content-Length được chuẩn hóa
sau buffering, Transfer-Encoding bị bỏ ở replay. Oversized payload không reach upstream. Join giải phóng
DataBuffers khi lỗi/cancel. Filter error response constant JSON/no-store, không echo IP/token/body.
429 có Retry-After1;413 không tạo recovery time giả. Timeout sau commit cancel/close stream, không biến
response đã commit thành JSON408. Security chạy trước admission;401/403 vẫn đúng, oversize unauthenticated
có thể bị401 trước filter (ingress vẫn có body cap trước authentication).

Native HTTP framing: TE+CL cùng request bị NGINX400; không forwarded. Unit body với CL1 nhưng1025 actual
bytes vẫn413. CL thấp mà **không** có transfer framing chỉ mô tả body ngắn hơn theo HTTP; trailing bytes
không được coi là body dài hơn. Tests không giả tuyên bố mọi framing-invalid packet đều trả413.
Ingress idle timeout không là total request timeout; slow-client/disk/resource envelope phải đo downstream.

Fail-fast: Public Demo requires both independent mode/read-only markers, trusted numeric CIDRs (≤16,
no `/0`), all effective admission bounds, bounded header/idle/keepalive/client/pool settings and
`server.forward-headers-strategy=none`. Empty/invalid/unresolved/missing settings reject startup with
redacted error, including marker-only mode without required limits. Lab admission stays disabled.

## 5. Trusted proxy model

`CLIENT → single ingress TLS → Gateway / Keycloak private TLS → authenticated internal Risk API`.
Generated ingress dùng **proxy_pass_request_headers off** + explicit application header allowlist;
không dùng `real_ip_header`, `$proxy_add_x_forwarded_for`, client-provided identity hoặc multi-hop parser.

| Input | Quy tắc/ưu tiên |
|---|---|
| Remote socket | NGINX: nguồn client IP. Gateway: peer phải thuộc explicit CIDRs trước mọi header trust, ngoài list403 |
| X-Forwarded-For | Ingress overwrite thành một `$remote_addr`; Gateway nhận đúng một header/một literal từ trusted peer; thiếu/duplicate/comma/invalid400 |
| Forwarded | Drop tại ingress, strip tại Gateway; không tham gia canonical IP/authentication |
| X-Real-IP / X-Client-IP / True-Client-IP | Drop tại ingress, strip tại Gateway; không có fallback hoặc ưu tiên |
| X-Forwarded-Host/Proto/Port | Ingress fixed canonical host/https/443; Gateway strip, Portal/Risk không tự transform socket/request |
| Authorization / roles | Bearer giữ nguyên cho API JWT verification; X-Role/X-Subject và arbitrary forwarded/identity aliases không grant quyền |
| Missing/conflicting chain | Không fallback dùng proxy IP để tính client. Multi-hop/CDN chưa được duyệt; phải review parser/allowlist riêng |

Gateway không chuyển XFF cho backend như một nguồn quyền. Portal/Risk Public Demo startup reject
`framework`/`native` automatic header processing. Không có new role/caller bypass cho direct requests.
Native NGINX test gửi Forwarded/XFF-chain/X-Real-IP/proto/host/port/role/subject mâu thuẫn và kiểm exact
outgoing socket-derived XFF, fixed authority và header stripping ở **cả hai** upstream stubs.

## 6. Canonical client IP extraction

Gateway normalizer chỉ nhận numeric literals, không hostname/DNS. IPv4 quad1–3digits/octet được chuẩn hóa
leading zeros, range0–255. IPv6 canonical lower-case/full address; hỗ trợ valid embedded IPv4 tails;
reject IPv4-mapped IPv6, brackets/ports/scopes/unknown/chains. Quy ước khớp Risk `IpAddressNormalizer`.
CIDR byte-mask matching IPv4/IPv6, không IPv4/IPv6 family cross-match; tests boundary/trusted/untrusted.

SPI **không đổi production code**: `KeycloakLoginContextExtractor` lấy native
`context.getConnection().getRemoteAddr()`, event listener lấy native event IP. Test đưa forged headers
nhưng context DTO vẫn203.0.113.10 và verify không đọc Forwarded/XFF/X-Real-IP. Native Keycloak phải áp
dụng trusted-proxy config trước bước đó; SPI unit không chứng minh Quarkus parser thực.

Risk evaluation/authentication failure dùng IP trong DTO từ caller JWT đúng role; MockMvc signed-token
tests gửi forged forwarding headers và capture LoginContext/history service argument vẫn203.0.113.10;
missing JWT + spoofed local headers401/no service work. Normalizer/CIDR/NetworkRisk/HistoryHMAC canonical
key tests pass đầy đủ, không sửa calculator, history key/counter algorithm hoặc Lua.

## 7. Keycloak ingress contract

Source: [ingress contract](../../../deploy/public-demo/ingress-contract.json),
[renderer](../../../deploy/public-demo/render_ingress.py),
[contract/operator notes](../../../deploy/public-demo/INGRESS_CONTRACT.md).
Renderer strict JSON/schema validates inputs before writing NGINX config, Keycloak fragment and Gateway
env fragment from **the same trusted CIDRs**. No secret contents read, no process launch from renderer.
Primary Keycloak26.7.0 definitions support
[proxy headers/trusted addresses](https://github.com/keycloak/keycloak/blob/26.7.0/quarkus/config-api/src/main/java/org/keycloak/config/ProxyOptions.java)
and [HTTP queue/thread bounds](https://github.com/keycloak/keycloak/blob/26.7.0/quarkus/config-api/src/main/java/org/keycloak/config/HttpOptions.java).
Queue overflow is native503, distinct from edge429; no runtime queue test claimed.

Proposed: public full HTTPS hostname, strict hostname, fixed issuer `<auth_host>/realms/<realm>`,
`proxy-headers=xforwarded`, explicit `proxy-trusted-addresses`, private admin hostname, HTTP disabled,
ingress-to-Keycloak TLS verify/SNI. No auth-host admin/master/health/management route; no public route
for private admin hostname. Hostname-admin **alone** is not access isolation. Real private operator path,
network rules, redirect allowlists/web origins and issuer/client config require Phase03/04/05 acceptance.
Authorization/Cookie/Origin/Referer/language/UA pass through; native TLS stub302 Location and secure
HttpOnly/SameSite=None cookie preserve exact values. Actual browser cookies/PKCE/OTP not verified.
No realm, Browser Flow, MFA/session, brute-force policy or Keycloak server version changed.

References: [Keycloak reverse proxy](https://www.keycloak.org/server/reverseproxy),
[NGINX request limiting](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html),
[body/header/time directives](https://nginx.org/en/docs/http/ngx_http_core_module.html),
[upstream header/buffering/TLS directives](https://nginx.org/en/docs/http/ngx_http_proxy_module.html).

## 8. Source/configuration changes

New Gateway `ClientIp`, `GatewayEdgePolicy`, `BoundedAdmissions`, `GatewayAbuseFilter` + Public Demo profile;
extended `CanonicalRequestFilter` peer/IP trust and alias stripping; independent base markers added.
Portal/Risk startup pin forwarding off; Portal Public Demo profile explicitly sets none.
Five new Gateway test classes, extra Portal/Risk config negatives, Risk HTTP security cases and SPI IP
regression; ingress JSON/renderer/notes and two Python test modules. No dependency changes in this task.
Full input SHA-256 manifest below binds dirty-tree implementation independently of unchanged Git HEAD.

## 9. Security regression tests

Portable JDK17.0.21+9, Spring Boot3.5.16/Cloud2025.0.3 dependency candidate from PD-02-02 unchanged.
Four independent POMs, `verify` (no clean/skipTests), Gateway server bound127.0.0.1. Fresh totals derived
only from classes named `Running` in each **current log**, avoiding stale experimental Surefire XML.

| Suite | Total | PASS | FAIL/ERROR | SKIP |
|---|---:|---:|---:|---:|
| Portal,48 classes |523|523|0/0|0|
| Risk,67 classes |828|732|0/0|96|
| Gateway,8 classes |111|111|0/0|0|
| Keycloak SPI,28 classes |259|232|0/0|27|
| **Java total** |**1721**|**1598**|**0/0**|**123**|
| Node24.22.2 auth/portal-route/student-dashboard |22|22|0|0|
| Python configuration10 + ingress validator6 + native ingress8 |24|24|0|0|

**92 additional Java cases** since PD-R5: Gateway86, Portal2, Risk4; strengthened existing SPI extractor
test without changing its count. New mandatory PD-02-05 cases: **0 SKIP**. Portal's90 PD-02-01 cases,
PD-02-03 fail-fast/grants coverage, PD-02-04 B0/JWT/nonce/JSON/MFA/trust/event regressions retained.
Risk96 skipped =43 opt-in HTTP audit +30 real Redis +23 MySQL/investigation/timestamp cases; SPI27
opt-in audit cases. No Docker/real stores/Keycloak run to force these green; historical opt-in permissive
characterizations remain subject to PD-02-08 review as recorded in PD-R5. They are not release proof.

Gateway49 policy tests,21 IP/peer cases,3 admissions cases,4 body/cancel/virtual-time cases and9 native
HTTP cases cover normal/burst/refill/NAT, key-table cap/TTL, global/subject concurrency, cancellation,
body/request deadlines, stream sizes, signed JWT/RBAC, missing/duplicate/chained XFF, IPv6, actual
header431 and bound FIXED pool. Native ingress8 cases cover both upstreams/auth/token/connection denial,
exact header overwrite, declared/chunked bodies, NAT8,302/cookies, admin/internal isolation and TE+CL400.

Native tool: official portable NGINX Windows1.31.8 from
[nginx.org download](https://nginx.org/download/nginx-1.31.8.zip), ZIP SHA-256
`fbb1501009be34655cc238d460714cf20391b639013f4c73859813d7938783fd`.
Downloaded over official HTTPS, version checked; **not PGP verified or selected as a release image**.
Harness runs `nginx -t` per config then native TLS on127.0.0.1 only; two HTTPS stubs + self-signed test
certificate/private key generated with test-only keytool PKCS12. No Lab CA/signing material used or changed.
Own-process finally shutdown, no NGINX process left after run. No stress/brute-force or live Keycloak.

Reproduce with existing portable tools (all paths below are repo-relative test inputs):

```powershell
$env:JAVA_HOME=(Resolve-Path 'target/pd-02-02/toolchain/jdk/jdk-17.0.21+9').Path
$env:Path="$env:JAVA_HOME\bin;$env:Path"
.\mvnw.cmd --batch-mode --no-transfer-progress -f pom.xml verify
.\mvnw.cmd --batch-mode --no-transfer-progress -f risk-scoring-service/pom.xml verify
.\mvnw.cmd --batch-mode --no-transfer-progress -f gateway/pom.xml '-Dserver.address=127.0.0.1' verify
.\mvnw.cmd --batch-mode --no-transfer-progress -f keycloak-risk-extension/pom.xml verify
$env:PD05_JAVA_HOME=$env:JAVA_HOME
$env:PD05_NGINX_EXE=(Resolve-Path 'target/pd-02-05/toolchain/nginx-1.31.8/nginx.exe').Path
python -m unittest discover -s scripts/public_demo -p 'test*.py' -v
# From frontend directory:
& ../target/pd-02-02/toolchain/node/node-v24.22.2-win-x64/node.exe --test tests/authentication-contract.test.mjs tests/portal-route.test.mjs tests/student-score-dashboard.test.mjs
```

Logs under ignored `target/pd-02-05`: portal/risk/gateway/spi-full.log, node-tests.log, python-full.log;
ingress-harness/<run>/<fixture>/syntax.txt and generated native config. Final renderer includes common
Gateway env output and token trailing-slash parity;24 Python cases rerun after these extensions.
Development failures corrected: test client API compile error, fixture prefix missing temp directory,
validator incorrectly accepting upstream port0, and concurrency fixture using ADMIN JWT on STUDENT-only
route (correct403). No assertions/security policies disabled; final suites above all green. The last
concurrency fixture failure log retained separately in ignored target; no unresolved implementation failure.

## 10. HTTP status verification

| Case | Verified result / boundary |
|---|---|
| Valid signed JWT + small declared/chunked body |200 real Netty; body reaches upstream once; signed original bearer retained |
| API token burst capacity3, frozen clock | First3=200, next429/Retry-After1/no upstream call; +1s refill200 |
| Same NAT different JWT subjects | SubjectB200 while A exhausted; changing header IP does not reset A |
| Held same-subject concurrent request | Other request429/Retry-After1; after release200, native HTTP |
| Oversized declared1025 / chunked700+700, cap1024 |413 real Gateway, no upstream call |
| Missing Content-Length / CL1+1025 actual |413 filter boundary; unknown-length chunked413 also native HTTP |
| Gateway missing JWT / STUDENT→ADMIN / forged role |401 /403 /403; upstream untouched |
| Gateway untrusted TCP peer + forged headers |403 canonical filter; cannot grant privilege; direct Risk no JWT401 via signed-security MVC fixture |
| Trusted peer missing/duplicate/comma/invalid XFF |400 native Gateway; IPv6 client accepted200 and forwarding stripped |
| Gateway header17000bytes |431 native Netty before upstream |
| Body/request virtual time deadline |408 before commit; no upstream on body timeout; lease released on cancel |
| Ingress auth/token each rate1+burst1 override |200,200,429 independently, Retry-After1/constant JSON |
| Ingress declared/chunked oversize API/login/token |413, no upstream call; valid chunked `abcdef` preserved |
| Ingress held active connection / per-IP1 override |429/Retry-After1; after release200 |
| Ingress forged chain/authority/identity |200 with exact socket127.0.0.1/fixed host/https/443 outgoing, attacker headers absent |
| Ingress admin/master/internal/management |404 or unknown-host421, no Keycloak upstream call |
| Ingress TE+CL / ambiguous path / oversized single header |400 native NGINX; no body bypass |
| Backend401 through ingress / stub redirect+cookie |401 preserved /302 Location and secure cookie preserved |

## 11. Các giới hạn chưa kiểm chứng

Không có public URL, final domain/PKI/issuer, Linux ingress/release image/network/port proof, actual
Gateway↔Portal TLS, real Keycloak trusted-proxy parser, real browser PKCE/OTP/session/cookie/redirect,
private operator access hoặc DB/Redis/dependency acceptance. Gateway HTTP uses synthetic local JWKS/
HTTP upstreams; ingress uses **HTTPS stubs**, không native Keycloak hoặc full integrated deployment.
IPv6 parsing/CIDR/header values được test, không real dual-stack Internet network. Native ingress burst
timing is bounded fixture (<1s for3requests), không benchmark/soak. No SLA/throughput/latency/headroom
or resilience claim. Quota local/reset/replica, idle/progress vs absolute deadline and shared NAT limits
ở mục3–4 là residual constraints, không waivers.

**Docker daemon unavailable** ở baseline và final metadata reads (dockerDesktopLinuxEngine pipe absent).
Không bật daemon/Desktop, không dùng lỗi này để start/recreate Lab. Current container IDs/images/mounts/
networks/states **NOT_VERIFIED trong PD-R6**. Mốc10 exited ở PD-R5 chỉ là historical, không fresh proof.
Source/config preservation và không có hành động mutation được kiểm; không giả xác nhận trạng thái live.

## 12. Các yêu cầu nghiệm thu Staging

Phase03 phải integrate rendered ingress/Gateway/Keycloak fragments với PD-02-03 secret/data/TLS config,
pin effective markers/limits/trusted egress CIDRs và exact release lineage; chọn maintained dependencies/
server theo D-15/D-16 trước closure. D-04 chọn domain/issuer/redirects/certs; D-06 duyệt workload/NAT mix/
limits/error budgets; D-10 chốt reset/operator/enrollment/session policy. Không thực hiện các task đó ở đây.

Phase04–06 cần final private network/direct-port negatives cho tất cả services, Keycloak native trusted/
untrusted/duplicate/conflicting/IPv4/IPv6 cases, signed SPI→Risk Network/History signals, real HTTPS chain/
SNI/issuer/PKCE/redirect/cookies/OTP/refresh/logout/recovery và paired Risk-SPI nonce/strict JSON/MFA trust.
Đo auth/token/API/static normal/burst/NAT/concurrency/slow-body/header/pool/timeouts/disk+memory/soak/
failure recovery, verify413/429/Retry-After/401/403 và resource envelope trên đúng final candidate.

**PR-003/PR-004 OPEN**, chưa FIXED/MITIGATED; **G2/G3 PARTIAL**, **G5 PARTIAL** chỉ source/isolated
guardrails (từ NOT_VERIFIED), không capacity PASS; G1/G4 PARTIAL/G6–G7 NOT_VERIFIED/G8 BLOCKED.
PD-02-02 PARTIAL/D-15,D-16 pending. NO-GO FOR PUBLIC ACCESS. Next eligible PD-02-06 (PD-01-05 PASS),
chưa thực hiện và không được task này cấp quyền.

## 13. Preservation verification

Baseline captures674 nonignored tracked/untracked file hashes trước mutation. Final checks:
**664/674 preexisting files unchanged,10 intentionally changed (9 inputs +roadmap),16 new (15 inputs +report),
0 removed**.44 historical readiness/audit/evidence files unchanged.12 PD-02-01 inputs unchanged;
13 PD-02-02 input hashes exactly match immutable dependency inventory. At PD-R5 checkpoint:
11/16 PD-02-03 inputs unchanged; five explicit extensions =two startup initializers, Portal profile,
two fail-fast tests.24/26 PD-02-04 inputs unchanged; only Risk initializer (forwarding pin, B0 intact)
and RiskApiSecurityTests (two additional IP/security cases) extended. No PD-02-04 production SPI/nonce/
strict JSON/MFA/trust/event class changed. All prior evidence left immutable.

V5ChecksumContractTest PASS **661092940**; four compiled class hashes exactly match PD-02-02 inventory:
V5 and SubjectIdentityMigrationPreflight/Plan/Snapshot unchanged. Source migrations/calculators/Lua và
nonignored Lab Compose/Dockerfiles/config/dependency inputs giữ hash theo baseline. Không đọc/sửa secrets,
database, realm, CA hoặc signing keys Lab; không dùng file hashes thay attestation cho ignored/external state.
HEAD/branch unchanged, no staging/commit/push/reset/worktree/source copy/delete/deploy; no Lab mutation.
Only own synthetic loopback listeners/processes launched/closed; current Docker metadata limitation above.
Git diff whitespace check PASS (preexisting LF/CRLF notices only). Final roadmap/source/link/DAG QA below.

### Input SHA-256 manifest

Hashes cover24 source/config/test/contract inputs; exclude this report and SSOT to avoid self-hashing.

| Input | SHA-256 |
|---|---|
| [deploy/public-demo/INGRESS_CONTRACT.md](../../../deploy/public-demo/INGRESS_CONTRACT.md) | `05399154aade09c694463f7a620bdea55ba720f5d55e756f59fb4d4ae80bd462` |
| [deploy/public-demo/ingress-contract.json](../../../deploy/public-demo/ingress-contract.json) | `01f1b9117ed0309fba24c386ab72f90e68ecc9fbedb20007c7bf47672d1156c3` |
| [deploy/public-demo/render_ingress.py](../../../deploy/public-demo/render_ingress.py) | `f7351d22ba811613f5c768f64a0e78960ed19f6263a0bcbf9d33a5a48c0b3d54` |
| [gateway/src/main/java/com/zerotrust/gateway/BoundedAdmissions.java](../../../gateway/src/main/java/com/zerotrust/gateway/BoundedAdmissions.java) | `8a5f1ff08dbb88ba988db2063e5b9353c39968e8b86a8dcd8f61e3e5f4d495da` |
| [gateway/src/main/java/com/zerotrust/gateway/CanonicalRequestFilter.java](../../../gateway/src/main/java/com/zerotrust/gateway/CanonicalRequestFilter.java) | `51076772290202691346b96bc5f326a53fd1ea9509dc0ea71b8cab756ddd5786` |
| [gateway/src/main/java/com/zerotrust/gateway/ClientIp.java](../../../gateway/src/main/java/com/zerotrust/gateway/ClientIp.java) | `2fabc74531c0f041d57a23035626b3febfe7c7048c99b6bfec4ee171137450f8` |
| [gateway/src/main/java/com/zerotrust/gateway/GatewayAbuseFilter.java](../../../gateway/src/main/java/com/zerotrust/gateway/GatewayAbuseFilter.java) | `0398823df5c5984554608b16e6d6b7b6433566dca18a85042207f7af61f3529d` |
| [gateway/src/main/java/com/zerotrust/gateway/GatewayEdgePolicy.java](../../../gateway/src/main/java/com/zerotrust/gateway/GatewayEdgePolicy.java) | `097942c8183cd2761e47b4e7e91a7169ac98b41c8631fdc8512fbef82d280332` |
| [gateway/src/main/resources/application-public-demo.properties](../../../gateway/src/main/resources/application-public-demo.properties) | `2c13c82fb95f9a9d34a0b1038a2782daf39b4ef3c4e06397639a4a57426a8b2a` |
| [gateway/src/main/resources/application.properties](../../../gateway/src/main/resources/application.properties) | `88a155195e54818fc22f014a05ccc10442757e7782968f7aadded16c7953ed8c` |
| [gateway/src/test/java/com/zerotrust/gateway/BoundedAdmissionsTest.java](../../../gateway/src/test/java/com/zerotrust/gateway/BoundedAdmissionsTest.java) | `78f694dc9c4fed04695dd7b25db4b157b2b84b36944e78eff09a65fd7dda2a72` |
| [gateway/src/test/java/com/zerotrust/gateway/GatewayAbuseFilterTest.java](../../../gateway/src/test/java/com/zerotrust/gateway/GatewayAbuseFilterTest.java) | `886612fb9b561b21a36e49e38124f59c9331aa23640b3a2038942e48cadab75d` |
| [gateway/src/test/java/com/zerotrust/gateway/GatewayAbuseHttpTest.java](../../../gateway/src/test/java/com/zerotrust/gateway/GatewayAbuseHttpTest.java) | `223ceee34580c89f06e82c396ab1cf2e18980b2cf8b0ea900800994068d271a4` |
| [gateway/src/test/java/com/zerotrust/gateway/GatewayCanonicalIpTest.java](../../../gateway/src/test/java/com/zerotrust/gateway/GatewayCanonicalIpTest.java) | `8188cad47f0d83ec748f0148ef8259a1f0993ba9c833d873264fd2ea3acbde7a` |
| [gateway/src/test/java/com/zerotrust/gateway/GatewayEdgePolicyTest.java](../../../gateway/src/test/java/com/zerotrust/gateway/GatewayEdgePolicyTest.java) | `8c419f91c2b78ba43fb5f507390e1e00cf7abf368ca14740b803960974e81042` |
| [keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/context/KeycloakLoginContextExtractorTest.java](../../../keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/context/KeycloakLoginContextExtractorTest.java) | `2d1cd687c84138b5bce38e0730c6800d642e0f2a65aa0d68eba8a3fede25af9e` |
| [risk-scoring-service/src/main/java/com/zerotrust/risk/config/PublicDemoStartupInitializer.java](../../../risk-scoring-service/src/main/java/com/zerotrust/risk/config/PublicDemoStartupInitializer.java) | `113f82fca2591814686ffd48efc090fb5f445eb181529e85a692eafcf1e3e876` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/config/PublicDemoStartupConfigurationTest.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/config/PublicDemoStartupConfigurationTest.java) | `de0dcb5d28b414b20055d47c8421748a1220fe68269e5115cb847b830ffd5961` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/security/RiskApiSecurityTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/security/RiskApiSecurityTests.java) | `ebe21c893c716e3fa4bdc16418a4fc2a8f943cb71e5cf29d40e106cff60ff698` |
| [scripts/public_demo/test_ingress_contract.py](../../../scripts/public_demo/test_ingress_contract.py) | `5483bb8e8da8d47cf721cfc44e664f5cea9c1f6e8835c9953a0ee9357d0be32d` |
| [scripts/public_demo/test_ingress_http.py](../../../scripts/public_demo/test_ingress_http.py) | `4a7da697ada1b6994296d152432de32f8cc53386a6876931d09cf579ae29be30` |
| [src/main/java/com/zerotrust/zerotrust/config/PublicDemoStartupInitializer.java](../../../src/main/java/com/zerotrust/zerotrust/config/PublicDemoStartupInitializer.java) | `b6d8fcd497918a9ace3ddd9ebbd136e18f7dd1cebfc9804b6908d36561afc26f` |
| [src/main/resources/application-public-demo.properties](../../../src/main/resources/application-public-demo.properties) | `efebedb5ee3da516ed941da8a1d6e2b1ba75e2f09fbc1d01985918ddfe01de46` |
| [src/test/java/com/zerotrust/zerotrust/config/PublicDemoStartupConfigurationTest.java](../../../src/test/java/com/zerotrust/zerotrust/config/PublicDemoStartupConfigurationTest.java) | `095fdede43c6317911d504b546f36cc1f488ce2f93b9424d2d7a35c9fa20209e` |

Document QA PASS:50 unique tasks/16fields;9PASS/35TODO/1PARTIAL/5BLOCKED;18OPEN findings/18risks/16pending decisions/16approved entries;task DAG acyclic;81 local link occurrences resolved across SSOT/report/ingress notes;24source input hashes match. NextPD-02-06 dependencies PASS, task remains TODO.
