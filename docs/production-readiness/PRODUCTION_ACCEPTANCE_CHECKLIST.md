# Production Acceptance Checklist

**06/11/2026 — c401e17 — chưa nghiệm thu Production, overall NO-GO.** Checklist Proposed; chốt mục tiêu/owners trước chạy. [Findings](SECURITY_AUDIT.md), [report](PRODUCTION_READINESS_REPORT.md), [deployment](PRODUCTION_DEPLOYMENT_PLAN.md), [rollback](PRODUCTION_ROLLBACK_PLAN.md). Không đánh dấu PASS từ source/unit test cho gate đòi runtime.

Mỗi mục khi đóng phải có: release SHA/image digest/config/schema, ngày/môi trường, test method/result, evidence location redacted và owner ký. Dùng VERIFIED/SOURCE REVIEWED/TEST VERIFIED/HISTORICAL VERIFIED/NOT VERIFIED/FAIL/NOT APPLICABLE đúng phạm vi. Baseline Java1.136 pass/123skip, frontend/ops/Lua/microbench không tự đánh dấu các checkbox Production bên dưới.

## G1 — Release và supply chain

- [ ] PR-001: mọi runtime package/image đúng digest có scan mới, bao gồm OS/JDK/Keycloak/provided SPI dependencies; SBOM + scanner/advisory DB timestamp + triage applicability/fix/waiver. Không còn applicable Critical/High chưa xử lý.
- [ ] Exact release SHA đã được phép push, review/required checks xanh; CI kết quả đúng SHA, không dùng run của1c9fa97 cho c401e17. PR-010.
- [ ] Source snapshot→build args→image labels→registry digest→deployed digest khớp; N-1 và recovery images kéo được từ máy khác.
- [ ] Secret scanning source/history/build layers/logs trong phạm vi được chọn hoàn tất, findings đã triage, không có known leaked active secret. Regex60candidate không phải60secret.
- [ ] Frontend build args domain/realm/client/API đúng Production; không dùng image `*-lab` chứa localhost.

**Hiện tại:** FAIL release gate/NOT VERIFIED full scans; có local build/test evidence, chưa có release Production.

## G2 — Hạ tầng, cấu hình, mạng, TLS và secrets

- [ ] Chọn A/B, region/provider/domain/OS/resource/disk/owner/budget/SPOF/maintenance/SLO/RPO/RTO. Hạ tầng chưa tồn tại không coi là NA.
- [ ] Prod fail-fast DB URL/user/secret/validate/TLS và các issuer/host/ports; không inherit root/useSSL=false/ddl-auto=update. PR-002.
- [ ] Project/network/volume/config/secret riêng, không gắn Lab/preservation/backup data vào Production.
- [ ] External reachability: chỉ public ingress/auth routes đã duyệt; DB/Redis/Risk/management/admin/cluster ports bị chặn; thử từ network không được tin cậy.
- [ ] Canonical client IP: ingress overwrite headers, Keycloak trusted proxy allowlist, direct bypass denied; forged Forwarded/X-Forwarded/chain/IPv6/NAT tests. PR-003.
- [ ] Public certificate chain/SAN/hostname/TLS1.2+ từ máy chưa trust Lab CA; internal MySQL VERIFY_IDENTITY/Redis TLS/app TLS đúng; không insecure trust-all.
- [ ] Renewal/CRL freshness/revocation/expiry alert và recovery PKI diễn tập được; backup CRL cũ không mở traffic.
- [ ] Fresh prod secrets/identity grants/peppers/signing keys/CA; access/rotation/recovery escrow tested, backup encryption key tách host.

**Hiện tại:** Lab file config/ACL/TLS metadata VERIFIED, domain/firewall/PKI/secrets Production NOT VERIFIED.

## G3 — Authentication, tokens, MFA, trust và authorization

| Ca bắt buộc | Kỳ vọng | Evidence hiện tại |
|---|---|---|
| Code + PKCE S256; invalid verifier/missing challenge; exact redirect/logout | Invalid request bị từ chối; không code/token leak/open redirect | SOURCE/TEST + historical, prod NOT VERIFIED |
| JWT signature/alg/issuer/aud/exp/nbf/missing exp | Invalid401, valid wrong role/caller403, no alg-none/HMAC confusion | Signed-JWT suites TEST VERIFIED; realm đích chưa |
| Risk caller matrix | risk-caller chỉ evaluate/events/register; portal-risk-admin chỉ revoke/complete; SPA/provisioner/user không thay thế | TEST VERIFIED |
| Password/lockout/rate limits | Correct auth; failed-password controls theo policy, không khóa toàn NAT ngoài policy | Realm/limits đích NOT VERIFIED |
| Missing/new/pending/expired device, cold-start, missing features | MFA và state/reason đúng; thiếu data không thành LOW giả | TEST VERIFIED; historical một phần |
| Mandatory guard score LOW; weighted MEDIUM/HIGH; priority DENY | Guard không bị score bypass, weighted ≥75 DENY; priority không fabricate score | TEST VERIFIED; weighted HIGH Browser NOT VERIFIED |
| Risk HTTP unavailable/timeout/malformed response | failureMode DENY; không phát token/cookie trust mới; lý do unavailable khác HIGH | TEST VERIFIED mock, prod-like fault chưa |
| OTP/recovery/enrollment | Challenge khác success; CONFIGURE_TOTP không tự trust; real execution success mới register204 | TEST/HISTORICAL VERIFIED một phần |
| Cookie/account/replay/revoke | Secure/HttpOnly/Lax/host/path/expiry đúng; cross-account không trust; same-account cloned-cookie limitation ghi rõ | SOURCE/TEST; domain đích chưa |
| Reset lifecycle/race | Revoke/generation/pending→Keycloak reset→completion; stale attempt409; timeout-after-commit không clear pending bừa | TEST VERIFIED H2/mock, MySQL/Keycloak end-to-end chưa |
| SSO/refresh/logout/old access token | Phân biệt Risk-not-run; accepted residual window đúng TTL/revocation policy; không hứa immediate revocation nếu chưa có cơ chế | Historical/source, prod policy chưa |
| ADMIN sensitive actions | Fresh MFA/acr/auth_time hoặc compensating control được owner chấp thuận rõ; role-only limitation không che giấu | Baseline role-only, prod decision chưa |
| STUDENT self-only | Hai students khác subject thấy riêng profile/score; cross-user/admin denied; token/header spoof không đổi subject | TEST + historical16 checks, prod chưa |
| ADMIN CRUD/reset | Authorized paths và data validation; STUDENT/non-business roles không được CRUD/reset | TEST VERIFIED, prod chưa |

Không thay B0/thresholds/failureMode để đạt ca test. Realm flow/grants/lockout/session TTL/key rotation readback và Browser suite trên target environment là điều kiện đóng PR-012.

## G4 — Data integrity, migrations, privacy

- [ ] PR-005 fixed: response version/ETag + expectedVersion/If-Match; sequential stale edit/batch/delete bị409/412, không mất update; overlap transaction test vẫn đạt; UI reload/merge đúng.
- [ ] MySQL thực đích: clean install + upgrade migration/ledger/checksum/FK/unique/CHECK/index/case behavior, transactional batch/concurrent lock/deadlock/retry semantics. H2 không thay thế.
- [ ] Risk V5 Java: đường đi qua MySQL8.0.46 preflight được chốt và thử trước khi chọn LTS khác; writer quiescence/COPY-EXCLUSIVE/partial-DDL restore và bytecode checksum661092940 across build toolchain được xác minh; không sửa applied V5 hoặc repair để ép PASS.
- [ ] School9.1 logical migration nếu chuyển engine; không raw downgrade, không chạy SQL Teacher/scheduling; đúng academic identity crosswalk.
- [ ] App/migrator/backup grants least privilege, DB TLS/encryption-at-rest policy, SQL injection/sort/input/request bounds verified.
- [ ] EXPLAIN/query latency/connection pool/slow query/N+1 evidence trên synthetic production-size data, gồm danh sách users chưa phân trang nếu còn dùng.
- [ ] Redis nonempty AOF/restart/TTL/dedup/counter loss/memory/noeviction/failover contract tested; standalone hoặc Sentinel, không nguyên script trên Cluster.
- [ ] Grade actor/change audit + authorized read, retention/purge jobs/privacy notice/GeoLite license + update age đã chốt và thử. Temporal query90day không coi là purge.

**Hiện tại:** PR-005 characterization xác nhận FAIL; schema/H2/Lua có evidence; Production data gates chưa đạt.

## Performance gate

**G5 — capacity acceptance.**

**Chưa chạy tải HTTP/login trên Lab và không tạo nhiều login thật.** Kế hoạch dưới chỉ chạy trên stack cô lập synthetic có quyền test, separate realm/users/keys/volumes/network, cùng candidate digests, engine/TLS/resource profile của target. Không sử dụng credentials/user data Lab. Manual browser OTP acceptance tách khỏi automated synthetic throughput. Lấy startup/warm caches và cold paths riêng; không dùng stub để chứng minh full chain.

| Phép thử | Workload đề xuất để bắt đầu | Duration/request count | Đo và mục đích |
|---|---|---|---|
| Risk HTTP baseline | Synthetic authorized evaluations, concurrency1/5/10/20, input mixes trusted/new/incomplete/deny | 500 requests/mức, ghi actual duration/rate; warmup100 không tính | p50/p95/p99/error/timeout, DB/Redis/TLS/JWT cost và guards |
| Normal A | 5 API req/s +0,2 synthetic auth/s; mix80% student reads/15% admin read/5% writes fixture | Warmup5m, steady15m: khoảng4.500 API+180auth ngoài warmup | End-to-end processing (không thời gian người nhập OTP), latency/resource/pools |
| Burst A | Từ steady tăng20 API/s +2auth/s | 60s:1.200 API+120auth, sau đó15m steady recovery | Queue/backpressure/429, deny reasons không đổi sai, hồi phục saturation |
| Increased concurrency | API/Risk concurrency1→5→10→20, chỉ tăng khi stage trước ổn | ≥2m/stage, ghi actual count/rate | CPU/RSS/heap/GC/threads/DB+HTTP pool saturation, throughput knee |
| DB/query | Synthetic data gần cardinality dự kiến, own-scores/admin sheet/users/batch100 | ≥500 request/query type, same indexes/engine | EXPLAIN, query p95, lock wait/deadlocks, N+1/pagination |
| Risk slowdown | Fault fixture/network độc lập thêm delay dưới/gần/vượt socket timeout, connect/token/JWKS latency riêng | ≥20 synthetic auth/case, bounded concurrency | Security DENY vs auth availability, wall-clock deadline/pool wait/401 retry |
| DB latency/unavailable | Isolated DB proxy/fixture latency và network outage | ≥20 eval/API/case + recovery | No fail-open/data corruption; readiness/error type/reconnect |
| Redis unavailable/restart | Synthetic nonempty counters/AOF, disconnect/recover; simulate memory pressure riêng | ≥20 eval/event/case, log key count/TTL drift không giá trị | INCOMPLETE/MFA vs HTTP unavailable DENY, event loss/recovery/durability |
| Keycloak unavailable | Isolated service unavailable + JWKS/token cold/warm cache cases | ≥20 synthetic request/case + recovery | Cache boundary/401/retry budgets, no forged/new tokens |
| Process/host recovery | Kill/restart **isolated** app node/host, drain/rolling nếu B | Một drill/node + steady synthetic control traffic | Restart policy/readiness/session consistency, actual outage/data loss |
| Soak | Workload đạt steady approved envelope | Khởi đầu30m; release critical nên2h theo budget | Memory leaks/GC/backlog/disk/AOF/binlog/log growth |

Các số trên là test input đề xuất, **chưa phải capacity/SLO được duyệt**. B cần workload profile riêng theo kiến trúc, không tự nhân A lên10. Dừng tăng tải nếu resource guardrails của stack test chạm, errors tăng bất thường, integrity invariant sai hoặc target ngoài scope; giữ raw aggregates, không sửa criteria sau đo để PASS.

Mỗi report phải ghi: host/VM/container CPU-RAM-disk/OS/JDK/version/digests, resource limit/heap/GC, TLS/realm/policy/data shape/index, warmup, requests/concurrency/duration/offered-achieved rate, p50/p95/p99/error/timeout numerator+denominator, CPU/RSS peak/heap/GC/pools/DB/Redis/disk, result scope/limitations. Error security negatives không trộn với unexpected server error. Không lấy thời gian response mock/mock JWT làm full-auth latency.

- [ ] Workload + SLO/error budget/maintenance window được owner duyệt **trước** benchmark.
- [ ] Normal/burst/concurrency/soak đạt approved thresholds, có headroom và không bỏ security checks.
- [ ] Failure cases giữ fail-safe, hồi phục được trong budget; timeout tổng và retry không gây request storm.
- [ ] Capacity/cohort/rate limits trong deployment không vượt envelope đã nghiệm thu.

**Hiện tại:** chỉ có [in-process scoring microbenchmark](evidence/scoring-microbenchmark.jsonl), 1m operations ở concurrency1/4, sub-second samples; không có bằng chứng hàng nghìn user hoặc HTTP SLA. PR-013 còn mở.

## G6 — Reliability và observability

- [ ] Production restart/supervision + graceful drain/reconnect/fault recovery tested; health/readiness có dependency semantics, backend401 không là DB proof.
- [ ] Correct-attempt trace từ Keycloak→Risk→MFA/outcome; four signals/decision/source/timeout visible; serializer/logging failures không đổi auth result.
- [ ] Alerts phát hiện availability/deny/error/latency/pool/disk/DB/Redis/CRL/backup/event-loss/reset-pending, được gửi/ack bởi primary và backup operator.
- [ ] Logs/metrics có access control/retention/quota/redaction, không raw token/OTP/IP/deviceId; no public Observatory exports.

**Hiện tại:** source/trace tests tốt, thiếu essential ops deployment/alert evidence. PR-008/009/015/017.

## G7 — Backup, restore, rollback, disaster

- [ ] Encrypted offsite backup + separate escrow, image/config/secret/PKI recovery, restore từ một host mới thực hiện được.
- [ ] MySQL+Redis recovery với nonempty security state; point-in-time witness/consistent checkpoint; JGROUPS_PING/SERVER_CONFIG investigation có giới hạn rõ.
- [ ] Full restored application: realm/user credentials/MFA/signing/JWKS/token issuance, Risk data/School, service accounts, TLS/CRL và Browser/API acceptance.
- [ ] Security state sau backup được reconcile; revoked sessions/devices/MFA resets không hồi sinh do state lùi.
- [ ] App N→N-1 rollback không mất data; incompatible schema chọn forward fix/full restore, không DB binary downgrade.
- [ ] RPO/RTO thực đo đạt mục tiêu được duyệt; failure of backup/key/image/restore alerts đã thử.

**Hiện tại:** archive và DB restore HISTORICAL VERIFIED một phần, full app/DR/rollback execution NOT VERIFIED. PR-006/007 còn mở.

## G8 — Go-live và bàn giao

- [ ] Production owner/data owner/security owner ký decision, phạm vi cohort/traffic, residual P2/P3, SLO/RPO/RTO và rollback trigger.
- [ ] On-call/contact/change window/support/privacy notice, access approvals và runbook handover hoàn tất.
- [ ] Không còn P0/P1 blocker áp dụng; NOT VERIFIED bắt buộc có evidence hoặc quyết định scope hẹp có căn cứ, không đổi thành NA tùy tiện.
- [ ] Cutover được duyệt riêng, backup checkpoint mới và rollback packet accessible; stabilization monitoring/owner sẵn sàng.

Chỉ sau G1–G8 mới xem xét GO hoặc CONDITIONAL GO giới hạn có risk acceptance cụ thể. Checklist này chưa có ô Production nào tự đánh dấu đạt chỉ vì tài liệu đã được tạo.
