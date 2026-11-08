# Production Readiness — ZeroTrust Adaptive Authentication

**Ngày:** 06/11/2026, Asia/Saigon. **Baseline:** `zerotrust-v4-risk-scoring`, HEAD `c401e17029d64f9a96738d845b8c0ad0f03fc164`. **Overall verdict: NO-GO.**

Không nên mở Production ngay: đã xác nhận dependency có advisory, lỗi ghi đè điểm từ màn hình cũ, thiếu kiểm soát tải ở Gateway, và manifest Lab không tự phục hồi tiến trình. Hạ tầng đích, realm Production, tải/SLO và phục hồi đầy đủ chưa được nghiệm thu. Không xác nhận exploit bypass MFA/RBAC mới trong lượt này; điều đó không chứng minh không có lỗ hổng.

Không chấm điểm 0–100: chưa có Production target và trọng số được chấp thuận. Tỷ lệ test đạt không phải điểm readiness.

## Phạm vi và bằng chứng

Đã rà soát Portal, Risk, Keycloak SPI, Gateway, SPA/theme, ba MySQL, Redis, TLS/PKI, Docker, CI và backup/restore. Chỉ ADMIN/STUDENT. B0, thresholds, failureMode, Browser Flow, secrets, dữ liệu và image/volume Lab giữ nguyên. Không start Lab, deploy, đổi DNS/firewall, tạo cloud resource hoặc push Git.

| Nhãn | Ý nghĩa |
|---|---|
| VERIFIED | Quan sát metadata/config hiện hữu, chỉ đúng phạm vi quan sát |
| SOURCE REVIEWED | Đối chiếu implementation, chưa chứng minh runtime |
| TEST VERIFIED | Thực thi kiểm thử có nêu môi trường/phạm vi |
| HISTORICAL VERIFIED | Bằng chứng có ngày trước audit |
| NOT VERIFIED | Chưa đủ bằng chứng, không coi là PASS hoặc lỗi chắc chắn |
| FAIL | Đã xác nhận vấn đề/không đáp ứng gate được nêu |
| NOT APPLICABLE | Không dùng tính năng đó, có giải thích |

Chi tiết: [Evidence](EVIDENCE_REGISTER.md), [inventory](BASELINE_INVENTORY.md), [security/findings](SECURITY_AUDIT.md), [gaps](PRODUCTION_GAP_ANALYSIS.md), [quyết định](PRODUCTION_GO_NO_GO.md). JSON chỉ chứa metadata/tọa độ dependency/kết quả tổng hợp, không chứa credentials hoặc row dữ liệu người dùng.

Đã đối chiếu README, ARCHITECTURE, CURRENT_RUNTIME, RUNBOOK, ENVIRONMENTS, LOCAL_SETUP, RESTORE_VERIFICATION_REPORT, CLEANUP_REVIEW, BUILD_PIPELINE, ADAPTIVE_AUTH_ACCEPTANCE_REPORT, TRUST_SCORE_RESEARCH_AND_EXPERIMENT_PLAN, FINAL_CONSOLIDATION và Observatory/Live Acceptance. Một đoạn ARCHITECTURE còn mô tả compose.yaml dựng service; file hiện tại rỗng, entrypoint Lab là compose.lab.yaml. Không lấy tài liệu cũ thay trạng thái hôm nay.

## Baseline thực tế

- HEAD đi trước upstream **3 commit**. GitHub branch còn `1c9fa97`; API không tìm thấy `c401e17`. Branch không protected, rulesets rỗng. [CI run 41021344954](https://github.com/NguyenTruong-An/zerotrust/actions/runs/41021344954) thành công cho `1c9fa97`, không chứng minh HEAD đạt CI. E02.
- Trước audit có hai tài liệu Observatory và `presentation/` untracked; không sửa/stage/xóa. Tài liệu audit mới cũng chưa commit.
- Docker Engine 29.4.1, context desktop-linux. **10/10 container canonical đang dừng**; stored health không phải live health. Doctor: 0 lỗi cấu trúc/10 cảnh báo stopped; config-check đạt. E01.
- Có sáu build image lịch sử HEAD c401e17, snapshot `74d896368c3a…`; **473/473 input hash khớp Git blobs HEAD**. Image gắn trong container Lab khác các build image đó. Không có service nào đang phục vụ request lúc audit. E03.

## Kiểm thử thực chạy

Java chạy Maven offline verify từng POM độc lập trên Git HEAD snapshot riêng; JDK 17.0.10, helper network none, không gắn volume Lab. Host i5-11400H, 12 logical CPU, 16,89 GB RAM; Docker 12 CPU/8,18 GB; helper suite giới hạn 2 CPU/3 GiB. H2/mock/HTTP loopback không chứng minh engine/realm Production.

| Module | Tổng | Đạt | Skipped | Failure/error |
|---|---:|---:|---:|---:|
| Portal | 327 | 327 | 0 | 0 |
| Risk | 709 | 613 | 96 | 0 |
| SPI | 203 | 176 | 27 | 0 |
| Gateway | 20 | 20 | 0 | 0 |
| Tổng baseline | 1.259 | **1.136** | **123** | **0** |

123 ca audit/diagnostic có điều kiện không được bật, không biến skipped thành PASS. Frontend lint/typecheck đạt, một ESLint warning có sẵn; 15 Node test ứng dụng + 4 viewer đạt. 49 Python test đạt; sáu Dockerfile BuildKit check đạt. Không build/deploy lại application image trong audit. E04–E06.

Harness riêng: **1 H2 characterization test xác nhận stale edit PR-005**, không phải assertion chứng minh đã sửa lỗi; **1 compiled migration/metadata characterization** xác nhận V5 từ chối MySQL8.4.13 trước SQL và checksum661092940; **7 ca Redis 7.4.7 thật** đạt cho Lua/dedup/TTL/counter validation trên tmpfs/network none. Không kiểm chứng MySQL migration/Redis TLS/persistence/HA bằng các ca này. E07–E08/E17.

## Kiến trúc, bảo mật và ranh giới

Browser dùng Code + PKCE S256; Gateway và Portal kiểm bearer JWT. Portal sở hữu học vụ, gọi Risk khi reset trust/MFA. SPI gọi Risk evaluate/registration/events; Risk truy cập Risk DB/Redis. Không thấy dependency vòng nghiệp vụ. Login phụ thuộc đồng bộ vào Risk; service-token/JWKS cần Keycloak khi cache không đáp ứng; listener gửi event đồng bộ, lỗi chỉ log, không có durable delivery. Mỗi application/data service một instance là SPOF.

SOURCE REVIEWED/TEST VERIFIED: chữ ký, issuer, exp bắt buộc, audience ở Portal/Gateway/Risk; Risk còn kiểm azp/client role và default deny. STUDENT lấy subject từ JWT, query hồ sơ/điểm của mình. ADMIN có path và method security. DTO/sort allowlist, bound JPA queries và page/batch ≤100 giảm mass assignment/SQL injection. CSRF tắt phù hợp bearer stateless hiện tại; không suy ra Keycloak browser CSRF đã nghiệm thu. Không thấy `dangerouslySetInnerHTML` trong UI nghiệp vụ đã rà soát.

Cookie device ngẫu nhiên 256 bit, host-only, realm Path, HttpOnly, Lax, Secure dựa secure context, 30 ngày; server có expiry/revocation/HMAC(subject, device)/generation fence. Registration chỉ sau evaluation đủ điều kiện, MFA thật và API 204; CONFIGURE_TOTP pending không thành proof MFA. Cookie bị đánh cắp có thể replay cùng tài khoản, không ràng buộc phần cứng. Cần thử flags/lifecycle trên domain đích.

HISTORICAL VERIFIED: báo cáo A1–A6 và LIVE-L1 có form login/OTP/trust/priority DENY/read-only RBAC/ownership trong phạm vi ghi nhận. Weighted HIGH ≥75, toàn bộ recovery/refresh và nguyên nhân TIMEOUT cũ chưa đủ bằng chứng live. SSO cookie/refresh có thể bỏ form/Risk; reset/logout không lập tức vô hiệu mọi access token đã phát. Chốt TTL, cửa sổ revocation và fresh MFA cho thao tác quản trị trước go-live.

## Risk, IP, Redis và timeout

Priority DENY thắng scoring; incomplete/cold-start → MFA; mandatory guard không bị score LOW bỏ qua. CIDR trước GeoLite local; không remote lookup theo request. Giữ B0. Numeric policy vẫn là baseline nghiên cứu chưa được phê duyệt cho Production.

SPI lấy `ClientConnection.getRemoteAddr()`, không tự đọc X-Forwarded-For. Keycloak Lab dùng HTTPS trực tiếp, không khai báo proxy-header/trusted proxy. Thêm proxy mà giữ nguyên có thể chấm IP proxy; tin header từ mọi nguồn lại tạo spoofing. Gate: ingress overwrite, Keycloak allowlist, chặn direct path, thử forged headers/IPv6/NAT/proxy chain. [Keycloak reverse proxy](https://www.keycloak.org/server/reverseproxy).

Redis Lua atomic trên standalone: dedup 1 giờ, failure TTL 15 phút từ thất bại đầu chu kỳ, không phải sliding window. Predictable errors được kiểm trước ghi; Lua không rollback mọi lỗi tài nguyên. Các key không chung hash tag nên không dùng nguyên script với Redis Cluster. Runtime AOF everysec/TLS/password có; không thấy khai báo maxmemory/eviction. Mất counter có thể làm H thấp đi, Redis là dữ liệu bảo mật. PR-014.

SPI mặc định pool wait 500 ms/connect 2 s/socket 3 s, response 64 KiB, tối đa cấu hình 1 MiB; không follow redirect, retry có giới hạn khi 401. Gateway connect 2 s/response 5 s. Portal admin connect 3 s/read 5 s/pool 10. Không coi socket timeout là deadline login vì còn token refresh/pool/multiple phases. Hikari/Tomcat connection budget và saturation chưa được đo. Risk API lỗi + DENY bảo vệ security availability nhưng làm giảm authentication availability. Redis feature lỗi trả incomplete/MFA nếu Risk vẫn trả được; khác Risk HTTP unavailable. Không tự đổi DENY/timeout/retry.

## Database và toàn vẹn dữ liệu

School schema có InnoDB/FK/unique/CHECK/version, transaction và giới hạn input. Risk có **V1–V4 SQL và V5 Java** (db/migration/V5__isolate_subject_identity.java); index subject/client/time, unique event/device, subject lock INSERT IGNORE/FOR UPDATE và generation fence. V5 preflight chỉ chấp nhận MySQL8.0.46, đòi writers quiesced, đổi subject/client collation exact bằng ALTER COPY/EXCLUSIVE không atomic và checksum gắn bytecode. Không khởi tạo nguyên trạng bằng Flyway trên MySQL8.4 rồi mong V5 PASS; cần đường migration/version riêng được thử. H2 không chứng minh toàn bộ MySQL locking/DDL semantics. PR-011.

**PR-005 đã tái hiện:** hai form đều thấy midterm=7; A lưu 8; B gửi form cũ 7/final=10 sau đó. DB chấp nhận version 2 và đưa midterm về 7. API request/response không mang expectedVersion. Cần version/If-Match xuyên HTTP, batch conflict semantics, UI nhận 409; giữ @Version hiện có.

School MySQL **9.1.0 Innovation**, Risk **8.0.46**, Keycloak **8.4.13** theo image metadata. School chưa có migration ledger tự động; SQL Teacher/scheduling lịch sử không thuộc release mới. Chốt schema baseline ADMIN/STUDENT và migration checksum. Không mount datadir 9.1 vào 8.4; chuyển version cần logical migration thử riêng. [MySQL release model](https://dev.mysql.com/doc/refman/9.1/en/mysql-releases.html).

Runtime DB yêu cầu TLS, JDBC VERIFY_IDENTITY, application user không root. Actual grants, encryption at rest, EXPLAIN, DB latency/deadlocks/binlog/PITR hiện tại NOT VERIFIED; không khởi động DB chứa dữ liệu chỉ để audit.

## TLS, secrets và mạng

VERIFIED file metadata: leaf SAN service name/localhost, hết hạn **24/01/2027 14:32 GMT+7**; CA hết hạn 26/10/2027. CRL hiện tại chữ ký đúng, nextUpdate **11/11/2026 10:52:23 GMT+7**. Không phải handshake/CRL availability live. Private CA và endpoint localhost chưa phù hợp browser Internet mặc định; cần domain/PKI/renewal/expiry alerts riêng. Không thay truststore.

Core network internal, DB/Redis không publish; chỉ Gateway/Keycloak/CRL nối edge, ba cổng host bind loopback. Gateway→frontend HTTP cần quyết định threat model, không mang bearer/cookie nhưng có nội dung công khai; multi-server phải bảo vệ link. Các app chính non-root; filesystem/capability/resource hardening chưa đồng đều.

Runtime ngoài Git, ACL root runtime/backup giới hạn operator/SYSTEM/Administrators. Scan giới hạn **1.186 reachable text blobs**, 60 candidate chủ yếu fixture/nhãn/expression; chưa xác nhận token/private key thật bị commit qua các mẫu đó. Không thay Gitleaks; binary keystore/unreachable refs/CI logs/image layers chưa quét đầy đủ. Không tuyên bố secrets toàn hệ thống PASS. Backup tar.gz chứa runtime/authority private material nhưng script chưa mã hóa.

## Backup, reliability và observability

[Restore 04/11](../operations/RESTORE_VERIFICATION_REPORT.md) xác minh archive/hash/readability; School/Risk và Redis keyspace rỗng đối chiếu đạt. Keycloak schema khớp, JGROUPS_PING/SERVER_CONFIG checksum khác. JGROUPS_PING 0 row ở restore/1 row khi DB chạy phù hợp JDBC discovery; không chứng minh thời điểm thay đổi. SERVER_CONFIG chưa xác định nguyên nhân vì không có snapshot/checksum tại backup. Không sửa DB để khớp.

Chưa phục hồi full app/realm/MFA/signing keys/token issuance/flow/TLS/service accounts. CRL backup nextUpdate **06/11/2026 09:30:48 GMT+7**, hết hạn sau mốc đó dù CRL Lab mới hơn. Không mở restored stack với CRL cũ chưa xử lý theo quy trình PKI.

10 restart policies đều `no`. Backend probe chỉ đòi /api/students/me trả 401, không kiểm query/DB; Gateway probe trang / không chứng minh API. Risk health không chứng minh end-to-end login. Rotation log 5 MiB ×2 không phải retention theo ngày. Chưa có alert routing/JVM/DB/Redis monitoring/audit bất biến. Observatory có correlation/evaluation + D/N/T/H nhưng là công cụ thực nghiệm, không thay monitoring Production.

## Hiệu năng đã đo

Microbenchmark đúng RiskScoringService B0, warmup 100.000, 1.000.000 operation/mức concurrency, network none/2 CPU/512 MiB/heap tối đa 256 MiB. [JSONL](evidence/scoring-microbenchmark.jsonl).

| Concurrency | Duration | p50 | p95 | p99 | Error | CPU time / GC time | Heap sau đo |
|---:|---:|---:|---:|---:|---:|---|---:|
| 1 | 468,141 ms | 0,263 µs | 0,451 µs | 0,754 µs | 0/1.000.000 | 690 / 50 ms | 30,54 MB |
| 4 | 778,270 ms | 0,945 µs | 2,734 µs | 14,870 µs | 0/1.000.000 | 1.590 / 34 ms | 48,57 MB |

Mẫu ngắn, một JVM, có JIT/UUID/clock/shared sink, không phải JMH/CI thống kê. Không HTTP/JWT/TLS/feature I/O/DB/Redis/MMDB/MFA. Full evaluation/login/API/query latency, timeout rate, pool saturation, peak RSS **NOT VERIFIED**. Không suy ra concurrent users/RPS/SLO. [Performance gate](PRODUCTION_ACCEPTANCE_CHECKLIST.md#performance-gate).

## Production readiness scorecard

| Hạng mục | Status | Evidence | Blocker | Action |
|---|---|---|---|---|
| Architecture | SOURCE REVIEWED; target NOT VERIFIED | E01/E09 | Có điều kiện | Chọn A/B, SPOF budget |
| Authentication | TEST/HISTORICAL VERIFIED; prod NOT VERIFIED | E04/E10 | Có | PR-012 realm/SSO/MFA policy |
| Authorization | TEST/HISTORICAL VERIFIED | E04/E10 | Runtime gate | Hai role trên release đích |
| API Security | FAIL | E09 | Có | PR-001/004 |
| Risk Scoring | TEST VERIFIED; policy SOURCE REVIEWED | E04/E11 | Có | IP boundary/B0 approval |
| TLS/PKI | VERIFIED files; prod NOT VERIFIED | E12 | Có | Domain/PKI/renewal |
| Secrets | VERIFIED placement; full scan NOT VERIFIED | E13 | Có | Secret/backup protection |
| Database | TEST VERIFIED H2/historical restore | E04/E07/E14 | Có | PR-005/011 |
| Redis | TEST VERIFIED Lua; durability NOT VERIFIED | E08/E12 | Có | PR-014 sizing/recovery |
| Backup/Restore | HISTORICAL VERIFIED DB; DR NOT VERIFIED | E14 | Có | PR-006/007 |
| Performance | TEST VERIFIED micro; E2E NOT VERIFIED | E15 | Có | PR-013 load gate |
| Reliability | FAIL | E01/E09 | Có | PR-008 probes/restart |
| Monitoring | FAIL readiness | E09/E11 | Có | PR-009 alerts/audit |
| Docker | VERIFIED metadata/checks; CVE NOT VERIFIED | E01/E03/E06 | Có | PR-001/008/016 |
| CI/CD | FAIL release gate; historical CI success | E02/E09 | Có | PR-010 |
| Deployment | NOT VERIFIED | Chưa có target | Có | Deployment plan |
| Rollback | SOURCE REVIEWED; execution NOT VERIFIED | E03/E14 | Có | App/schema rehearsal |
| Documentation | SOURCE REVIEWED; có đoạn lịch sử lỗi thời | E09/E10 | Không riêng lẻ | PR-018 |

## Điều kiện tiếp tục

Sửa dependency và stale edit trước; khóa cấu hình/domain/proxy/realm; bổ sung limits, migration, secrets/backup, restart/probes/alerts; nghiệm thu staging bằng đúng image digest sẽ phát hành. [Kiến trúc](PRODUCTION_ARCHITECTURE.md) khuyến nghị Compose một Linux server khi quy mô nhỏ và chấp nhận downtime; multi-server nếu cần tiếp tục phục vụ lúc hỏng host.

[Deployment](PRODUCTION_DEPLOYMENT_PLAN.md), [operations](PRODUCTION_OPERATIONS_RUNBOOK.md), [rollback](PRODUCTION_ROLLBACK_PLAN.md) và [acceptance](PRODUCTION_ACCEPTANCE_CHECKLIST.md) là đề xuất chưa triển khai. **Không nên Production ngay: phải đóng các gate G1–G8 trong [GO/NO-GO](PRODUCTION_GO_NO_GO.md).**
