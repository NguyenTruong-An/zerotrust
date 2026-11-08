# Production Go / No-Go Decision

**Ngày quyết định:** 06/11/2026, Asia/Saigon. **Baseline:** `c401e17029d64f9a96738d845b8c0ad0f03fc164`, branch zerotrust-v4-risk-scoring. **OVERALL VERDICT: NO-GO.** Đây là đánh giá hiện trạng, không phê duyệt triển khai.

| Phạm vi | Kết luận | Căn cứ |
|---|---|---|
| DEVELOPMENT READY | Có cơ sở: TEST VERIFIED | Bốn Java module verify đạt1.136 ca,123skip; frontend/tooling checks đạt |
| LAB / DEMO READY | Có bằng chứng lịch sử, hiện cần preflight/start/acceptance theo runbook | Audit thấy10container stopped, không chạy Browser hôm nay; historical healthy/login không thành live PASS |
| Application production readiness | **NO-GO** | Dependency risk/patch gate, stale grade write tái hiện, thiếu abuse limits/prod config/grade audit |
| Infrastructure production readiness | **NOT VERIFIED / INSUFFICIENT EVIDENCE** | Chưa provider/domain/workload/realm/security network/SLO/recovery target được chốt |
| Overall deployment readiness | **NO-GO** | Có thiếu hụt xác nhận và nhiều acceptance gates bắt buộc còn mở |

Không có cơ sở định lượng để chấm Production Readiness Score0–100. Không dùng trung bình/test ratio che blocker. Không có P0 exploit mới được xác minh; P1 blockers vẫn đủ để dừng go-live. [Report](PRODUCTION_READINESS_REPORT.md), [security](SECURITY_AUDIT.md), [evidence](EVIDENCE_REGISTER.md).

## Top 10 risks

1. **PR-001:** Next16.2.6/sharp0.34.5 và Java runtime dependencies có advisory matches, có upstream Critical; all-image OS/JDK/Keycloak scan chưa hoàn tất. Điều kiện khai thác phải triage từng advisory, chưa xác nhận mọi CVE là exploitable.
2. **PR-005:** Hai ADMIN dùng form cũ có thể ghi đè điểm mới; H2 harness đã tái hiện, @Version không đi qua API.
3. **PR-003/012:** Localhost/private CA/issuer và canonical-IP proxy contract chưa chuyển sang domain/realm Production; SSO/refresh/old-token/fresh-admin-MFA policy chưa chốt.
4. **PR-002/004:** Profile prod còn kế thừa unsafe DB defaults; Gateway chưa có rate limit/hard body-size enforcement.
5. **PR-006:** Backup chứa DB/secrets/authority private material trong tar.gz chưa mã hóa; encrypted offsite/key escrow chưa chứng minh.
6. **PR-007:** Mới restore DB; full app/realm/MFA/signing/TLS/service accounts/DR và rollback execution chưa nghiệm thu; SERVER_CONFIG khác checksum chưa có nguyên nhân đủ bằng chứng.
7. **PR-008/009:** Restart=no và probes yếu; thiếu alerting/on-call/monitoring Production, fail-closed có thể khiến toàn bộ login ngừng khi dependency lỗi.
8. **PR-010/011:** HEAD ahead3 chưa CI trên GitHub; School9.1/manual migration, Risk V5 Java hard-pin MySQL8.0.46/bytecode checksum và đường nâng cấp chưa chốt.
9. **PR-013/014/017:** Không có end-to-end load/failure capacity evidence; Redis memory/durability và synchronous best-effort event loss có thể ảnh hưởng security signals/availability.
10. **PR-015:** Chưa có audit chỉnh điểm theo actor/change và retention/purge thực thi cho history/security metadata.

## Điều kiện chính xác trước triển khai

| Gate | Bắt buộc hoàn thành | Bằng chứng đóng |
|---|---|---|
| **G1** Release | Patch/triage applicable advisories, image/dependency/secret scans + SBOM, exact SHA CI/review và immutable registry images | CI URL/SHA, scan scope/date/waivers, provenance+digests, N-1 pull |
| **G2** Infrastructure/config | Chọn A/B/target/domain, fail-fast prod config, network/admin isolation, trusted client IP, TLS/renewal và fresh secrets | Manifest/config/realm references; reachability/proxy/TLS/escrow tests |
| **G3** Auth/security | Approve B0 unchanged/scope, realm lockout/PKCE/redirect/service grants/session TTL/SSO/refresh/fresh admin MFA, actual Browser negative tests | Exact release/realm/domain auth + JWT/RBAC/ownership/trust/reset matrix |
| **G4** Data | Fix stale edit xuyên API/UI/batch; MySQL engine/migration/grants; Redis loss/memory; grade audit và retention | Serial+overlap MySQL conflict tests, ledger/schema/EXPLAIN, Redis persistence tests, audit/purge proof |
| **G5** Capacity | Chốt workload/SLO rồi đo HTTP Risk/login/API/DB với normal/burst/concurrency/failure/soak | Request count/concurrency/duration/p50-p95-p99/errors/timeouts/resources, approved envelope |
| **G6** Operations | Restart/readiness/drain/reconnect; essential monitoring/log retention/alert delivery/on-call | Process/host/dependency failure drills, trigger→notification→ack evidence |
| **G7** Recovery | Encrypted offsite+separate key/image recovery; full stack restore + app/data rollback; reconcile old security state | Actual recovered app/MFA/data/TLS; measured RPO/RTO; no resurrection of revoked trust |
| **G8** Release decision | Owners ký scope/cohort/residual risks, maintenance/cutover/support/rollback packet | Signed go/no-go/change record và operator handover |

Chi tiết kiểm thử từng gate: [acceptance checklist](PRODUCTION_ACCEPTANCE_CHECKLIST.md). Cách thực hiện: [25 bước deployment](PRODUCTION_DEPLOYMENT_PLAN.md), [runbook](PRODUCTION_OPERATIONS_RUNBOOK.md), [rollback](PRODUCTION_ROLLBACK_PLAN.md). Tài liệu không tự đóng gate.

## Kiến trúc khuyến nghị có điều kiện

[A — một Linux server Compose](PRODUCTION_ARCHITECTURE.md) khoảng8vCPU/16GiB/200–250GB là sizing để nghiệm thu cho cohort nhỏ, chấp nhận SPOF/downtime; fresh secrets/PKI/data, ingress443, private data network, encrypted offsite backup/monitoring bắt buộc. RPO24h/RTO4h chỉ phù hợp khi chủ dữ liệu chấp thuận; grade system cần RPO15m phải có PITR hoặc kiến trúc B và diễn tập phù hợp. Không gọi A là HA.

B dùng LB + app replicas + data replication/managed HA, private TLS/secret/backup/monitoring. Chỉ tách hai host app/data chưa HA. Không mặc định Kubernetes. Budget2–4triệu/tháng A và6–15triệu/tháng B trong tài liệu là **planning envelope nội bộ, chưa phải báo giá**, không gồm nhân công và tùy region/HA/egress.

## Các quyết định chủ hệ thống cần chốt

1. Production thử nghiệm giới hạn hay sổ điểm chính thức? Ai sở hữu dữ liệu và được phép chuyển những dữ liệu nào?
2. Số tài khoản/active sessions, peak/burst/login/enrollment/write traffic, mùa cao điểm và growth?
3. Domain/provider/region/hạ tầng Linux A/B, budget compute/backup/monitoring/nhân sự và chấp nhận SPOF?
4. SLO/maintenance/error budget và **RPO/RTO được chấp nhận**, thời gian mất điểm/credentials tối đa?
5. Tạo realm/users/keys mới (khuyến nghị) hay migrate có kiểm soát? Crosswalk UUID, user re-login/MFA enrollment, quyền dùng Lab data và key handling?
6. B0 Production scope, network/GeoIP/NAT/missing-data policy; token/session TTL/old-token revocation và fresh MFA cho ADMIN sensitive actions?
7. Operator/on-call/data/security/release owners; access/admin VPN, secret/PKI/offsite key custody?
8. Retention/privacy/audit/GeoLite update/license; scan/waiver và patch/release cadence?

**Trả lời cuối cùng:** Với hiện trạng và bằng chứng đã kiểm chứng, **không nên triển khai Production ngay bây giờ**. Dự án đủ nền tảng phát triển và có nghiệm thu Lab đáng kể, nhưng phải khắc phục các vấn đề cụ thể và hoàn thành G1–G8 trước khi mở dữ liệu/người dùng thật. Sau đó mới đánh giá lại GO hoặc CONDITIONAL GO theo một target, workload và mức vận hành cụ thể. Không có triển khai Production nào được thực hiện trong nhiệm vụ audit này.
