# Production Rollback & Recovery Plan

**06/11/2026 — Proposed, chưa thực hiện rollback Production. c401e17 hiện NO-GO.** [Deployment](PRODUCTION_DEPLOYMENT_PLAN.md), [operations](PRODUCTION_OPERATIONS_RUNBOOK.md), [restore baseline](../operations/RESTORE_VERIFICATION_REPORT.md), [acceptance](PRODUCTION_ACCEPTANCE_CHECKLIST.md).

## Đầu vào bắt buộc

Release N/N-1 immutable image digests và registry/offsite access; configuration/realm/PKI references có version; schema/migration compatibility matrix; pre-change encrypted full backup + binlog/recovery checkpoint; secret/key escrow; operator/data/security owners; rollback window/traffic cohort, write-freeze và reconciliation plan. Chưa có các assets Production nên execution NOT VERIFIED.

Build manifest/source hash hoặc local image ID không tự chứng minh có thể phục hồi trên máy mới. `docker compose down -v`, xóa/reuse canonical Lab volumes, raw DB downgrade, nhập realm đè users và nới security không nằm trong kế hoạch.

## Trigger và quyền quyết định

Đóng traffic hoặc writes ngay khi có unauthorized data access/MFA bypass/trust invariant sai, grade mất/corrupt, issuer/SAN/cert mismatch, schema migration sai/checksum bất thường, image/SHA sai release hoặc secret exposure. Security/data owner quyết định containment và recovery branch; operator thực hiện release packet cụ thể.

Latency/error/capacity trigger theo SLO đã duyệt + so baseline/control cohort, chưa có ngưỡng số được chấp thuận trong audit. Service restart không hồi phục sau dependency repair hoặc monitoring mất essential visibility cũng dừng rollout. Không chờ p95 vượt ngưỡng nếu đã có vi phạm bảo mật/toàn vẹn dữ liệu.

## Chọn đúng nhánh

| Trạng thái | Nhánh an toàn | Không làm |
|---|---|---|
| Chỉ đổi app/config; schema compatible N-1 | Rollback app digest/config chọn lọc, giữ data hiện tại | Restore DB cũ làm mất writes mới |
| Migration additive được thử backward compatible | N-1 app với schema mới nếu acceptance đã chứng minh | Tự drop cột/index để giống schema cũ |
| Migration destructive hoặc Keycloak schema không compatible | Freeze writes, forward fix nếu an toàn hoặc full restore checkpoint trên volumes mới | Chạy binary cũ trên schema/datadir mới |
| Dữ liệu sai/corrupt | Data recovery/PITR/transaction correction do data owner duyệt | Chỉ rollback app rồi gọi data recovered |
| Secret/key bị lộ | Incident rotation/revocation + recovery, đánh giá N-1 có cùng secret không | Revert secret version đã bị lộ |
| Host/data services mất | Disaster restore full stack từ offsite | Tạo empty DB rồi mở traffic vì health xanh |

## Quy trình rollback app

1. **Freeze rollout:** đưa ingress về maintenance/cohort cũ; chặn writes nếu có nghi ngờ dữ liệu. Ghi giờ/last accepted transaction và stop condition. Giữ logs/audit/correlation riêng, không dump credentials.
2. **Đối chiếu packet:** N-1 digest/config/realm compatibility, signed scan/acceptance, DB version/ledger hiện tại. Thiếu compatibility proof → chuyển recovery/forward-fix, không đoán.
3. **Bảo toàn trạng thái:** checkpoint dữ liệu mới/encrypted snapshot nếu an toàn, giữ immutable logs; xác định changes sau pre-release backup. Không xóa artifacts N để “dọn lỗi”.
4. **Thay app có chọn lọc:** operator dùng manifest Production đã review, đúng project/service list, N-1 digests, no dependency recreation ngoài scope. DB/Redis/Keycloak chỉ thay nếu release packet nêu rõ; static SPA build args phải khớp domain.
5. **Khởi động/drain:** chờ dependency readiness và TLS/JWKS, kiểm synthetic API + login/MFA/roles/grade version/audit. Risk giữ B0/guards/failureMode đã duyệt, không bypass để chữa timeout.
6. **Canary mở lại:** chỉ sau functional/security checks, theo traffic/rate envelope đã nghiệm thu. Monitor errors/latency/deny/event loss/pools, giữ khả năng stop.
7. **Chốt:** owner ghi outcome/actual downtime/data loss/rollback digest và follow-ups. Không gọi successful app restart là successful data recovery.

## Full data/application recovery

1. Đóng ingress/writers và cô lập suspect host; lập recovery point bằng full backup/binlog position + key/config/image inventory. Data owner chấp nhận RPO cụ thể; không chỉ dùng thời gian tên file.
2. Chuẩn bị host/project/networks/volumes **mới**, không canonical Lab hoặc production volumes cũ. Giải mã qua escrow riêng, kiểm SHA256/cỡ/archive members; ảnh/key/config có sẵn ngoài host mất.
3. Dùng đúng compatible MySQL version cho physical restore; School9.1 không mount vào8.4. Logical conversion chỉ theo rehearsed plan. Redis restore thử nonempty keys/TTL/AOF, không chỉ PONG/keyspace empty.
4. Kiểm schema/ledger/row consistency/academic identity crosswalk/credential metadata. JGROUPS_PING là discovery động, có thể thay khi nodes boot; SERVER_CONFIG không được mặc định vô hại nếu chưa có witness. Không UPDATE để checksum giống.
5. Restore runtime/secrets/realm/PKI đúng recovery point. Kiểm SAN/chain/clock/CRL; CRL trong backup Lab cũ hết hạn 06/11/2026 09:30:48 GMT+7, không đủ mở restored stack. CA private material chỉ operator PKI được duyệt sử dụng.
6. **Reconcile security state:** đối chiếu MFA resets, user disable/role change/session invalidations/device security revocations sau backup với offsite audit. Khôi phục snapshot cũ có thể làm trust generation/credentials lùi và cho cookie/token cũ hoạt động. Giữ ingress đóng cho tới khi reconcile/invalidate sessions/trust và force reauth/enrollment theo quy trình được phê duyệt. Không giảm generation/clear pending tùy tiện. Nếu không có audit đủ, cần security owner chọn conservative recovery scope và chấp nhận data loss, không tự báo PASS.
7. Start data → migration validation → Keycloak → Risk → Portal/SPA → Gateway, kiểm cluster/session nếu B. Production images mới do operator chọn, không dùng synthetic demo seed/import job.
8. Nghiệm thu full application: Code+PKCE, password/MFA/recovery/SSO/refresh boundary, service caller negatives, ADMIN/STUDENT/ownership, grade conflict/audit, trace, backup/alert/restart. Dùng synthetic fixture, không đăng nhập hàng loạt người thật.
9. Đo RTO từ declaration/detection đến accepted service và RPO từ last recoverable transaction; báo actual vs target, gồm thời gian lấy keys/images/DNS. Chỉ promote sau data/security/release owners ký.
10. Giữ nguồn cũ và recovery evidence để điều tra; chuyển traffic có kế hoạch DNS/LB, mở writes sau reconciliation. Không tự xóa volumes/backups/images.

## Nghiệm thu diễn tập trước go-live

- App rollback N→N-1 giữ data mới, schema compatibility được chứng minh.
- Full restore từ **encrypted offsite** trên fresh host/volumes, operator dự phòng lấy được key/image/config.
- Nonempty Redis + real MySQL + Keycloak realm/credentials/MFA/signing/JWKS/TLS/service account functioning, không chỉ DB checksum.
- Restore mất một phần state bảo mật không làm old revoked cookie/session/token được chấp nhận trái policy.
- Failures giữa remote commit/timeout của MFA reset không bị “rollback” giả; pending/operation owner đúng.
- Actual RPO/RTO, reconciliation deltas và observed downtime được ghi, không lấy estimated duration làm PASS.

**Hiện trạng:** DB restore lịch sử đạt một phần; app rollback/config đọc được, nhưng full execution/DR readiness chưa kiểm chứng. Gate PR-007 còn mở.
