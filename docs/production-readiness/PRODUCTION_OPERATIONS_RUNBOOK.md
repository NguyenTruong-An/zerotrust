# Production Operations Runbook

**06/11/2026 — Proposed; chưa có Production runtime. Baseline c401e17 NO-GO.** Chỉ áp dụng sau [deployment/acceptance](PRODUCTION_DEPLOYMENT_PLAN.md). Lab hiện đang dừng; các script `zt.py`, `backup.py`, `renew-crl` hiện ràng buộc Lab, **không dùng nguyên lệnh đó cho Production**. [Architecture](PRODUCTION_ARCHITECTURE.md), [rollback](PRODUCTION_ROLLBACK_PLAN.md), [findings](SECURITY_AUDIT.md).

## Hồ sơ vận hành bắt buộc

Trước mở traffic, ghi project/environment, public/internal endpoints, DNS/issuer/realm, host/region/fault domains, release SHA/digests/config hash/schema version, data volumes, secret references/rotation owner, backup checkpoint/escrow, monitoring links và primary/backup operator. Chưa có các giá trị Production trong audit nên các mục này NOT VERIFIED; không thay bằng paths/keys của Lab.

| Vai trò vận hành | Trách nhiệm |
|---|---|
| Release owner | Freeze/promote/approve, quyết định rollback cùng data owner |
| Security/identity owner | Realm/service grants/PKI, incident credentials/trust/token |
| Data owner/DB operator | Schema, backup/PITR/reconciliation, khôi phục data |
| On-call + người dự phòng | Nhận alert, triage, handover và ghi timeline |

Đây là trách nhiệm người vận hành, không thêm business role ngoài ADMIN/STUDENT. Admin console/metrics/DB/backup access qua private/VPN/allowlist, tách người quản trị release và người duyệt dữ liệu theo năng lực đội.

## Kiểm tra hằng ngày và trước thay đổi

1. Kiểm metadata chọn lọc: service running/ready, digest đúng release, restart/OOM/CPU/RSS/heap/GC, disk/inodes, volume/network đúng prod. Không dump `Config.Env`, private config hoặc Compose render có secret vào ticket.
2. TLS chain/hostname và discovery/JWKS từ ngoài ingress; kiểm certificate/CRL nextUpdate và renewal job. HTTP200 của CRL không đủ, kiểm chữ ký/freshness. Không cài private CA Root vào máy người dùng để chữa public TLS.
3. Readiness có dependency proof: DB SELECT1/connection budget, Redis authenticated TLS PING/persistence, API read-only fixture. Backend401 và homepage200 hiện tại chỉ là liveness/routing evidence; chưa có endpoint readiness đầy đủ trong baseline.
4. Check backup encryption/offsite age, job status, binlog coverage nếu dùng PITR, escrow/image availability; không chỉ thấy file tar.gz là PASS.
5. Xem latency/error/timeout/deny/pending-reset và event-delivery loss. Chỉ dùng synthetic users cho probe được duyệt, không chạy hàng loạt password/MFA login thật làm healthcheck.

## Monitoring tối thiểu và ngưỡng đề xuất

Các ngưỡng sau là **đề xuất khởi đầu cần tune/approve**, không phải SLA đã được chấp thuận.

| Tín hiệu | Thu thập/alert | Hành động |
|---|---|---|
| Public availability | HTTPS/discovery/JWKS probe, dependency-ready vs process-alive riêng | Đối chiếu last change, TLS/network/app trước restart |
| Latency/errors | HTTP p50/p95/p99, 4xx/5xx, timeout theo service/endpoint; so approved SLO và baseline | Kiểm pool wait/DB/Redis/JWKS/token endpoint, traffic/rate limits |
| Authentication | Risk unavailable, INCOMPLETE, DENY/STEP_UP ratio, OTP failures, reset pending, event-send errors | Phân biệt abuse/policy/data missing/availability; không đổi failureMode |
| JVM | Heap/RSS, GC pause, thread count, active/queued requests, connection pools | Capture bounded diagnostics không chứa tokens; size/tune từ evidence |
| MySQL | Connections/threads/slow query/deadlock/replication lag/disk/binlog age | Không tăng maxConnections độc lập với app pools; phân tích query/index |
| Redis | Used/max memory, fragmentation, evicted keys/rejected writes/AOF/persistence/replication lag | Không FLUSHDB; giữ counter integrity và incomplete behavior |
| TLS/CRL | Leaf warning14ngày/critical7ngày; CRL warning48h/critical6h trước nextUpdate | Renewal theo PKI runbook, test freshness/end-to-end |
| Storage/backups | Disk warning70%/critical85% (tune theo growth), backup age/RPO, decrypt/restore-test age | Tăng capacity/quota, không xóa bản backup verified cuối |
| Security/audit | MFA reset/role change/grade conflict/grade change, unauthorized access attempts | Correlation, access-controlled incident trail; alert không lộ subject/token |

Có thể dùng Prometheus/Grafana + log backend hoặc hosted equivalent. Bắt buộc có nguồn đo/owner/notification và kiểm trigger→delivery→ack; dashboard đơn lẻ không đủ. Không public management ports, tránh userId/evaluationId thành metric labels tạo cardinality lớn.

## Theo dõi một lần đăng nhập

Lấy correlation/evaluation ID đã được allowlist, nối Risk details → SPI decision → MFA execution → registration204/cookie → LOGIN outcome; không ghép theo IP/user/time gần nhau. Ghi rõ SSO/refresh không có evaluation, unavailable không có score hợp lệ, challenge rendered chưa proof OTP thành công. D/N/T/H dùng snapshot lúc tính, không query lại để dựng lời giải khác.

Observatory file cục bộ có GeoIP metadata tổng hợp, không có raw IP/token nhưng vẫn nhạy cảm. Không host công khai, không đưa export private JSON vào Git/ticket public. Docker size rotation không phải retention thời gian. Policy retention/purge cho successful history, revoked devices, reset audit, grade audit, logs/exports và backups phải được data owner duyệt; job purge có dry-run/count/idempotency/last-success alert, giữ legal/incident hold nếu đã được tổ chức xác định.

## Backup và recovery

- **Consistency:** nếu vẫn cold backup thì có maintenance window, stop writers theo thứ tự, xác nhận DB shutdown sạch, archive data/config/key metadata ở recovery point; downtime phải tính vào availability budget. Khi cần RPO15m dùng daily full + binlog liên tục/offsite, ghi chính xác vị trí/GTID và keycloak consistency; replication không thay backup.
- **Confidentiality:** mã hóa trước offsite, key ngoài host và quyền backup-read riêng restore-key. Manifest chứa SHA256/cỡ archive/image digests/schema/config references, không token/secret. Backup authority/signing/OTP material trong compartment kiểm soát chặt.
- **Retention đề xuất:** daily7 + weekly4 + monthly3 và ít nhất hai mốc đã full-restore-verified, điều chỉnh theo privacy/data owner và dung lượng; chưa phải policy được duyệt. Giữ immutable/offsite version và thử mất host. Không tự xóa archive/worktree/volume/image trong audit hoặc theo tuổi mà chưa có bản thay thế verified.
- **Rehearsal:** monthly full app restore hoặc sau schema/Keycloak/PKI major change; quarterly disaster drill có operator dự phòng. Đo detect→restore→acceptance RTO và last recoverable transaction RPO, kiểm cả encryption keys/registry availability. Không dùng file CRL cũ từ backup để mở traffic.
- **Recovery state:** restore Keycloak/Risk/School/Redis cùng checkpoint/known consistency; xác định sessions/device revocations/MFA resets phát sinh sau backup. Mất state bảo mật không được ngầm biến thành trusted/ALLOW. Giữ ingress/write closed cho tới reconciliation/force reauth/trust invalidation qua quy trình được duyệt.

## Xử lý sự cố

| Dấu hiệu | Xác minh an toàn | Xử lý | Điều kiện mở lại |
|---|---|---|---|
| Login bị DENY hàng loạt/TIMEOUT | Dependency latency, pool/JWKS/token/DB/Redis, Risk call timing; phân biệt priority DENY/unavailable | Rate-limit abuse, khôi phục dependency/revert release nếu phù hợp; giữ DENY, không tăng retry mù | Synthetic login/MFA + capacity và error trở về approved envelope |
| Redis unavailable/memory full | TLS/auth/rejected write/AOF/disk/lag, feature incomplete và event loss | Fix capacity/dependency theo contract; không FLUSHDB/đổi eviction mù | Nonempty counter/TTL behavior và history guard đúng |
| MySQL unavailable/migration lỗi | Digest/version/schema ledger/pool/TLS/disk, không đọc user rows ra log | Freeze writes, restore/recover trên volume mới hoặc forward fix; không hạ binary9.1→8.4 | Reconciliation/FK/schema/grade tests đạt |
| Keycloak unavailable | DB/cluster discovery/cert/JWKS/cache/management health riêng | Khôi phục process/node; app không mint JWT riêng hay bỏ issuer validation | Code+PKCE/MFA/roles/token issuance đúng |
| MFA reset pending | operationId/stage và remote outcome; timeout có thể sau commit | Reconcile đúng subject/requester/operation, dùng completion contract khi reset được chứng minh | Pending đóng đúng operation, stale generation không trust |
| Grade conflict/sai điểm | HTTP version409 + audit actor/change, không chỉ updated_at | Bảo toàn audit, không autosave overwrite; data owner duyệt correction mới | Corrected record/audit + regression proof |
| TLS/CRL expired | Chuỗi/SAN/signature/clock/nextUpdate, renewal failure | Cấp/gia hạn theo PKI procedure, giữ verify bật, kiểm all clients | Valid handshake/revocation và alert clear |
| Secret/token nghi lộ | Giữ evidence riêng, xác định phạm vi service/backup/access | Security owner revoke/rotate có kiểm soát, invalidate sessions/trust phù hợp; không chia sẻ giá trị | New refs/keys verified, old access rejected, incident accepted |
| Host mất/backup lỗi | Last encrypted offsite checkpoint/key/image access | Kích hoạt DR/rollback plan, thông báo downtime theo channel đã duyệt | Full acceptance + RPO/RTO thực đo được chấp nhận |

Không xóa pending flag/giảm generation/khôi phục cookie cũ để mở login. Không tắt TLS, audience, authorization hoặc MFA để xử lý sự cố. Dữ liệu restore có thể làm lùi revocations; phải reconcile trước cho old sessions/trusted device hoạt động.

## Patch/release định kỳ

Review advisory/dependency/base image theo cadence đã duyệt và sự kiện khẩn; lưu SBOM/scan date/applicability, cập nhật compatible train, staging, backup, rollout/rollback. Không `npm audit fix --force`, tag latest tự động hoặc pull/recreate toàn stack không có release packet. Keycloak signing key rotation và internal CA lifecycle cần drill JWKS overlap/cache/rollback; không rotate bất kỳ secret Lab nào trong audit.

Mỗi incident/release ghi timeline, SHA/digest/config/schema, symptom/evidence, owner, decision, recovery point, customer impact và follow-up; bản public chỉ tổng hợp/redacted. Đóng incident sau khi monitor và synthetic acceptance xác nhận, không chỉ process xanh.
