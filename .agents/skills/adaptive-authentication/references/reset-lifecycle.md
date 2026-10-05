# Reset MFA và trust lifecycle

Đọc [MFA_RESET_LIFECYCLE.md](../../../../docs/authentication/MFA_RESET_LIFECYCLE.md), UserServiceImpl, RiskDeviceAdminClient, DeviceTrustLifecycle, registration service và V4 trong [source-map](source-map.md). Rollout trong tài liệu không chứng minh realm đã provision.

## Contract reset

Portal yêu cầu ADMIN/kiểm tra hồ sơ; resolve Portal user ID sang Keycloak subject, requester từ auth context và operation UUID. Không dùng Portal DB ID trong path subjectId.

1. Portal identity riêng zerotrust-portal-risk-admin gọi POST /internal/v1/subjects/{subjectId}/trusted-devices/revocations với risk:device:revoke.
2. Risk khóa subject, tăng generation, revoke devices qua entity lifecycle, ghi audit operation và mark pending trong transaction.
3. Portal gọi IdentityProviderGateway reset OTP/recovery, set enrollment actions, logout Keycloak sessions.
4. Portal gọi path thêm /completion cùng operationId/requestedBy. Chỉ báo thành công sau completion 204.

SPA/provisioner/risk-caller không revoke/complete. Không dùng chung secret chữa 403. Giữ JWT validation, khác azp/role của evaluation; code provisioning không chứng minh realm thực đã cấp quyền.

## Lỗi từng bước

| Giai đoạn | Contract/tác động |
|---|---|
| Không xác nhận revoke | RISK_DEVICE_REVOCATION_FAILED, không Keycloak reset; timeout có thể đã commit Risk |
| Revoke xong, Keycloak reset lỗi | MFA_RESET_PARTIAL, pending có thể chặn login, không báo thành công |
| Keycloak xong, completion chưa xác nhận | MFA_RESET_COMPLETION_PENDING, visible error và retry sau khôi phục |
| Operation sai subject/requester hoặc completion cũ superseded | Từ chối, không complete reset khác |

DB transaction không rollback remote side effect. Không xóa pending/giảm generation/phục hồi cookie cũ để chữa partial failure. Cùng operation ở tầng HTTP giữ idempotency; manual reset mới tạo operation mới. Giữ lỗi visible và correlation ID không secrets.

## Generation và trạng thái

- requireGeneration với transaction MANDATORY khóa subject như revoke tới commit registration. Đọc FOR UPDATE/INSERT IGNORE và engine; H2 không chứng minh mọi semantics MySQL.
- SPI echo generation từ evaluation. Attempt MFA trước reset không re-trust sau reset dù dùng ID mới; generation cũ bị 409.
- Pending reset chặn evaluation/registration. Guarantee login bị chặn phụ thuộc Risk được gọi và outage policy; fallback MFA khi Risk lỗi không bảo đảm pending block, DENY phù hợp nếu cần chặn outage.
- Server trust expiry 30 ngày theo code hiện tại. Expired/MFA-reset device cần MFA và ID mới; security-revoked vẫn DENY. Missing/new/pending ID cũng cần MFA, xóa cookie không bypass.
- CONFIGURE_TOTP pending không tạo trust; subsequent MFA login sau enrollment có thể tạo.
- Reset/logout không vô hiệu ngay mọi token đã phát; SSO/refresh bỏ qua Risk và fresh admin MFA là các biên cần xem riêng.

## Kiểm chứng theo hành vi

- UserServiceImplTest/RiskDeviceAdminClientTest: revoke → Keycloak → complete, dừng bước sau khi lỗi, visible partial/completion error, 204/retry.
- DeviceTrustLifecycleTests/registration service tests: stale generation/pending, subject/requester, idempotency, completion cũ, race và security revoke không re-trust.
- SPI registration/RiskDecisionHandler tests: generation, rotation, enrollment pending, no fallback trust, 409 không issue cookie.
- Staging nếu được yêu cầu: MySQL/Flyway V4, providers/Browser Flow thật, identity provisioning, reset/reenroll/OTP/recovery, old cookie/session/token và attempt MFA pause trước reset. Không tự backup/rollout chỉ vì đọc skill.

Nêu test thực chạy và giới hạn H2/mock. Chỉ phân tích thì đưa kịch bản kiểm chứng, không khẳng định đã chạy.
