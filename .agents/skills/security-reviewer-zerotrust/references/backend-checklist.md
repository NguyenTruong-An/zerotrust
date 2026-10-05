# Checklist bảo mật backend

Chọn mục theo phạm vi review; các mục là câu hỏi kiểm tra, không khẳng định mọi biện pháp đã triển khai.

## Portal API và Spring Security

- JWT: đọc [SecurityConfig](../../../../src/main/java/com/zerotrust/zerotrust/config/SecurityConfig.java), converter/validator lân cận; xác minh chữ ký, issuer, audience, thời hạn và realm role. Authentication giả lập trong MockMvc không chứng minh decoder từ chối token giả.
- Authorization: ADMIN/STUDENT ở path/method, subject từ security context, quyền sở hữu, trạng thái hồ sơ, DTO/mass assignment và pagination. Thay ID không được chuyển quyền sang sinh viên khác.
- Theo [login contract](../../../../docs/authentication/LOGIN_FLOW.md): Code + PKCE S256, không browser secret hoặc token trong persistent browser storage; Portal stateless. Đánh giá CORS/CSRF theo cách mang credential thật, không áp cookie session như mặc định.
- JPA: binding tham số, giới hạn input/response, lazy fetch trong transaction. Remote identity update và DB không có transaction phân tán; kiểm tra partial success/timeout và compensation theo đường gọi.

## Risk API và service identity

Đọc [RiskApiSecurityConfig](../../../../risk-scoring-service/src/main/java/com/zerotrust/risk/config/RiskApiSecurityConfig.java), converter cùng module và [Risk security contract](../../../../docs/security/RISK_API_SECURITY.md).

| Caller / azp | POST endpoint | Client role dưới zerotrust-risk-api |
|---|---|---|
| zerotrust-risk-caller | /internal/v1/risk/evaluations | risk:evaluate |
| zerotrust-risk-caller | /internal/v1/trusted-devices | risk:device:write |
| zerotrust-risk-caller | /internal/v1/authentication-failures và authentication-successes | risk:events:write |
| zerotrust-portal-risk-admin | /internal/v1/subjects/{subjectId}/trusted-devices/revocations và /completion | risk:device:revoke |

Kiểm tra chữ ký/JWKS, iss, exp/nbf, aud và tổ hợp azp + role. Role cùng tên nhưng sai client/realm không cấp quyền. JWT sai/thiếu trả 401; JWT hợp lệ nhưng sai caller/role trả 403. Kiểm tra denied path/method, HTTPS và proxy header đáng tin. Không áp risk-caller lên revocation hoặc ngược lại; provisioner/SPA không thay thế hai identity này.

## Risk, SPI, MFA và device trust

- Trace RiskEvaluationService → feature extractor/scoring, RiskAuthenticator → RiskDecisionHandler → RiskStepUpCondition → TrustedDeviceRegistrationAuthenticator. Priority deny trước scoring, thiếu feature/cold-start không thành LOW, mandatory MFA không bị score thấp bỏ qua.
- Risk outage: đọc failureMode; DENY khác fallback STEP_UP_MFA. Fallback không tạo TRUST_DEVICE_ELIGIBLE; không tạo trust từ quyết định giả.
- Browser Flow phải chạy Risk đúng entrypoint và MFA trước registration. CONFIGURE_TOTP chưa phải bằng chứng OTP thành công; recovery branch cần kiểm chứng riêng. Không suy ra live flow từ code authenticator/tên test.
- Cookie chỉ là định danh: realm scope, entropy, HttpOnly/SameSite/Secure theo môi trường, HMAC thay raw identifier trong DB, expiry server-side, status/revocation và rotation. Cookie tồn tại không chứng minh trust/MFA.
- Registration echo trustGeneration; Risk khóa cùng subject với revocation tới transaction commit. Lỗi/409 không issue cookie mới. Login hiện tại sau MFA và trust tương lai cần phân tích riêng.
- Event listener failure không đổi auth result. Failure dedup/counter TTL dùng Redis Lua; successful event có eventId uniqueness. Kiểm tra realm/client, thiếu subject, clock và data exposure; mock không chứng minh atomic Lua.

## Reset MFA qua Portal, Risk, Keycloak

Đọc [reset contract](../../../../docs/authentication/MFA_RESET_LIFECYCLE.md), [UserServiceImpl](../../../../src/main/java/com/zerotrust/zerotrust/service/impl/UserServiceImpl.java), [DeviceTrustLifecycle](../../../../risk-scoring-service/src/main/java/com/zerotrust/risk/service/DeviceTrustLifecycle.java) và clients liên quan.

- Revoke/increment generation/pending → Keycloak reset OTP/recovery + enrollment + logout → completion. Chỉ báo thành công khi xác nhận completion; subject Keycloak khác Portal user ID.
- OperationId gắn đúng subject/requester; reset cũ không complete reset mới. Pending chặn evaluation/registration; generation fence attempt MFA cũ dù gửi ID mới.
- Timeout có thể sau remote commit; giữ partial/reset-pending thay vì khẳng định rollback. Không tự xóa pending để khôi phục login.
- Explicit security revoke là DENY; expired/MFA-reset device yêu cầu MFA và ID mới. Xóa cookie không bypass MFA.
- Reset/logout không vô hiệu ngay mọi token đã phát. Kiểm tra SSO/refresh bỏ qua Risk; bảo đảm mới là khoảng trống/đề xuất, không suy ra đã có.

## Dữ liệu/vận hành khi liên quan

Theo [DATA_PRIVACY.md](../../../../docs/security/DATA_PRIVACY.md), kiểm tra raw IP/device ID/secret/token ở storage và lỗi/log, HMAC key và retention. GeoIP mmdb local với CIDR precedence, không remote lookup theo request. Canonical issuer/TLS/network isolation cần bằng chứng deployment; compose local không phải toàn bộ topology production.
