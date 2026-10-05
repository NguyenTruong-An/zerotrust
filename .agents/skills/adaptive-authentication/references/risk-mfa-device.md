# Risk → SPI → MFA → trusted device

Contract/điểm trace từ repository ngày 2026-10-05, xác nhận lại code/config qua [bản đồ nguồn](source-map.md). Tài liệu local cũ không là chứng cứ realm hiện tại.

## Risk evaluation

RiskEvaluationService chạy priority rules trước feature extraction/scoring. Feature extractor có thể thêm priority violation, dataStatus, mandatory step-up. Giữ thứ tự priority violation → dữ liệu không COMPLETE → mandatory step-up → scoring. Không bỏ INCOMPLETE hoặc coi fallback 0 của feature như số đo an toàn.

Bốn feature: device, network/location, temporal, authentication history. Implementation weighted score đã có, nhưng trọng số/ngưỡng chính thức còn mở trong ARCHITECTURE.md; giữ reasons/dataStatus/guardrails.

Missing/new/pending device yêu cầu MFA; trusted không bypass feature khác. Security-revoked là priority deny; expired/MFA-reset cần reauthentication/rotation, xem [lifecycle](reset-lifecycle.md). Network high-risk và history high-risk mandatory MFA; cold-start/unavailable dẫn INCOMPLETE/STEP_UP_MFA. Pending reset chặn trong evaluation contract: kiểm tra controller/lifecycle ngoài scoring.

GeoIP CIDR precedence và MaxMind mmdb local, trạng thái disabled/unavailable cần xử lý như contract hiện có. Không thêm external lookup trong login/persist raw IP để chữa feature. Temporal dựa successful-login events; failure counters không thay Keycloak password validation/lockout.

## SPI và quyết định

RiskAuthenticator thu context/gọi HTTP; RiskDecisionHandler ghi auth notes; RiskStepUpCondition đọc STEP_UP_REQUIRED. ALLOW qua bước Risk, STEP_UP đánh dấu để flow thực chạy MFA, DENY thất bại auth. context.success() của bước Risk không chứng minh login/MFA hoàn tất.

| Tình huống | Hành vi cần giữ |
|---|---|
| STEP_UP hợp lệ + trustGeneration hợp lệ | Đủ điều kiện registration sau MFA, giữ evaluator config ID/generation |
| Risk unavailable + DENY | Chặn login |
| Risk unavailable + fallback STEP_UP_MFA | MFA nhưng không tạo trust eligibility/generation từ quyết định giả |
| Lỗi config/unexpected action | Kiểm tra đường DENY hiện có, không fail-open |

Runtime cần xác minh Browser Flow: password trước Risk, condition + OTP/recovery, registration sau MFA. Provider/JAR tồn tại không chứng minh flow bind. SSO/cookie execution có thể bỏ Risk; phân tích đúng đường login/refresh được hỏi.

## HTTP và danh tính máy

Client Credentials risk-caller: aud zerotrust-risk-api, azp đúng, role theo endpoint risk:evaluate / risk:device:write / risk:events:write. Đọc RiskApiSecurityConfig/converter, phân biệt 401/403, denied routes/HTTPS. Issuer host/container local có thể khác; sửa canonical hostname thay vì nới validation.

HTTP client cache token, invalidate token bị 401 và retry một lần theo code hiện có. Kiểm tra idempotency trước retry timeout/5xx; không retry vô hạn, timeout có thể sau remote commit. Registration/events đòi 204; 200/409 không thay thế.

## Registration/cookie

Registration authenticator chỉ đăng ký khi auth note đủ điều kiện từ evaluation thật, bỏ qua khi CONFIGURE_TOTP còn pending, tham chiếu evaluator config và echo subjectId/deviceId/trustGeneration. Risk kiểm tra generation/pending dưới subject lock tới commit registration.

OTP/recovery do Keycloak xác thực. Flow phải bảo đảm MFA thực trước registration, không chỉ dựa tên execution/auth note. Nếu chưa kiểm chứng recovery/required action, nêu giới hạn.

ZT_DEVICE_ID định danh ngẫu nhiên 256 bit, realm-scoped, HttpOnly, SameSite=Lax, Secure theo secure context. Server trust expiry khác cookie expiry. HMAC subject/device ID lưu trong Risk, raw ID không persist. Reset/expired trust rotate ID theo reason/generation.

Chỉ issue cookie khi registration 204. Registration lỗi: login đã MFA có thể xong nhưng không cookie mới. 409/generation mismatch expire rejected cookie, không đổi generation để ép đăng ký. Phân tích login hiện tại và trust tương lai riêng.

## Events

RiskEventListener lọc realm/client/event hỗ trợ, gửi LOGIN_ERROR/LOGIN tới endpoint thích hợp; lỗi gửi không đổi auth result. Failure store HMAC keys, Redis Lua SET NX event dedup + counter TTL; success event DB uniqueness. Event ID cần ổn định khi retry, đọc fallback ID trước khi kết luận dedup mọi trường hợp.

Không log token/secret/raw IP/device ID. Event không thay quyết định password hợp lệ. Đổi history/contract cần test listener/DTO/controller/service/calculator liên quan, không chỉ scoring cuối.

## Regression chọn theo thay đổi

- Priority deny thắng score thấp/INCOMPLETE; mandatory MFA ở score LOW.
- Feature thiếu/cold-start; trusted nhưng temporal/network unavailable.
- STEP_UP thật khác Risk-timeout fallback; fallback không register.
- OTP/recovery, pending enrollment, registration 204/lỗi/409, rotation.
- Token sai issuer/aud/caller/role hoặc role sai client.
- Event duplicate/Redis outage/TTL clock boundary khi sửa hành vi này.

Chọn test qua source-map, integration thật chỉ khi cần và trong phạm vi được phép; không chạy toàn danh sách cho mọi sửa nhỏ.
