---
name: adaptive-authentication
description: Phân tích, sửa và kiểm thử xác thực thích ứng ZeroTrust qua Risk Service, Keycloak SPI, step-up MFA, trusted device và reset MFA. Dùng cho scoring guardrail, lỗi liên dịch vụ và vòng đời trust; không dùng cho CRUD Java thông thường hoặc tác vụ chỉ viết tài liệu kiến trúc.
---

# Xác thực thích ứng ZeroTrust

Skill riêng của repository, xây từ code/config/test và tài liệu, không phải bản tải GitHub. Thực hiện đúng loại công việc được yêu cầu: phân tích/review chỉ đọc, sửa/test khi được yêu cầu; không tự deploy hoặc đổi Browser Flow đang chạy.

## Nguồn và phạm vi

Đọc POM module và nguồn liên quan trong [bản đồ nguồn](references/source-map.md). Portal/Risk hiện dùng Java 17, Spring Boot 3.5.7; SPI dùng Java release 17, Keycloak 26.7.0, không phải Spring Boot. Portal admin-client là 26.0.11, không tự đồng bộ phiên bản. Ba POM độc lập; wrapper gốc chọn bằng -f.

Theo [ARCHITECTURE.md](../../../ARCHITECTURE.md): Keycloak sở hữu password/MFA/token; SPI thu context, gọi Risk và áp quyết định; Risk sở hữu scoring/history/device trust; Portal là resource server, điều phối reset MFA. Không đưa scoring vào SPI, password validation vào Portal hoặc cho SPI truy cập Risk DB trực tiếp.

Chọn reference theo hành vi:

- Scoring/login/Risk timeout/events/OTP/recovery/registration: đọc [Risk → SPI → MFA → trusted device](references/risk-mfa-device.md).
- Reset/revocation/partial failure/expiry/generation/concurrency: đọc [reset và lifecycle](references/reset-lifecycle.md).
- Tìm implementation/config/test: dùng [bản đồ nguồn](references/source-map.md), không đọc toàn repository như bước bắt buộc.

## Invariant chính

- Giữ ALLOW / STEP_UP_MFA / DENY. Priority deny trước scoring; dữ liệu thiếu/cold-start không mặc nhiên LOW; mandatory MFA không bị score thấp bỏ qua. Giá trị cấu hình không tự là trọng số/ngưỡng chính thức, phần còn mở cần người dùng chốt.
- Quyết định Risk hợp lệ khác Risk unavailable. FailureMode DENY khác fallback STEP_UP_MFA; fallback không đủ điều kiện tạo trust.
- Trust chỉ sau MFA thực thành công, evaluation đủ điều kiện và Risk registration xác nhận 204. CONFIGURE_TOTP chưa chứng minh MFA; cookie không phải credential/trạng thái trust.
- Evaluate/registration/events dùng zerotrust-risk-caller với role riêng; revoke/completion dùng zerotrust-portal-risk-admin và risk:device:revoke. Kiểm tra chữ ký, issuer, expiry, aud, azp, client role; không thay bằng provisioner/SPA/user token.
- Reset khóa subject, tăng generation/mark pending trước Keycloak reset; completion xác nhận mới báo thành công. Timeout không chứng minh remote chưa commit; DB transaction không rollback remote service.
- Giữ trustGeneration từ evaluation đến registration để fence attempt MFA cũ. Pending reset, security-revoked, expired và MFA-reset trust có hành vi khác nhau; đọc lifecycle.
- Không persist raw identifier thay HMAC, không log token/secret/raw IP. GeoIP mmdb local/CIDR precedence, không remote lookup theo request. Telemetry lỗi không thay auth result Keycloak.

## Sửa và kiểm chứng

Trace entrypoint → caller/callee → state/transaction → lỗi/test. Đổi contract phải kiểm tra DTO/enums/status và cả hai phía; không sửa một phía để test pass. Schema Risk dùng migration Flyway mới theo quy ước; giữ Java 17/security hiện có.

Chọn test theo hành vi và [DEVELOPMENT_CHECKS.md](../../../docs/development/DEVELOPMENT_CHECKS.md). Ví dụ từ gốc Windows, chọn lệnh phù hợp:

```powershell
.\mvnw.cmd --batch-mode --no-transfer-progress -f risk-scoring-service/pom.xml '-Dtest=RiskEvaluationServiceTests,DeviceTrustLifecycleTests' test
.\mvnw.cmd --batch-mode --no-transfer-progress -f keycloak-risk-extension/pom.xml '-Dtest=RiskDecisionHandlerTest,TrustedDeviceRegistrationAuthenticatorTest' test
.\mvnw.cmd --batch-mode --no-transfer-progress -f pom.xml '-Dtest=UserServiceImplTest,RiskDeviceAdminClientTest' test
```

H2/mock không chứng minh Browser Flow, Redis Lua/TTL hoặc MySQL locking thật. Không thêm Spring context vào SPI test, không yêu cầu Docker/Testcontainers cho mọi thay đổi. Chỉ mở rộng integration khi kết luận phụ thuộc semantics thực; nêu phần chưa kiểm chứng. Không disable security/Flyway/assertion để test xanh.

Phân biệt thiết kế đã chốt, code hiện tại, test thực chạy và runtime theo ngày/môi trường. Khoảng trống refresh/SSO/token cũ phải nêu như giới hạn, không tự thêm continuous authentication hay tuyên bố reset thu hồi mọi token. Đề xuất thay policy/ranh giới cần nêu tác động; triển khai cần chấp thuận rõ ràng theo ARCHITECTURE.md, chấp thuận đã có không cần hỏi lại.

Bàn giao hành vi đã phân tích/thay đổi, nguồn, test/lệnh thật và giới hạn. Review không tự cho phép sửa realm, reset account thật hoặc deploy JAR.
