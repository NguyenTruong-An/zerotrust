---
name: java-spring-boot
description: Viết, sửa lỗi, refactor và review Java backend của ZeroTrust Portal và Risk Scoring Service theo Spring Boot và quy ước repository. Áp dụng khi thay đổi API, service, JPA hoặc tích hợp Keycloak; không dùng cho công việc chỉ sửa frontend hoặc chỉ viết tài liệu.
---

# Java Spring Boot cho ZeroTrust

## Xác định module trước khi sửa

Các đường dẫn dưới đây tính từ gốc repository. Đọc POM của module liên quan, cấu hình profile và lớp/test gần phần cần sửa; kiểm tra lại phiên bản thay vì xem bản ghi dưới đây là cố định.

| Module | Build hiện có | Cấu trúc và vai trò |
|---|---|---|
| Portal API | `pom.xml`: Java 17, Spring Boot 3.5.7, Keycloak admin client 26.0.11 | `src/main/java/com/zerotrust/zerotrust`: nghiệp vụ người dùng, sinh viên, lớp, môn và điểm |
| Risk Service | `risk-scoring-service/pom.xml`: Java 17, Spring Boot 3.5.7 | `risk-scoring-service/src/main/java/com/zerotrust/risk`: đánh giá rủi ro, device trust, lịch sử xác thực |
| Keycloak extension | `keycloak-risk-extension/pom.xml`: Java release 17, Keycloak SPI 26.7.0 | `keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk`: authenticator, event listener và HTTP client; không phải Spring Boot |

Đây là ba dự án Maven độc lập, không phải reactor có parent chung. Dùng Maven Wrapper ở gốc với `-f` để chọn POM. Không tự đồng bộ hai phiên bản Keycloak hoặc nâng Java/Spring Boot trong một thay đổi chức năng.

## Quy ước triển khai

- Portal dùng `controller`, `service`/`service/impl`, `repository`, `entity`, `model/request`, `model/response`, `converter`, `exception`, `config`, `security` và `identity`. Theo lớp lân cận; không ép Risk Service dùng cùng layout.
- Risk dùng `dto/request`, `dto/response`, `domain`, `feature`, `rule`, `service`, `repository` và `config`; giữ pipeline đánh giá trong service/feature/rule, controller chỉ điều phối HTTP và validation.
- Dùng `jakarta.*`, dependency injection qua constructor và Lombok theo code hiện có. Giữ code tương thích Java 17; không đưa tính năng Java mới hơn hoặc preview vào.
- Portal trả `ApiResponse<T>`/`PageResponse`, lỗi qua `WebException`, `ErrorCode`, `GlobalExceptionHandler`. Risk có response DTO và error handler riêng. Đọc contract của endpoint và caller trước khi thay payload, status, nullability hoặc enum.
- Giữ DTO ở biên API; đặt transaction ở thao tác persistence/service thích hợp. Cả hai backend tắt Open Session in View: kiểm tra fetch/join và mapping trong phạm vi transaction khi đụng quan hệ lazy.
- Portal tích hợp danh tính qua `IdentityProviderGateway` và `identity/keycloak`. Tham khảo `StudentCreationService`/`StudentPersistenceService` khi thao tác vừa gọi Keycloak vừa ghi DB: DB transaction không rollback được remote call, cần giữ cơ chế bù và xử lý lỗi từng bước.
- Risk dùng Flyway tại `risk-scoring-service/src/main/resources/db/migration`. Khi đổi schema, kiểm tra migration và entity cùng nhau; thêm migration mới thay vì sửa migration đã áp dụng. Portal hiện không có Flyway trong POM, không giả định cùng cơ chế quản lý schema.
- Cấu hình mới đi qua property/configuration class và profile thích hợp. Đọc tên biến từ `.env.example`, không chép secret hay giá trị cấu hình riêng vào code, tài liệu hoặc log.

## Ranh giới ZeroTrust của dự án

Đọc `ARCHITECTURE.md` và phần liên quan trong `docs/authentication/LOGIN_FLOW.md`, `docs/authentication/MFA_RESET_LIFECYCLE.md`, `docs/security/RISK_API_SECURITY.md` trước khi thay đổi xác thực, quyền hoặc device trust.

- Portal là resource server stateless, kiểm tra JWT/JWKS và quyền tài nguyên. `STUDENT` xem dữ liệu của mình theo subject; `ADMIN` quản lý theo policy. Không đưa login/password validation hoặc scoring vào Portal.
- Keycloak sở hữu primary authentication, MFA và phát token; SPI gọi Risk, không chứa công thức scoring. Portal DB và Risk DB là hai miền dữ liệu riêng.
- Risk evaluation/registration/event dùng caller `zerotrust-risk-caller` và role riêng từng endpoint; device revocation/completion dùng caller `zerotrust-portal-risk-admin` và `risk:device:revoke`. Kiểm tra config/converter hiện có để xác nhận issuer, audience, `azp` và authority; không thay bằng provisioner hoặc user token.
- Giữ ba quyết định `ALLOW`, `STEP_UP_MFA`, `DENY`, priority deny và mandatory MFA guardrails. Dữ liệu thiếu/cold-start không mặc nhiên là rủi ro thấp. Công thức, trọng số và ngưỡng chính thức còn mở: không tự chốt từ ví dụ hoặc mặc định cấu hình.
- Khi sửa Geo-IP, theo `GeoIpProvider` và `MaxMindGeoIpProvider`: CIDR và dữ liệu `.mmdb` local, không thêm remote lookup theo request hoặc persist raw IP như một thay đổi phụ.

Thực hiện sửa lỗi/chức năng trong phạm vi yêu cầu. Nếu cần đổi ranh giới dịch vụ, luồng xác thực hoặc policy kiến trúc đã chốt, trình bày phương án và tác động trước; chỉ triển khai khi có chấp thuận rõ ràng theo `ARCHITECTURE.md`. Chấp thuận đã có trong phiên làm việc không cần hỏi lại.

## Kiểm chứng và bàn giao

Chọn test có ý nghĩa cho hành vi thay đổi, theo `docs/development/DEVELOPMENT_CHECKS.md`; chạy từ gốc bằng `mvnw.cmd` trên Windows hoặc `bash mvnw` trên Linux. Ví dụ:

```powershell
.\mvnw.cmd --batch-mode --no-transfer-progress -f pom.xml test
.\mvnw.cmd --batch-mode --no-transfer-progress -f risk-scoring-service/pom.xml test
.\mvnw.cmd --batch-mode --no-transfer-progress -f keycloak-risk-extension/pom.xml test
```

Chỉ chạy các module bị ảnh hưởng; thay đổi contract Risk/SPI hoặc Portal/Risk cần kiểm tra cả caller và callee. Báo cáo hành vi đã đổi, test thực sự chạy và giới hạn còn lại. Không coi test mock/H2 là bằng chứng hệ thống Keycloak/MySQL/Redis thật đã chạy, và không sửa thay đổi đang có của người dùng ngoài phạm vi công việc.
