---
name: spring-boot-testing
description: Viết, sửa và chạy unit test, Spring MVC/security test, JPA/migration test và integration test Java trong repository ZeroTrust. Dùng khi kiểm chứng backend, chẩn đoán Maven test hoặc kiểm tra contract với Keycloak SPI; không dùng cho kiểm thử frontend hay triển khai hệ thống.
---

# Kiểm thử backend ZeroTrust

## Baseline cần xác nhận

Đọc POM của module, test gần hành vi thay đổi và `docs/development/DEVELOPMENT_CHECKS.md`. Đường dẫn/lệnh trong skill tính từ gốc repository.

- Portal (`pom.xml`) và Risk (`risk-scoring-service/pom.xml`): Java 17, Spring Boot 3.5.7, starter-test (JUnit Jupiter, Mockito, AssertJ), spring-security-test và H2.
- Keycloak SPI (`keycloak-risk-extension/pom.xml`): Java release 17, JUnit 5.12.2, Mockito core 5.20.0, Surefire 3.5.3; không có Spring context. Không giả định SPI có Mockito JUnit extension chỉ vì Portal dùng nó.
- Ba POM độc lập; CI `.github/workflows/ci.yml` chạy từng POM trên Java 17. Không dùng `-pl`/`-am` như thể đây là reactor.
- Hiện chưa có Testcontainers trong các POM. Chỉ thêm khi nhiệm vụ cần semantics MySQL/Redis hoặc integration thật và thay đổi dependency đó nằm trong phạm vi yêu cầu; không biến Docker thành điều kiện của bộ test hiện tại.

## Chọn mức test theo hành vi

| Hành vi cần kiểm chứng | Cách dùng trong repository |
|---|---|
| Logic nghiệp vụ, scoring guardrail, gateway orchestration | JUnit/Mockito, không bật Spring context nếu không cần; tham khảo `src/test/java/com/zerotrust/zerotrust/service/impl/student/StudentCreationServiceTest.java` và test service của Risk |
| Portal HTTP validation, status và phân quyền | `@WebMvcTest`, MockMvc, `@MockitoBean`, import security config cần thiết; tham khảo `StudentControllerSecurityTest`/`AdminControllerSecurityTest` |
| Repository, mapping, truy vấn và lazy fetching | `@DataJpaTest`, profile `test`; tham khảo `StudentRepositoryTest`, flush/clear để quan sát dữ liệu thực thay vì persistence cache |
| Wiring và endpoint Risk | `@SpringBootTest`, `@AutoConfigureMockMvc`, `@ActiveProfiles("test")`; tham khảo `RiskEvaluationControllerTests` và `RiskApiSecurityTests` |
| Flyway và schema Risk | Test migration/repository với cấu hình test hiện có; tham khảo `risk-scoring-service/src/test/java/com/zerotrust/risk/migration/` |
| SPI authentication/event hoặc client HTTP | JUnit với Keycloak objects giả lập; tham khảo test authenticator/listener và `HttpRiskScoringClientTest` dùng HTTP server loopback, cổng ngẫu nhiên |

Theo package và hậu tố `Test`/`Tests` đang dùng ở module. Test phải bắt được regression về kết quả, dữ liệu hoặc quyền; không chỉ assert implementation nội bộ hay tăng coverage bằng test trùng.

## Cấu hình và giới hạn của test

- Spring tests dùng `@ActiveProfiles("test")` khi cần cấu hình riêng; đọc `src/test/resources/application-test.properties` của đúng module trước khi thêm override.
- Portal H2 dùng MySQL mode, `ddl-auto=create-drop`; Risk H2 dùng MySQL mode, `ddl-auto=validate` và Flyway migrations. Không tắt Flyway hoặc chuyển Risk sang create-drop để làm test schema pass.
- Bộ test hiện tại không cần Keycloak, MySQL hoặc Redis đang chạy. Mock/stub external dependency ở đúng biên; test context không được phụ thuộc realm hoặc secret production.
- H2 không chứng minh mọi semantics MySQL; Redis mock không thực thi Lua/TTL/concurrency của Redis thật. Ghi rõ giới hạn đó nếu task liên quan locking, SQL đặc thù, duplicate event hoặc atomic counter.
- Authentication đã inject vào MockMvc chứng minh authorization ở lớp đang test, không tự chứng minh chữ ký/issuer/expiration/audience của JWT. Kiểm tra decoder/validator riêng khi thay logic xác minh token.
- Khi tạo service JWT, bám converter và config thật: realm role Portal khác client role Risk; claims `azp`, `resource_access` và authority phải phù hợp endpoint. Test trường hợp sai caller/role khi sửa quyền Risk.
- Khi sửa quyền Portal, kiểm tra thiếu token, sai role và quyền sở hữu theo subject nếu liên quan. Khi sửa device trust/MFA, kiểm tra revoke/expiry, lỗi từng bước hoặc generation race theo hành vi được sửa, không tắt security filter cho test pass.
- Ưu tiên clock/input cố định theo thiết kế sẵn có cho time/TTL; tránh chờ thực hoặc dùng secret, IP/danh tính thực. Đóng server/response/resource trong HTTP tests.

## Chạy và chẩn đoán

Chạy test mục tiêu trước rồi suite module khi đã sửa code; kiểm tra cả hai phía nếu đổi contract. Lệnh từ gốc repository trên Windows:

```powershell
.\mvnw.cmd --batch-mode --no-transfer-progress -f pom.xml '-Dtest=StudentControllerSecurityTest' test
.\mvnw.cmd --batch-mode --no-transfer-progress -f risk-scoring-service/pom.xml '-Dtest=RiskEvaluationControllerTests' test
.\mvnw.cmd --batch-mode --no-transfer-progress -f keycloak-risk-extension/pom.xml '-Dtest=HttpRiskScoringClientTest' test
.\verify-project.ps1 -Scope Backend
```

Ba lệnh đầu là lựa chọn theo module, không phải chuỗi bắt buộc. Dùng dấu nháy cho `-Dtest=ClassA,ClassB` trong PowerShell. Linux/CI dùng `bash mvnw --batch-mode --no-transfer-progress -f <pom> test`. Script `verify-project.ps1 -Scope Backend` chạy cả ba suite; `-Scope All` còn kiểm tra frontend và cần frontend dependencies.

Đọc `target/surefire-reports` dưới module bị lỗi. Phân biệt lỗi dependency/JDK/environment, failure có từ trước và regression của thay đổi; không bỏ assertion, disable test, dùng skipTests hoặc đổi profile production để đạt trạng thái xanh. Maven Wrapper có thể cần tải Maven/dependencies, nên tuân thủ quyền network/filesystem của phiên chạy.

Bàn giao bằng lệnh thực sự đã chạy, module/test đạt hoặc lỗi, nguyên nhân còn mở và phạm vi kiểm chứng. Không dùng số test ở báo cáo cũ làm kết quả hiện tại; không coi suite Java đạt là đã kiểm chứng Browser Flow, MFA hoặc rollout trên Keycloak thật.
