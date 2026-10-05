[Mục lục tài liệu](../README.md) · [Trang dự án](../../README.md)

# Kế hoạch kiểm thử và pentest cơ bản ZeroTrust

**Ngày xây dựng:** 05/10/2026. **Cơ sở:** mã, cấu hình và test trong working tree hiện tại.

Bộ này gồm **40 kịch bản chức năng/tích hợp** và **24 kịch bản pentest cơ bản**, dành cho Portal, SPA, Keycloak Risk Extension và Risk Scoring Service. Đây là kế hoạch thực hiện; trạng thái ban đầu của các kịch bản thủ công là **NOT_RUN**. Kết quả chạy test mục tiêu được ghi riêng ở cuối tài liệu.

## 1. Tài liệu sử dụng

| Tài liệu | Nội dung |
|---|---|
| [Kịch bản chức năng](FUNCTIONAL_SCENARIOS.md) | Tiền điều kiện, thao tác, kết quả mong đợi và test liên quan |
| [Pentest cơ bản](BASIC_PENTEST.md) | Vượt quyền, JWT/OIDC, MFA/device, input, CORS, cấu hình và dữ liệu |
| [6 kịch bản pentest sâu hơn](ADVANCED_PENTEST.md) | Race/reset, mất response sau commit, response binding, SSO/token cũ, danh tính máy và proxy; hướng dẫn tự thực hiện, chưa chạy |
| [Mẫu báo cáo](REPORT_TEMPLATE.md) | Ghi từng lần chạy, bằng chứng, lỗi và kiểm thử lại |
| [Các bước kiểm tra hiện có](../development/DEVELOPMENT_CHECKS.md) | Maven, frontend và giới hạn CI |
| [Thiết lập local](../operations/LOCAL_SETUP.md) | Cách dựng môi trường trước khi kiểm thử thủ công |

## 2. Phạm vi và mức ưu tiên

Mục tiêu là xác minh đúng chức năng, đúng chủ thể và đúng ranh giới tin cậy: Keycloak xác thực và phát token; SPI gọi Risk và áp quyết định; Risk quản lý scoring/history/device trust; Portal xử lý nghiệp vụ và điều phối reset MFA.

- **P0:** đăng nhập, MFA, phân quyền, quyền sở hữu, JWT, thu hồi trust và lỗi có thể tạo bypass. Chạy trước khi demo hoặc phát hành.
- **P1:** validation, tính điểm, lỗi liên dịch vụ, chống lạm dụng mức nhỏ, cấu hình và riêng tư.
- **T:** có test tự động liên quan; phải đọc assertion và chạy test để xác nhận phạm vi thực.
- **M:** cần kiểm chứng thủ công trên môi trường local riêng với Keycloak/MySQL/Redis thật.
- **G:** mục tiêu bảo mật hoặc khoảng trống cần đo và quyết định; chưa khẳng định code hiện tại đáp ứng.

Một dòng `T + M` cần hai loại bằng chứng. Test với mock/H2 đạt không tự hoàn tất phần `M`. Mức ưu tiên của kịch bản khác mức độ nghiêm trọng của finding.

Các phép thử chủ động chỉ thực hiện trên target/tài khoản kiểm thử đã ghi trong báo cáo. Bộ cơ bản dùng từng request hoặc hai request đồng thời; phép thử sai mật khẩu giới hạn tối đa 5 lần, cách nhau ít nhất 2 giây. Scanner chủ động, gây tải lớn hoặc thử trên production cần phạm vi riêng.

## 3. Môi trường và dữ liệu mẫu

### 3.1. Target mặc định của repository

| Thành phần | Target local | Ghi chú |
|---|---|---|
| SPA | `http://localhost:3000` | Client public `zerotrust-spa`, PKCE S256 |
| Portal API | `http://localhost:8080` | Audience `zerotrust-api`; realm role `ADMIN`/`STUDENT` |
| Keycloak | `http://localhost:8180/realms/DoAn` | Browser Flow phải được kiểm tra trực tiếp |
| Risk API | `http://localhost:8081` | HTTP chỉ cho profile `dev` local; cấu hình mặc định yêu cầu HTTPS |
| Risk MySQL/Redis | `127.0.0.1:3307` / `127.0.0.1:6379` | Không phải endpoint để quét Internet |

Issuer của service token trong topology Docker có thể là cổng nội bộ `8080`, khác issuer browser `8180`. Ghi chính xác `iss` và cấu hình của từng resource server; sai issuer phải bị từ chối, không nới validator để làm test đạt.

### 3.2. Bộ fixture cần chuẩn bị

| Ký hiệu | Dữ liệu/đặc điểm |
|---|---|
| `ADMIN_A` | Tài khoản admin riêng cho kiểm thử, có OTP và recovery codes nếu realm hỗ trợ |
| `STUDENT_A`, `STUDENT_B` | Hai sinh viên ACTIVE, chỉ role STUDENT, có điểm khác nhau để phát hiện lộ chéo |
| `STUDENT_EMPTY` | Sinh viên ACTIVE chưa có điểm |
| `USER_INACTIVE` | Hồ sơ Portal INACTIVE, dùng để kiểm tra các đường có kiểm tra trạng thái |
| `USER_UNLINKED` | Danh tính Keycloak chưa liên kết với hồ sơ Portal |
| `USER_NO_ROLE` | Token Portal hợp lệ nhưng không có ADMIN/STUDENT |
| `CLASS_TEST`, `SUBJECT_TEST` | Lớp `ZT_TEST_01`, môn `ZT_TEST_01`, dữ liệu mang nhãn kiểm thử |
| `BROWSER_NEW`, `BROWSER_TRUSTED` | Hai profile trình duyệt riêng; profile thứ hai đã hoàn thành MFA và đăng ký trust |
| `IP_TEST` | IP giả `192.0.2.10` dùng trong unit test/API fixture; không tạo lưu lượng tới IP này |

Ghi riêng **Portal user ID**, **student ID** và **Keycloak subject UUID**. Endpoint reset Portal nhận Portal user ID; endpoint Risk nhận Keycloak subject. Các ID này không được hoán đổi.

Đăng nhập SPA để lấy token người dùng. Không bật password grant để tiện test. Token service lấy qua Client Credentials của client kiểm thử đúng trách nhiệm:

| Caller | Audience / role tại client `zerotrust-risk-api` | Endpoint cho phép |
|---|---|---|
| `zerotrust-risk-caller` | `zerotrust-risk-api` / `risk:evaluate` | Evaluate |
| Cùng risk caller | `risk:device:write` | Register trusted device |
| Cùng risk caller | `risk:events:write` | Gửi success/failure event |
| `zerotrust-portal-risk-admin` | `risk:device:revoke` | Revoke / completion |
| `zerotrust-provisioner` | Quyền Keycloak Admin API theo cấu hình | Không mặc nhiên có quyền Risk |

Trong Postman hoặc công cụ tương đương, giữ token/secret trong biến local đánh dấu nhạy cảm. Không xuất giá trị hiện hành vào collection, Git, ảnh hoặc HAR. Bằng chứng chỉ giữ claim cần thiết đã che danh tính và trạng thái HTTP.

### 3.3. Chuẩn bị để kết quả Risk có thể lặp lại

Ghi profile, ngưỡng/trọng số đang dùng, Browser Flow, failure mode, network/GeoIP policy, thời hạn trust và cấu hình brute-force. Ngưỡng development hiện tại là `40`/`75`, trọng số mỗi nhóm `0.25`; kiến trúc chưa chốt các giá trị này cho production.

`ALLOW` cần dữ liệu COMPLETE và không có guardrail; cookie trusted riêng lẻ chưa đủ. Network intelligence/GeoIP tắt hoặc lịch sử chưa đủ có thể dẫn tới INCOMPLETE/MFA. Dùng fixture của unit test cho nhánh score biên; kiểm thử E2E cần lịch sử thành công và cấu hình network rõ ràng. Không tắt guardrail để ép nhánh ALLOW.

Tạo snapshot dữ liệu/realm local trước các ca reset, expiry hoặc lỗi liên dịch vụ. Sau ca: khôi phục dịch vụ và policy, xóa dữ liệu thử qua UI/API phù hợp, xóa profile browser thử nếu cần. Không có endpoint DELETE student trong controller hiện tại; việc dọn fixture user/student cần quy trình local riêng. Không xóa toàn bộ volume hoặc reset tài khoản thật.

## 4. Bản đồ endpoint để chọn request

| Nhóm | Method và path | Kết quả thành công thông thường |
|---|---|---|
| User | `GET /api/users/me` | 200; danh tính từ JWT `sub` |
| Sinh viên | `GET /api/students/me`, `/me/scores`, `/me/scores/summary` | 200; chỉ dữ liệu của sinh viên hiện tại |
| Danh mục admin | `GET/POST /api/admin/student-classes`, `/subjects`; `DELETE /.../{id}` | GET 200, POST 201, DELETE 204 |
| Sinh viên admin | `GET/POST /api/admin/students`; `GET/PATCH /api/admin/students/{id}` | GET/PATCH 200, POST 201 |
| Điểm admin | `GET/POST /api/admin/students/{studentId}/scores`; `PATCH/DELETE /api/admin/scores/{scoreId}` | GET/PATCH 200, POST 201, DELETE 204 |
| Bảng điểm môn | `GET /api/admin/subjects/{subjectId}/score-sheet`; `POST /api/admin/subjects/{subjectId}/scores/batch` | 200 |
| Reset MFA | `GET /api/admin/users`; `POST /api/admin/users/{id}/mfa/reset` | GET 200; reset 204 sau khi hoàn tất cả ba bước |
| Risk | `POST /internal/v1/risk/evaluations` | 200 với `decision`, kể cả `DENY` |
| Trust/event | `POST /internal/v1/trusted-devices`, `/authentication-failures`, `/authentication-successes` | 204 |
| Thu hồi trust | `POST /internal/v1/subjects/{subjectId}/trusted-devices/revocations` và path thêm `/completion` | 204 |
| Health Risk | `GET /actuator/health` | 200 nếu healthy; có thể 503 khi dependency unhealthy; không lộ chi tiết |

Missing/invalid bearer thường là **401**; token hợp lệ nhưng thiếu quyền là **403**. HTTP không an toàn khi Risk bật `require-https` bị **403 HTTPS_REQUIRED** trước kiểm tra token. Một request bị chặn phải không đọc/ghi dữ liệu trái quyền, dù thông báo HTTP trông đúng.

## 5. Trình tự thực hiện

1. Ghi môi trường và fixture trong [mẫu báo cáo](REPORT_TEMPLATE.md); kiểm tra dịch vụ/Browser Flow.
2. Chạy test tự động mục tiêu ở mục 6, ghi output và số test của lần chạy hiện tại.
3. Chạy smoke: `F-A01`, `F-A02`, `F-P01`, `F-P02`, `F-R01`, `F-R05`, `F-D01`, `F-M01`, `P01`, `P02`, `P03`, `P06`.
4. Chạy các ca P0 còn lại rồi P1. Mỗi biến thể dữ liệu có một dòng kết quả riêng.
5. Chạy nhóm `G`, ghi hành vi quan sát và đánh giá giới hạn thay vì mặc định PASS.
6. Khôi phục fixture/cấu hình; kiểm tra lại login bình thường; lập finding và retest các lỗi đã sửa.

## 6. Lệnh test tự động liên quan

Chạy từ gốc repository với **JDK 17**. Ba POM độc lập; không dùng `-pl/-am`. `JAVA_HOME` phải trỏ JDK 17; kiểm tra phiên bản Maven Wrapper thay vì suy luận từ `java` trên PATH.

```powershell
.\mvnw.cmd --version

# Portal: quyền HTTP, danh tính, reset orchestration và công thức điểm
.\mvnw.cmd --batch-mode --no-transfer-progress -f pom.xml '-Dtest=AdminControllerSecurityTest,StudentControllerSecurityTest,UserControllerTest,SecurityConfigTest,UserServiceImplTest,RiskDeviceAdminClientTest,ScoreCalculatorTest' test

# Risk: JWT ký thật với JWKS giả lập, HTTPS, scoring và lifecycle
.\mvnw.cmd --batch-mode --no-transfer-progress -f risk-scoring-service/pom.xml '-Dtest=RiskApiSecurityTests,RiskApiHttpsSecurityTests,RiskEvaluationServiceTests,RiskScoringServiceTests,DeviceTrustLifecycleTests,TrustedDeviceRegistrationServiceTests' test

# SPI: quyết định, fallback, điều kiện MFA, registration, HTTP và cookie
.\mvnw.cmd --batch-mode --no-transfer-progress -f keycloak-risk-extension/pom.xml '-Dtest=RiskAuthenticatorTest,RiskDecisionHandlerTest,RiskStepUpConditionTest,TrustedDeviceRegistrationAuthenticatorTest,HttpRiskScoringClientTest,KeycloakDeviceCookieWriterTest' test
```

Mở rộng theo ca cần kiểm chứng:

```powershell
# Provisioning, CRUD, điểm và ownership ở tầng service
.\mvnw.cmd --batch-mode --no-transfer-progress -f pom.xml '-Dtest=StudentCreationServiceTest,StudentQueryServiceTest,StudentUpdateServiceTest,StudentClassAdministrationServiceImplTest,SubjectAdministrationServiceImplTest,ScoreAdministrationServiceImplTest' test

# Endpoint reset, device/network/history và telemetry
.\mvnw.cmd --batch-mode --no-transfer-progress -f risk-scoring-service/pom.xml '-Dtest=TrustedDeviceRevocationControllerTests,DeviceRecognitionServiceTests,NetworkRiskCalculatorTests,TemporalRiskCalculatorTests,AuthenticationHistoryRiskCalculatorTests,RedisAuthenticationFailureStoreTests,AuthenticationSuccessServiceTests' test

.\mvnw.cmd --batch-mode --no-transfer-progress -f keycloak-risk-extension/pom.xml '-Dtest=RiskEventListenerTest,ClientCredentialsTokenProviderTest,KeycloakLoginContextExtractorTest' test

# Suite backend đầy đủ, khi cần xác nhận tích hợp thay đổi
.\verify-project.ps1 -Scope Backend

# Kiểm tra mã frontend, chưa thay thế test trình duyệt
.\verify-project.ps1 -Scope Frontend
```

Portal MockMvc chủ yếu kiểm tra authorization với authentication giả lập; `SecurityConfigTest` kiểm tra converter/audience, chưa chứng minh mọi trường hợp decoder của Portal. `RiskApiSecurityTests` dùng JWT RSA và JWKS loopback nên kiểm tra được decoder Risk. H2 không chứng minh toàn bộ locking/SQL MySQL; mock Redis không chứng minh Lua/TTL thật. SPI mock không chứng minh execution order hoặc realm binding đang chạy.

## 7. Điều kiện đánh giá

- **PASS:** mọi biến thể của ca thỏa expected, có bằng chứng cần thiết và không có tác động trái quyền.
- **FAIL:** có hành vi trái expected và có thể tái hiện. Đính kèm finding; không coi mọi lỗi 500 hoặc alert scanner là exploit đã xác nhận.
- **BLOCKED:** thiếu fixture, quyền hoặc môi trường để thực hiện; nêu điều kiện còn thiếu.
- **NOT_RUN:** chưa thực hiện. **N/A:** không áp dụng, có lý do và bằng chứng cấu hình.

Đạt đợt cơ bản khi các ca P0 áp dụng đã PASS, P1 có kết quả, finding nghiêm trọng đã được xử lý hoặc có quyết định chấp nhận được ghi rõ, và các ca G có đánh giá riêng. Không đổi ca G thành PASS chỉ vì code hiện tại chưa hỗ trợ mục tiêu.

Các giới hạn cần công bố: refresh/SSO có thể không chạy Risk; Portal JWT stateless có thể chấp nhận access token cũ tới khi hết hạn; MFA mới cho thao tác admin cần kiểm chứng riêng; cookie thiết bị sao chép cùng tài khoản chưa có cơ chế chứng minh sở hữu phần cứng.

## 8. Kết quả kiểm tra khi xây dựng tài liệu

Đã chạy ba nhóm test mục tiêu ở mục 6 ngày **05/10/2026**, trên Windows với **JDK 17.0.10**, working tree hiện tại. Thứ tự tham số thực tế là `.\mvnw.cmd test --batch-mode --no-transfer-progress -f <pom> '-Dtest=<selector>'`, với cùng selector tại mục 6.

| Nhóm | Test / failure / error / skipped | Kết quả | Thời điểm hoàn tất (Asia/Saigon) |
|---|---|---|---|
| Portal, 7 test class mục tiêu | 80 / 0 / 0 / 0 | BUILD SUCCESS, exit 0 | 10:28:55 |
| Risk, 6 test class mục tiêu | 29 / 0 / 0 / 0 | BUILD SUCCESS, exit 0 | 10:29:01 |
| Keycloak SPI, 6 test class mục tiêu | 33 / 0 / 0 / 0 | BUILD SUCCESS, exit 0 | 10:26:40 |
| **Tổng** | **142 / 0 / 0 / 0** | **Đạt các nhóm đã chọn** | |

Report Maven nằm ở `target/surefire-reports`, `risk-scoring-service/target/surefire-reports` và `keycloak-risk-extension/target/surefire-reports`. Các lần thử trong sandbox đã dừng vì tiến trình không tiếp tục ở bước khởi tạo test dùng Mockito; kết quả đạt ở bảng là lần chạy lại ngoài sandbox theo quyền đã cấp.

Đã kiểm tra tài liệu: **40 ID chức năng + 24 ID pentest**, không trùng ID, không có liên kết nội bộ thiếu đích, **35 tên test class** trong toàn bộ lệnh hướng dẫn tồn tại, **5 JSON mẫu** parse hợp lệ. Các lệnh mở rộng, suite đầy đủ và kiểm tra frontend chưa chạy trong đợt này.

Các kết quả trên không thay cho 64 kịch bản thủ công: **chưa pentest lên dịch vụ đang chạy, chưa xác minh Browser Flow/Keycloak thật, MySQL locking/Redis TTL thật hoặc các ca G**.

## 9. Nguồn đối chiếu

Các nhóm xác thực, phân quyền, session, input và business logic tham chiếu [OWASP WSTG v4.2](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/). Nhóm ownership, authentication, function/property authorization và cấu hình API tham chiếu [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/). Đây là lựa chọn cho phạm vi cơ bản của dự án, chưa phải đánh giá đầy đủ mọi mục OWASP.

Chi tiết vận hành realm cần đối chiếu [Keycloak Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/index.html) với **phiên bản Keycloak thực sự chạy**; tài liệu latest không thay cho bằng chứng cấu hình local.
