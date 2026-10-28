[Kế hoạch](TEST_PLAN.md) · [Pentest cơ bản](BASIC_PENTEST.md) · [Mẫu báo cáo](REPORT_TEMPLATE.md)

# 40 kịch bản kiểm thử chức năng và tích hợp

Phạm vi hiện tại được xác nhận ngày 27/10/2026: chỉ ADMIN/STUDENT, quản lý và xem điểm.
Teacher, phân công và lịch học không thuộc các ca nghiệm thu. Kiểm tra tự động bổ sung
trong `ZerotrustApplicationTests` xác nhận các API cũ không còn được cung cấp; Gateway
kiểm tra token chỉ có role TEACHER không truy cập được API điểm Student hoặc API Admin.

Fixture, mức ưu tiên và ký hiệu `T/M/G` được định nghĩa trong [kế hoạch](TEST_PLAN.md). Mỗi bộ dữ liệu trong một ca phải ghi kết quả riêng. Tên test bên dưới chỉ là điểm bắt đầu đối chiếu; các ca E2E vẫn cần chạy với hệ thống thật. Trạng thái ban đầu: **NOT_RUN**.

## 1. Đăng nhập và phiên — 6 ca

| ID / mức / cách | Tiền điều kiện | Bước thực hiện | Kết quả mong đợi | Test hoặc nguồn liên quan |
|---|---|---|---|---|
| F-A01 / P0 / M | STUDENT_A ACTIVE, browser mới; Browser Flow đã bind | Mở SPA; login đúng mật khẩu; hoàn thành OTP/enrollment được yêu cầu; gọi `/api/users/me` và `/api/students/me` | Login hoàn tất; API 200 đúng A; UI sinh viên; không có quyền admin | `frontend/lib/keycloak.ts`, `UserControllerTest`, `StudentControllerSecurityTest` |
| F-A02 / P0 / M | ADMIN_A chỉ role ADMIN, có OTP | Login; mở danh sách sinh viên/môn; gọi `/api/students/me/scores` | Admin API 200; endpoint sinh viên 403 nếu thiếu STUDENT; không mặc định admin bao gồm mọi role | `AdminControllerSecurityTest`, `StudentControllerSecurityTest` |
| F-A03 / P0 / M | Tài khoản thử chưa khóa | Nhập mật khẩu sai một lần; nếu tới OTP, nhập OTP sai/hết cửa sổ hiệu lực; hủy flow | Không nhận phiên đăng nhập mới từ attempt thất bại; không tạo trust mới; password/OTP do Keycloak xử lý | `RiskEventListenerTest`; realm thật |
| F-A04 / P1 / M | A đăng nhập, access token sắp hết hạn | Gọi API; quan sát refresh; thử lại khi refresh không còn hợp lệ | Refresh hợp lệ giữ UI; refresh lỗi xóa token trong memory, UI về chưa login; mỗi API 401 chỉ có tối đa một lần force-refresh/retry | `frontend/lib/api.ts` |
| F-A05 / P0 / M | A đang login trong profile thử | Logout qua UI; reload; thử refresh token cũ bằng công cụ local | Token cục bộ được dọn; khi end-session thành công, refresh gắn session cũ bị từ chối; ghi riêng hành vi access token cũ theo P18 | Login/logout frontend; cấu hình realm |
| F-A06 / P1 / T + M | USER_UNLINKED hoặc USER_INACTIVE; token Portal hợp lệ | Gọi `/api/users/me`; với sinh viên INACTIVE thử thêm endpoint điểm | Chưa liên kết trả 404; INACTIVE tại các đường có kiểm tra status trả 403; không lộ hồ sơ khác | `UserServiceImplTest`, `ScoreAdministrationServiceImplTest`; không suy rộng thành global revocation |

## 2. Nghiệp vụ Portal — 10 ca

| ID / mức / cách | Tiền điều kiện | Bước thực hiện | Kết quả mong đợi | Test hoặc nguồn liên quan |
|---|---|---|---|---|
| F-P01 / P0 / T + M | A/B có môn và điểm khác nhau | A gọi `/api/students/me`, `/me/scores`, `/me/scores/summary`; lặp lại với B | Cả ba 200; mỗi token chỉ thấy hồ sơ/điểm/summary của mình, resolver dùng JWT sub | `StudentControllerSecurityTest`, `StudentQueryServiceTest`, `ScoreAdministrationServiceImplTest` |
| F-P02 / P1 / T + M | STUDENT_EMPTY ACTIVE | Gọi list và summary; tìm một keyword không tồn tại | 200, danh sách rỗng; tổng số phù hợp; giá trị summary theo DTO, không NaN/lỗi 500 | `ScoreAdministrationServiceImplTest` |
| F-P03 / P1 / T + M | ADMIN_A; mã lớp/môn mới | POST lớp rồi môn; GET danh sách; lặp lại cùng mã; thử credits 0/21 | Tạo mới 201, đọc được; duplicate 400 theo error tương ứng; credits 0/21 trả 400 và không ghi | `StudentClassAdministrationServiceImplTest`, `SubjectAdministrationServiceImplTest`, DTO tests |
| F-P04 / P0 / T + M | Lớp đã có; username/email/studentCode riêng | POST sinh viên bằng fixture ở dưới; đọc user/student/Keycloak role | 201; liên kết đúng Keycloak ID; role STUDENT; response không chứa password; A mới có thể login | `StudentCreationServiceTest`, `AdminControllerSecurityTest` |
| F-P05 / P1 / T + M | Fixture tạo student; mock hoặc dependency local riêng | Thử lớp không tồn tại/trùng studentCode; giả lập lỗi assign role hoặc DB sau khi tạo Keycloak user | Lỗi trước provisioning không tạo user; lỗi sau tạo gọi compensation xóa identity; kiểm tra dữ liệu mồ côi/khả năng compensation thất bại riêng | `StudentCreationServiceTest`; DB transaction không rollback Keycloak |
| F-P06 / P1 / T + M | ADMIN_A; student fixture | PATCH một field; thử email sai, ngày sinh tương lai, `{}`; GET lại | Cập nhật hợp lệ 200 chỉ field được phép; dữ liệu sai/empty update trả 400; dữ liệu cũ không bị ghi đè bất ngờ | `StudentUpdateServiceTest`, `UpdateStudentRequestDTOTest` |
| F-P07 / P1 / T + M | Student/môn hợp lệ; chưa có score | POST attendance=8, midterm=7, final=9; PATCH final=10; GET | Tạo 201: total=8.5, grade=A; patch 200: total=9.2, grade=A+; backend tự tính lại | `ScoreCalculatorTest`, `ScoreAdministrationServiceImplTest` |
| F-P08 / P1 / T + M | Score fixture | Thử -0.1, 10.1, null khi create, semester 0/3, academicYear `2026-2026`; tạo trùng student/môn | 400 và không ghi; giới hạn 0..10, học kỳ 1..2; năm kết thúc phải lớn hơn năm bắt đầu; duplicate SCORE_EXISTS | DTO tests, `ScoreAdministrationServiceImplTest` |
| F-P09 / P1 / T + M | ADMIN_A; bảng điểm môn; A/B ACTIVE | Batch hợp lệ hai sinh viên; lặp batch; thử student trùng trong batch, 101 dòng, student không tồn tại | Batch hợp lệ 200, create/update đúng; không tạo điểm trùng; batch invalid bị chặn, không ghi một phần | `UpsertSubjectScoresRequestDTOTest`, `ScoreAdministrationServiceImplTest`; cần DB thật cho atomicity |
| F-P10 / P1 / T + M | Danh mục đang được dùng; một score thử có thể xóa | GET page=0,size=100 rồi page=-1,size=0/101, sort sai; DELETE lớp có student/môn có score; DELETE score thử | Pagination invalid 400; lớp/môn đang dùng 409; xóa score 204; GET sau xóa không còn score; summary cập nhật | Query/service tests, `AdminControllerSecurityTest` |

Kiểm tra bổ sung cho cập nhật điểm đồng thời: hai transaction cùng đọc một
`scores.version`, transaction đầu lưu điểm giữa kỳ và commit, transaction sau
thử lưu điểm cuối kỳ từ bản đọc cũ. Chỉ transaction đầu thành công; transaction
sau rollback với lỗi optimistic locking; điểm, tổng kết và điểm chữ trong DB
thuộc kết quả đã commit. `ScoreUpdateConcurrencyTest` dùng hai thread và hai
transaction JPA/H2 thật; `AdminControllerSecurityTest` kiểm tra lỗi Spring/JPA
được trả thành `409 CONCURRENT_MODIFICATION` với thông báo an toàn. Ca này không
thay thế kiểm chứng migration và concurrency trên MySQL thật.

### Fixture request tạo sinh viên

Chỉ dùng mật khẩu do người kiểm thử tự tạo cho tài khoản disposable. Giá trị password dưới đây là placeholder, phải thay trong biến local của công cụ; không dùng cho tài khoản thật.

```json
{
  "username": "zt_student_a",
  "password": "<mat-khau-rieng-cho-fixture>",
  "email": "zt_student_a@example.invalid",
  "firstName": "Sinh viên",
  "lastName": "Kiểm thử A",
  "studentCode": "ZT_SV_A",
  "dateOfBirth": "2004-01-01",
  "gender": "OTHER",
  "classCode": "ZT_TEST_01"
}
```

### Fixture điểm

POST `/api/admin/students/{studentId}/scores` với token ADMIN và subjectId thật của **môn fixture**:

```json
{
  "subjectId": "11111111-1111-4111-8111-111111111111",
  "semester": 1,
  "academicYear": "2026-2027",
  "attendanceScore": 8,
  "midtermScore": 7,
  "finalScore": 9
}
```

Công thức hiện tại: `round_half_up(0.30 × (0.70 × midterm + 0.30 × attendance) + 0.70 × final, 1)`. Điểm chữ dùng điểm đã làm tròn; kiểm tra các biên 4.0, 4.8, 5.5, 6.3, 7.0, 7.8, 8.5, 9.0 và giá trị sát biên bằng `ScoreCalculatorTest`.

## 3. Risk scoring và telemetry — 9 ca

| ID / mức / cách | Tiền điều kiện | Bước thực hiện | Kết quả mong đợi | Test hoặc nguồn liên quan |
|---|---|---|---|---|
| F-R01 / P0 / T + M | Request authorized; device mới, thiếu temporal hoặc network intelligence tắt | Evaluate; login qua browser; ghi dataStatus/reasons/decision | STEP_UP_MFA vì INCOMPLETE hoặc device guardrail; không mặc định LOW/ALLOW do feature thiếu | `RiskEvaluationServiceTests`, feature extractor tests |
| F-R02 / P0 / T + M | Data COMPLETE; không priority/mandatory guardrail; policy dev 40/75 | Unit fixture score 39.99, 40, 74.99, 75; thêm weighted sum 39.995/74.995 trước làm tròn; E2E bằng fixture thích hợp | Weighted sum làm tròn HALF_UP 2 số thập phân trước phân loại: 39.995 thành 40, 74.995 thành 75; score dưới 40 ALLOW, 40 tới dưới 75 STEP_UP_MFA, từ 75 DENY | `RiskScoringServiceTests`; ca biên bổ sung nếu assertion hiện có chưa phủ |
| F-R03 / P0 / T + M | IP fixture nằm blocked list, hoặc device security-revoked | Đặt các feature khác thấp/thiếu; evaluate và thử browser login | Priority DENY thắng score thấp và INCOMPLETE; không cấp phiên mới từ attempt bị deny | `BlockedIpPrioritySecurityRuleTests`, `RiskEvaluationServiceTests`, `DeviceRecognitionServiceTests` |
| F-R04 / P0 / T + M | Network hoặc authentication history high; weighted score thấp | Evaluate với fixture; lặp khi weighted score đã HIGH | Mandatory MFA giữ STEP_UP_MFA dù score thấp; không hạ DENY thành STEP_UP khi score HIGH | `RiskScoringServiceTests`, network/history calculator tests |
| F-R05 / P0 / T + M | Risk trả decision DENY | POST evaluate; quan sát HTTP/body; login qua SPI | API evaluate có thể 200 + DENY; SPI chặn với trang lỗi 403; không coi 200 là ALLOW | `RiskApiSecurityTests`, `RiskDecisionHandlerTest` |
| F-R06 / P0 / T + M | Hai fixture failure mode DENY/STEP_UP_MFA; Risk stub timeout/response lỗi | Thử từng mode với timeout, 5xx hoặc response sai; hoàn thành MFA ở fallback | DENY mode chặn; fallback mode yêu cầu MFA, không tạo trust eligibility/cookie mới; không fail-open | `RiskAuthenticatorTest`, `RiskDecisionHandlerTest`, `HttpRiskScoringClientTest` |
| F-R07 / P1 / T + M | Event fixture có eventId ổn định; Redis/MySQL thật cho phần M | Gửi cùng failure event hai lần, rồi success event hai lần; kiểm tra số tăng; quan sát TTL failure | Failure duplicate không tăng hai lần; success duplicate không thêm hai baseline; failure window hết hạn đúng cấu hình | `RedisAuthenticationFailureStoreTests`, `AuthenticationSuccessServiceTests`; mock chưa chứng minh Lua/TTL |
| F-R08 / P1 / T + M | Dependency telemetry local riêng có thể gián đoạn | Giả lập Redis lỗi khi đọc history; lỗi gửi event sau login/password sai; khôi phục | History unavailable dẫn INCOMPLETE/MFA; lỗi listener không đổi kết quả xác thực Keycloak; không rò event/token trong log | History tests, `RiskEventListenerTest` |
| F-R09 / P1 / T + M | CIDR/GeoIP fixture và baseline temporal; clock cố định trong unit test | Thử CIDR trùng policy country; GeoIP disabled/missing mmdb/private IP; thời gian quen/lạ/cold start | CIDR áp precedence hiện có; GeoIP thiếu không gán điểm an toàn; temporal ít lịch sử giữ INCOMPLETE; reasons phản ánh nguồn thực | `NetworkRiskCalculatorTests`, `MaxMindGeoIpProviderTests`, `TemporalRiskCalculatorTests` |

Fixture API evaluate dùng service token `risk:evaluate`; thay subject bằng Keycloak UUID của fixture. Timestamp evaluate lấy từ server, không do caller chọn:

```json
{
  "subjectId": "22222222-2222-4222-8222-222222222222",
  "authenticationSessionId": "zt-test-session-01",
  "clientId": "zerotrust-spa",
  "ipAddress": "192.0.2.10",
  "userAgent": "ZeroTrust-Test/1.0",
  "deviceId": null
}
```

## 4. Thiết bị tin cậy — 7 ca

| ID / mức / cách | Tiền điều kiện | Bước thực hiện | Kết quả mong đợi | Test hoặc nguồn liên quan |
|---|---|---|---|---|
| F-D01 / P0 / T + M | User đã enrollment; evaluation STEP_UP thật, generation hợp lệ | OTP thành công; quan sát register rồi Set-Cookie và bản ghi Risk | Register 204 trước khi cấp ZT_DEVICE_ID; hash lưu gắn subject; cookie HttpOnly, SameSite=Lax, realm path; Secure trên HTTPS | `TrustedDeviceRegistrationAuthenticatorTest`, `KeycloakDeviceCookieWriterTest`, registration tests |
| F-D02 / P0 / T + M | BROWSER_TRUSTED; mọi feature COMPLETE/thấp | Login mới cùng profile, rồi tạo tình huống network/history high | Thiết bị được recognized; ALLOW chỉ khi tất cả điều kiện đủ; trust không bỏ guardrail MFA/DENY | `DeviceRecognitionServiceTests`, feature tests |
| F-D03 / P0 / T + M | User còn required action CONFIGURE_TOTP | Login/enroll lần đầu; kiểm tra trust; sau đó login mới với OTP | Không tạo trust khi enrollment còn pending ở registration execution; login MFA hợp lệ tiếp theo có thể tạo | `TrustedDeviceRegistrationAuthenticatorTest` |
| F-D04 / P0 / T + M | Device trusted; có clock fixture hoặc bản ghi local snapshot | Evaluate ngay trước và đúng/sau hạn server 30 ngày; giữ cookie chưa hết hạn | Server expiry thắng cookie; sau expiry cần reauthentication; MFA hợp lệ rotate ID, không hồi sinh ID hết hạn | `KnownDeviceEntityTests`, `DeviceRecognitionServiceTests`, registration authenticator tests |
| F-D05 / P0 / T + M | Có thiết bị security-revoked và thiết bị MFA-reset riêng | Evaluate từng ID; thử register lại với generation hiện tại | Security-revoked vẫn DENY/reject; MFA-reset cần reauthentication và ID mới; không gộp hai loại revoke | Device recognition/entity/lifecycle tests |
| F-D06 / P0 / T + M | OTP đã thành công; Risk registration stub trả timeout/200/409/5xx | Thử từng response; kiểm tra cookie/trust và login hiện tại | Chỉ 204 được coi register thành công; lỗi không cấp cookie trust mới; 409 expire cookie bị từ chối; login đã MFA có thể hoàn tất | `HttpRiskScoringClientTest`, `TrustedDeviceRegistrationAuthenticatorTest` |
| F-D07 / P0 / T + M | BROWSER_TRUSTED và profile mới | Xóa cookie hoặc đặt ID ngẫu nhiên/sai định dạng; login lại | Cookie mất/sai không bypass password/MFA; không recognized thành thiết bị trusted; cookie không thay token | Context/device recognition tests; P16/P17 |

## 5. Reset MFA và lỗi liên dịch vụ — 8 ca

| ID / mức / cách | Tiền điều kiện | Bước thực hiện | Kết quả mong đợi | Test hoặc nguồn liên quan |
|---|---|---|---|---|
| F-M01 / P0 / T + M | ADMIN_A; user thử ACTIVE có OTP/recovery/trust | POST reset bằng **Portal user ID**; kiểm tra audit/state/Keycloak; đăng nhập lại | Revoke → Keycloak reset → completion; 204 sau cả ba bước; generation tăng, trust cũ thu hồi, session/credential cũ xử lý theo gateway; enrollment lại | `UserServiceImplTest`, `KeycloakUserClientTest`, lifecycle/controller tests |
| F-M02 / P0 / T + M | USER_INACTIVE hoặc Portal user ID không tồn tại | Gửi reset với token admin | INACTIVE 403; không tồn tại 404; không gọi revoke/reset cho subject khác | `UserServiceImplTest` |
| F-M03 / P0 / T + M | Revoke call lỗi/timeout ở fixture | Reset; kiểm tra stage log và Keycloak credential; kiểm tra Risk state | Portal 503 RISK_DEVICE_REVOCATION_FAILED; không tiếp tục Keycloak reset; timeout vẫn phải kiểm tra Risk có thể đã commit | `UserServiceImplTest`, `RiskDeviceAdminClientTest` |
| F-M04 / P0 / T + M | Revoke thành công; Keycloak reset lỗi | Reset rồi evaluate/login mới của user thử | 503 MFA_RESET_PARTIAL; pending chưa được gỡ; evaluate khi Risk reachable trả DENY/MFA_RESET_IN_PROGRESS; không báo thành công | `UserServiceImplTest`, reset controller tests |
| F-M05 / P0 / T + M | Keycloak reset xong; completion lỗi/timeout | Reset; kiểm tra credential, pending; khôi phục và retry có kiểm soát | 503 MFA_RESET_COMPLETION_PENDING; không coi reset hoàn tất; không khôi phục trust cũ; phân biệt completion đã commit nhưng response mất | `UserServiceImplTest`, `RiskDeviceAdminClientTest` |
| F-M06 / P0 / T + M | MFA attempt lấy generation g; pause trước register | Admin reset tới generation g+1; tiếp tục register của attempt cũ, kể cả device ID mới | Register stale generation 409, không trust/cookie mới; attempt login đã MFA có thể xong nhưng không được re-trust | `DeviceTrustLifecycleTests`, registration tests |
| F-M07 / P0 / T + M | Hai reset operation riêng; caller revoke hợp lệ | Replay cùng operation/requester; thử sai requester/subject; complete operation cũ sau reset mới | Replay hợp lệ idempotent; sai binding hoặc completion cũ chưa hoàn tất 409; không gỡ pending của operation mới | `DeviceTrustLifecycleTests`, `TrustedDeviceRevocationControllerTests`; Portal retry tạo operation mới |
| F-M08 / P0 / T + M | MySQL local disposable; hai request đồng thời | Register đang giữ subject lock; gửi revoke; thử thứ tự ngược với registration g cũ | Revoke chờ commit registration rồi thu hồi device, hoặc registration bị generation fence; không để trust cũ còn active sau revoke | `DeviceTrustLifecycleTests`; chạy M để xác nhận locking MySQL thật |

Các ca timeout/reset/concurrency ưu tiên chạy bằng mock hoặc môi trường disposable. Không sửa generation/pending trực tiếp để làm test qua. Chặn reset-pending phụ thuộc Risk được gọi và failure mode; fallback MFA khi Risk unavailable không bảo đảm kiểm tra pending, xem P20.

## 6. Điểm trace trong mã

Đường dẫn dưới đây tính từ gốc repository:

- Portal: `src/main/java/com/zerotrust/zerotrust/config/SecurityConfig.java`, `controller/`, `service/impl/UserServiceImpl.java`, `service/impl/ScoreCalculator.java`, `risk/RiskDeviceAdminClient.java`.
- Risk: `risk-scoring-service/src/main/java/com/zerotrust/risk/config/RiskApiSecurityConfig.java`, `service/RiskEvaluationService.java`, `service/DeviceTrustLifecycle.java`, `service/TrustedDeviceRegistrationService.java`, `controller/RiskEvaluationController.java`.
- SPI: `keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/policy/RiskDecisionHandler.java`, `authenticator/TrustedDeviceRegistrationAuthenticator.java`, `context/KeycloakDeviceCookieWriter.java`.
- Frontend: `frontend/lib/keycloak.ts`, `frontend/lib/api.ts`, `frontend/lib/admin-api.ts`.

Khi gặp kết quả khác expected, lưu request/response đã che dữ liệu, state trước/sau và stage liên dịch vụ. Dùng [mẫu báo cáo](REPORT_TEMPLATE.md), không sửa code/realm ngay trong lúc thu thập bằng chứng.
