# PD-02-01 — Backend academic read-only verification

Evidence ID: **EV-PD-02-01-01**. Ngày **06/11/2026, GMT+7**.
Nguồn: canonical working tree trên branch `zerotrust-v4-risk-scoring`, base HEAD
`c401e17029d64f9a96738d845b8c0ad0f03fc164`; source chưa commit, không deploy.
Phạm vi: **CONTROLLED OFFLINE — source/configuration + direct Backend MockMvc/security/service/JPA/H2**.
Tiến độ chính thức chỉ ở [PUBLIC_DEMO_ROADMAP](../PUBLIC_DEMO_ROADMAP.md).

## Cơ chế và cấu hình được kiểm chứng

- `PublicDemoAcademicReadOnlyFilter` nằm **sau AuthorizationFilter** trong chuỗi Spring Security
  của Portal. JWT/URL roles được kiểm trước; method/service authorization hiện có vẫn giữ.
  Không đăng ký filter như servlet bean thứ hai và không sửa Gateway/UI/Keycloak/Risk.
- Filter dùng **RequestMappingHandlerMapping thực tế** để phân loại handler mà MVC sẽ chạy,
  không cấp quyền dựa riêng vào GET hoặc prefix URL. `@PublicDemoEndpoint(READ)` chỉ nhận
  GET/HEAD; thao tác học vụ không có annotation và handler chưa phân loại bị từ chối.
  Cả alias và GET có side effect mới đều default deny. Unknown mapping/unsupported method
  được từ chối; lỗi phân loại không cho request chạy tiếp. GET/HEAD của BasicErrorController
  giữ được xử lý lỗi, không là ngoại lệ cho academic controller.
- `SECURITY_STATE` hiện chỉ đánh dấu **POST reset MFA ADMIN sẵn có**. Filter không cấp role mới,
  không thay policy/lifecycle reset, không mở thêm public route. Quyết định D-10 vẫn pending.
  Risk evaluation/trust/events/counters ở service khác không nằm trong filter này.
- Request protected thiếu xác thực **401**; authenticated academic mutation **403** trước khi
  controller/service được gọi. Path không hợp lệ có thể bị StrictHttpFirewall trả **400**.
  CORS preflight thành công không cho phép academic POST phía sau.

Hai marker cấu hình của deployment Public Demo:

```properties
PUBLIC_DEMO_MODE=public-demo
PUBLIC_DEMO_ACADEMIC_READ_ONLY=true
```

`application.properties` bind các marker **độc lập active profile**. Mode enum sai/flag thiếu,
false hoặc khác literal `true` ở Public Demo làm context thất bại. Chỉ có flag nhưng mode LAB
cũng thất bại, tránh bỏ sót selector. `application-public-demo.properties` không có fallback
cho cả hai biến; profile `public-demo` không thể override sang LAB để mở CRUD.
Đủ hai marker thì thiếu hoặc gõ nhầm tên profile vẫn bật guard, đã test.
Không khai báo marker/profile Public Demo thì default LAB giữ hành vi cũ.

Đây chỉ là contract chọn chế độ. Nếu loại bỏ **mọi** dấu hiệu Public Demo khỏi deployment,
ứng dụng không thể tự suy ra mục đích thay cho LAB. PD-03-03 phải pin/validate mode và flag
ngoài lựa chọn profile; PD-04-04/PD-06-03 phải kiểm effective configuration và thử ghi trên
đúng artifact. Không coi lựa chọn profile đơn độc hoặc report này là deployment proof.
Không thêm fail-fast DB/TLS/grants/schema thuộc PD-02-03 trong task này.

## Endpoint coverage matrix — source hiện tại

Đã đối chiếu toàn bộ ba controller Portal và service/repository mà chúng gọi.
**22 mappings = 11 READ + 10 ACADEMIC WRITE + 1 SECURITY STATE**.
Không có PUT endpoint hay academic write qua GET trong source hiện tại; PUT và GET mutation
probes vẫn có negative tests. HEAD dùng handler GET tương ứng; OPTIONS là protocol/preflight.
Inventory regression so sánh các mappings thực với danh sách dưới đây để buộc review khi đổi route.

| Method / endpoint | Phân loại / đường thực thi | Kiểm chứng trong Public Demo |
|---|---|---|
| GET /api/admin/student-classes | READ; StudentClassAdministrationService.getStudentClasses | ADMIN GET/HEAD 200, School snapshot không đổi |
| POST /api/admin/student-classes | ACADEMIC WRITE; createStudentClass | ADMIN/STUDENT 403; anonymous 401; snapshot không đổi |
| DELETE /api/admin/student-classes/{classId} | ACADEMIC WRITE; deleteStudentClass | ADMIN/STUDENT 403; anonymous 401; snapshot không đổi |
| GET /api/admin/subjects | READ; SubjectAdministrationService.getSubjects | ADMIN GET/HEAD 200, snapshot không đổi |
| POST /api/admin/subjects | ACADEMIC WRITE; createSubject | ADMIN/STUDENT 403; anonymous 401; snapshot không đổi |
| DELETE /api/admin/subjects/{subjectId} | ACADEMIC WRITE; deleteSubject | ADMIN/STUDENT 403; anonymous 401; snapshot không đổi |
| GET /api/admin/subjects/{subjectId}/score-sheet | READ; ScoreAdministrationService.getSubjectScoreSheet | ADMIN GET/HEAD 200, snapshot không đổi |
| POST /api/admin/subjects/{subjectId}/scores/batch | ACADEMIC WRITE; upsertSubjectScores | ADMIN/STUDENT 403; anonymous 401; snapshot không đổi |
| POST /api/admin/students/{studentId}/scores | ACADEMIC WRITE; createStudentScore | ADMIN/STUDENT 403; anonymous 401; snapshot không đổi |
| GET /api/admin/students/{studentId}/scores | READ; getStudentScores | ADMIN GET/HEAD 200, snapshot không đổi |
| PATCH /api/admin/scores/{scoreId} | ACADEMIC WRITE; updateScore | ADMIN/STUDENT 403; anonymous 401; snapshot không đổi |
| DELETE /api/admin/scores/{scoreId} | ACADEMIC WRITE; deleteScore | ADMIN/STUDENT 403; anonymous 401; snapshot không đổi |
| POST /api/admin/students | ACADEMIC WRITE + remote provisioning; StudentCreationService → IdP + StudentPersistenceService | ADMIN/STUDENT 403; anonymous 401; no IdP/Risk call, snapshot không đổi |
| GET /api/admin/students | READ; StudentQueryService.getStudents | ADMIN GET/HEAD 200; STUDENT 403 |
| GET /api/admin/students/{id} | READ; StudentQueryService.getStudent | ADMIN GET/HEAD 200; STUDENT vẫn không được vào ADMIN route |
| PATCH /api/admin/students/{id} | ACADEMIC WRITE + possible remote profile update; StudentUpdateService → IdP + StudentPersistenceService | ADMIN/STUDENT 403; anonymous 401; no IdP/Risk call, snapshot không đổi |
| GET /api/admin/users | READ; UserService.getAllUsers | ADMIN GET/HEAD 200, snapshot không đổi |
| POST /api/admin/users/{id}/mfa/reset | SECURITY STATE; UserService.resetMfa → Risk revoke → IdP reset → Risk complete | ADMIN 204 đúng thứ tự, School không đổi; STUDENT 403; anonymous 401 |
| GET /api/students/me | READ; StudentQueryService.getCurrentStudent | STUDENT GET/HEAD 200; dùng JWT subject, không nhận studentId của caller làm owner |
| GET /api/students/me/scores | READ; getCurrentStudentScores | STUDENT GET/HEAD 200; query studentId khác không lộ điểm; subject khác nhận dữ liệu của chính mình |
| GET /api/students/me/scores/summary | READ; getCurrentStudentScoreSummary | STUDENT GET/HEAD 200, snapshot không đổi |
| GET /api/users/me | READ; UserService.getCurrentUser | Authenticated GET/HEAD 200, snapshot không đổi; source lấy owner từ JWT sub |

Các read service được rà theo code; không thấy academic save/delete, remote provisioning hay
security-state update trong các handler READ này. Security reset chỉ đọc UserEntity trong
School rồi gọi các biên Risk/IdP. Không block toàn bộ POST của hệ thống.

Security-state ngoài Portal, **SOURCE REVIEWED / không gọi live trong task này**:

| Thành phần / routes | State vẫn cần ghi / giới hạn bằng chứng |
|---|---|
| Keycloak/SPI login/password/OTP/enrollment/logout/token | Keycloak session/credential/auth state; source/flow/realm không đổi, chưa browser nghiệm thu lại |
| POST /internal/v1/risk/evaluations | Risk evaluation/history/feature state; caller + risk:evaluate giữ nguyên |
| POST /internal/v1/trusted-devices | Trust registration sau MFA; caller + risk:device:write giữ nguyên |
| POST /internal/v1/authentication-failures và /authentication-successes | History/security events/Redis counter-dedup; risk:events:write giữ nguyên |
| POST /internal/v1/subjects/{subjectId}/trusted-devices/revocations và /completion | Caller portal-risk-admin + risk:device:revoke; mock Portal integration xác nhận orchestration, không thay logic Risk |

## Regression execution

JDK **17.0.10**, Maven Wrapper offline trên host. JAVA_HOME/Path chỉ thay trong process kiểm thử.
Không tạo container/Compose project/volume/worktree/source copy; không kết nối Lab stores/realm.
H2 URL của integration mới là `jdbc:h2:mem:public-demo-readonly`, profile `test`, IdP/Risk mock.

Lệnh thực sự chạy từ canonical repository, với JDK 17 được chọn:

```powershell
.\mvnw.cmd --offline --batch-mode --no-transfer-progress '-Dtest=PublicDemoConfigurationTest,PublicDemoAcademicReadOnlyTest' test
.\mvnw.cmd --offline --batch-mode --no-transfer-progress test
```

| Run | Tests | Failures | Errors | Skipped | Result / kết thúc GMT+7 |
|---|---:|---:|---:|---:|---|
| Targeted, hai class mới | 90 | 0 | 0 | 0 | BUILD SUCCESS, 06/11/2026 11:40:42 |
| Full Portal suite, 45 classes | 417 | 0 | 0 | 0 | BUILD SUCCESS, 06/11/2026 11:42:07 |

90 tests mới đã nằm trong 417, **không cộng thành 507 unique tests**.
Hai class mới: PublicDemoConfigurationTest **18**; PublicDemoAcademicReadOnlyTest **72**.
Negative startup tests cố ý tạo context failure; Maven vẫn PASS vì đúng expected rejection.
Log constraint violations của các test DB cũ cũng là expected negative cases, không là suite failure.

Coverage mới gồm 20 ADMIN/STUDENT write cases, 10 anonymous write cases, 22 GET/HEAD reads,
ownership, sai role/no bearer, PUT/PATCH/DELETE/POST trên read route, path variants,
method override, unclassified GET/POST aliases, CORS, MFA reset orchestration/authorization,
mapping inventory và 18 startup configuration cases.
Mỗi denied mutation/path case kiểm dữ liệu **cả năm bảng** `users`, `students`,
`student_classes`, `subjects`, `scores` qua JDBC snapshots sau flush/clear, gồm values/version,
không chỉ đếm rows. Fixtures synthetic được rollback sau từng test.

Full suite còn kiểm default LAB ADMIN CRUD, STUDENT ownership, signed-JWT decoder,
IdP provisioning/compensation và MFA reset failure/revoke/complete contracts hiện có.
Không thay assertion hay skip test để có kết quả xanh.

## Giới hạn và phần còn mở

- Đây không là LIVE VERIFIED. MockMvc đi thẳng vào Backend filter/controller/service/JPA,
  không qua Gateway; chưa chứng minh port/firewall/ingress của deployment thật.
- Jwt request post-processor kiểm authorization, không chứng minh phát token/JWKS/issuer
  live. Full suite có decoder tests riêng với JWKS test; không là browser Keycloak acceptance.
- H2 snapshots không chứng minh MySQL grants/TLS/migration/SELECT-only hoặc schema production.
  DB user SELECT-only sẽ cần ở PD-02-03/PD-04-02 và kiểm deployment ở PD-04-04/PD-06-03.
- MFA reset trong test chỉ mock orchestration; OTP/login/trust/Redis/B0/mandatory/priority/fail-closed
  runtime chưa test lại. Không sửa source các service đó hoặc dùng logs cũ để tuyên bố PASS mới.
- PR-005 **OPEN**: root stale update concurrency vẫn tồn tại khi CRUD được bật. Chỉ sau
  Staging và final candidate proof mới xét MITIGATED FOR PUBLIC DEMO, không phải FIXED.
- PR-015 **OPEN**: grade-write boundary mới có source evidence; retention/privacy/security audit
  chưa thực hiện. PR-002 **OPEN**: mới có mode guard, toàn bộ fail-fast DB contract còn PD-02-03.
- Public admin MFA reset exposure/operator policy tiếp tục theo D-10/PD-02-04/06. Không dùng
  việc giữ hành vi backend hiện có làm approval mở endpoint đó ra Internet.

## Preservation verification

Đối chiếu hashes của các file có trước task và selected Docker metadata trước/sau:
Git HEAD giữ nguyên; 10 Lab containers vẫn exited, IDs/images/mounts/networks không đổi.
README pointers, tài liệu/untracked có trước, 39 audit/evidence files cũ, Compose/Dockerfiles/CI,
Gateway/Risk/SPI source và mọi cấu hình Lab có trong repository giữ nguyên byte.
Chỉ thay source/config/tests Portal trực tiếp của task, roadmap và evidence mới này.
Không start/restart/recreate, không đọc/ghi Lab DB/Redis/realm/secrets, không commit/push/deploy.

## Source/test working-tree manifest

SHA-256 ghi nhận đúng source/tests đã được test, không phải release SHA/digest.

| File | SHA-256 |
|---|---|
| [SecurityConfig.java](../../../src/main/java/com/zerotrust/zerotrust/config/SecurityConfig.java) | `ffa4f86fdb6e021a1957a21c5f3e46446d549c36b1b34d532b984248d8b47f57` |
| [PublicDemoConfiguration.java](../../../src/main/java/com/zerotrust/zerotrust/config/PublicDemoConfiguration.java) | `ab65abfc60bbe9a8a1e9bcff7569531209c53b60f598671e4fa9dd2855c36a2c` |
| [PublicDemoProperties.java](../../../src/main/java/com/zerotrust/zerotrust/config/PublicDemoProperties.java) | `a7fb0de2ae6453af9f064fa9d21707d874e2a382aa6ce7d713dd202bcd5c7803` |
| [PublicDemoAcademicReadOnlyFilter.java](../../../src/main/java/com/zerotrust/zerotrust/security/PublicDemoAcademicReadOnlyFilter.java) | `5bb61f394415b1b233c4790eb13a94098e7811472d9aad1ed0e27342e5f75b2d` |
| [PublicDemoEndpoint.java](../../../src/main/java/com/zerotrust/zerotrust/security/PublicDemoEndpoint.java) | `723892c37fd5cae8119e603be3b0b4c89d78697ccf2ba72061d1dcefbd86afcb` |
| [AdminController.java](../../../src/main/java/com/zerotrust/zerotrust/controller/AdminController.java) | `f1c4f4d2cabeeb1f412ff6f422c088500c3c87c3dacebfb6f8c4f4204656944d` |
| [StudentController.java](../../../src/main/java/com/zerotrust/zerotrust/controller/StudentController.java) | `460b3700fae4f0bb1eccfeefc7b2b580189af8bd744f56253c30514d774592cb` |
| [UserController.java](../../../src/main/java/com/zerotrust/zerotrust/controller/UserController.java) | `fa24dbe5edb2126af1d456bc0aaedfde3cda13e1a682c79412aff6c2bac2e62e` |
| [application.properties](../../../src/main/resources/application.properties) | `912f434b17a15a224a45b4f44c04eaed55940d8741f9e17994d74d0782c4c284` |
| [application-public-demo.properties](../../../src/main/resources/application-public-demo.properties) | `7409252cfe88eb4e03f3c84abd919e50ee75b2f318dc7ef7437740d22a0b54d2` |
| [PublicDemoConfigurationTest.java](../../../src/test/java/com/zerotrust/zerotrust/config/PublicDemoConfigurationTest.java) | `be84ed779e02fba66ca72c18df4c3d48ff2104f44a56ddc6c078870a176605d5` |
| [PublicDemoAcademicReadOnlyTest.java](../../../src/test/java/com/zerotrust/zerotrust/controller/PublicDemoAcademicReadOnlyTest.java) | `1cd4bc784732395cc7ce9f5bd9dcddc21d4a3b1dccb8935f78f4db76a64981fb` |

## Full Portal results by class

JUnit XML được tổng hợp từ target/surefire-reports sau full run; đây là output local, không phải artifact phát hành.

| Test class | Tests | Failures | Errors | Skipped |
|---|---:|---:|---:|---:|
| config.KeycloakAdminConnectionPoolTest | 1 | 0 | 0 | 0 |
| config.KeycloakAdminPropertiesTest | 18 | 0 | 0 | 0 |
| config.PortalJwtDecoderTest | 7 | 0 | 0 | 0 |
| config.PublicDemoConfigurationTest | 18 | 0 | 0 | 0 |
| config.SecurityConfigTest | 3 | 0 | 0 | 0 |
| controller.AdminControllerSecurityTest | 49 | 0 | 0 | 0 |
| controller.PublicDemoAcademicReadOnlyTest | 72 | 0 | 0 | 0 |
| controller.SchoolPortalPersistenceAcceptanceTest | 2 | 0 | 0 | 0 |
| controller.StudentControllerSecurityTest | 6 | 0 | 0 | 0 |
| controller.UserControllerTest | 2 | 0 | 0 | 0 |
| converter.UserConverterTest | 4 | 0 | 0 | 0 |
| entity.ScoreEntityMappingTest | 2 | 0 | 0 | 0 |
| entity.UserEntityLifecycleTest | 3 | 0 | 0 | 0 |
| identity.keycloak.KeycloakExceptionMapperTest | 7 | 0 | 0 | 0 |
| identity.keycloak.KeycloakRoleClientTest | 4 | 0 | 0 | 0 |
| identity.keycloak.KeycloakUserClientTest | 19 | 0 | 0 | 0 |
| model.request.CreateScoreRequestDTOTest | 3 | 0 | 0 | 0 |
| model.request.CreateStudentClassRequestDTOTest | 2 | 0 | 0 | 0 |
| model.request.CreateStudentRequestDTOTest | 2 | 0 | 0 | 0 |
| model.request.CreateSubjectRequestDTOTest | 2 | 0 | 0 | 0 |
| model.request.ScoreValueContractTest | 7 | 0 | 0 | 0 |
| model.request.UpdateScoreRequestDTOTest | 2 | 0 | 0 | 0 |
| model.request.UpdateStudentRequestDTOTest | 2 | 0 | 0 | 0 |
| model.request.UpsertSubjectScoresRequestDTOTest | 3 | 0 | 0 | 0 |
| repository.StudentClassRepositoryTest | 1 | 0 | 0 | 0 |
| repository.StudentRepositoryTest | 1 | 0 | 0 | 0 |
| repository.SubjectRepositoryTest | 2 | 0 | 0 | 0 |
| risk.RiskAdminPropertiesTest | 13 | 0 | 0 | 0 |
| risk.RiskDeviceAdminClientHttpTest | 1 | 0 | 0 | 0 |
| risk.RiskDeviceAdminClientTest | 20 | 0 | 0 | 0 |
| security.CredentialExposureTest | 3 | 0 | 0 | 0 |
| service.impl.ScoreAdministrationServiceImplTest | 34 | 0 | 0 | 0 |
| service.impl.ScoreCalculatorTest | 21 | 0 | 0 | 0 |
| service.impl.ScoreUpdateConcurrencyTest | 1 | 0 | 0 | 0 |
| service.impl.student.StudentCreationServiceTest | 5 | 0 | 0 | 0 |
| service.impl.student.StudentPersistenceServiceTest | 2 | 0 | 0 | 0 |
| service.impl.student.StudentQueryServiceTest | 6 | 0 | 0 | 0 |
| service.impl.student.StudentUpdateServiceTest | 6 | 0 | 0 | 0 |
| service.impl.StudentAdministrationServiceImplTest | 4 | 0 | 0 | 0 |
| service.impl.StudentClassAdministrationServiceImplTest | 8 | 0 | 0 | 0 |
| service.impl.SubjectAdministrationServiceImplTest | 11 | 0 | 0 | 0 |
| service.impl.SubjectCreationTransactionTest | 4 | 0 | 0 | 0 |
| service.impl.UserServiceImplTest | 8 | 0 | 0 | 0 |
| service.support.QueryParametersTest | 18 | 0 | 0 | 0 |
| ZerotrustApplicationTests | 8 | 0 | 0 | 0 |
