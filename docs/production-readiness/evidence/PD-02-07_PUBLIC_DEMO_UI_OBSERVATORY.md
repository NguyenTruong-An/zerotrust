# PD-02-07 — Public Demo UI & Risk Observatory Boundary

**EV-PD-02-07-01 · PD-R8 · 07/11/2026, Asia/Saigon (GMT+7)**

**PASS — source, production build cục bộ và kiểm thử cô lập.** Runtime trên release candidate và Production chưa được nghiệm thu. Quyết định chương trình vẫn là **NO-GO FOR PUBLIC ACCESS**.

Base SHA `c401e17029d64f9a96738d845b8c0ad0f03fc164`, branch `zerotrust-v4-risk-scoring`, working tree có sẵn thay đổi PD-02-01–06. Phạm vi này dựa trên Backend read-only của PD-02-01, cấu hình dữ liệu PD-02-03 và ranh giới ingress/service identity PD-02-05/06. [Master Roadmap](../PUBLIC_DEMO_ROADMAP.md) · [PD-02-01](PD-02-01_BACKEND_READ_ONLY.md) · [PD-02-03](PD-02-03_FAIL_FAST_CONFIGURATION.md) · [Ingress contract](../../../deploy/public-demo/INGRESS_CONTRACT.md) · [Secrets và identity contract](../../../deploy/public-demo/SECRETS_IDENTITY_CONTRACT.md)

## 1. Kiểm kê routes và thao tác

Các path API dưới đây bỏ phần query phân trang, tìm kiếm và bộ lọc. `{id}` là UUID của tài nguyên thích hợp.

| Route / component | Thao tác và API thực tế | Phân loại |
|---|---|---|
| `/`, `PortalRoute`, `/silent-check-sso.html` | Keycloak check-sso, đăng nhập, chuyển trang theo role. Trang silent check trả kết quả về parent cùng origin. | SECURITY/IDENTITY ACTION |
| `/admin`, `OverviewPanel` | Khi tải trang, GET `/api/admin/students`, `/api/admin/student-classes`, `/api/admin/subjects` lấy tổng số. Điều hướng qua menu và các thẻ thống kê. | READ VIEW |
| `/admin`, thao tác nhanh | Chế độ chuẩn liên kết tới luồng tạo sinh viên, lớp, môn và nhập điểm. Click shortcut điều hướng, form đích mới thực hiện ghi. | ACADEMIC WRITE UI |
| `/admin/students`, `StudentsPanel` | GET danh sách sinh viên và lớp cho bộ lọc, GET `/api/admin/students/{id}` khi mở hồ sơ. Tìm kiếm, phân trang, chuyển sang bảng điểm. | READ VIEW |
| `/admin/students`, modal tạo và cập nhật | POST `/api/admin/students` tạo hồ sơ và provisioning tài khoản Keycloak. PATCH `/api/admin/students/{id}` cập nhật hồ sơ. | ACADEMIC WRITE UI |
| `/admin/classes`, `ClassesPanel` | GET `/api/admin/student-classes`, lọc theo khoa/khóa, tìm kiếm và phân trang. | READ VIEW |
| `/admin/classes`, modal tạo và xác nhận xóa | POST `/api/admin/student-classes`, DELETE `/api/admin/student-classes/{id}`. | ACADEMIC WRITE UI |
| `/admin/subjects`, `SubjectsPanel` | GET `/api/admin/subjects`, tìm kiếm, lọc và phân trang. | READ VIEW |
| `/admin/subjects`, modal tạo và xác nhận xóa | POST `/api/admin/subjects`, DELETE `/api/admin/subjects/{id}`. | ACADEMIC WRITE UI |
| `/admin/scores`, `ScoresPanel` | GET sinh viên và danh mục môn. Khi chọn sinh viên, GET `/api/admin/students/{id}/scores`, cho phép lọc và phân trang. | READ VIEW |
| `/admin/scores`, modal nhập, sửa, xóa | POST `/api/admin/students/{id}/scores`, PATCH và DELETE `/api/admin/scores/{id}`. | ACADEMIC WRITE UI |
| `/admin/scores`, `SubjectScoreSheet` | GET danh mục lớp khi mở tab theo môn. GET `/api/admin/subjects/{id}/score-sheet` theo lớp, từ khóa và trang khi chọn tải. | READ VIEW |
| `/admin/scores`, bảng nhập theo môn | Ô chỉnh sửa và nút lưu gọi POST `/api/admin/subjects/{id}/scores/batch`. | ACADEMIC WRITE UI |
| `/admin/users`, `UsersPanel` | GET `/api/admin/users` và lọc danh sách tài khoản synthetic trên client. | READ VIEW |
| `/admin/users`, reset MFA | POST `/api/admin/users/{id}/mfa/reset` sau xác nhận. Endpoint ghi trạng thái bảo mật theo quyền ADMIN hiện hành. | SECURITY/IDENTITY ACTION |
| `/student/scores`, `StudentScoreDashboard` | GET `/api/users/me`, `/api/students/me`, `/api/students/me/scores/summary` và `/api/students/me/scores`. Hồ sơ cá nhân nằm trong trang này. | READ VIEW |
| Header ADMIN/STUDENT | Liên kết Account Security của Keycloak, đăng xuất qua IdP. Adapter refresh access token trong memory. | SECURITY/IDENTITY ACTION |
| `admin-ui`, CSS và tài nguyên tĩnh | Modal, trạng thái chờ/lỗi/trống, phân trang, icon và ảnh. API do component gọi; shell và bộ lọc dùng chung không có endpoint riêng. | READ VIEW / SECURITY/IDENTITY ACTION theo tác vụ chứa |
| Collector, viewer và bản xuất Risk Observatory | File và lệnh cục bộ của operator, tách khỏi frontend. | OPERATOR-ONLY |
| Path ngoài bảng, export chưa phân loại hoặc method/body ngoài contract | Adapter Public Demo từ chối mặc định. Quyền Backend vẫn do JWT, role và endpoint policy quyết định. | UNCLASSIFIED |

Kiểm kê chế độ chuẩn không tìm thấy UI xóa sinh viên, sửa lớp hay sửa môn. Các hành vi ghi thực sự ở trên được đối chiếu với ma trận 22 mappings của PD-02-01. [Ma trận Backend](PD-02-01_BACKEND_READ_ONLY.md) · [ADMIN components](../../../frontend/components/admin-portal.tsx) · [STUDENT component](../../../frontend/components/student-score-dashboard.tsx)

## 2. Giao diện Public Demo

`NEXT_PUBLIC_PORTAL_MODE=public-demo` bật banner chỉ đọc, nhãn tra cứu và shortcut xem bảng điểm. Giao diện dùng lại điều hướng, bảng, modal, bộ lọc và CSS hiện hành. Modal sinh viên hiển thị dữ liệu dưới dạng danh sách trường, không render form cập nhật. Bảng điểm theo môn hiển thị tổng điểm, điểm chữ và kỳ/năm học từ hàng đã lưu. Bộ lọc học kỳ/năm học vốn phục vụ thao tác lưu theo lô được ẩn ở tab này vì endpoint đọc chỉ lọc theo lớp, môn và từ khóa. Chế độ chuẩn vẫn là mặc định. [Layout](../../../frontend/app/layout.tsx) · [Hồ sơ](../../../frontend/components/admin-students.tsx) · [Bảng điểm theo môn](../../../frontend/components/admin-subject-score-sheet.tsx)

## 3. Hành vi ADMIN và STUDENT

- **ADMIN** xem tổng quan, danh sách, hồ sơ, lớp, môn, bảng điểm theo sinh viên hoặc theo môn/lớp và danh sách tài khoản synthetic. Account Security, đăng xuất và reset MFA theo quyền hiện hành vẫn có.
- **STUDENT** xem hồ sơ, tóm tắt và bảng điểm của chính mình. Truy cập trực tiếp trang ADMIN chuyển về `/student/scores` trước khi component quản trị gửi API. Không có role TEACHER hoặc điều hướng operator.
- **Chưa đăng nhập** dùng Keycloak ở route gốc. Kiểm thử Backend xác nhận protected API trả 401 với request thiếu token.

## 4. Bao phủ thao tác ghi học vụ

Public Demo không render shortcut ghi, nút thêm/sửa/xóa, modal ghi hoặc xác nhận xóa, ô nhập điểm, nút lưu theo lô hay vùng thông báo lưu. Các handler ghi thoát sớm. Adapter dùng same-origin, chỉ cho các GET đã phân loại không body và ngoại lệ reset MFA POST không body. Request bị chặn trước refresh hoặc fetch, và fetch Public Demo từ chối redirect. Chế độ chuẩn vẫn mở modal tạo lớp và gửi POST hợp lệ trong kiểm thử DOM cô lập. [Adapter](../../../frontend/lib/api.ts) · [Kiểm thử UI và adapter](../../../frontend/tests/public-demo-ui.test.mjs)

## 5. Xác minh quyền Backend

72 test `PublicDemoAcademicReadOnlyTest` và 18 test `PublicDemoConfigurationTest` chạy lại thành công. Request ghi trực tiếp bằng ADMIN/STUDENT, kể cả provisioning và batch, trả 403 và snapshot các bảng School giữ nguyên. Anonymous trả 401. STUDENT vào API ADMIN trả 403, còn các route `/me` dùng JWT subject và bỏ qua ID sinh viên do client đưa vào. Request sửa method hoặc biến thể path được kiểm tra riêng. Reset MFA synthetic vẫn trả 204 cho ADMIN, 403 cho STUDENT và 401 khi thiếu bearer. Boundary được thực thi ở Backend, độc lập với mode frontend. [Kiểm thử quyền trực tiếp](../../../src/test/java/com/zerotrust/zerotrust/controller/PublicDemoAcademicReadOnlyTest.java)

## 6. Bề mặt Risk Observatory

| Bề mặt | Nguồn và ranh giới |
|---|---|
| Collector và wrapper | `observe.py` cùng wrapper PowerShell/CMD đọc Docker logs của operator, file log được cung cấp rõ ràng hoặc fixture `--demo`. Không lắng nghe HTTP. Lần này chỉ chạy `--demo`. |
| HTML/JSON operator | `.local-legacy/risk-observation/latest/index.{html,json}` là đầu ra mặc định của dữ liệu thực. Preview synthetic tách riêng. HTML nhúng snapshot đã lọc cho operator. Viewer hiển thị dữ liệu bằng text nodes. Snapshot vẫn mang ID/timestamp và ngữ cảnh đủ để truy vết, nên giữ trong vùng operator. |
| Artifacts trình bày | `presentation/` và đầu ra cục bộ `.local-legacy/`, `.local-demo/` nằm ngoài frontend public assets. Giữ nguyên artifacts lịch sử. |
| Route/API nội bộ | Risk và Keycloak SPI sinh trace từ scoring, giao dịch xác thực và lifecycle MFA/trust. Các API Risk private phục vụ service identity. Inventory không có API đọc Observatory trên Portal, controller Risk public hoặc route App Router cho viewer/export. |
| Public ingress và Gateway | Portal host đưa `/api` tới Portal Backend và trang tĩnh tới frontend qua Gateway. Auth host định tuyến realm và resources được phép tới Keycloak. Không có upstream Risk/Observatory trên hai host. |

[Thiết kế Observatory hiện hành](../../testing/RISK_OBSERVATORY.md) · [Collector](../../../scripts/observation/observe.py) · [Ingress renderer](../../../deploy/public-demo/render_ingress.py)

## 7. Kiểm soát truy cập Observatory

NGINX Public Demo và Gateway loại các segment nội bộ/Observatory sau bước kiểm tra path canonical. Danh sách gồm `internal`, `observation`, `observatory`, `risk-observation`, `risk-observatory` cùng biến thể tên thư mục evidence, `raw-trace(s)`, `risk-trace(s)`, `presentation`, `.local-legacy` và `.local-demo`. Matching không phân biệt hoa thường và xử lý alias ký tự percent-encoded. Hai tầng trả 404 trước upstream với các probe tài liệu HTML, JSON, JS, API export và đường dẫn Risk nội bộ đã thử.

Gateway thử 21 request bằng anonymous và token ký tổng hợp cho ADMIN/STUDENT. Tất cả 404 với body rỗng và không có upstream call. NGINX TLS thử 14 request trên cả hai hostname với upstream loopback giả lập và kiểm tra call count không đổi. ADMIN/STUDENT không được cấp quyền operator hoặc truy cập file cục bộ qua HTTP. Quyền filesystem, quyền Docker và phân tách mạng thực tế còn cần nghiệm thu riêng. [Gateway filter](../../../gateway/src/main/java/com/zerotrust/gateway/CanonicalRequestFilter.java) · [Gateway HTTP test](../../../gateway/src/test/java/com/zerotrust/gateway/GatewayAbuseHttpTest.java) · [NGINX HTTP test](../../../scripts/public_demo/test_ingress_http.py)

## 8. Phân loại trường dữ liệu

| Trường | Xử lý trong bản chiếu dùng để trình diễn |
|---|---|
| Evaluation/correlation/event/request ID, account/subject/user/session/device ID, username/email | Bỏ toàn bộ định danh gốc. Dùng nhãn `DEMO-ATTEMPT-01` chỉ trong một bản xuất, không tra ngược hoặc nối giữa các bản. |
| Risk score và risk/calculated/effective level | Số hữu hạn trong miền hoặc enum LOW/MEDIUM/HIGH đã biết. Thiếu hoặc sai kiểu thành `null`. Không tính lại điểm, không suy level hoặc HIGH từ quyết định DENY. |
| Device, network, temporal, authentication history | Chỉ tên bốn nhóm đã biết và các số `score`, `weight`, `contribution` trong miền hợp lệ. Bỏ toàn bộ input, source, reason và chi tiết sự kiện. |
| Decision, data status, MFA evidence, Keycloak outcome | Enum cố định từ snapshot. MFA proof, challenge, enrollment và kết quả login phân biệt. Không đổi trạng thái thiếu thành thành công. |
| Timestamp, IP, User-Agent, fingerprint, timezone, location, ASN/org, trust/cookie context, header/URL và raw auth context | Giữ ngoài bản chiếu. Bản trình diễn này không cần thời gian đánh giá hoặc địa chỉ mạng. |
| Password, OTP, recovery credential, access/refresh token, service JWT, session/Trusted Device cookie, client secret, private key, raw logs, trường chưa phân loại | Bỏ mặc định ở mọi tầng của phép chiếu. Giữ raw logs và HTML/JSON private ngoài tài nguyên công khai. |

## 9. Trình diễn do operator kiểm soát

Operator chọn một attempt đã tương quan trong snapshot cục bộ và chỉ dùng JSON đã chiếu cho phiên trình diễn. CLI đọc file explicit tối đa 16 MiB, yêu cầu vị trí 1-based, từ chối schema/mode sai hoặc attempt có xung đột correlation/detail. Output chỉ tới stdout, không tạo API hay tự phát hành file. Định dạng là `SYNTHETIC_ILLUSTRATION` cho demo fixture, `FILTERED_HISTORICAL` cho snapshot nhập file/Docker, không có chế độ tự gắn nhãn LIVE.

```powershell
python -X utf8 scripts/observation/observe.py --demo --output target/pd-02-07/operator-fixture/index.html
python -X utf8 scripts/observation/filtered_evidence.py --report target/pd-02-07/operator-fixture/index.json --attempt 1
```

Lần chạy thực tế xuất đúng một `SYNTHETIC_ILLUSTRATION` với điểm 27.5, calculated LOW, effective MEDIUM, COMPLETE, STEP_UP_MFA và hai enum kết quả MFA/login riêng. Bốn thành phần đóng góp 15, 12.5, 0, 0 với trọng số 0.25. Đây là số từ fixture có sẵn. Kiểm thử canary xác nhận projection loại ID/timestamp/IP/credentials/private context và giữ đúng số đã quan sát. Collector, HTML viewer và thuật toán ghép snapshot theo ID được giữ nguyên. [CLI](../../../scripts/observation/filtered_evidence.py) · [Kiểm thử projection](../../../scripts/observation/test_filtered_evidence.py)

## 10. Source thay đổi

- **Portal** gồm layout/CSS, trang đăng nhập và các component ADMIN cho sinh viên, lớp/môn, điểm đơn và điểm theo môn. `api.ts` giữ allowlist request. `admin-api.ts` dùng thông báo cố định cho lỗi Public Demo, giữ thông báo trạng thái reset MFA đã phân loại.
- **Build và CI** gồm `.env.example`, `next.config.ts`, `Dockerfile.frontend`, script `npm test` và CI gọi cả bốn suite frontend. Fixture cũ `authentication-contract.test.mjs` chỉ đổi tên biến local từ `module` sang `compiledModule` để tương thích lint, không đổi assertions.
- **Biên HTTP** gồm `CanonicalRequestFilter`, `render_ingress.py` và hai regression HTTP. **Observatory** thêm phép chiếu offline và test. Manifest §18 liệt kê đủ 23 input.

## 11. Kiểm thử hồi quy

| Suite | Kết quả | Điều kiện thực thi |
|---|---|---|
| Frontend `npm test` | 34 PASS, 0 skip, gồm 12 test PD-02-07 | React/DOM thật, TypeScript modules và adapters thật. Router, IdP adapter transport và fetch dùng fixture. Kiểm số và loại request, đọc role-scoped, trạng thái loading/error/empty, error canaries, no write requests và tương thích standard. |
| Portal `verify` | 534 PASS, 0 skip | MockMvc/H2, startup/config/RBAC/ownership, 90 test PD-02-01 và hồi quy JWT/caller/PD-02-06. |
| Gateway `verify` | 112 PASS, 0 skip | WebFlux và HTTP native loopback, synthetic JWKS, RBAC/abuse/forwarding, thêm một test 21 probe operator paths. |
| Risk Service `verify` | 903 PASS, 96 skip | B0, JWT/caller, fail-closed, startup, V5, security. Conditional cases cần runtime HTTP hoặc real stores không chạy. |
| Keycloak SPI `verify` | 251 PASS, 27 skip | HTTP synthetic, response/nonce/JSON, trusted-device and MFA lifecycle, event ID/caller. Conditional runtime cases không chạy. |
| Python Public Demo | 42 PASS, 0 skip | Có NGINX TLS và age native dùng dữ liệu fixture. |
| Python Observatory + JS viewer | 18 + 4 PASS, 0 skip | Gồm 5 test projection mới và test collector/correlation/viewer hiện hữu. |

Java tổng cộng **1.923 test, 1.800 PASS, 123 conditional SKIPPED, 0 failure/error** trên JDK 17.0.21. Các test component/validator là **UNIT VERIFIED**. DOM/API adapters, MockMvc/H2, native HTTP loopback và trình xuất dùng fixture là **CONTROLLED OFFLINE VERIFIED**. Không sử dụng kết quả skip làm acceptance. [Frontend regression](../../../frontend/tests/public-demo-ui.test.mjs) · [Java test V5](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/migration/V5ChecksumContractTest.java)

## 12. Kết quả build frontend

Node 24.22.2, npm 11.21.2 và Next.js 16.4.5. `npm run check` đạt với 0 lỗi lint và typecheck thành công. Còn một warning lint có trước trong `postcss.config.mjs` về anonymous default export.

| Thử nghiệm | Kết quả |
|---|---|
| Standard production build | PASS, đủ tám route ứng dụng và không có banner Public Demo. |
| Public Demo production build | PASS với `https://portal.example.invalid`, `https://auth.example.invalid`, realm synthetic explicit, `zerotrust-spa` và API base rỗng. Tám trang dựng sẵn có banner, manifest chỉ có route Portal và trang lỗi Next. |
| Public Demo với auth localhost | Build dừng khi load config, báo tên biến lỗi, không in giá trị config. |
| Kiểm tra đầu ra | Kiểm 9 browser chunks có auth origin fixture, không có fallback Portal API/Keycloak localhost hoặc token/error canaries. Standalone output và public assets không chứa collector/viewer/export Observatory. |

Mode, site/auth origin, realm, client ID và API base là giá trị công khai được cố định lúc build. Demo yêu cầu hai hostname HTTPS rõ ràng, tách biệt, API same-origin và application realm. Dockerfile nhận `PORTAL_MODE`, `SITE_URL` và tham số public sẵn có. Phase 03 cần kiểm lại args/metadata/config trên artifact được chọn. [Build config](../../../frontend/next.config.ts) · [Dockerfile](../../../deploy/docker/Dockerfile.frontend) · [Next.js build-time environment](https://nextjs.org/docs/app/guides/environment-variables)

## 13. Authentication regression

Login UI vẫn gọi Keycloak với callback cùng origin. Actual `keycloak.ts` trong fixture xác nhận check-sso và PKCE S256, không gửi client secret. Regression adapter xác nhận Authorization dùng token đã refresh, omit cookies, 401 buộc refresh và retry đúng một lần. Route guard, logout với ID hint, lỗi logout có thể thử lại và refresh lỗi trong lúc logout được chạy lại. Keycloak flow, storage token trong memory, MFA/trust, B0 và các contract JWT/nonce/strict response/Event ID không đổi. Nghiệm thu với IdP thật, browser, OTP và Trusted Device thật thuộc các bước downstream. [Auth contract](../../../frontend/tests/authentication-contract.test.mjs) · [Portal route tests](../../../frontend/tests/portal-route.test.mjs)

## 14. Trạng thái PR-005, PR-009 và PR-015

| Finding | Trạng thái | Căn cứ và phần cần chứng minh |
|---|---|---|
| PR-005 | OPEN | UI và Backend read-only có regression. Exact candidate chưa có write-denial witness và School SELECT-only live. Concurrency/stale overwrite trong CRUD mode vẫn tồn tại. |
| PR-009 | OPEN | Đã kiểm biên operator-private và filtered export. Chưa có alert delivery/ack, monitoring, access control vận hành và owner drill. |
| PR-015 | OPEN | Write-denial giảm bề mặt sửa điểm trên source. Retention, purge, quyền vào log/export và security audit cần kiểm chứng riêng. |

## 15. Trạng thái G3, G4 và G6

| Gate | Trạng thái | Evidence bổ sung và điều kiện còn thiếu |
|---|---|---|
| G3 | PARTIAL | Route guards, auth regression và operator-path negatives đạt. Còn browser/realm/MFA/trust thật và operator access nghiệm thu. |
| G4 | PARTIAL | UI read-only và Backend authorization đạt offline. Còn exact-candidate write-denial, MySQL grants/SELECT-only thực tế và retention/purge. |
| G6 | NOT_VERIFIED | Projection/404 cô lập bổ sung bằng chứng biên Observatory. Còn monitoring/alert delivery, readiness/recovery, quyền vận hành và drill. |

## 16. D-10 và D-13

- **D-10 PENDING.** Giữ nút reset MFA hiện tại và quyền ADMIN hiện hành. Hành động này có thể làm người dùng được chọn phải enrollment lại MFA. Test chỉ dùng stub/fixtures. Việc giới hạn sang operator-private cần quyết định riêng.
- **D-13 PENDING.** Baseline cho task là operator-private và chỉ trình diễn bản chiếu đã duyệt. Việc cấp viewer cho giảng viên hoặc phân phối artifact lịch sử cần scope/quyền riêng. D-15 và D-16 vẫn PENDING, PD-02-02 vẫn PARTIAL.

## 17. Giới hạn runtime

- **RUNTIME NOT VERIFIED.** Chưa có release candidate, public HTTPS/domain thật, native realm/grants, kiểm chứng Browser/OTP/trust, MySQL/Redis vận hành, quyền filesystem/Docker của operator hoặc alert end-to-end. DOM tests xác nhận nội dung và tương tác, còn kiểm tra trực quan theo viewport trên browser thật chưa thực hiện.
- **HISTORICAL VERIFIED.** Các bằng chứng Lab có trước vẫn ở report lịch sử. Kết quả PD-02-07 dùng dữ liệu synthetic, không đọc log Lab. Bản chiếu chưa có quy trình retention/phân phối được nghiệm thu.
- PD-02-08 đứng kế tiếp trong Phase 02 và còn phụ thuộc PD-02-02 PARTIAL. D-15/D-16 và các advisory chưa xử lý còn chặn việc hoàn tất dependency prerequisite.

## 18. Bảo toàn Lab và repository

Đối chiếu trước/sau theo SHA-256 cho 708 file tracked/untracked hiện hữu thuộc Git inventory. **687 giữ nguyên, 21 file thay đổi trong phạm vi gồm 20 input và SSOT, thêm 4 file gồm 3 input và báo cáo này, 0 bị xóa.** Cả 46 tài liệu audit/evidence lịch sử giữ nguyên. Các input PD-02-01, PD-02-03 và PD-02-06 giữ nguyên so với PD-R7. Mở rộng có chủ đích gồm ba input build/CI của PD-02-02, một fixture lint của PD-02-04 và bốn input HTTP boundary/test của PD-02-05. Các dependency, lockfile, image base, phiên bản framework và cấu hình Lab không đổi.

HEAD, branch, ahead 3 so với local upstream và các thay đổi có trước được giữ. Flyway V5 checksum **661092940** và SHA-256 của bốn compiled class liên quan khớp evidence PD-02-02. Metadata Docker không đọc được lúc baseline và cuối task do daemon unavailable. Lab không được khởi động hay thay đổi. Không tạo tài khoản, reset thật, chỉnh realm, đọc secrets/DB/log thật, chạy Staging/Production, commit hoặc push. [V5 và dependency manifest](PD-02-02_DEPENDENCY_DATA.json)

QA đối chiếu 50 task duy nhất, đủ 16 cột, dependency graph không có vòng, 18 findings OPEN, 16 pending decisions, 18 approved entries, 125 liên kết cục bộ và 23 hash input. Chưa có task TODO thỏa đủ prerequisites tại checkpoint này.

### Manifest input PD-02-07

| Input | SHA-256 |
|---|---|
| [.github/workflows/ci.yml](../../../.github/workflows/ci.yml) | `a8c11d7cc7035295ea3ef88ce0798fb9ef723fe0129341af1c5a12dda1b546b7` |
| [deploy/docker/Dockerfile.frontend](../../../deploy/docker/Dockerfile.frontend) | `403faa020d4020ff6cac1a2116520b0af49c3963bdd9810253032b4721286418` |
| [deploy/public-demo/render_ingress.py](../../../deploy/public-demo/render_ingress.py) | `e342ac94e0537ee877395387c319decf87fee5b67bfefa5e1af115aa6be54c67` |
| [frontend/.env.example](../../../frontend/.env.example) | `11b6fdfbffda9b27fa64be0b9a5dafe0b43876ff641a5b442b36d5d1d4b1b80c` |
| [frontend/app/globals.css](../../../frontend/app/globals.css) | `5088834af5cb863ae4125a425e7124877382c070966ad803084b6969f7a76408` |
| [frontend/app/layout.tsx](../../../frontend/app/layout.tsx) | `157f63ad4fd30823284ba779de508966f95d7f5f7b0fd6e8673ea6bbbda695d1` |
| [frontend/components/admin-catalogs.tsx](../../../frontend/components/admin-catalogs.tsx) | `4f20ec9b00c1fa5146721f9ef9c3780aa7c731e498855fbe65831349c2836a58` |
| [frontend/components/admin-portal.tsx](../../../frontend/components/admin-portal.tsx) | `98fba585013336b2e2c06d9256b61ae993d18395b964184512b43309a91fd8da` |
| [frontend/components/admin-scores.tsx](../../../frontend/components/admin-scores.tsx) | `6c55015e490e2bab34baefe8cb3f8dfab26b5b8d4684b18e152407d3a2ed31dc` |
| [frontend/components/admin-students.tsx](../../../frontend/components/admin-students.tsx) | `d3bb315609197709d9be8c76fa38abcfff50e3ab44a7d6a005d6ca068c0fd47c` |
| [frontend/components/admin-subject-score-sheet.tsx](../../../frontend/components/admin-subject-score-sheet.tsx) | `34589926daf28b0e3586109256fa33962a2d74d311c6c06279ddec0618cd73ea` |
| [frontend/components/portal-route.tsx](../../../frontend/components/portal-route.tsx) | `3b4c6a0dabbd343c5fad972ca658c472188c68a0dff654b4cc03cc6c2ac0960c` |
| [frontend/lib/admin-api.ts](../../../frontend/lib/admin-api.ts) | `a71c38a85b03ccb69099259bc074a139079e26cfeff47df4e5acfe7cc8ec4f26` |
| [frontend/lib/api.ts](../../../frontend/lib/api.ts) | `dea7ed397c201e1eef047bc0a79743f9b02cd70d7b972762cf5af0b6adf7ed0d` |
| [frontend/next.config.ts](../../../frontend/next.config.ts) | `0e421da7d240f3f0c5c51f05ca8ad9a4a8e8aafafce57e3ab5f1f12013ec3121` |
| [frontend/package.json](../../../frontend/package.json) | `dd7bd2403e4f0609b06ba4dc8aa46b1ffb4d5e583baba86ccc2582c68451b8ff` |
| [frontend/tests/authentication-contract.test.mjs](../../../frontend/tests/authentication-contract.test.mjs) | `0eb233d5d093399b6561955fdd2d308600ffe2731c558a7c681843f8c81fbdf7` |
| [frontend/tests/public-demo-ui.test.mjs](../../../frontend/tests/public-demo-ui.test.mjs) | `070c3f5320072655cbb9e8aa8ce12c8e947ba1baeffde8d61354ecf7dfa3887d` |
| [gateway/src/main/java/com/zerotrust/gateway/CanonicalRequestFilter.java](../../../gateway/src/main/java/com/zerotrust/gateway/CanonicalRequestFilter.java) | `d053ad245e89895d286e552e004d15203a3621f349b6bd22927061b3f13805eb` |
| [gateway/src/test/java/com/zerotrust/gateway/GatewayAbuseHttpTest.java](../../../gateway/src/test/java/com/zerotrust/gateway/GatewayAbuseHttpTest.java) | `c1262974005dfb4c7bb2f723792be6b18d10ef2bacf08e05b4c74c011da4b3b2` |
| [scripts/observation/filtered_evidence.py](../../../scripts/observation/filtered_evidence.py) | `dde37127f0a6e4aff4ba0190fc910805c3c02d9ab30a351f94bee41f37ffa974` |
| [scripts/observation/test_filtered_evidence.py](../../../scripts/observation/test_filtered_evidence.py) | `348725156572ff68f070c469bd39d19be09726bbcf4b75bee62a6c75a059ff15` |
| [scripts/public_demo/test_ingress_http.py](../../../scripts/public_demo/test_ingress_http.py) | `d7f6ea982e66725730b22f15ac8222ed7a91fafd9baadacb071872300ad5b64b` |
