# ZeroTrust — Source ADMIN/STUDENT, Windows TLS và nghiệm thu

Bắt đầu27/10/2026; source/TLS lịch sử28/10, bổ sung Git/workspace checkpoint30/10/2026, Asia/Saigon. Đây là báo cáo tổng hợp duy nhất của nhiệm vụ;
các số liệu được cập nhật tại chỗ khi có bằng chứng mới.

**Cập nhật30/10:** B0 đã nghiệm thu A1–A6 và21 RBAC/ownership checks; A5/A6 fixture
cleanup/data preservation PASS theo [báo cáo nghiên cứu](TRUST_SCORE_RESEARCH_AND_EXPERIMENT_PLAN.md#185-a6-scored-high--deny--pass).
B1 source ở commit `40fea6a`, **chưa deploy**; B0 tiếp tục chạy. Chủ đồ án đã duyệt
xóa đúng worktree/marker/wrapper và commit hai báo cáo rồi push branch hiện tại.
Đã xóa đủ allowlist bằng Git chuẩn và lệnh xóa literal không recursive/force;
hậu kiểm Docker10/10 healthy, source và24 nhóm dữ liệu/cấu hình khớp baseline,
native Windows HTTPS200. Backup/ref rollback, archives và release source65 staged
được giữ nguyên. Inventory12 Git roots trước xóa còn11 sau xóa; chỉ C là canonical
phát triển. Kết quả thực hiện ở phần bổ sung30/10; kế hoạch trước duyệt được giữ
để đối chiếu. Commit/push được thực hiện sau khi ghi hậu kiểm vào đúng hai báo cáo;
hash commit cuối và đối chiếu remote được lưu riêng, không tự ghi hash của chính nó.

**Mốc source/TLS28/10 bên dưới là lịch sử**, gồm các trạng thái Browser chưa kiểm
chứng lúc đó và các image đã được cập nhật tiếp ở nhiệm vụ sau. Hiện trạng nghiệm
thu mới nhất nằm trong báo cáo nghiên cứu mục17–18; hiện trạng Git/workspace ở
phần bổ sung30/10 cuối tài liệu này. Không dùng các bảng cũ để suy B1 đã deploy.

**Kết luận tổng hợp: NOT VERIFIED.** Source ADMIN/STUDENT đã review; TLS Windows với CA file và
kết nối nội bộ có kiểm tra thu hồi PASS sau triển khai được phê duyệt ngày 28/10/2026.
Windows native trust hiện PASS sau khi chủ đồ án duyệt thêm đúng public CA vào
CurrentUser Root. Portal, OIDC Discovery và Keycloak 3p-cookie iframe đều HTTP 200
không cần CA file; System chain/online revocation PASS. Chủ đồ án đã xác nhận ADMIN/STUDENT đăng nhập được, có OTP và đã tải được dữ liệu
sau sửa API origin. Ảnh Network xác nhận token, students và subjects trả 200.
Ảnh owner sau mở lại Cốc Cốc đã có ổ khóa HTTPS. Lỗi onboarding được xác định
thuộc Content scripts → Tải video & audio của trình duyệt; cảnh báo iframe thuộc
keycloak-js và không ngăn token/API thành công. Không gán lỗi browser component
thành lỗi Portal hoặc sửa auth chỉ để dập Console.
Runtime hiện **10/10 running/healthy** sau khi chủ đồ án bật lại Docker và yêu cầu
chạy tiếp; đã kiểm tra lại lúc 08:35 ngày 28/10. Lần dừng khoảng 07:41 được giữ
trong phần lịch sử bên dưới. Không start/restart/recreate thêm vì cả 10 đã hoạt động.
Database, credentials/MFA, JWT signing keys và Trusted Device tiếp tục khớp snapshot
sau sửa TLS; HTTPS Windows và kết nối nội bộ có kiểm tra thu hồi đều PASS sau bật lại. Browser Flow, nghiệp vụ có user login và LOW/MEDIUM/HIGH thực tế còn
NOT VERIFIED. Source được chốt và push theo phê duyệt trực tiếp của chủ đồ án;
bằng chứng là commit chứa báo cáo này và remote branch khớp sau push. Cleanup trước đó đã hoàn tất;
không cleanup bổ sung trong workflow TLS này.

## 1. Source revision và trạng thái Git

**PASS:** canonical source `C:\Users\DELL\Documents\zerotrust\zerotrust`, branch
`zerotrust-v4-risk-scoring`. Baseline trước thay đổi:
`da16120e8e93c8cbea0872f90cbe90ab9379057d`. Source cuối được chốt trong commit chứa
phiên bản báo cáo này, với message ở dưới. Đã giữ và lưu các thay đổi loại bỏ Teacher,
Teaching Assignment và Schedule; không rewrite history.
Snapshot `df8fa2b01df0c00e316d1798bf137ade664c5d1c147d9d3312da1cb0e3839b18` bao gồm mã module, Maven/build/deploy/scripts/SQL và Compose liên quan; tài liệu đọc không thuộc hash này. Tại thời điểm build, working tree còn dirty; các thay đổi đã được chốt theo approval sau nghiệm thu TLS.
Chỉ ADMIN/STUDENT; không reset hoặc checkout đè. Commit/push được chủ đồ án phê duyệt riêng ngày 28/10.

Kiểm tra đã thực hiện trong lượt sửa source trước: Portal 324 tests, Gateway 20 tests,
6 Python tests, frontend lint/typecheck/build đạt. Không chạy lại các suite không đổi.
Build mặc định vẫn có checks; lượt build này tái sử dụng kết quả đã PASS của cùng source.
Image đã gắn revision và hash snapshot mã/cấu hình build để truy nguồn cả phần chưa commit.

### Review source ngày 28/10/2026

**PASS trong phạm vi review:** không còn Teacher/Scheduling dependency trong mã production
Backend/Gateway/Frontend; API Student lấy identity từ JWT subject và chỉ truy vấn `/me`.
Admin được bảo vệ tại Gateway, Backend và method security. Các regression test tên role
Teacher và SQL lịch sử được giữ có chủ đích; không chạy SQL lịch sử.

So với snapshot application đã build/nghiệm thu, chỉ có thêm sửa PKI ở
`deploy/legacy/prepare.py`, công cụ offline `deploy/legacy/tls_material.py`,
`scripts/legacy/test_tls_material.py`, cùng tài liệu.
Mã application không đổi; tái sử dụng 324 Portal/20 Gateway/6 Python và frontend checks
đã PASS, không build/test lại toàn bộ. 7 kiểm thử mới chỉ cho PKI PASS.
`git diff --check` PASS. Rà 525 file tracked/candidate không phát hiện PEM private key,
literal JWT, access token theo mẫu hoặc keystore/dump; đây là scan theo mẫu và review,
không phải bảo đảm phát hiện mọi dạng secret. `.local-legacy` và private evidence được
Git/Docker ignore. Không stage/commit runtime state, CA/server keys, encrypted keystores,
passwords, exports/dumps, build output hoặc private evidence.

Snapshot source review (không gồm narrative docs):
`e40e6427da47f81082b7140348b691c4d026870308ff943b9bdd8c065924d347`.
Application artifacts vẫn thuộc snapshot triển khai cũ vì mã app không đổi.

**PASS — commit/push:** chủ đồ án đã duyệt đúng 69 file và push lên
`NguyenTruong-An/zerotrust`, branch `zerotrust-v4-risk-scoring`. Source commit
`a09e4caf5900c8088d83d4c5075a75e5f365f2e3` có parent là baseline trên, lưu đúng
69 paths được duyệt (Git hiển thị 68 entries nếu gộp rename School validator).
Bản cập nhật báo cáo sau đó chỉ ghi nhận runtime đã dừng trước commit; không thay
source ứng dụng hoặc Docker. Đối chiếu remote branch bằng
`git ls-remote --heads origin zerotrust-v4-risk-scoring` với local `git rev-parse HEAD`
sau push, không force push/amend. Working tree được kiểm tra sạch sau commit.
Bằng chứng Git cụ thể được trả kèm kết quả thực thi; không cần ghi hash của chính
commit chứa báo cáo vào nội dung của commit đó.
Commit message: `fix(portal): restore admin-student scope and repair local TLS CRL discovery`.

## 2. Application images

**PASS:** Backend, Frontend và Gateway đã build từ canonical source, bao gồm các thay đổi chưa commit.
Keycloak, Risk và CRL không build lại. Backend/Gateway giữ snapshot đầu vào `df8fa2b01df0c00e316d1798bf137ade664c5d1c147d9d3312da1cb0e3839b18`
và revision baseline + dirty tree của lần gỡ Teacher. Frontend hiện dùng snapshot
`fa8e749e03782c1fd4d5c72d37f090c0a0acfce5c74b2ebd1970e9990f1aa510` và revision
`4a7033726d8d1a4d6a783e56614de7b79171a72c` + cấu hình API origin chưa commit lúc build.
Image labels lưu revision và snapshot; commit source fix được lưu sau kiểm tra.
Không rebuild Backend/Gateway/Risk/Keycloak cho thay đổi chỉ thuộc frontend build.
Không chạy lại các suite đã PASS của cùng source; Docker build vẫn biên dịch/package và Next build.

| Service | Image ID mới | Image ID đang chạy/rollback | Reference rollback được giữ |
|---|---|---|---|
| backend | `sha256:ea0942f875185551a0a86f68547f2d6ccee764fee311a401e284d06a4649dec2` | `sha256:979e917142b6920f5fff0b7ef97a114eef12349873009b2f9cbc95acf74e0451` | `zerotrust-legacy-backend:rollback-final-20261027-979e917142b6` |
| frontend | `sha256:6a548c25f8946e9bb0e4eb42b9ddde9e1f33ff21e2726ebdc203e37c1645372c` | `sha256:a4d8c9df4054d42d90873d104f647352c2f5c4bb707cc4cd9b8f263b7863294c` | `zerotrust-legacy-frontend:rollback-api-origin-20261028-a4d8c9df4054` |
| gateway | `sha256:66d7b52fb53ca1693f958e658366d8f0f440a6340d147a467adf8290bff80c36` | `sha256:890ce31102ef053f38c14fe08d28ee8a4550f0179e01d51c08cf57180882250c` | `zerotrust-legacy-gateway:rollback-final-20261027-890ce31102ef` |

Ba rollback references của lần gỡ Teacher và sáu references Phase 2B tiếp tục được giữ;
đã thêm rollback ref frontend a4d8c9 trước sửa API origin (tổng 10 references cần giữ).
Evidence: `.local-legacy/final-consolidation-evidence/source-snapshot.json`, `build-*.json`, `rollback.json`.

## 3. Docker deployment

**PASS:** đã nhận phê duyệt trực tiếp và chỉ thay Backend, Frontend, Gateway. Runtime hiện 10/10 healthy; các service khác giữ nguyên container/image IDs.
Trong khi build, runtime cũ giữ nguyên. Deployment sau đó dùng đúng image IDs và source labels đã duyệt.
Đã recreate/start `backend`, `frontend`, `gateway` bằng canonical Compose prefix,
`--no-deps --no-build --pull never`; không chọn các service khác hoặc job init/import/migrate.

| Data service giữ nguyên | Container ID | Volume giữ nguyên |
|---|---|---|
| school | `517a789a16e3ef110ad1641d36f8e097617ba0e9e27c04b2fec101f8c4d4a69f` | `zerotrust-legacy-integration-20261026_school-data` |
| risk-db | `0fe17431055dc108a2ae65e0d42854cac408bffb45bd5f00a7bc74097ee37d63` | `zerotrust-legacy-integration-20261026_risk-db-data` |
| keycloak-db | `f9175074e84ea2d80c4a610d0afd3a25c97a0625627d66ab3e7f540db47888d3` | `zerotrust-legacy-integration-20261026_keycloak-db-data` |
| redis | `9f5f22d7d8b0188b254bf56e424883641065f2bfc18b405c3053c2a881dfe559` | `zerotrust-legacy-integration-20261026_redis-data` |

Keycloak, Risk, CRL cùng credentials/MFA/signing keys và port mappings được giữ nguyên.
Rủi ro: gián đoạn ngắn trong lúc thay ba ứng dụng hoặc lỗi tương thích/config sau khởi động.
Nếu preflight hoặc health thất bại, dừng thao tác tiếp theo, giữ evidence và dữ liệu.
Rollback chỉ cần chọn lại ba image ID đã bảo vệ và recreate đúng ba application containers;
không restore DB, không reset realm/volumes. Runtime approval đã bao gồm phạm vi rollback này; không cần sử dụng rollback trong lần triển khai.


Container IDs mới: backend `ce2477790b1a12de44257314a07412112f1d861904f69dd5bd3caf3783991dad`, frontend `aa090e320fab009b69c7ad44063fe557846f37400ed34c2b9624d12f66919a81`, gateway `331a754eb8b8e704858a7fe26c0f2bd4c8650169eb62b6efaf2e5ff8eec5ee73`.

Trong lượt đồng bộ ba application images trước đó, private runtime, bốn data-service IDs
và toàn bộ mounts giữ nguyên; không có init/import/migration. Lượt TLS dưới đây chỉ
đổi đúng 5 file được duyệt và restart hai container hiện có.

## 4. ADMIN/STUDENT acceptance

**PASS trong phạm vi packaging và biên truy cập:** `/admin`, `/student/scores` trả page shell 200;
`/teacher`, `/admin/teaching` trả 404. JAR Backend/Gateway lấy trực tiếp từ container không có
Teacher/TeachingAssignment/Schedule controller/entity/service; Next route manifest cũng không có chúng.
Không dùng unauthenticated 401 để suy ra API đã gỡ trả 404 cho người có quyền.

**PASS trong phạm vi đọc cơ bản theo chủ đồ án:** ADMIN/STUDENT đăng nhập có OTP,
sau sửa API origin đã tải được dữ liệu. Ảnh owner cho thấy ADMIN `/admin/scores`,
token exchange 200 và API students/subjects 200. STUDENT tải dữ liệu được theo phản hồi
owner; chưa có ảnh/negative test chứng minh ownership xuyên tài khoản.
**NOT VERIFIED:** Admin CRUD ghi đầy đủ, STUDENT bị chặn API ADMIN/dữ liệu người khác
trên phiên thật. Không mở rộng kết quả đọc cơ bản thành toàn bộ nghiệp vụ PASS.
Không giả user token, tạo role/account, sử dụng signing keys để tự ký JWT hoặc sửa 49 business rows.
Các test nguồn 324 Portal/20 Gateway PASS đã tái sử dụng, không thay thế nghiệm thu user flow thật.

## 5. Adaptive Authentication acceptance

- LOW → ALLOW: **NOT VERIFIED** trên user flow của bản triển khai này.
- MEDIUM → STEP_UP_MFA và hoàn tất OTP: **NOT VERIFIED**.
- HIGH → DENY trong Browser Flow: **NOT VERIFIED**; không tạo tín hiệu giả, revoke device hoặc đổi policy.
- Trusted Device đăng ký: **PASS trong phạm vi persistence** — hai thiết bị phát sinh
  trong cửa sổ owner login có status TRUSTED/trusted_at; agent không tạo fixture/reset.
  Nhận diện cookie và bỏ OTP khi relogin cùng thiết bị: **NOT VERIFIED**.
- Login ADMIN/STUDENT và OTP challenge/completion: **PASS theo phản hồi owner**;
  chưa suy từ OTP thành MEDIUM hoặc xác nhận mọi nhánh risk.
- Risk API service authentication/authorization: **PASS**; token đúng caller được qua security và
  payload rỗng bị validation 400 trước scoring; caller revoke bị từ chối evaluate bằng 403.
  Đây không phải phép đo Risk decision hay bằng chứng MFA.

Quy tắc [computer-use SKILL.md](C:/Users/DELL/.codex/plugins/cache/openai-bundled/computer-use/26.1021.31345/skills/computer-use/SKILL.md)
trỏ tới [guidance.md](C:/Users/DELL/.codex/plugins/cache/openai-bundled/computer-use/26.1021.31345/docs/guidance.md),
trong đó ghi **“Do not automate user authentication dialogs.”** Không tự thao tác hộp thoại
đăng nhập/OTP và không thay bằng browser automation khác để vượt giới hạn này. Các HTTP/API
checks dùng service-account grant chính thức, TLS verification và token có quyền đúng phạm vi;
không giả danh ADMIN/STUDENT. Browser acceptance cần thao tác thủ công Windows.

## 6. Security verification

**PASS:** 15/15 HTTP public-route/API rejection/discovery/JWKS checks bằng TLS chain/hostname
verification của Python/OpenSSL; issuer discovery đúng. OIDC authorization entrypoint/PKCE **PASS**:
thiếu hoặc dùng plain PKCE bị từ chối bằng OAuth callback `302 invalid_request`, không có code;
S256 hợp lệ hiển thị login form (200), chưa nhập password/OTP. Probe ban đầu tự follow redirect
về Portal nên nhìn thấy 200; đã giữ evidence ban đầu và kiểm tra first-hop thay vì suy từ status cuối.
Ba kiểm tra TLS kết nối Gateway→Backend, Gateway→Keycloak JWKS, Backend→Risk health **PASS**;
không thấy fatal startup patterns trong log của ba app mới. Thiếu token,
token sai và header giả quyền bị 401; CORS origin lạ bị 403. Sáu service-JWT checks PASS:
chữ ký token thật/đúng issuer/audience/azp được chấp nhận; sai audience tại Portal/Gateway bị 401,
sai caller/role tại Risk bị 403; token bị sửa bị 401. Token thật, không chỉnh sửa, được kiểm tra
sau expiry và clock-skew allowance, trả 401 (**PASS**). Trường hợp wrong-issuer độc lập và
RBAC/ownership của ADMIN/STUDENT chưa có user-flow live; chỉ có bằng chứng unit tests đã PASS.

### Windows TLS/CRL sau sửa ngày 28/10/2026

**PASS.** Chủ đồ án đã phê duyệt thay đúng 5 file và restart Gateway/Keycloak, gồm
rollback trong cùng phạm vi. Đã cài `public-ca/ca.crl`, `gateway/server.crt`,
`gateway/server.p12`, `keycloak/server.crt`, `keycloak/server.p12`.
Không rebuild/recreate images; cả 10 container IDs, image IDs, mounts giữ nguyên;
chỉ Gateway/Keycloak được restart. CA/private keys, passwords, Windows Root/DNS/hosts,
Keycloak realm/accounts/OTP/MFA/JWT signing keys không bị thay đổi.

Nguyên nhân trước sửa: cả hai leaf chỉ có CDP `http://crl:8080/ca.crl`;
Windows không resolve `crl`, native chain báo `RevocationStatusUnknown` và
`OfflineRevocation`. CA/chain, key matching, SAN/EKU, issuer/chữ ký CRL đều đúng;
CRL cũ còn hạn tới 02/11, nên không phải lỗi hết hạn. Chứng chỉ ứng viên xác minh
Windows online thành công với chính CRL cũ, xác nhận lỗi đường truy cập.
Thiếu CRLNumber ở CRL cũ là cải thiện profile, không được kết luận là nguyên nhân
Schannel. Giữ nguyên CA, private keys, subject/SAN/EKU và hạn leaf 24/01/2027;
thay serial và CDP bằng một DistributionPoint với hai URI của cùng CRL:
`http://localhost:28445/ca.crl` và `http://crl:8080/ca.crl`, theo
[RFC 5280 §4.2.1.13](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.13).
Không mở CRL khỏi loopback Windows, không đổi DNS/hosts.

| Bằng chứng sau triển khai | Kết quả |
|---|---|
| Windows `curl.exe --cacert <CA>`, Schannel, không tùy chọn bỏ xác minh/thu hồi | **PASS**: Gateway `/` và Keycloak OIDC discovery đều exit 0, HTTP 200 |
| Chứng chỉ lấy trực tiếp từ hai HTTPS endpoints | **PASS**: khớp byte với ứng viên đã cài, SAN `localhost` và tên service |
| Windows native chain trên leaf thực sự đang phục vụ | **PASS**: process-only `CustomRootTrust`, `Online/ExcludeRoot`, `NoFlag`; hai chain đều 2 phần tử, không lỗi |
| CRL Windows `localhost:28445` và Docker `crl:8080` | **PASS**: HTTP 200, cùng DER; issuer/chữ ký/thời hạn hợp lệ, giữ nguyên 0 entry thu hồi |
| Gateway→Backend, Gateway→Keycloak, Backend→Keycloak, Backend→Risk | **PASS** 4/4: Java HTTPS có chain/hostname verification và `checkRevocation=true`, `enableCRLDP=true` |
| Đường CRL trong JVM của Docker | **PASS**: log `Trying to fetch CRL from DP` thử localhost rồi crl; `Returning 1 CRLs`, request thành công |
| Public HTTP/security rejection/discovery/JWKS | **PASS** 17/17 sau restart, gồm hai Schannel HTTPS checks |
| Service JWT security | **PASS** 6/6; caller đúng → validation 400, role sai → 403, thiếu/token sai → 401; không scoring payload rỗng |
| Token thật với public JWKS | **PASS**: chữ ký RS256, issuer, audience, expiry; token thật đã hết hạn bị Risk từ chối 401 |
| Startup và health | **PASS**: 10/10 healthy, không thấy fatal startup/TLS/JDBC patterns trong log được kiểm tra |

Lần cài đầu HTTPS đã PASS nhưng guard đối chiếu mounts dùng thứ tự list, trong khi
Docker trả hai mounts Redis đảo thứ tự, nên kích hoạt rollback không cần thiết.
Đã xác minh không có mount/data thay đổi, sửa guard thành so sánh theo destination,
giữ journal lần đầu và triển khai lại đúng 5 file/hai service theo approval hiện có.
Lần thứ hai PASS, không phải bỏ qua khác biệt tài nguyên thật.

CRL hiện tại hạn đến **04/11/2026 01:49:27 giờ Việt Nam**; cần gia hạn trước
**02/11**. Công cụ `deploy/legacy/tls_material.py --check` PASS và chỉ đọc public
files; cảnh báo khi còn <= 2 ngày. Stage gia hạn giữ mọi revocation entry, tăng
CRLNumber và không cài file/restart. Kiểm tra mỗi ngày khi sử dụng và trước demo;
không coi việc sửa CDP là làm CRL không bao giờ hết hạn.
Hướng dẫn: `docs/operations/LEGACY_INTEGRATION.md`. 7 PKI tests PASS.

Bản rollback 5 file cũ, ứng viên và input hashes được giữ trong ignored private
`tls-maintenance-20261028/manifest.json`. Evidence mới gồm
`tls-deployment-20261028-attempt2.json`, `tls-windows-served-chain-20261028.json`,
`tls-served-certificates-20261028.json`, `tls-internal-connectivity-20261028.json`,
`tls-crl-verification-20261028.json`, `tls-http-public-checks.json`,
`tls-http-service-security.json`, `tls-jwt-verification-20261028.json`.
Không đưa private evidence hoặc keystores/private keys vào Git.

## 7. Data preservation

**PASS trước/sau deployment và sau HTTP/API checks:** toàn bộ schema/row hashes của năm bảng
School giữ nguyên, tổng 49 rows và 23 scores. Sáu UUID mappings giữ nguyên và đều tồn tại
trong Keycloak. Risk table/schema hashes, Flyway V1–V5 và Keycloak identities/roles/role mappings,
credentials/OTP/components/signing material/configuration giữ nguyên. Private runtime hashes trong lượt deployment ứng dụng trước đó
không đổi; ngoại lệ 5 file TLS được duyệt ngày 28/10 được ghi riêng dưới đây. Redis snapshot TLS trước/sau có 0 keys; không coi Redis rỗng là bằng chứng xóa an toàn
các volume khác. Không có SQL mutation, business fixture, import, migration hoặc reset.

Service-account token requests có thể sinh session/audit bình thường ngoài tập protected tables;
không coi đó là thay đổi business data. Không thực hiện user password/OTP login trong lượt này.

### Đối chiếu sau TLS ngày 28/10/2026

**PASS:** snapshot ngay trước/sau khớp chính xác School schema/row hashes (49 rows,
23 scores), sáu UUID mappings, toàn bộ Risk tables/Flyway V1–V5 và các bảng Keycloak
ổn định: users, roles/mappings, credentials/OTP, components/signing configuration,
realm/client/flows/config/required-actions/attributes. Trusted Device state trong
Risk không đổi; không reset/revoke device hoặc thao tác browser cookie. Redis TLS
snapshot vẫn 0 keys, không suy Redis rỗng là đã nghiệm thu vòng đời device.
CA/server private keys, passwords và toàn bộ runtime files ngoài allowlist 5 file
có hash giữ nguyên. Không SQL write/init/import/reset/restore/migration hoặc xóa volume.
Service-account token requests và HTTP entrypoints có thể phát sinh session/audit
hợp lệ; không dùng những thay đổi đó để suy dữ liệu nghiệp vụ bị sửa.
Evidence: `tls-data-immediate-before-20261028-attempt2.json`,
`tls-data-after-20261028.json`, `tls-preservation-20261028.json`.

## 8. Cleanup containers/images/networks/cache/worktree

**PASS trong đúng allowlist đã được duyệt.** Đã nhận phê duyệt trực tiếp và xóa
16 containers, 4 release-check images, 7 networks và đủ 257 cache records.
Danh sách dưới đây là các tài nguyên đã xác minh và đã xóa; không gồm canonical, rollback cần thiết,
Demo/source/restore data containers, bất kỳ volume nào hoặc worktree bị tiến trình sử dụng.
Full IDs và cache record IDs: `.local-legacy/final-consolidation-evidence/cleanup-plan.json`.

| Resource name / ID | Loại | Lý do xóa an toàn | Dung lượng dự kiến | Dữ liệu/rollback giữ lại |
|---|---|---|---|---|
| `qa02b-899effc1-mysql` / `9448a5d75179` | container | QA độc lập đã dừng; giữ volumes, configs và images dữ liệu | 0.0 MB | Toàn bộ volumes/configs, images và backups |
| `qa02b-899effc1-redis` / `2a6f31ad46d5` | container | QA độc lập đã dừng; giữ volumes, configs và images dữ liệu | 0.0 MB | Toàn bộ volumes/configs, images và backups |
| `qa02c-5a51c51a-mysql` / `a9d0e152b7f0` | container | QA độc lập đã dừng; giữ volumes, configs và images dữ liệu | 0.1 MB | Toàn bộ volumes/configs, images và backups |
| `qa02c-5a51c51a-redis` / `ebd21ca1e04d` | container | QA độc lập đã dừng; giữ volumes, configs và images dữ liệu | 0.0 MB | Toàn bộ volumes/configs, images và backups |
| `zerotrust-demo-backend-1` / `f3064eae1b1c` | container | Ứng dụng/reader Demo cũ đã được thay bằng canonical; giữ Demo DB/Redis, images và private state | 0.2 MB | Toàn bộ volumes/configs, images và backups |
| `zerotrust-demo-crl-1` / `2a208af77605` | container | Ứng dụng/reader Demo cũ đã được thay bằng canonical; giữ Demo DB/Redis, images và private state | 0.0 MB | Toàn bộ volumes/configs, images và backups |
| `zerotrust-demo-frontend-1` / `39379da1f563` | container | Ứng dụng/reader Demo cũ đã được thay bằng canonical; giữ Demo DB/Redis, images và private state | 0.0 MB | Toàn bộ volumes/configs, images và backups |
| `zerotrust-demo-gateway-1` / `e3564b33917d` | container | Ứng dụng/reader Demo cũ đã được thay bằng canonical; giữ Demo DB/Redis, images và private state | 0.0 MB | Toàn bộ volumes/configs, images và backups |
| `zerotrust-demo-init-1` / `821c490e53cb` | container | Ứng dụng/reader Demo cũ đã được thay bằng canonical; giữ Demo DB/Redis, images và private state | 0.0 MB | Toàn bộ volumes/configs, images và backups |
| `zerotrust-demo-keycloak-1` / `4b161839c3b8` | container | Ứng dụng/reader Demo cũ đã được thay bằng canonical; giữ Demo DB/Redis, images và private state | 1.1 MB | Toàn bộ volumes/configs, images và backups |
| `zerotrust-demo-migrate-1` / `aa1fd412e611` | container | Ứng dụng/reader Demo cũ đã được thay bằng canonical; giữ Demo DB/Redis, images và private state | 0.0 MB | Toàn bộ volumes/configs, images và backups |
| `zerotrust-demo-risk-1` / `21ccbc5d4341` | container | Ứng dụng/reader Demo cũ đã được thay bằng canonical; giữ Demo DB/Redis, images và private state | 0.2 MB | Toàn bộ volumes/configs, images và backups |
| `zt-mysql-qa` / `1f52a697ab4c` | container | QA độc lập đã dừng; giữ volumes, configs và images dữ liệu | 0.0 MB | Toàn bộ volumes/configs, images và backups |
| `zt-mysql-qa-postfix03a` / `3af21eb9b601` | container | QA độc lập đã dừng; giữ volumes, configs và images dữ liệu | 0.0 MB | Toàn bộ volumes/configs, images và backups |
| `zt-mysql-qa-postfix03b` / `896966ebcf2a` | container | QA độc lập đã dừng; giữ volumes, configs và images dữ liệu | 0.0 MB | Toàn bộ volumes/configs, images và backups |
| `zt-redis-qa` / `7e7e049477a3` | container | QA độc lập đã dừng; giữ volumes, configs và images dữ liệu | 0.0 MB | Toàn bộ volumes/configs, images và backups |
| `zerotrust-release-check-crl:20261026` / `b24486896dfd` | image | Image kiểm tra release cũ không được container hoặc rollback reference sử dụng | 220.8 MB | Canonical + 9 rollback refs + 6 Demo images |
| `zerotrust-release-check-frontend:20261026` / `a262d8a91168` | image | Image kiểm tra release cũ không được container hoặc rollback reference sử dụng | 92.4 MB | Canonical + 9 rollback refs + 6 Demo images |
| `zerotrust-release-check-keycloak:20261026` / `8c3389448129` | image | Image kiểm tra release cũ không được container hoặc rollback reference sử dụng | 269.9 MB | Canonical + 9 rollback refs + 6 Demo images |
| `zerotrust-release-check-risk:20261026` / `ded3e8b94a79` | image | Image kiểm tra release cũ không được container hoặc rollback reference sử dụng | 241.3 MB | Canonical + 9 rollback refs + 6 Demo images |
| `qa02b-899effc1-net` / `f6ece9ef2316` | network | Mạng QA chỉ liên quan containers trong danh sách xóa; không có endpoint đang chạy | Không đáng kể | Mạng canonical/restore/Demo được giữ |
| `qa02c-5a51c51a-ingress-net` / `3aef78bd4426` | network | Mạng QA chỉ liên quan containers trong danh sách xóa; không có endpoint đang chạy | Không đáng kể | Mạng canonical/restore/Demo được giữ |
| `qa02c-5a51c51a-net` / `8f609157d4cd` | network | Mạng QA chỉ liên quan containers trong danh sách xóa; không có endpoint đang chạy | Không đáng kể | Mạng canonical/restore/Demo được giữ |
| `zt-mysql-qa-fix03-net` / `a9090c141611` | network | Mạng QA chỉ liên quan containers trong danh sách xóa; không có endpoint đang chạy | Không đáng kể | Mạng canonical/restore/Demo được giữ |
| `zt-mysql-qa-postfix03a-net` / `4a6b69fd0437` | network | Mạng QA chỉ liên quan containers trong danh sách xóa; không có endpoint đang chạy | Không đáng kể | Mạng canonical/restore/Demo được giữ |
| `zt-mysql-qa-postfix03b-net` / `5d5b6bbbe7ed` | network | Mạng QA chỉ liên quan containers trong danh sách xóa; không có endpoint đang chạy | Không đáng kể | Mạng canonical/restore/Demo được giữ |
| `zt-redis-qa-fix05-net` / `46fd57f7ef1b` | network | Mạng QA chỉ liên quan containers trong danh sách xóa; không có endpoint đang chạy | Không đáng kể | Mạng canonical/restore/Demo được giữ |
| Builder `desktop-linux`: 257 cache IDs đã ghi trong allowlist | Build cache | Tất cả reclaimable, 0 active build; lọc đúng 257 IDs đã duyệt | Ước tính ban đầu 11.27GB; Buildx báo loại bỏ 19.09GB | Runtime/rollback image references, source và private data |

Ước lượng image/container dựa trên metadata và có shared layers; không cộng số này thành
cam kết giải phóng host C. Dùng bộ lọc ID cache cụ thể theo [Docker Buildx prune](https://docs.docker.com/reference/cli/docker/buildx/prune/),
không dùng system/volume prune. Trước khi xóa đã kiểm tra lại IDs, refs, active builds và 10/10 health.
Lần đầu selector `inuse=false` không khớp record nào trên engine hiện tại, nên trả 0B và không
được coi là hoàn thành. Đã kiểm tra chỉ đọc, xác nhận đúng 257 IDs vẫn reclaimable, rồi dùng
chính allowlist ID regex đó để dọn; hậu kiểm xác nhận 0 ID được duyệt còn tồn tại.
Không mở rộng allowlist, không xóa volumes hoặc đổi runtime canonical để xử lý lỗi bộ lọc.

Hậu kiểm: Docker còn **19 containers, chỉ 10 canonical containers running/healthy**, 30 images,
8 networks, 25 volumes, 0 build-cache records. Không còn tên/ID QA/Demo ứng dụng trong danh sách đã duyệt;
những resource giữ lại được ghi riêng ở mục 9. Toàn bộ IDs/images/mounts của containers được giữ nguyên.
Source snapshot, School/Risk/Keycloak, Redis app DB, private runtime, 9 rollback refs và 6 Demo images đều PASS.
Cleanup hoàn tất lúc **2026-10-28T00:56:38+07:00**; allowlist SHA-256
`271f8591ca5dbbff663c4d8cb92f597b4ec99fcdb94650e9978b926a6a670020`. Evidence: `cleanup-results.json`, `final-verification.json`
và các data snapshots trong `.local-legacy/final-consolidation-evidence/`.

Worktree **BLOCKED**: Git registration thuộc archive hợp lệ, source clean và 5 evidence đã bảo toàn,
nhưng các PID `28588`, `11956`, `34632`, `19276` vẫn có CWD tại worktree. Không kill process,
không force/remove/prune; worktree không nằm trong allowlist. Bốn data containers có labels Compose
lịch sử trỏ tới worktree nhưng không bind mount nguồn từ đó; không recreate DB để đổi labels.

## 9. Volumes, rollback và backups được giữ

**PASS về bảo vệ:** metadata (name/driver/mountpoint/creation time/labels/scope) của cả 25 volumes khớp inventory Phase 1; giữ toàn bộ 25 volumes, bao gồm bốn canonical School/Risk/Keycloak/Redis,
`door_iot_mysql_data`, data volumes nguồn/restore/Demo/QA và năm volumes UNKNOWN.
Không có đủ chứng cứ thay thế/restore cho mọi volume lịch sử, nên không xóa chúng.
Giữ original Keycloak container, hai Demo data containers, bốn restore containers,
hai original Risk DB/Redis containers, archives, private inputs và backups.

Giữ 9 rollback references (6 cũ + 3 trước lần đồng bộ này) và cả 6 Demo images để phục vụ
khôi phục/điều tra khi Windows TLS và user authentication acceptance còn thiếu.
Configs đầy đủ của containers đã backup vào protected ignored evidence, không in credentials ra báo cáo.

## 10. Dung lượng

**PASS — đã đo trước/sau.** Docker reporting và host C là hai phép đo khác nhau;
không cộng shared layers/cache với image usage để suy ra dung lượng vật lý.

| Docker resource | Trước cleanup: count / size | Sau cleanup: count / size |
|---|---|---|
| Images | 34 / 23.45GB | 30 / 8.724GB |
| Containers | 35 / 360.6MB | 19 / 358.9MB |
| Local Volumes | 25 / 3.226GB | 25 / 3.226GB |
| Build Cache | 257 / 19.09GB | 0 / 0B |

Buildx báo `Total: 19.09GB`; đủ 257 approved cache IDs đã biến mất,
cache usage/record count sau bằng 0. Đây là số Docker/Buildx báo, không phải 19.09GB host C.

- Ổ C trống ngay trước cleanup: **119,770,337,280 bytes** (119.770 GB thập phân).
- Ổ C trống sau cleanup: **119,787,040,768 bytes** (119.787 GB thập phân).
- Chênh lệch quan sát riêng cleanup: **+16,703,488 bytes**, khoảng **16.70 MB**.
- So với đầu toàn nhiệm vụ (trước build, 122,878,701,568 bytes trống), ổ C đang trống ít hơn
  **3,091,660,800 bytes** (khoảng 3.092 GB). Build/artifacts và thay đổi nền
  có thể ảnh hưởng phép đo; không khẳng định toàn bộ chênh lệch host do riêng cleanup.

Không chạy compact VHDX, dừng Docker/WSL hoặc thay đổi storage. Xóa cache trong Docker VM
không được đồng nhất với việc thu nhỏ file lưu trữ trên Windows. Giữ các image rollback/Demo
cần thiết và 25 volumes khiến một phần Docker storage vẫn được sử dụng hoặc được giữ có chủ đích.

## 11. Công việc chưa hoàn thành

- **PASS:** Windows Schannel, served certificate chain/SAN, CRL và kết nối nội bộ sau sửa TLS.
  Cần duy trì gia hạn CRL trước 02/11/2026; đây là bảo trì định kỳ, không phải tắt revocation.
- **NOT VERIFIED:** CRUD ghi và ownership/negative RBAC trên phiên thật; LOW/MEDIUM/HIGH
  theo decision thực, Trusted Device relogin/skip OTP và logout đầy đủ. Login/OTP và
  đọc dữ liệu cơ bản được owner xác nhận; không dùng chúng để gán PASS cho các mục còn lại.
- **BLOCKED trong cleanup lịch sử:** linked worktree được giữ vì process CWDs. Không xử lý lại
  trong nhiệm vụ TLS; không phải blocker của TLS hoặc source ADMIN/STUDENT.
- **PASS:** cleanup allowlist đã hoàn tất; 25 volumes được giữ. Các volumes UNKNOWN và worktree ngoài allowlist không được xóa.
- Dung lượng host C chỉ tăng khoảng 16.70MB trong cleanup; chưa thu nhỏ VHDX và không tuyên bố giải phóng 19.09GB trên ổ C.

### Checklist Windows để nghiệm thu thủ công

**NOT VERIFIED** cho tới khi có kết quả thực tế từ chủ đồ án. Dùng browser profile
đã tin CA riêng tư được cho phép trước đó; không chấp nhận cảnh báo chứng chỉ,
không tự sửa Windows Root khi chưa được duyệt và không gửi password/OTP/token/cookie vào báo cáo.
Chỉ dùng các tài khoản hiện có theo realm role, đã liên kết UUID với School:
ADMIN, STUDENT A và một STUDENT B để đối chiếu ownership. Không tạo tài khoản mới.

| Kiểm tra thủ công | URL/thao tác | Kết quả cần đối chiếu |
|---|---|---|
| Login/PKCE | `https://localhost:28443/` → Keycloak `https://localhost:28444/realms/DoAn`; đăng nhập từng role bằng password/OTP hiện có | Authorization request có `response_type=code`, `code_challenge_method=S256`; token exchange thành công; không ghi nội dung token |
| ADMIN đọc nghiệp vụ | `/admin/users`, `/admin/students`, `/admin/classes`, `/admin/subjects`, `/admin/scores` | UI và Network: API `/api/admin/users`, `/students`, `/student-classes`, `/subjects` theo prefix `/api/admin` trả dữ liệu đúng; chưa xác nhận thao tác ghi chỉ từ màn hình |
| STUDENT hồ sơ/điểm | `/student/scores`; Network GET `/api/students/me`, `/api/students/me/scores`, `/api/students/me/scores/summary` | 200 và chỉ đúng sinh viên tương ứng JWT subject; dữ liệu khớp bảng gốc |
| STUDENT sai quyền | Từ phiên STUDENT dùng request hiện có trong DevTools, GET `/api/admin/students`, `/api/admin/students/{id-B}/scores` | 403; không chia sẻ bearer token/cookie. Không có API Student nhận studentId để đổi chủ thể |
| LOW/trusted relogin | Login từ ngữ cảnh thiết bị hợp lệ đã có trust; logout rồi login lại | Chỉ ghi PASS khi Risk thực tế báo LOW/ALLOW và Browser hoàn thành; cold-start/incomplete có thể buộc MFA đúng guardrail |
| MEDIUM/MFA | Ngữ cảnh hợp lệ phát sinh STEP_UP_MFA; nhập OTP trực tiếp trong browser | Challenge xuất hiện và completion thành công; không revoke/reset device hoặc sửa OTP để tạo kịch bản |
| HIGH/DENY | Chỉ khi có tín hiệu rủi ro thật hoặc kế hoạch kiểm thử trạng thái được duyệt riêng | Risk HIGH/DENY và Browser chặn, không cấp phiên truy cập; chưa có tình huống phù hợp thì NOT VERIFIED |
| Logout | Nút logout, sau đó mở lại Portal và API được bảo vệ | Phiên SSO kết thúc, yêu cầu đăng nhập lại; access token JWT có thể còn hạn tới exp, không suy logout là thu hồi mọi JWT ngay |
| Chức năng đã gỡ | `/teacher`, `/admin/teaching` | 404; không có lịch học hoặc menu Teacher |

Ghi mốc giờ, role, request path/status và correlation/evaluation ID nếu có. Đối chiếu
log cùng thời điểm của canonical `keycloak`, `risk`, `gateway`, `backend` và Risk
audit/history để nối decision với lần đăng nhập; không chỉ nhìn container healthy.
Không xuất raw credentials, OTP secret, cookie hoặc bearer token. CRUD ghi/sửa/xóa
chưa được kiểm chứng live; cần disposable record và kế hoạch hoàn nguyên được
chủ đồ án duyệt trước, không dùng 49 dòng gốc để thử ghi.
Không cleanup/worktree removal bổ sung trong workflow TLS hiện tại.

## 12. Start/stop/rebuild từ canonical source

Từ thư mục canonical:

```powershell
python -X utf8 scripts/legacy/operate.py status
python -X utf8 scripts/legacy/operate.py start
python -X utf8 scripts/legacy/operate.py stop
```

Các lệnh trên chỉ thao tác container hiện có, không recreate/init/import/migrate.
Build/deployment dùng `compose_prefix` trong manifest Phase 2A đã xác minh;
không chạy unqualified Compose vì `compose.yaml` mặc định là môi trường synthetic cũ.
Rebuild từ đúng prefix đã có (mặc định vẫn chạy các checks của Dockerfiles):

```powershell
$entryFile = 'C:\Users\DELL\Documents\zerotrust-legacy-preservation\20261026-1344ea0d\phase2a-docker-canonicalization-20261027\CANONICAL_COMPOSE_ENTRYPOINT.json'
$entry = Get-Content -LiteralPath $entryFile -Raw | ConvertFrom-Json
$composeArgs = @($entry.compose_prefix | Select-Object -Skip 1)
docker @composeArgs build backend frontend gateway
# Chỉ sau khi đã duyệt việc cập nhật ba ứng dụng:
docker @composeArgs up -d --no-deps --no-build --pull never backend frontend gateway
```

Không dùng bootstrap/migration profile cho restart hoặc rebuild. Khi source thay đổi,
kiểm tra phần liên quan và lưu source snapshot/image IDs mới; không mặc định báo cáo này vẫn áp dụng.

## Nguồn đối chiếu

- `PHASE1_FINAL_CLEANUP_REPORT.md`: inventory và evidence worktree đã bảo toàn.
- `PHASE2A_DOCKER_CANONICALIZATION_REPORT.md`: canonical Compose entrypoint.
- `PHASE2B_CANONICAL_IMAGE_BUILD_REPORT.md`: bộ image/rollback trước khi gỡ Teacher.
- `CANONICAL_RUNTIME_ACCEPTANCE_REPORT.md`: baseline dữ liệu, TLS và các bước triển khai cũ.

Các báo cáo lịch sử nằm trong `C:\Users\DELL\Documents\zerotrust-legacy-preservation\20261026-1344ea0d`.
Evidence mới của nhiệm vụ được lưu trong `.local-legacy/final-consolidation-evidence/`
ở canonical source, được Git/Docker bỏ qua; không chứa source clone hoặc environment mới.

## Xác minh cuối cùng

**PASS trong phạm vi source/runtime/deletion/data preservation:** 16 kiểm tra hậu cleanup đều đạt.
Source vẫn ở canonical branch; các thay đổi được lưu trong commit đã duyệt, không bị mất;
không worktree/clone/environment mới.
Chỉ canonical project có containers đang chạy; không còn resource ID đã duyệt xóa.
Bốn data-container IDs/mounts, toàn bộ 25 volumes, original Keycloak, 9 rollback references và 6 Demo images còn nguyên.
Archives/backups và worktree bị khóa không nằm trong thao tác xóa. Runtime được cập nhật đúng source snapshot trên image labels.

**Toàn hệ thống: NOT VERIFIED**, do user/Adaptive Browser Flow và CRUD/ownership live chưa nghiệm thu.
Windows Schannel và kết nối nội bộ sau sửa TLS đã PASS. Không đổi policy/MFA/device trust
hoặc dữ liệu để ép các mục chưa xác minh thành PASS. Source được commit/push theo approval riêng.

## Kết quả workflow source/TLS và chốt source ngày 28/10/2026

| Tiêu chí | Trạng thái | Bằng chứng/giới hạn |
|---|---|---|
| Source ADMIN/STUDENT review | **PASS** | 69 paths: 36 sửa, 28 xóa, 5 mới; không còn Teacher dependency production; app source khớp bản đã kiểm thử |
| Commit/push | **PASS** | Source commit `a09e4ca`, parent `da16120`, đúng allowlist 69 paths; cập nhật báo cáo riêng, local/remote branch khớp sau push, working tree sạch |
| Windows TLS/CRL | **PASS** | Schannel HTTP 200 hai endpoint, online native chain và CRL ký hợp lệ |
| Docker hiện tại | **PASS** | 10/10 running/healthy sau chủ đồ án bật lại, kiểm tra 08:35; IDs/images/mounts giữ nguyên |
| OIDC discovery/PKCE entrypoint | **PASS** | Discovery sau TLS; tái sử dụng bằng chứng S256 form/missing+plain bị từ chối của cùng client config; chưa hoàn tất user login/code exchange |
| JWT/service authorization | **PASS** | Chữ ký/issuer/audience/expiry thật, 401/403, 6 service-JWT checks; wrong-issuer live độc lập chưa xác minh |
| ADMIN/STUDENT đọc cơ bản | **PASS theo owner** | Đăng nhập/OTP và tải dữ liệu; ảnh ADMIN token/students/subjects 200; STUDENT theo phản hồi owner |
| RBAC/ownership âm tính và CRUD ghi | **NOT VERIFIED** | Chưa có bài thử phiên thật cho sai quyền/dữ liệu khác hoặc disposable write fixture |
| OTP challenge/completion | **PASS theo owner** | Owner thao tác đăng nhập thành công với OTP; không tự động hóa nhập secrets |
| LOW/MEDIUM/HIGH và Trusted Device relogin | **NOT VERIFIED** | Không suy risk level từ OTP; không tạo tín hiệu/state giả; checklist mục 11 |
| Dữ liệu/credentials/MFA/trust | **PASS** | Protected row/schema/file hashes trước/sau khớp, chỉ 5 TLS files đổi |

Các nhóm file trong commit: (1) gỡ Teacher/Scheduling backend + regression tests;
(2) UI ADMIN/STUDENT; (3) Gateway RBAC; (4) canonical Docker/fixtures và School
read-only validation; (5) PKI preparation/offline maintenance + 7 tests;
(6) README/architecture/operations/testing và chính báo cáo này.
Không đưa `.local-legacy`, external runtime/archives/backups, credentials/private
keys/keystores, database dumps, logs/tokens/evidence riêng tư hoặc build output vào Git.
Năm file mới trong commit gồm báo cáo này, `scripts/demo/test_fixtures.py`,
`scripts/legacy/school_validate.py`, `deploy/legacy/tls_material.py`,
`scripts/legacy/test_tls_material.py`. Chỉ stage đúng allowlist 69 file đã duyệt;
không đưa private/runtime evidence vào commit. Push chỉ chạy workflow kiểm tra hiện có,
không triển khai production; không đồng nhất CI với Browser acceptance.

Commit message:
`fix(portal): restore admin-student scope and repair local TLS CRL discovery`

## Final Git checkpoint và workspace cleanup — 30/10/2026

Các bảng kế hoạch/inventory dưới đây ghi trạng thái **trước phê duyệt**. Kết quả
thực hiện đã được duyệt nằm ở mục “Kết quả thực hiện và hậu kiểm” cuối phần này.

### Hiện trạng đã đối chiếu

- Canonical `C:\Users\DELL\Documents\zerotrust\zerotrust`; standalone `.git`,
  branch `zerotrust-v4-risk-scoring`, HEAD
  `40fea6a455a9a43eb9d68bcf86b884fbd23e97cd`. Không Git alternates/shared object
  store phụ thuộc worktree/release source cũ.
- `origin/zerotrust-v4-risk-scoring` và actual remote ls-remote cùng
  `0893c09cebb80ccd9e559d0df00398716cad376f`; ahead2/behind0 tại thời điểm đọc.
  Không fetch/reset/stash/rebase/amend hoặc rewrite history.
- Trước lượt này chỉ `TRUST_SCORE_RESEARCH_AND_EXPERIMENT_PLAN.md` modified,
  +409/−9 dòng sau commit B1, gồm actual A5/A6 acceptance và cleanup. Đã review
  score50/82.50, COMPLETE, evaluation IDs/enforcement/session và các giới hạn
  inferred decision_source/token observation, đối chiếu manifests riêng tư.
- Cập nhật thêm chính báo cáo consolidation này để lưu workspace plan. Candidate
  commit chỉ gồm **2 tài liệu**, không production source/config, index vẫn rỗng.
- Scan47 blobs của hai commit chưa push và hai docs working tree bằng mẫu
  private-key/JWT/PAT/access-key và đối chiếu kín21 current runtime secrets:
  không phát hiện match hoặc private/generated path được commit. Review có phạm
  vi, không phải bảo đảm phát hiện mọi dạng secret. Private reports/logs/CSV/XML,
  credentials, keys, keystores, dumps, `.local-legacy` và backup ZIP không vào Git.
- Không rerun A1–A6,21 RBAC,76 Risk/26 SPI hoặc build/redeploy. B0 giữ nguyên;
  trường hợp B1 Browser/ground-truth detection/Risk unavailable Browser và nguyên
  nhân Portal logout A6 còn1 session vẫn theo giới hạn đã ghi ở báo cáo nghiên cứu.

Runtime ban đầu trong lượt này: Engine phản hồi nhưng cả19 containers stopped.
Agent không start container. Sau khi chủ đồ án mở canonical runtime, actual
10/10 healthy;6 build contexts từ effective canonical Compose đều trỏ C. Native
Windows Schannel GET Gateway/Discovery HTTP200. Read-only data snapshot08:46:39
GMT+7 xác nhận School49 rows/23 scores,6 mappings, Flyway V1–V5; Risk93 history,
18 devices,8 subject states,3 revocations. Không tạo account, fixture hoặc ghi DB.
Runtime file hashes vẫn khớp baseline A5/A6; Risk image vẫn B0
`167274d5b40404e0bb47d763c2e322d5a8ae3c8d2722691d661f66419f2e60ee`.

### Danh sách commit được duyệt push — trạng thái lúc chuẩn bị

| Thứ tự | Commit / message | Trạng thái |
|---|---|---|
|1 | `917aeebdb672d04984c4eccc98fc57c5144df943` — `feat(auth): add risk tracing and fix student score reset` | Local, chưa push; đã được duyệt commit ở nhiệm vụ trước |
|2 | `40fea6a455a9a43eb9d68bcf86b884fbd23e97cd` — `feat(risk): add opt-in B1 scoring and offline evaluation` | Local, chưa push; B0 vẫn mặc định/runtime |
|3 | **Chưa tạo** — `docs: finalize adaptive acceptance and workspace inventory` | Đề nghị commit2 docs sau thao tác đã được duyệt/hậu kiểm; không tự có hash hoặc coi đã push |

Allowlist của commit tài liệu:

```text
TRUST_SCORE_RESEARCH_AND_EXPERIMENT_PLAN.md
ZEROTRUST_FINAL_CONSOLIDATION_REPORT.md
```

Đề nghị sau khi được duyệt: hoàn tất đúng cleanup allowlist/hậu kiểm, cập nhật
kết quả thật vào cùng hai docs, scan lại phần mới, stage đúng2 paths, commit với
message trên rồi **fast-forward push chỉ branch này**. Kiểm tra lại remote trước
push; nếu có divergence/thay đổi chưa review thì dừng, không force. Không push
tags/branch khác. `.github/workflows/ci.yml` chạy tests/frontend checks trên
GitHub-hosted runner khi push; không có deployment job hoặc lệnh cập nhật Docker
runtime. CI chưa chạy cho push mới, không gán CI PASS trước bằng chứng.

### Workspace inventory trước xóa: KEEP / SAFE_TO_REMOVE / BLOCKED

Các alias trong bảng là đường dẫn tuyệt đối sau:

| Alias | Đường dẫn |
|---|---|
| C | `C:\Users\DELL\Documents\zerotrust\zerotrust` |
| A | `C:\Users\DELL\Documents\zerotrust\zerotrust-archive-20261027` |
| B | `C:\Users\DELL\Documents\zerotrust\zerotrust-archive-partial-move-preserved-20261027` |
| W | `C:\Users\DELL\.codex\worktrees\legacy-data-integration\zerotrust` |
| R | `C:\Users\DELL\Documents\zt-release-source-20261026` |
| P | `C:\Users\DELL\Documents\zerotrust-legacy-preservation\20261026-1344ea0d` |

Đã tái sử dụng inventory Phase1, kiểm tra existence/HEAD/common-dir/registrations
của12 Git roots vật lý; không suy toàn hệ thống chỉ từ `git worktree list` tại C.
C chỉ đăng ký C. W thực thuộc A: W/.git round-trip tới A/.git/worktrees/zerotrust.
B có bản sao metadata registration W, nhưng W/.git không chọn B; giữ metadata
backup đó, không repair/prune để che một snapshot lịch sử. App không có active
worktree artifact attached chat này. Không tạo worktree/clone mới.

| Git root trước xóa | HEAD rút gọn | Phân loại | Lý do |
|---|---|---|---|
| C |40fea6a | KEEP | Canonical phát triển; B1 source và evidence riêng tư phải giữ |
| A |07701b6 | KEEP | Archive được bảo vệ; common Git owner của W, giữ refs/history/source |
| B |07701b6 | KEEP | Partial-move preservation;368 entries không đọc được khi đo, không đổi ACL/force để xóa |
| W |7ffe0be | **SAFE_TO_REMOVE**, chỉ sau duyệt và preflight lại | Clean tracked/untracked; toàn bộ files/registration đã backup/hash verify; không active CWD/handle hoặc functional Docker dependency tại lần kiểm tra cuối |
| R |8e10c1f | **BLOCKED** |65 staged paths (33M/32A); chưa xác minh đủ việc bảo toàn current index/worktree state trong recovery package riêng cho R; không tự reset/commit/delete |
| A/output/development-demo/final-source-verification |8e10c1f | KEEP | Snapshot trong archive; không phải linked worktree dư được phép xóa |
| A/output/development-demo/workspace |8e10c1f | KEEP | Frozen Demo source có thay đổi và private runtime; Demo MySQL/Redis còn bind qua C/output junction |
| A/output/postfix-03a-subject-identity/native-approved-20261016/git-final-workspace |1e15dc8 | KEEP | Historical Git/evidence snapshot trong archive |
| A/output/postfix-03b-timestamp-lifecycle/candidate |c0b1b01 | KEEP | Historical Git/evidence snapshot trong archive |
| A/output/qa02b-keycloak-runtime/candidate |c0b1b01 | KEEP | Historical Git/evidence snapshot trong archive |
| A/output/qa02c-full-application-e2e/candidate |c0b1b01 | KEEP | Historical source/evidence, không xóa archive hoặc unique data |
| A/output/qa02c-full-application-e2e/final-source-review-20261022/commit-workspace |894e7fc | KEEP | Frozen historical source review trong archive |

Phạm vi tìm bổ sung: Documents/Codex, Desktop, Downloads, source/repos, Projects
(max depth6, không đi theo reparse points/generated trees),339 directories, không
thấy thêm related repository. Đây là bounded project inventory, không tuyên bố
đã scan mọi ổ/thư mục trên máy. `C/output` là junction tới `A/output`, không phải
bản source vật lý khác; **KEEP junction và archive target**.

Các vùng ngoài Git roots vẫn KEEP:

- P: private runtime, TLS/signing inputs, database backups, rollback evidence,
  source bundles/ZIP và bản khôi phục mới. Khoảng1.16GB logic, không đưa vào xóa.
- `C:\Users\DELL\Documents\zerotrust\qa-checkpoints`: khoảng382.96MiB checkpoint/
  evidence; `...\qa-secrets`:4 files/311 bytes private inputs, không xóa.
- `C:\Users\DELL\Documents\zt-release-empty-runtime-20261026`:76 bytes historical
  input; chưa có đủ lý do/xác nhận thay thế để xóa, giữ nguyên.
- Canonical `compose.legacy.yaml`, `scripts/legacy`, `deploy/legacy`, private
  canonical Compose entrypoint/overrides trong P: vẫn dùng để vận hành/build.
- Mọi Docker container/image/network/volume, rollback references, original
  Keycloak/Demo data, databases/backups và `door_iot_mysql_data`: ngoài allowlist.

### Điều kiện an toàn của W và bản khôi phục đã chuẩn bị

W HEAD `7ffe0be2f0a423634bbf0e33d9933be342ea84d5` vẫn có ref
`codex/legacy-data-integration` trong A, đồng thời là ancestor của canonical HEAD.
C có object store độc lập, không Git alternates/hardlink dependency vào W.
`git status --porcelain --untracked-files=all` tại W rỗng; không initialized
workspace dependency được phát hiện. Không xóa branch/ref rollback khi remove W.

Ignored files không bị coi mặc định là rác:541 files, gồm target/classes/JAR/
Surefire XML/TXT/SQL, Python cache và5 evidence. Năm evidence đã bảo toàn trước
vẫn SHA-256 khớp. Để giữ cả historical generated evidence, đã tạo một backup ZIP
trong **existing P/backups**, không tạo source checkout/environment mới:

`P/backups/legacy-worktree-files-before-remove-20261030.private.zip`

-3,318,715 bytes; SHA-256
  `b00e486188d277fe2b27724be0dcd14f4d6aea32334cc84ae29313ae577ee2da`.
- Toàn bộ1.089 worktree files (kể cả ignored, trừ .git pointer) và10 registration
  files được chứa trong ZIP; .git pointer/context được ghi riêng trong package.
- CRC và SHA-256 từng file trong ZIP khớp source, source không đổi khi backup;
  registry/index/reflog/config của W được bảo toàn. ACL ZIP explicit user hiện
  tại/SYSTEM/Administrators, không publish Git. ZIP là KEEP sau cleanup.

Process check ban đầu thấy TGitCache PID27456 giữ handle W/output/legacy-integration;
không còn các CWD blockers cũ. Chủ đồ án đóng cache; agent không kill process.
Lần đọc cuối:0 handle match dưới W/registration/R, process CWDs liên quan đều ở C;
2.816 disk handles kiểm tra được,183 protected/inaccessible processes không đọc
được. DELETE-access sharing probes của W và registration đều mở được; **không
set delete-on-close, không thực hiện delete**. Đây là snapshot trong phạm vi
quyền đọc, cần kiểm tra lại trước remove; nếu TGitCache/IDE/build hoạt động lại
hoặc Git báo sharing lock thì dừng, không force/kill tự động.

Docker kiểm tra cả19 containers, gồm stopped: không bind source vào W hoặc R.
Effective canonical Compose có6 build contexts là C.9 private runtime mounts
canonical đều ở P; Demo data mounts đi qua C/output tới A/output/development-demo/
workspace/.local-demo nên Demo/Archive phải KEEP.4 data containers canonical còn
**labels provenance lịch sử** trỏ W/config cũ, không phải functional mount/build
dependency sau canonicalization. Docker Desktop mở link project cũ có thể hết
đường dẫn sau remove; dùng canonical entrypoint trong P để vận hành. Không
recreate DB containers chỉ để sửa labels. Không thấy W/R references trong scripts/
legacy, deploy/legacy hoặc .idea runtime/development path configuration đã scan.

### Allowlist đã được duyệt — kế hoạch trước thực hiện

| Đường dẫn chính xác | Thao tác sau duyệt | An toàn/khôi phục | Bytes logic dự kiến |
|---|---|---|---:|
| `C:\Users\DELL\.codex\worktrees\legacy-data-integration\zerotrust` | `git -C A worktree remove W`, **không force**; Git tự gỡ registration thật `A/.git/worktrees/zerotrust` | Source clean, refs/ZIP bảo toàn, không runtime bind/build vào W; giữ A/B/C/P và branch rollback |7,694,503 +84,508 registration |
| `C:\Users\DELL\.codex\worktrees\legacy-data-integration\.codex-worktree-name` | Chỉ sau remove W thành công, xác nhận file thường0 byte/không reparse rồi xóa đúng file | Marker wrapper rỗng, không source/evidence; trạng thái0 byte được ghi trong manifest để khôi phục nếu cần |0 |
| `C:\Users\DELL\.codex\worktrees\legacy-data-integration` | Chỉ sau hai bước trên và **directory hoàn toàn rỗng**, Remove-Item literal path không recursive | Không xóa parent `.codex/worktrees`, không chạm folder/worktree khác |0 |

Không `git worktree prune`, force removal, recursive delete rộng, `git clean`,
Docker prune/cleanup hoặc xóa A/B/R/P. Bản sao registration W trong B là historical
backup, giữ nguyên dù sau remove có thể được Git hiển thị stale/prunable.

Khôi phục nếu cần: C vẫn nguyên; A giữ ref/commit7ffe. Sau khi xác nhận trạng
thái actual removal, dùng Git bình thường khôi phục đúng worktree path/ref cũ
nếu cần rollback, rồi phục hồi payload `worktree-files` từ ZIP. Không chép mù Git
registration/index lên common repo hoặc overwrite canonical; phần registration
đã backup phục vụ đối chiếu. Marker wrapper0 byte có thể tạo lại theo manifest.
Không tạo checkout khôi phục trong lượt preflight này. Nếu remove thất bại một
phần thì dừng và đối chiếu/khôi phục từ bản đã verify; không xóa tiếp cho xong.

### Dung lượng, giới hạn và hậu kiểm sau duyệt

W logical7,694,503 bytes; registration84,508 bytes; gross7,779,011 bytes
(~7.78MB). Backup mới giữ lại3,318,715 bytes (~3.32MB), nên net logical so trước
chuẩn bị backup là **4,460,296 bytes (~4.46MB,4.25MiB)**. Không có hardlink/reparse
file trong W được đếm. Đây là ước lượng logical, không cam kết dung lượng vật lý
NTFS/MFT/SSD hoặc chênh lệch ổ C đúng bằng giá trị này.

Phần lớn dung lượng ngoài canonical nằm trong **protected archive A**, khoảng
7,136,875,461 bytes (~6.65GiB); không đưa vào allowlist. B đo được ít nhất
16,257,991 bytes, có368 errors nên đây là lower bound; R5,508,792 bytes vẫn
BLOCKED. C khoảng719.24MiB không tính output junction; không xóa canonical cache
hoặc research output. QA checkpoints khoảng382.96MiB KEEP. Không hứa thu hồi GB
bằng việc xóa worktree nhỏ này.

Ổ C free snapshot trong inventory116,484,079,616 bytes; sau backup/user mở Docker
116,146,925,568 bytes. Chưa có deletion, không gán chênh lệch background/VM growth
cho cleanup. Sẽ đo lại ngay trước/sau actual removal để báo số quan sát và lượng
payload được xóa riêng, không thu nhỏ Docker VHDX.

Sau duyệt, tuần tự: preflight lại path/HEAD/status/file hashes/backup/process/
mounts/remote và data/TLS baseline; remove đúng3 targets; xác nhận canonical
source/B1/Git không mất thay đổi, W không còn và real registration đã gỡ, các
KEEP/BLOCKED còn nguyên; canonical Compose còn resolve/build từ C; container IDs,
images/volumes, School/credentials/OTP/signing/Trust/Risk/Flyway/Redis và native
TLS giữ nguyên. Không chạy lại A1–A6/RBAC hoặc build/redeploy. Nếu live runtime
stopped hoặc TLS/preflight fail thì ghi BLOCKED, không giả định healthy hoặc tự
start/disable verification. Cập nhật outcome vào cùng hai docs trước commit/push
đã được duyệt. Rollback push nếu cần phải là commit sửa/revert mới có duyệt,
không force push/rewrite history.

**CRL cần bảo trì trước04/11/2026 01:49:27 GMT+7**
(03/11/2026 18:49:27 UTC). File hash còn khớp bản có issuer/signature/expiry đã
verify; native HTTPS hiện200. Nên xử lý trước ngày03/11 khi còn thời gian kiểm
tra, không đợi nextUpdate. Lượt này không renew CRL/cert, sửa trust store/DNS/hosts
hoặc tắt revocation check; bảo trì TLS là scope riêng cần duyệt.

### Kết quả thực hiện và hậu kiểm — 30/10/2026

**PASS — cleanup đúng allowlist, hoàn tất09:12:30 GMT+7:**

- `git -C A worktree remove W` exit0, không force; W và registration thật
  `A/.git/worktrees/zerotrust` đã hết. `git worktree list` tại C chỉ còn C, tại A
  chỉ còn A. Bản sao metadata lịch sử trong B giữ nguyên, không prune.
- Xóa marker sau khi xác nhận file thường0 byte/không reparse; xóa wrapper sau
  khi xác nhận hoàn toàn rỗng. Cả hai dùng literal path, không recursive/force.
- Lệnh gộp ban đầu bị automatic approval review chặn trước khi thực thi. Không
  có thay đổi từ lệnh đó; ba lệnh literal riêng, phạm vi hẹp hơn được review cho
  phép và thực hiện thành công. Không dùng force hoặc biện pháp phá hủy thay thế.
- Preflight đối chiếu lại1.089 files/10 registration files với backup; clean
  Git/HEAD, không active handle/CWD hay Docker dependency vào W. Backup ZIP SHA-256
  vẫn khớp, ref `codex/legacy-data-integration` tại A vẫn trỏ `7ffe0be`.
- C/A/B/P, junction C/output và các snapshot KEEP còn nguyên. R vẫn65 staged
  paths (33M/32A), **BLOCKED** cho cleanup; không reset/commit hoặc xóa R.

**PASS — hậu kiểm09:14:05–09:14:38 GMT+7:**

| Kiểm tra | Bằng chứng sau xóa |
|---|---|
| Canonical source | Snapshot mã/config/test khớp trước xóa; B1 commit40fea6a còn nguyên, chỉ hai báo cáo thay đổi |
| Docker | Cùng10 canonical container IDs/image IDs,10/10 healthy; tất cả19 containers/36 image-reference rows/8 networks/25 volumes giữ nguyên |
| Compose và dependency | Effective canonical Compose resolve khi W không còn;6 build contexts đều là C;0 functional mounts vào W; không recreate data containers vì labels provenance cũ |
| School |49 business rows/23 scores và6 School–Keycloak mappings khớp |
| Keycloak | Các row hashes/schema được chọn của realm/users/roles/credentials/OTP/config/Browser Flow/signing components khớp baseline |
| Risk/Flyway |93 success events/18 devices/8 subject states/3 revocations và V1–V5 khớp |
| Đối chiếu dữ liệu | Toàn bộ24 row-hash multisets và normalized schemas khớp; không reset/import/restore/reseed sequence hoặc ghi dữ liệu để ép khớp |
| Runtime/private/TLS | Runtime file hashes giữ nguyên; native Schannel GET Gateway và OIDC Discovery đều200 với xác minh mặc định, không bỏ kiểm tra certificate/revocation |
| Phạm vi giữ lại | `door_iot_mysql_data`, original Keycloak/Demo/rollback resources, backups/private evidence và archives còn nguyên |

Source publication được chủ đồ án duyệt gồm hai commit917aeeb/40fea6a và một
commit mới **chỉ hai báo cáo** với message đã nêu. Sau ghi nhận kết quả này:
scan lại docs, stage đúng hai paths, commit rồi push fast-forward chỉ branch
`zerotrust-v4-risk-scoring`; đối chiếu remote SHA với local HEAD và working tree
sạch. Hash commit cuối/kết quả push được lưu trong evidence riêng tư và thông
báo hoàn tất để tránh tự tham chiếu hash trong nội dung commit. CI của push mới
**NOT VERIFIED** ở thời điểm chuẩn bị commit này; không coi push là deployment B1.

**Dung lượng thực tế quan sát:** payload logic đã xóa7,779,011 bytes; backup mới
giữ lại3,318,715 bytes, net logic4,460,296 bytes (~4.46MB). Ổ C free tại approved
preflight115,520,274,432 bytes, sau xóa115,100,020,736 bytes: giảm420,253,696 bytes
trong khoảng quan sát. Có hoạt động hệ thống đồng thời, không đủ bằng chứng quy
chênh lệch vật lý đó cho cleanup và **không tuyên bố C free tăng4.46MB**. Không
dọn Docker/cache hoặc compact VHDX để làm đẹp số liệu.

**Giới hạn còn lại:** R có thay đổi chưa bảo toàn đầy đủ nên vẫn BLOCKED; các Git
snapshots trong archive/Demo là KEEP, không tuyên bố chỉ còn một Git directory
vật lý. B1 chưa deploy; các hạn chế Browser B1/ground truth/Risk unavailable và
logout A6 giữ nguyên trong báo cáo nghiên cứu. Không chạy lại A1–A6/RBAC hoặc
tests/builds đã PASS. CRL vẫn cần bảo trì trước04/11/2026 01:49:27 GMT+7 như trên.

## Tiếp tục phần ghi nhận lịch sử ngày28/10/2026

Kiểm thử tái sử dụng: 324 Portal, 20 Gateway, 6 Python, frontend lint/typecheck/build
đã PASS khi mã app hiện tại không đổi. Kiểm thử mới: 7 PKI PASS. `git diff --check`
PASS và scan 525 files không có findings theo mẫu secret đã kiểm tra. Không tuyên bố
source review là chứng nhận toàn hệ thống an toàn. Không có blocker TLS còn biết;
blocker nghiệm thu đồ án còn lại là kết quả đăng nhập/OTP và Adaptive/ownership thực.

### Quan sát runtime sau khi chốt Git — 28/10/2026, 08:30 giờ Việt Nam

**PASS — Git:** source commit `a09e4caf5900c8088d83d4c5075a75e5f365f2e3`
đã push đúng branch; remote khớp local và working tree sạch. Không force/amend,
không đưa runtime/evidence/keys vào Git. Bổ sung tài liệu này trong một commit
riêng để giữ nguyên lịch sử và phản ánh đúng trạng thái runtime quan sát được.

**NOT VERIFIED tại 08:30 — quan sát lịch sử, đã được thay bằng kết quả 08:35 bên dưới:** cả 10 canonical containers khi đó đang
`exited`. Docker `FinishedAt` ghi thời điểm dừng khoảng 07:40:59–07:41:32, trước
source commit lúc 08:28:39. Cả 10 vẫn cùng IDs, image IDs và mounts; không ghi nhận
OOMKilled. Chưa xác định tác nhân dừng từ những bằng chứng này, không quy kết lỗi
TLS hoặc lỗi code. Lượt commit/push không chạy stop/start/restart/recreate, không
thay runtime files hoặc volume. Giữ nguyên trạng thái, không tự bật lại hệ thống.

Các PASS TLS/HTTP/JWT/data preservation ở trên là bằng chứng lần nghiệm thu trước
khi runtime dừng; không tuyên bố HTTPS đang phục vụ khi containers đã dừng. Dùng
lệnh start hiện có ở mục 12 khi chủ đồ án muốn chạy lại; không init/import/migration.
Evidence riêng tư: `git-post-push-runtime-observation-20261028.json`.
Browser/OTP/Adaptive và live ADMIN/STUDENT vẫn NOT VERIFIED.

### Tiếp tục sau khi chủ đồ án bật lại Docker — 28/10/2026, 08:35 giờ Việt Nam

**PASS — runtime:** 10/10 canonical containers đang running/healthy. IDs, images,
mounts và 5 file TLS khớp bản đã duyệt. CA/private keys và passwords khớp hashes cũ.
Không cần start/restart/recreate thêm; không build, init/import/reset/migration,
cleanup, đổi Windows trust store hoặc thay dữ liệu.

**PASS — kiểm tra có trọng tâm sau bật lại:** hai Windows Schannel HTTPS endpoint
trả 200 với CA file và revocation mặc định; bốn kết nối Gateway→Backend/Keycloak,
Backend→Keycloak/Risk đạt khi JVM bật kiểm tra thu hồi. Windows lấy được đúng CRL
hiện tại; OIDC Discovery giữ issuer/S256; service-account grant chính thức và Risk
caller authorization đạt (payload rỗng bị validation 400 trước scoring).
Tái sử dụng các test source và bộ security checks trước đó; không chạy lại toàn suite.

**PASS — persistence qua lần dừng/bật:** School schema/row hashes giữ nguyên (49
rows, 23 scores), sáu School–Keycloak UUID mappings, Keycloak credentials/OTP/MFA/
roles/components/realm/client/flow configuration, toàn bộ Risk tables/Flyway V1–V5
và Redis đều khớp snapshot sau TLS. Không có bảng nào đổi fingerprint; Trusted
Device state trong Risk giữ nguyên. Không thao tác browser cookie/device trust.

**BLOCKED — nghiệm thu user flow:** chủ đồ án đã báo lỗi “Chưa thể kết nối máy chủ”
và gửi ảnh Network: Keycloak `step1.html` bị chặn với `net::ERR_CERT_AUTH...`.
Chưa login được nên không ghi PASS cho login/logout, OTP, LOW/MEDIUM/HIGH,
Trusted Device Browser Flow hoặc ownership/RBAC trên phiên thật.
Checklist mục 11 tiếp tục áp dụng. CRL vẫn cần gia hạn trước 02/11/2026.

Evidence riêng tư: `resume-runtime-before-20261028.json`,
`resume-http-tls-verification-20261028.json`, `resume-data-20261028.json`,
`resume-preservation-20261028.json`, `resume-runtime-final-20261028.json`.

### Chẩn đoán lỗi Cốc Cốc từ ảnh của chủ đồ án — 28/10/2026

**FAIL trước import — browser/default Windows trust (đã khắc phục native trust bên dưới):** ảnh Network cho thấy Keycloak third-party
cookie iframe `step1.html` lỗi `net::ERR_CERT_AUTH...`; thanh địa chỉ Portal “Không
bảo mật”. Kiểm tra lại đúng URL
`https://localhost:28444/realms/DoAn/protocol/openid-connect/3p-cookies/step1.html`:
Windows Schannel dùng native trust mặc định trả `SEC_E_UNTRUSTED_ROOT` (exit 60),
trong khi cùng request có `--cacert <project CA>` trả exit 0 / HTTP 200 và vẫn giữ
revocation mặc định. Không dùng tùy chọn bỏ kiểm tra chứng chỉ.

Đã kiểm tra chỉ đọc: CA `CN=ZeroTrust Legacy Integration CA`, thumbprint SHA1
`5DFA54E7FE9DC555E0A56BAE2DA635B05187ADA0`, không nằm trong cả
`Cert:\CurrentUser\Root` và `Cert:\LocalMachine\Root`. Kết quả TLS PASS trước đó
là xác minh với CA file hoặc process-only custom trust; không phải xác nhận CA
đã được browser/Windows mặc định tin cậy. CRL/CDP đã sửa vẫn hoạt động.

Keycloak-js được cấu hình silent check SSO nên tạo iframe kiểm tra 3p cookie,
chờ message tối đa 10 giây. Khi TLS iframe bị chặn, init thất bại và Portal hiển thị
thông báo generic đang thấy. Chưa có bằng chứng cần sửa API hoặc thay policy/MFA.
Lỗi onboarding.js trong Console không được dùng để kết luận lỗi source Portal.

**BLOCKED tại thời điểm chẩn đoán — phê duyệt và import đã hoàn tất bên dưới:** đã đề xuất thêm đúng public CA trên vào
CurrentUser Root của user đang sử dụng, không LocalMachine. Windows/app dùng
trust store này sẽ tin các TLS certificate do CA đó ký; phạm vi không chỉ riêng
một tab Portal. Giữ CA/private keys, TLS leaf, Docker, PKCE, realm, credentials và
MFA nguyên vẹn. Rollback chỉ gỡ chính CA đã thêm, theo fingerprint và journal,
không gỡ root khác. Phương án thay thế là dùng profile riêng đã tin CA, giữ
Windows trust store nguyên trạng. Tại bước chẩn đoán chưa thay trust; bước thực hiện sau duyệt được ghi riêng bên dưới.

Computer Use trên Cốc Cốc Windows đã bị chặn bởi URL policy enforcement chưa
được hỗ trợ; không dùng công cụ/UI khác để né giới hạn. Việc chẩn đoán trên dùng
ảnh chủ đồ án cung cấp, source và HTTP/Windows certificate checks chỉ đọc.
Evidence riêng tư: `browser-native-trust-diagnosis-20261028.json`,
`browser-windows-root-presence-20261028.json`.
Tham chiếu thao tác trust store:
[Microsoft Import-Certificate](https://learn.microsoft.com/en-us/powershell/module/pki/import-certificate?view=windowsserver2025-ps).

### Windows CurrentUser Root — đã được chủ đồ án duyệt và thực hiện ngày 28/10/2026

**PASS — phạm vi thay đổi:** thêm đúng một public CA `CN=ZeroTrust Legacy Integration CA`,
thumbprint SHA1 `5DFA54E7FE9DC555E0A56BAE2DA635B05187ADA0`, vào
`Cert:\CurrentUser\Root` của user hiện tại. Hash PEM nguồn được pin theo manifest
đã bảo toàn. Đối chiếu toàn bộ root fingerprints chứng minh chỉ thêm CA này;
LocalMachine Root và các root cũ không đổi. Không import private key hoặc server
leaf. Chỉ thực hiện sau phản hồi trực tiếp “Duyệt thêm CA vào CurrentUser Root”.

**PASS — Windows native HTTPS:** ba request Portal `/`, Keycloak OIDC Discovery và
`/realms/DoAn/protocol/openid-connect/3p-cookies/step1.html` đều exit 0 / HTTP 200.
Dùng `curl.exe --disable` để bỏ cấu hình curlrc, native store mặc định, không `--cacert`,
không tùy chọn bỏ TLS/hostname/revocation. Native X509Chain trên cả Gateway/Keycloak
với `TrustMode=System`, `RevocationMode=Online`, `ExcludeRoot`, `NoFlag` đều hợp lệ,
2 phần tử, không lỗi và kết thúc tại đúng CA đã duyệt. Lỗi untrusted root được xử lý
mà không sửa OIDC/PKCE/MFA, không cấp lại leaf hoặc thay private keys.

**PASS theo xác nhận chủ đồ án — login ADMIN/STUDENT sau sửa trust:** chủ đồ án đã
reload và báo đăng nhập được cả ADMIN/STUDENT, có yêu cầu OTP. Không nhập password/OTP
thay người dùng. **FAIL — tải dữ liệu sau login:** cả hai role không lấy được dữ liệu;
nguyên nhân và bản sửa frontend ở mục tiếp theo. Chưa dùng đăng nhập thành công để
ghi PASS cho nghiệp vụ, ownership hoặc toàn bộ Browser Flow.
Các nhánh LOW/MEDIUM/HIGH, Trusted Device, RBAC/ownership live tiếp tục cần nghiệm thu.
Computer Use trên browser này vẫn bị chặn do URL policy enforcement chưa hỗ trợ;
không sử dụng công cụ khác để né giới hạn.

Rollback chỉ gỡ đúng CA đã được workflow thêm theo thumbprint/journal xác nhận
không tồn tại trước đó. Script/journal nằm trong ignored private evidence, không
đưa CA keystore/private keys hoặc runtime state vào Git. Hướng dẫn vận hành đã cập
nhật để phân biệt xác minh bằng CA file với Windows native/browser trust.
Evidence: `browser-root-approval-20261028.json`,
`browser-root-installation-20261028.private.json`,
`browser-native-trust-after-20261028.json`, `browser-system-chain-after-20261028.json`.

### Lỗi tải dữ liệu sau đăng nhập — frontend API origin

**PASS theo xác nhận thủ công:** chủ đồ án báo ADMIN và STUDENT đã đăng nhập được,
có OTP. **FAIL — tải dữ liệu:** cả hai role không hiển thị dữ liệu.

Đã đọc bundle JS từ chính container frontend đang phục vụ: API base vẫn là
`process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080"`.
Dockerfile không khai báo/đặt biến này khi Next build; canonical Compose cũng thiếu
build arg. Do đó browser gọi API địa chỉ development trong khi canonical API đi qua
Gateway `https://localhost:28443/api/...`. Không sửa RBAC/MFA để vượt lỗi kết nối.
SPA audience mapper đã kiểm tra chỉ đọc: `zerotrust-api` có trong access token,
đúng audience mà Gateway/Backend yêu cầu.

**PASS — sửa và build offline:** Dockerfile frontend đặt `NEXT_PUBLIC_API_BASE_URL`
từ build arg `API_BASE_URL` (mặc định chuỗi rỗng), canonical Compose và generator
truyền rõ chuỗi rỗng để API đi theo origin của Portal. Không sửa mã nghiệp vụ TS/Java.
Ba Compose portability tests PASS; production Next build PASS. Tái sử dụng frontend
lint/type checks đã PASS của cùng mã app, không chạy lại các suite Java không đổi.
Quét 11 JS chunks trực tiếp từ image archive (không tạo container) xác nhận compiled
API base là chuỗi rỗng; không còn `localhost:8080`/biến runtime chưa inline.

Image frontend mới: `sha256:6a548c25f8946e9bb0e4eb42b9ddde9e1f33ff21e2726ebdc203e37c1645372c`.
Snapshot source/build: `fa8e749e03782c1fd4d5c72d37f090c0a0acfce5c74b2ebd1970e9990f1aa510`.
Trước cập nhật, Frontend chạy `sha256:a4d8c9df4054d42d90873d104f647352c2f5c4bb707cc4cd9b8f263b7863294c`;
hiện đã chạy image mới ở trên, container `e40d1f6f2552910322620697fa3247a8f689b209df53eb8f88dc44bd2c7e6875`.
Đã bảo vệ rollback ref
`zerotrust-legacy-frontend:rollback-api-origin-20261028-a4d8c9df4054`.

**PASS — triển khai theo phê duyệt “Duyệt Frontend, commit và push”:** chỉ recreate
Frontend trong canonical project. 10/10 healthy; chín container còn lại cùng IDs,
images, mounts và StartedAt; toàn bộ private runtime files không đổi. Kiểm tra JS
thực sự phục vụ qua Gateway đã dùng API base mới. Missing-token APIs vẫn 401.
Windows native HTTPS vẫn 200; không cần restart Gateway/Keycloak. Rollback ref được
giữ, chưa cần sử dụng. Owner sau refresh xác nhận dữ liệu đã tải; ảnh Network token,
students, subjects đều 200. CRUD ghi và negative RBAC/ownership vẫn NOT VERIFIED.

**Bảo toàn:** School row/schema/mappings và Keycloak credentials/config hashes vẫn
khớp trước đăng nhập. Sau các lần login thật, `authentication_success_events` tăng
72→75 và `known_devices` tăng 14→16; Redis cũng đổi. Đây là thay đổi history/device
quan sát được trong cửa sổ người dùng login, được phân biệt với dữ liệu nghiệp vụ.
Không có thao tác reset/revoke/fixture từ agent; không tuyên bố toàn bộ Risk/Redis
fingerprints bất biến qua đăng nhập. Không suy OTP challenge tương đương MEDIUM:
LOW/incomplete/cold-start có thể yêu cầu MFA theo guardrail hiện có.

Evidence: `browser-post-login-api-bundle-diagnosis-20261028.json`,
`api-origin-source-snapshot-20261028.json`, `api-origin-rollback-20261028.json`,
`api-origin-frontend-build-20261028.json`, `api-origin-built-bundle-verification-20261028.json`,
`api-origin-spa-audience-check-20261028.json`, `manual-login-corroboration-20261028.json`,
`browser-root-preservation-20261028.json`.

### Console sau khi dữ liệu đã tải — bằng chứng và giới hạn

**PASS theo owner — tải dữ liệu:** owner xác nhận “đã tải được dữ liệu”, ảnh Network
có token 200, students 200, subjects 200 tại màn hình ADMIN scores. Không đưa nội dung
bảng điểm hoặc bearer token từ ảnh vào báo cáo. STUDENT tải dữ liệu theo phản hồi owner.

Cảnh báo sandbox liên quan `silent-check-sso.html` được tạo bởi keycloak-js 26.2.4.
Đã đối chiếu source adapter đang dùng và issue upstream
[#353](https://github.com/keycloak/keycloak-js/issues/353), cùng
[tài liệu silent SSO](https://www.keycloak.org/securing-apps/javascript-adapter).
Callback project là HTML tĩnh chỉ postMessage tới cùng origin. Cảnh báo cho biết
sandbox không cung cấp isolation với same-origin scripts; không phải bằng chứng
API request bị lỗi. Không bỏ sandbox flags, disable SSO/MFA hay sửa node_modules
chỉ để dập cảnh báo. Không khẳng định mọi iframe cùng cờ đều an toàn; nhận định này
chỉ dựa trên callback kiểm soát được của project và hành vi adapter hiện có.

**PASS — xác định nguồn onboarding.js:** app assets không có file/marker
`onboarding.js`, `createOnboardingFrame`, `content-script.js`. Ảnh Sources owner gửi
sau đó cho thấy `Content scripts → Tải video & audio → onboarding.js`; vậy nguồn
lỗi là thành phần browser chèn vào. Lỗi component vẫn có thể xuất hiện trong Console,
nhưng không phải file của Portal. Không chỉnh source project hoặc thay extension state.
Không lưu OAuth code/session_state/fragment do owner dán trong chat vào báo cáo/Git.

**PASS — browser HTTPS được owner xác nhận bằng ảnh:** sau mở lại Cốc Cốc, thanh
địa chỉ `/admin` hiển thị ổ khóa, hết dấu “Không bảo mật”. Kết quả này bổ sung cho
Windows native Schannel/System chain/Online revocation PASS và CurrentUser CA đã
được duyệt. Chỉ kết luận với browser/profile/hostname đang nghiệm thu, không suy
mọi máy hoặc mọi browser đã tin CA. Không dùng thao tác bỏ qua warning để đạt PASS.

School/mappings/Keycloak credentials/config trước/sau frontend deployment vẫn khớp.
Risk chỉ đổi `authentication_success_events` trong cửa sổ owner login/refresh;
không thay đổi dữ liệu nghiệp vụ hoặc reset MFA/trust. Hai known_devices mới có
TRUSTED/trusted_at là persistence từ login thật; chưa chứng minh trusted relogin.
Evidence: `api-origin-deployment-20261028.json`, `api-origin-preservation-20261028.json`,
`manual-login-device-registration-20261028.json`, `browser-console-diagnosis-20261028.json`.

Bản sửa cấu hình và cập nhật hai tài liệu được lưu đúng 5 file đã duyệt với message
`fix(frontend): route portal API calls through the gateway`; commit chứa phiên bản
báo cáo này tiếp nối `4a70337`. Kiểm tra staging không có private state/keys/evidence,
`git diff --cached --check`, local/remote branch và working tree sau push.

### Kết luận sau ảnh Sources cuối của chủ đồ án

- **PASS:** HTTPS browser có ổ khóa; Windows native chain/revocation và 3 endpoint
  Portal/Discovery/3p-cookie check đã đạt, CurrentUser CA đúng approval.
- **PASS theo owner và ảnh HTTP:** ADMIN/STUDENT đăng nhập có OTP, dữ liệu đã tải;
  token exchange và các GET students/subjects quan sát được trả 200.
- **PASS — phân loại lỗi Console:** `onboarding.js` thuộc content script “Tải video
  & audio”; đây là nguồn browser component, không thuộc build Portal. Cảnh báo iframe
  vẫn tồn tại trong keycloak-js 26.2.4 như issue upstream đã ghi, không sửa thư viện
  hoặc bỏ xác minh bảo mật để che thông báo.
- **NOT VERIFIED:** LOW/MEDIUM/HIGH theo policy decision thực, HIGH deny, trusted
  device relogin bỏ OTP, logout đầy đủ, cross-student/ADMIN negative RBAC trên phiên
  thật và CRUD ghi bằng fixture được duyệt. Không tuyên bố toàn hệ thống PASS.

Source fix nằm trong commit `39d9f55699521cb87a04880865025a65012d8589`, message
`fix(frontend): route portal API calls through the gateway`; đúng 5 file đã duyệt
và đã push. Bản bổ sung tài liệu này chỉ chốt evidence owner, không đổi app/runtime.
Evidence `browser-final-owner-evidence-20261028.json` không chứa code/token/session
values. Report vẫn là tài liệu tổng hợp duy nhất.
