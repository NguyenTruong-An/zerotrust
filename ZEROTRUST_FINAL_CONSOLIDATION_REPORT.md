# ZeroTrust — Source ADMIN/STUDENT, Windows TLS và nghiệm thu

Bắt đầu 27/10/2026, cập nhật 28/10/2026, Asia/Saigon. Đây là báo cáo tổng hợp duy nhất của nhiệm vụ;
các số liệu được cập nhật tại chỗ khi có bằng chứng mới.

**Kết luận tổng hợp: NOT VERIFIED.** Source ADMIN/STUDENT đã review; TLS Windows và
kết nối nội bộ có kiểm tra thu hồi PASS sau triển khai được phê duyệt ngày 28/10/2026.
Runtime 10/10 healthy; database, credentials/MFA, JWT signing keys và Trusted Device
được bảo toàn. Browser Flow, nghiệp vụ có user login và LOW/MEDIUM/HIGH thực tế còn
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
`NguyenTruong-An/zerotrust`, branch `zerotrust-v4-risk-scoring`. Commit chứa chính
phiên bản báo cáo này; parent là baseline trên. Đối chiếu remote branch bằng
`git ls-remote --heads origin zerotrust-v4-risk-scoring` với local `git rev-parse HEAD`
sau push, không force push/amend. Working tree được kiểm tra sạch sau commit.
Bằng chứng Git cụ thể được trả kèm kết quả thực thi; không cần ghi hash của chính
commit chứa báo cáo vào nội dung của commit đó.
Commit message: `fix(portal): restore admin-student scope and repair local TLS CRL discovery`.

## 2. Application images

**PASS:** Backend, Frontend và Gateway đã build từ canonical source, bao gồm các thay đổi chưa commit.
Keycloak, Risk và CRL không build lại. Snapshot đầu vào: `df8fa2b01df0c00e316d1798bf137ade664c5d1c147d9d3312da1cb0e3839b18`.
HEAD: `da16120e8e93c8cbea0872f90cbe90ab9379057d` + dirty working tree. Image labels lưu cả revision và snapshot hash.
Không chạy lại các suite đã PASS của cùng source; Docker build vẫn biên dịch/package và Next build.

| Service | Image ID mới | Image ID đang chạy/rollback | Reference rollback được giữ |
|---|---|---|---|
| backend | `sha256:ea0942f875185551a0a86f68547f2d6ccee764fee311a401e284d06a4649dec2` | `sha256:979e917142b6920f5fff0b7ef97a114eef12349873009b2f9cbc95acf74e0451` | `zerotrust-legacy-backend:rollback-final-20261027-979e917142b6` |
| frontend | `sha256:a4d8c9df4054d42d90873d104f647352c2f5c4bb707cc4cd9b8f263b7863294c` | `sha256:b49de98b73b532f63878f7cf4f36ee621635b6eaa7833f6a8ad59d79c0694412` | `zerotrust-legacy-frontend:rollback-final-20261027-b49de98b73b5` |
| gateway | `sha256:66d7b52fb53ca1693f958e658366d8f0f440a6340d147a467adf8290bff80c36` | `sha256:890ce31102ef053f38c14fe08d28ee8a4550f0179e01d51c08cf57180882250c` | `zerotrust-legacy-gateway:rollback-final-20261027-890ce31102ef` |

Ba rollback references mới và sáu references rollback Phase 2B đã được xác minh tồn tại.
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

**NOT VERIFIED cho nghiệm thu nghiệp vụ live:** Admin quản lý tài khoản/sinh viên/lớp/môn/điểm;
Student đọc hồ sơ/điểm đúng người và từ chối dữ liệu người khác cần user login hợp lệ.
Không giả user token, tạo role/account, sử dụng signing keys để tự ký JWT hoặc sửa 49 business rows.
Các test nguồn 324 Portal/20 Gateway PASS đã tái sử dụng, không thay thế nghiệm thu user flow thật.

## 5. Adaptive Authentication acceptance

- LOW → ALLOW: **NOT VERIFIED** trên user flow của bản triển khai này.
- MEDIUM → STEP_UP_MFA và hoàn tất OTP: **NOT VERIFIED**.
- HIGH → DENY trong Browser Flow: **NOT VERIFIED**; không tạo tín hiệu giả, revoke device hoặc đổi policy.
- Trusted Device đăng ký/relogin: **NOT VERIFIED** bằng flow thực; dữ liệu trust hiện có được bảo toàn.
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
- **NOT VERIFIED:** ADMIN/STUDENT functional/ownership acceptance và LOW/MEDIUM/HIGH,
  OTP, Trusted Device, login/logout qua Browser Flow thực tế.
- **BLOCKED trong cleanup lịch sử:** linked worktree được giữ vì process CWDs. Không xử lý lại
  trong nhiệm vụ TLS; không phải blocker của TLS hoặc source ADMIN/STUDENT.
- **PASS:** cleanup allowlist đã hoàn tất; 25 volumes được giữ. Các volumes UNKNOWN và worktree ngoài allowlist không được xóa.
- Dung lượng host C chỉ tăng khoảng 16.70MB trong cleanup; chưa thu nhỏ VHDX và không tuyên bố giải phóng 19.09GB trên ổ C.

### Checklist Windows để nghiệm thu thủ công

**NOT VERIFIED** cho tới khi có kết quả thực tế từ chủ đồ án. Dùng browser profile
đã tin CA riêng tư được cho phép trước đó; không chấp nhận cảnh báo chứng chỉ,
không sửa Windows Root và không gửi password/OTP/token/cookie vào báo cáo.
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
| Commit/push | **PASS** | Chủ đồ án đã duyệt; commit chứa báo cáo này có parent `da16120`; local/remote branch khớp sau push, working tree sạch |
| Windows TLS/CRL | **PASS** | Schannel HTTP 200 hai endpoint, online native chain và CRL ký hợp lệ |
| Docker | **PASS** | 10/10 healthy; IDs/images/mounts và data volumes giữ nguyên |
| OIDC discovery/PKCE entrypoint | **PASS** | Discovery sau TLS; tái sử dụng bằng chứng S256 form/missing+plain bị từ chối của cùng client config; chưa hoàn tất user login/code exchange |
| JWT/service authorization | **PASS** | Chữ ký/issuer/audience/expiry thật, 401/403, 6 service-JWT checks; wrong-issuer live độc lập chưa xác minh |
| ADMIN/STUDENT live/RBAC/ownership và CRUD ghi | **NOT VERIFIED** | Cần user session hợp lệ; regression tests đã PASS không thay thế nghiệm thu live |
| LOW/MEDIUM/HIGH, OTP, Trusted Device Browser Flow | **NOT VERIFIED** | Không tự động hóa login/OTP hoặc tạo tín hiệu/state giả; checklist mục 11 |
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

Kiểm thử tái sử dụng: 324 Portal, 20 Gateway, 6 Python, frontend lint/typecheck/build
đã PASS khi mã app hiện tại không đổi. Kiểm thử mới: 7 PKI PASS. `git diff --check`
PASS và scan 525 files không có findings theo mẫu secret đã kiểm tra. Không tuyên bố
source review là chứng nhận toàn hệ thống an toàn. Không có blocker TLS còn biết;
blocker nghiệm thu đồ án còn lại là kết quả đăng nhập/OTP và Adaptive/ownership thực.
