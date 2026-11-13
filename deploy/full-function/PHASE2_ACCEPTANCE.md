# Phase 2 — nghiệm thu Adaptive Authentication tại local

Ngày 11/11/2026, tiếp tục sau Windows shutdown. **OVERALL_LOCAL_ACCEPTANCE: PARTIAL.**
Không có phê duyệt release/public; **D-17 PENDING, G8 INTERNET_NO_GO**.

Profile đang chạy `zt-full-function-20261111b`: **9/9 healthy**, khởi động lại đúng
container hiện hữu; không import/reset database, realm hoặc tài khoản. Lab và PD-R19
giữ trạng thái sau shutdown, không được khởi động. Candidate sửa lỗi Risk được kiểm
riêng trên bản restore synthetic rồi dừng, **chưa thay pin profile đang chạy**.

## A. Baseline chính xác

- Canonical HEAD `81d6322a7624d3632f69215daf45537f922dd950`; working tree có thay đổi
  chưa commit. Không coi HEAD là bằng chứng mọi image được build tại cùng commit.
- Legacy: realm DoAn, Keycloak26.7.0 theo hồ sơ tích hợp; image IDs thực tế của
  container đang dừng được ghi trong [artifact matrix][artifacts]. Ví dụ Keycloak
  `sha256:2da03f08dad01f10f6b691c0a092c047cc246802aaa485c39b7bec9c35d661c3`, Risk
  `sha256:927cf372ecf4b1087d3801b32033fdcb68aafe517dfc153e386a1bd4c101e462`.
  Không suy commit nguồn legacy từ tên image. Không khởi động legacy để đọc cấu hình.
- Tham chiếu flow A: official legacy export, receipt import-model PASS và journal
  chỉ đổi endpoint/TLS/redirect. [Config đã lọc secrets][legacy],
  [journal endpoint đã lọc][legacy-urls]. HTTP trong export gốc thuộc trước migration;
  journal xác nhận chuyển sang HTTPS Risk8443/Keycloak28444.
- PD-R19 B: định nghĩa realm đã dùng cho demo và receipt cũ; không đọc live hoặc sửa
  PD-R19 trong lượt này. [Config B đã lọc][pd19].
- Full-function C: DoAn **synthetic mới**, Keycloak DHI26.8.2 + SPI/theme
  `sha256:29f942de9bfd6b2823d9922ebf13790bdb6519e0a70b3276a076324fe91b9085`.
  Backend/Risk/Gateway thực chạy Spring Boot4.1.2; nhãn build các RC image là
  `c223276e8a223251ae6df8c7b3381436c54195b2`. Frontend standard
  `sha256:b196bc742277855bc48736ae9df93af5c0b7426abc60b9884a795633321f13e1`.
  [Native config sau resume][runtime], [IDs đầy đủ của chín image][artifacts].
- MySQL runtime8.4.13 candidate `sha256:8afece5fe884d21fc2944b5f200daa9c94a00ba98c196a5765ae2bb665a7ee80`;
  bootstrap8.0.46 `sha256:1c9444499b0ab9000f008ce719c7fc2c2c279c97aae542356c9a1a7c03819f5d`.
  Bootstrap không chạy lại. V5 giữ **661092940**. NGINX/Redis giữ exact references trong matrix.

## B. Ma trận từng execution

Alias A và C hiện tại giống nhau. Viết tắt:
F0=`zerotrust-browser-recovery`; FO=`F0 zerotrust-browser Organization`;
FC=`F0 zerotrust-browser Browser - Conditional Organization`;
FF=`F0 zerotrust-browser forms`; FM=`F0 Risk step-up MFA`.
Các chuỗi `F0` trong viết tắt phải được thay bằng alias đầy đủ khi tra JSON.

| Parent | Execution/provider | A priority/requirement | B: demo trước đây | C sau sửa | A→C |
|---|---|---|---|---|---|
| F0 | auth-cookie |10 ALTERNATIVE|10 ALTERNATIVE|10 ALTERNATIVE|IDENTICAL|
| F0 | auth-spnego |20 DISABLED|Thiếu|20 DISABLED|IDENTICAL|
| F0 | identity-provider-redirector |25 ALTERNATIVE|Thiếu|25 ALTERNATIVE|IDENTICAL|
| F0 | FO |26 ALTERNATIVE|Thiếu|26 ALTERNATIVE|IDENTICAL|
| F0 | FF |30 ALTERNATIVE|demo-forms20 ALTERNATIVE|30 ALTERNATIVE|IDENTICAL|
| FO | FC |10 CONDITIONAL|Thiếu|10 CONDITIONAL|IDENTICAL|
| FC | conditional-user-configured |10 REQUIRED|Thiếu|10 REQUIRED|IDENTICAL|
| FC | organization |20 ALTERNATIVE|Thiếu|20 ALTERNATIVE|IDENTICAL|
| FF | auth-username-password-form |0 REQUIRED|10 REQUIRED|0 REQUIRED|IDENTICAL|
| FF | zerotrust-risk-authenticator |10 REQUIRED|20 REQUIRED|10 REQUIRED|IDENTICAL|
| FF | FM |21 CONDITIONAL|demo-mfa30 CONDITIONAL|21 CONDITIONAL|IDENTICAL|
| FF | zerotrust-device-registration |22 REQUIRED|40 REQUIRED|22 REQUIRED|IDENTICAL|
| FM | zerotrust-risk-step-up-condition |10 REQUIRED|10 REQUIRED|10 REQUIRED|IDENTICAL|
| FM | auth-otp-form |30 ALTERNATIVE|20 REQUIRED|30 ALTERNATIVE|IDENTICAL|
| FM | auth-recovery-authn-code-form |50 ALTERNATIVE|Thiếu|50 ALTERNATIVE|IDENTICAL|

[Đối chiếu 15/15 execution][flow]. Flow bindings được đọc lại bằng native Admin API
sau shutdown, không suy từ alias hoặc JAR có provider. UUID flow/execution giữa hai
realm cô lập được phép khác; thứ tự/hierarchy/provider/requirement được so rõ ràng.
Các nhánh không cấu hình IdP/Organization không được tuyên bố là external IdP login đã test.

| Khác biệt không phải execution | Nguyên nhân, tác động, phân loại | Hành động/evidence |
|---|---|---|
| C ban đầu kế thừa demo-browser, thiếu Recovery/nhánh phụ | Generator synthetic demo bị dùng làm baseline; mất lựa chọn recovery. **SECURITY_REGRESSION**, đã sửa | Khôi phục toàn bộ cây legacy bằng native flow APIs; giữ flow demo cũ không bound; [before][before], [repair][repair] |
| URLs, realm IDs, signing keys, redirects | Cô lập môi trường; fresh keys/accounts, không copy DoAn gốc. **BEHAVIORALLY_EQUIVALENT** cho contract, không phải cùng identity state | Issuer/PKCE/JWT/browser và restore kiểm thực tế |
| Risk secret inline → secret file; parser/correlation/nonce hardening | Giảm lộ secret và reject response lỗi. **HARDENED_COMPATIBLE** | Không nới aud/azp, failureMode vẫn DENY; [SPI receipt][spi] |
| Timeout cấu hình explicit → default | Cùng pool500ms/connect2000ms/socket3000ms,64KiB và token-refresh skew30s. **BEHAVIORALLY_EQUIVALENT** | Config resolver/constants trong exact tested SPI |
| Required Actions/ưu tiên quản trị | OTP và Recovery enabled, defaultAction=false; native required actions vẫn phải hoàn tất trước code. **BEHAVIORALLY_EQUIVALENT** ở các đường đã test | [Native config][runtime], enrollment/reset/recovery E2E |
| Event listeners/client overrides | jboss-logging + zerotrust-risk-events; SPA không đổi sang flow override khác | Native readback; event/subject assertions |
| SSO max10h →8h | Kế thừa cấu hình demo; idle30m và refresh rotation giữ nguyên. **HARDENED_COMPATIBLE**, khác semantics về thời hạn | Không tự sửa session policy; owner chốt D-10 |
| GeoIP true → false, CIDR policy khác | Fixture môi trường demo, không là bằng chứng network-input parity. **NOT_VERIFIED** về parity đầy đủ | Phase2.1A đã sửa lỗi parser `${VAR:}`: country lists thực tế đều rỗng; xem [GeoIP packet](PHASE21A_GEOIP_ACCEPTANCE.md). Không sửa policy để PASS |

## C. SPI: implementation và runtime

Toàn bộ **63 class SPI** trùng bytecode JAR đã có **278 test,30 suites**, dependency
Keycloak26.8.2: [bằng chứng reuse][spi]. Không chạy lại các suites này.

| Thành phần | Điều đã đối chiếu/kiểm thực tế |
|---|---|
| RiskAuthenticator / RiskDecisionHandler | Password trước Risk; ALLOW chỉ hoàn tất execution Risk; STEP_UP chọn MFA; DENY chặn code. Native trace/enrollment/recovery/pending reset xác nhận |
| RiskStepUpCondition | Không biến OTP tùy chọn; defer chỉ khi required enrollment phù hợp. Enrollment chưa tạo trust |
| TrustedDeviceRegistrationAuthenticator | Native OTP/Recovery SUCCESS trước registration; subject/root:tab/generation bị ràng buộc; cookie chỉ sau204 |
| KeycloakLoginContextExtractor | Subject/client/session từ Keycloak; peer IP từ connection. Giả X-Forwarded-For/X-Real-IP/Forwarded không đổi IP/subject |
| HttpRiskScoringClient | Bounded JSON, strict enums/duplicate/trailing data, subject/session và nonce mỗi attempt; mismatch/replay lỗi an toàn trong exact-artifact loopback/unit tests |
| ClientCredentialsTokenProvider | Danh tính risk-caller riêng; cache/expiry/skew; invalidate401 và retry một lần, không retry timeout vô hạn |
| CookieDeviceIdResolver / KeycloakDeviceCookieWriter | Cookie chỉ là identifier; realm path,Secure,HttpOnly,SameSite=Lax; không tự chứng minh trust |
| RiskEventListener | LOGIN/LOGIN_ERROR đúng identity/client; ghi history và trace, telemetry failure không đổi auth result |

[Runtime trace][trace], [test core][core], [test boundaries][boundaries]. Malformed/mismatched
response được chứng minh bằng test đúng artifact; không giả rằng đã dựng malicious Risk server trong live realm.

## D. B0 và khác biệt Network Risk

Cả legacy và C: `S=.25D+.25N+.25T+.25H`; BigDecimal, scale2, HALF_UP trước phân loại;
LOW<40,40≤MEDIUM<75,HIGH≥75. [Effective config][policy] xác nhận bốn trọng số/ngưỡng bằng nhau.

- Reuse thực nghiệm LOW0,MEDIUM40,HIGH77.5 và HIGH browser DENY từ [receipt trước][business].
  HIGH browser dùng địa chỉ fixture đã khai báo trước đó; không giả forwarded headers.
- Pending reset và SECURITY-revoked: DENY,NOT_EVALUATED, không bịa numeric HIGH.
  Cold-start/incomplete: STEP_UP với score chưa tính; không coi fallback0 là an toàn.
- Missing/new/expired/cross-user device, generation mismatch, mandatory MFA và Risk
  outage fail-closed được phân biệt và giữ nguyên. Không đổi weights/thresholds/fixtures trong Phase2.
- **Legacy GeoIP=true, C=false**; trusted/elevated/high CIDRs khác nhau. Đính chính Phase2.1A: country lists đều rỗng; parser receipt cũ đếm nhầm empty default thành một `<UNSET>` entry. Receipt cũ được giữ; [đối chiếu đúng](../../target/full-function-20261111b/phase21a/policy-corrected.json).
  Không copy City/ASN mmdb từ Lab. Numeric fixture PASS không đóng khoảng trống này.
  Strict network parity còn **PARTIAL**; cần dataset được phép dùng và policy cho môi trường mới.

## E. JWT và service identities

Issuer C=`https://auth.full-function.test:39443/realms/DoAn`; issuer/keys khác legacy
là hợp lệ khi cô lập. `sub` được bind đúng actor, không dùng tên hiển thị làm subject.
Ký RS256/kid/JWKS; có exp/iat, kiểm nbf khi hiện diện; token/seed không được xuất.

| Caller | aud/azp và quyền thực tế | Bằng chứng |
|---|---|---|
| SPA |aud zerotrust-api;azp zerotrust-spa;realm ADMIN hoặc STUDENT; không kc-admin-api|[SPA claims đã lọc][spa], browser/RBAC |
| SPI |aud zerotrust-risk-api;azp zerotrust-risk-caller;client roles risk:evaluate,risk:device:write,risk:events:write|Native service claims và Risk calls |
| Portal Risk admin |aud zerotrust-risk-api;azp zerotrust-portal-risk-admin;role risk:device:revoke|Revoke/completion thực, evaluate bị403 |
| Provisioner |azp zerotrust-provisioner;kc-admin-api scope và management audience realm DoAn;delegated manage-users/view/query roles|Native management và create/reset; không dùng business super-admin |

Provisioner còn aud Risk do mapper demo chung; **không có quyền Risk**: evaluate/revoke
bị403 theo azp/role. SPA không nhận management scope/authority; native Admin API từ
SPA bị từ chối. Các composite view/query grants không được tuyên bố là đã tối thiểu
hóa đến từng permission. Không broaden audience để làm test xanh.

**201 test mục tiêu PASS** trên class lấy trực tiếp từ ba image, không recompile app:
Portal12,Risk177,Gateway12. [Receipt][jwt]. Wrong issuer/cross-realm claim,audience,
service azp,expiry,nbf,signature,missing role và role sai resource bị reject theo contract.
Live SPA/service negative requests không đổi reset state. Portal/Gateway dùng issuer,
audience và realm role, **không có azp allowlist độc lập**; đây không phải lời hứa
mọi token có azp khác SPA đều bị reject. Bổ sung ràng buộc này là quyết định policy riêng.

## F. MFA, Recovery Code, Trusted Device

Real browser đã kiểm valid/invalid/consumed Recovery Code; một mã khác còn dùng
được chứng minh rejection không do tắt phương thức. Recovery thành công mới tạo trust.
OTP sai không cấp code hoặc tạo trust; OTP đúng, enrollment bắt buộc, fresh-device
step-up, trusted LOW, reset/re-enroll, old-cookie replay đều có receipt.
Cross-user cookie, trust30 ngày hết hạn, pending reset và stale generation được kiểm
riêng. Không bỏ Recovery Code hoặc bắt OTP mọi trusted LOW để đơn giản hóa B0.

## G. SSO, session và refresh

| Đường đi | Risk / MFA / token được quan sát | So với legacy và giới hạn |
|---|---|---|
| Fresh password |Risk chạy trước MFA; chỉ token khi flow/actions hoàn tất|Cấu trúc legacy giữ nguyên |
| Existing SSO cookie |Không Risk,không password/OTP,có token|Cùng cookie branch; không suy mỗi token là một Risk evaluation |
| Refresh |Không Browser Flow/Risk,có token khi session hợp lệ|Native refresh; rotation=true,maxReuse0 |
| Forced prompt=login |Password rồi Risk; pending reset DENY,không code|Đã test riêng sau resume |
| Logout rồi login mới |Refresh cũ400; password/Risk; pending DENY|Đã test riêng |
| Sau Reset MFA thành công |Refresh400,SSO cũ không bypass enrollment; MFA mới trước code|Native credentials/actions/logout + Risk completion thực |
| Sau Risk revoke đơn lẻ / partial reset |Risk API DENY pending nhưng SSO/refresh cũ vẫn cấp token|**Residual đã xác nhận**, cần D-10; không có live legacy receipt cho đúng case pending để gán runtime parity PASS |

[Trace định lượng][sessions]: fresh/recovery có Risk evaluation; SSO/refresh0.
[Các case pending/forced/logout sau resume][session-boundaries]. Không tự đổi TTL,
ép reauth mọi request, introspection hoặc dùng OTP bắt buộc toàn bộ LOW.

## H. ADMIN MFA Reset và lỗi cạnh tranh

Reuse real UI receipt: ADMIN → mapped active School user → Risk revoke/generation
→ xóa OTP/recovery + required actions → Keycloak logout → Risk completion/audit.
STUDENT403,unknown target404, audit preferred_username fallback sub; các fixture owner
khác không đổi credentials. **47 test điều phối trên exact backend bytecode PASS**:
[receipt][mfa-tests], bao gồm partial/completion errors, không rollback giả remote calls.

Các câu hỏi D-10 chưa được tự chốt:

1. API reset chỉ kiểm ADMIN JWT; **chưa bắt fresh MFA** cho thao tác nhạy cảm.
2. JWT đã cấp vẫn dùng được sau self-reset của ADMIN disposable: API200.
   Lifespan300s; actual decoder có skew60s. Giới hạn danh nghĩa có thể đến
   `exp+60`, tối đa khoảng360s sau issuance, phụ thuộc thời điểm reset.
   [Bytecode/config proof][expiry]; không chạy bài chờ hết toàn bộ360s.
3. Reset thành công thu hồi refresh/SSO; nếu lỗi sau Risk revoke trước logout,
   pending chặn fresh login nhưng không tự chặn SSO/refresh còn sống.
4. Lỗi revoke không tiếp tục Keycloak reset; lỗi native/completion báo partial/pending.
   Không tự xóa pending hoặc hạ generation. Retry nghiệp vụ tạo operation mới;
   retry cùng operation nội bộ có idempotency, operation superseded không complete.

**Lỗi thật phát hiện:** `INSERT IGNORE` lấy shared duplicate-key lock rồi nâng thành
FOR UPDATE; hai reset khác operation có thể deadlock. Không phát hiện cấp sai token
hoặc trust surviving reset từ lỗi này. Thay bằng no-op `ON DUPLICATE KEY UPDATE`
để lấy exclusive row lock, không reset generation/pending. Đây là sửa concurrency,
không đổi B0/session policy; semantics khóa phù hợp [MySQL8.4 manual](https://dev.mysql.com/doc/refman/8.4/en/innodb-locks-set.html).

Candidate local **chưa promote**:
`zt-full-function/risk:phase2-locking-20261111-1`, image ID
`sha256:1ec3c4db626d6c232ca9a30c61188d69e883d40eb0005c29bd0d15921258686a`.
26 affected lifecycle/registration/B0/V5 tests PASS. Trên MySQL8.4.13 thật của bản
restore: new/existing subject, hai request cùng operation, hai operation khác nhau,
generation3/2/1, superseded409, registration racing revoke không giữ trust cũ đều PASS.
Browser SPI/OTP/PKCE/own-grade/STUDENT403/V5 tiếp tục PASS. [HTTP cases][locking-http],
[candidate receipt][locking]. Chỉ ba class thuộc repository family khác bytecode
(hai record đổi debug line numbers); mọi class và dependency khác giữ nguyên.
**Profile đang chạy vẫn giữ Risk RC cũ**, nên chưa coi race fix đã rollout vào profile đó.

## I. Business parity không chạy lại toàn bộ

[Receipt CUD/UI/API trước][business] và source không đổi ở frontend/Portal chứng minh:
ADMIN list/reset; sinh viên create/read/update; lớp và môn create/read/delete nơi
được hỗ trợ; điểm create/update/delete/batch; STUDENT chỉ own profile/grades/summary.
Không thêm TEACHER, role editor, student delete hoặc class/subject update chưa tồn tại.
Restore/candidate chỉ bổ sung kiểm grade hydration và STUDENT403 liên quan runtime mới.

## J. Reuse CVE/provenance

| Artifact/evidence | Phân loại | Giới hạn còn lại |
|---|---|---|
| Exact Keycloak DHI29f942… / signed baseba20b9… provenance,SBOM,VEX |REUSABLE|Scan dated10/11:0C/3H; vendor not_affected không đồng nghĩa độc lập FIXED |
| CVE-2026-16742 / CVE-2025-69720 |REUSABLE applicability|Thành phần systemd-homed/infocmp vắng theo evidence exact image |
| CVE-2026-54369 libacl1 |REUSABLE residual assessment|Vendor VEX not_affected; thiếu full transparency verification/fix compatibility; không waiver |
| MySQL84/80 candidates |REUSABLE|0C/0H ở snapshot cũ; technical PASS, promotion D-14 vẫn PENDING |
| Backend/Gateway/Risk RC |REUSABLE + TARGETED_RETEST|201 JWT +47 MFA exact-bytecode tests; không đồng nhất local target/classes với image |
| New locking Risk |TARGETED_RETEST hoàn tất cho sửa lỗi|Dependencies/B0/V5 bytes không đổi; không scan lại toàn image; không có approval/promoted lock mới |
| Redis/NGINX |REUSABLE exact references|Runtime TLS/restore/admission kiểm trong scope; không mở audit mới |
| Frontend standard mới |TARGETED_RETEST chức năng đã có|34 tests/build và business receipts; không tuyên bố có scan mới cho exact frontend ID |
| SPI |REUSABLE|63 classes trùng exact tested artifact;278 tests không chạy lại |
| Waiver/giảm thiểu dựa trên academic read-only |INVALIDATED cho phạm vi full-write|Không tự chuyển DRAFT14 ngày thành acceptance cho quản trị điểm có quyền ghi |

[Artifact/scan matrix][artifacts], [handoff D-14/D-17][handoff]. Không downgrade
Keycloak, không sửa release pins và không tự chuyển D-17/G8 sang PASS/GO.

## K. Restart, restore và giới hạn

Restart receipt cũ được giữ riêng; không dùng thay backup/restore. Đã tạo checkpoint
synthetic mã hóa khi writers/Redis dừng, restore vào stores độc lập, không public ports.
15 bảng School/realm/users/credentials/key components/flow/Risk/generation/ledger và
Redis AOF khớp. Public JWKS so theo kid và nội dung key/cert, không dựa thứ tự array.
Post-restore password+OTP/PKCE, grade UI và ADMIN403 PASS: [data witness][restore-data],
[browser receipt][restore], [bốn request UI đều200][restore-ui].

Một probe ban đầu trả429 vì thêm request thứ năm lúc UI đang dùng bốn admission
slots; bài kiểm hoàn chỉnh chờ hydration và kiểm chính bốn response UI200, không
nới giới hạn. Tool đối chiếu binary UUID/public witness và refresh DNS ingress sau
stop/start được sửa; không chỉnh database để khớp test.

Sau Windows shutdown chỉ start9 container Full-Function hiện hữu; không seed/import.
163 container cũ sau shutdown giữ ID/image/mount/network; trạng thái chạy ngoài
profile được giữ như lúc resume. Sáu protected hashes/release locks/V5 khớp.
[Preservation cuối][preservation]. Restore và locking candidate đã dừng, giữ stores.

## L. Gates và hành động còn lại

Mỗi gate có file, test thực hiện, kết quả, gap và next action trong [gate receipt][gates].

| Gate | Trạng thái | Bằng chứng và kết quả | Gap / hành động tiếp |
|---|---|---|---|
| BUSINESS_PARITY |PASS|[Real CUD/RBAC][business]|Không tạo thêm chức năng ngoài legacy |
| AUTH_FLOW_PARITY |PASS|[15 execution][flow], [native resume][runtime]|Không suy test external IdP/Organization chưa cấu hình |
| SPI_PARITY |PASS|[63 classes/278 tests][spi], [runtime trace][trace]|Giữ hardening; không rebuild SPI |
| ADAPTIVE_AUTH_B0 |PARTIAL|[Math/inputs][policy], [boundaries][boundaries]|GeoIP thật đã test trong [Phase2.1A](PHASE21A_GEOIP_ACCEPTANCE.md); review network policy/promotion và public-peer browser còn chờ |
| JWT_SERVICE_SECURITY |PASS|[201 exact-bytecode tests][jwt], [live negatives][core]|Giữ rõ azp contract theo từng resource |
| MFA_RECOVERY_TRUST |PASS|[OTP/recovery][core], [expiry/cookie/generation][boundaries]|SSO boundary nằm ở D-10 |
| ADMIN_MFA_RESET |PARTIAL|[UI][business], [47 tests][mfa-tests], [new locking candidate][locking]|Review chọn Risk image mới; chốt fresh-MFA/JWT/session semantics |
| SECURITY_REGRESSION |PARTIAL|[SSO pending][session-boundaries], [CVE matrix][artifacts]|D-10,GeoIP/8h-vs10h,D-17 chưa đóng |
| RESTORE_ACCEPTANCE |PASS|[State][restore-data], [real restored login][restore]|Local synthetic, không là GCP acceptance |
| OVERALL_LOCAL_ACCEPTANCE |PARTIAL|[Gates][gates], [preservation][preservation]|Chưa đủ điều kiện nghiệm thu cuối/Cloud target |

**Hành động tiếp của owner:** nguồn MaxMind đã được cung cấp và kiểm trong [Phase2.1A](PHASE21A_GEOIP_ACCEPTANCE.md); review network policy/promotion,
các lựa chọn D-10 (fresh ADMIN MFA/SSO/refresh/JWT và session max), và chọn candidate
Risk đã test cho một profile mới được review. Không cần chạy lại CI/scan/build đã PASS.
Giữ workflow GCP read-only cũ PAUSED; chưa upload/deploy, không mở80/443, không commit/push.

[artifacts]: ../../target/full-function-20261111b/phase2/artifact-matrix.json
[legacy]: ../../target/full-function-20261111b/phase2/legacy-config.json
[legacy-urls]: ../../target/full-function-20261111b/phase2/legacy-endpoints-sanitized.json
[pd19]: ../../target/full-function-20261111b/phase2/pd19-config.json
[runtime]: ../../target/full-function-20261111b/phase2/runtime-resumed.json
[before]: ../../target/full-function-20261111b/phase2/runtime-before.json
[flow]: ../../target/full-function-20261111b/phase2/flow-parity.json
[repair]: ../../target/full-function-20261111b/phase2/flow-repair.json
[spi]: ../../target/full-function-20261111b/phase2/artifact-and-test-reuse.json
[trace]: ../../target/full-function-20261111b/phase2/runtime-auth-trace.json
[core]: ../../target/full-function-20261111b/phase2/targeted-security.json
[boundaries]: ../../target/full-function-20261111b/phase2/targeted-boundaries.json
[policy]: ../../target/full-function-20261111b/phase2/risk-policy-parity.json
[business]: ../../target/full-function-20261111b/results/acceptance.json
[spa]: ../../target/full-function-20261111b/phase2/spa-token-contract.json
[jwt]: ../../target/full-function-20261111b/phase2/artifact-jwt/results.json
[sessions]: ../../target/full-function-20261111b/phase2/session-runtime-proof.json
[session-boundaries]: ../../target/full-function-20261111b/phase2/session-boundaries.json
[mfa-tests]: ../../target/full-function-20261111b/phase2/artifact-mfa/results.json
[expiry]: ../../target/full-function-20261111b/phase2/jwt-expiry-bound.json
[locking-http]: ../../target/full-function-20261111b/phase2/locking/locking-http.json
[locking]: ../../target/full-function-20261111b/phase2/locking/candidate-acceptance.json
[handoff]: ../../target/bounded-remediation-20261110/PRE_CLOUD_FINAL_HANDOFF.md
[restore-data]: ../../target/full-function-20261111b/phase2/restore/state-witness.json
[restore]: ../../target/full-function-20261111b/phase2/restore/restore-acceptance.json
[restore-ui]: ../../target/full-function-20261111b/phase2/restore/browser-api-statuses.json
[preservation]: ../../target/full-function-20261111b/phase2/preservation-final.json
[gates]: ../../target/full-function-20261111b/phase2/acceptance-gates.json
