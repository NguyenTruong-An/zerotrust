# Phase 2.1 — GeoIP, Risk promotion và quyết định D-10

11/11/2026 (GMT+7). **PROPOSED / CHỜ OWNER DUYỆT.** Chỉ review source, receipts và
Docker metadata; không chạy test/build/scan, đọc lại MMDB hoặc khởi động container.
Full-Function `zt-full-function-20261111b`9/9healthy, Risk cũ và GeoIP=false giữ nguyên.
GeoIP5/7PASS,2/7PARTIAL; **D-17 PENDING, G8 INTERNET_NO_GO**.
[Bằng chứng kiểm tra trong lượt này][review].

**A. Policy GeoIP đề xuất**

Giữ nguyên B0 `S=.25D+.25N+.25T+.25H`, HALF_UP2; LOW<40, MEDIUM40–<75,HIGH≥75.
Không sửa guardrails, pending-reset DENY, incomplete STEP_UP hoặc MFA bắt buộc.

| Nhóm được code hỗ trợ | N với cấu hình hiện tại | Tác động |
|---|---:|---|
| TRUSTED country/CIDR |0|Chỉ giảm N, không tự tin cậy thiết bị hoặc bỏ mandatory MFA |
| ELEVATED country/CIDR |50|Bằng DEFAULT50; thêm country vào đây hiện không làm tăng điểm |
| HIGH country/CIDR |100|Đóng góp25 điểm và mandatory step-up; không tự đồng nghĩa final HIGH/DENY |
| Public country hợp lệ ngoài lists |50|Đóng góp12.50, nguồn GEOIP |
| Public missing country/record, provider unavailable |không có|INCOMPLETE/STEP_UP, không fallback trusted/0 |
| Private/loopback không khớp CIDR |50|DEFAULT_POLICY, không gán vị trí public |

CIDR được xét **trước** GeoIP; trong mỗi nhóm: HIGH → ELEVATED → TRUSTED → DEFAULT.
Country dùng ISO alpha-2, normalize uppercase. Tránh lists chồng nhau dù code có
precedence. N dùng country; city, timezone, accuracy radius và ASN chỉ là metadata.
Temporal dùng timezone cấu hình/lịch sử login, không dùng timezone GeoIP.
Không có ASN reputation, city scoring hoặc impossible-travel/IP-change scoring.
[Calculator][calculator], [properties][properties], [effective config][policy].

**Khuyến nghị P0:** bật GeoIP với cặp dữ liệu đã có; giữ ba country lists rỗng,
default/elevated/high=50/50/100. Chưa có căn cứ phân nhóm quốc gia, không tự chọn
VN trusted hoặc bất kỳ nước nào high. GeoIP vẫn có tác dụng: public country hợp lệ
cho phép tính N; country thiếu làm dữ liệu incomplete và step-up.

- Local acceptance: giữ các CIDR fixture hiện hữu nếu owner chọn strict regression
  tương đương profile; ghi rõ đó là fixtures, không là danh sách mạng đáng tin thật.
- Profile Cloud tương lai: đề xuất country lists và CIDR lists đều rỗng ban đầu;
  chỉ thêm trusted CIDR khi xác minh được egress được quản lý, high CIDR khi có
  bằng chứng/phạm vi/thời hạn review. Không trust Docker subnet, IP ingress/proxy
  hay copy CIDR Lab/test sang VPS. Đề xuất này **chưa áp dụng**, cần owner duyệt.
- Giữ canonical peer từ ingress /32; không tin header tự gửi. ULA hiện dẫn
  NOT_FOUND/STEP_UP; không đổi phân loại thành default/private để giảm MFA.

**B. Legacy parity và enhancement tùy chọn**

Parity bắt buộc: provider local City/ASN, country membership, CIDR precedence,
50/50/100, bốn trọng số/ngưỡng và fail-safe. Country lists legacy/current đều rỗng;
khôi phục GeoIP không có nghĩa tự thêm blacklist quốc gia.

[13 trace thật][network] đã chứng minh cùng D=T=H=0: public Google N50/S12.50,
trusted CIDR fixture N0/S0, high CIDR fixture N100/S25 nhưng vẫn STEP_UP; public
thiếu country/no record →score null/STEP_UP. Cùng nhóm policy giữ cùng N.
Đây là evidence đã chạy, không chạy lại trong lượt review.

Country TRUSTED→0/HIGH→100 đã có nhánh code và test nguồn
`trustedCountryUsesGeoIpWithoutPersistingTheRawAddress` /
`highRiskCountryRequiresStepUpEvenWhenItsWeightedContributionWouldBeLow` trong
[NetworkRiskCalculatorTests][country-tests]. Đọc test không phải một PASS mới.
Nếu owner muốn bật country list khác rỗng, chỉ cần **một matrix mới** trên real
lookup đã có với policy override fixture có khai báo: cùng country, đổi membership
trusted/default/high →0/50/100; city/ASN đổi không tự đổi N. Không sửa policy đang
chạy hoặc gán public IP giả cho browser để chứng minh điều này.

Country list có phần tử, đổi subscore ELEVATED để khác50, hoặc fresh-MFA cho thao
tác ADMIN là **enhancement/security-policy decision**, không phải khôi phục legacy.
Country alone không phải bằng chứng tấn công. Không thêm thuật toán ngoài scope.

**C. Candidate Risk và readiness promotion**

Candidate exact: `zt-full-function/risk@sha256:1ec3c4db626d6c232ca9a30c61188d69e883d40eb0005c29bd0d15921258686a`.
Risk đang chạy: `sha256:3f540f3de29a4ac69ec916a81d153b8d4befd9238c9c06b26b9b9f0f2b843571`.

| Hạng mục | Kết luận từ bằng chứng đã có |
|---|---|
| Artifact/provenance | Docker local image/RepoDigest và build log manifest index khớp exact candidate; amd64, user10001. Build log có attestation manifest, chưa xác minh chữ ký/source attestation; không gọi đây là signed release |
| Source | Build receipt ghi HEAD81d6322 + file sửa SHA256 `779cd1e507f1aa139e57dd8ed42422e7afebee95df3666abc2c18ceb19afdfe8`; file hiện tại khớp. HEAD đang đọc là **b0eaca9**, không phải81d6322. Git diff hai HEAD không đổi Risk src/POM/Dockerfile.java/.dockerignore đã kiểm. Ghi cả hai mốc trong manifest mới, không sửa receipt lịch sử hoặc tự rebuild |
| Delta/compatibility | Chỉ3class trong DeviceTrustStateRepository family khác RC cũ; dependency/classes khác giữ bytes. Giữ MySQL8.4.13, bootstrap8.0.46, V5 checksum661092940, TLS/JWT/SPI/flow contracts |
| Deadlock | No-op upsert lấy exclusive lock thay INSERT IGNORE; không hạ generation hoặc xóa pending.26 targeted tests và4 case MySQL/browser đã PASS, gồm same/distinct operation và registration race |
| GeoIP config/mount | Candidate retained đang dừng, GeoIP=true; City/ASN tại `/geoip/GeoLite2-{City,ASN}.mmdb`, mount release read-only, không mount GeoIP.conf/key; không publish port |
| Dataset/lifecycle | Reuse release `20261111T154359Z-a25e6a9fc2b8`; metadata/checksum/lookup trước đó PASS. Reader MEMORY cần controlled restart. Replacement/rollback cùng vendor build đã PASS; chưa claim upgrade vendor mới |

[Build receipt][build], [delta][delta], [26 tests][locking-tests], [MySQL/browser][locking-http],
[GeoIP packet](PHASE21A_GEOIP_ACCEPTANCE.md), [runtime metadata lượt này][review].

**TECHNICAL EVIDENCE READY cho một promotion local có review; PROMOTION ON HOLD.**
Còn thiếu owner authorization, tooling hỗ trợ pin/config mới, pre-promotion
checkpoint mới và post-promotion smoke. Candidate Risk này không sửa D-10 của
backend/Keycloak. Không tuyên bố FULL-FUNCTION PASS hoặc release/public READY.

Kế hoạch promotion, chỉ thực hiện sau khi được duyệt:

1. **Preflight read-only:** đúng project/ownership/local Docker;9healthy; ghi old
   image/config/mount và hashes của base receipts; kiểm exact candidate, expiry
   TLS/CRL, dung lượng, dataset được chọn còn hợp lệ/fresh. Không download/scan
   lại; chỉ revalidate dữ liệu khi thay đổi, quá hạn hoặc có drift. Chốt P0 local.
2. **Manifest/overlay riêng:** ghi from/to digest, source HEAD/hash, dataset release,
   effective policy, config diff, checkpoint và rollback. Chỉ override Risk image
   +GeoIP paths/mount/config đã duyệt; giữ loopback và private networks. Không sửa
   RC lock, `profile-images.json` hoặc marker `private/installed` hiện có.
3. **Tooling guard:** `operate.configure()` đang dựng image cũ và so receipt cũ;
   chỉ thêm Compose override sẽ bị drift hoặc lần restart sau quay về cũ. Cần
   hỗ trợ manifest promotion được review trong validate/status/restart/backup/
   rollback, vẫn kiểm base receipts nguyên vẹn. Chưa có hỗ trợ này trong hiện trạng.
4. **Checkpoint mới:** maintenance private, tạm ngừng writers thuộc Full-Function;
   backup mã hóa School/Keycloak/Risk +Redis cùng mốc, config/realm/dataset pointer,
   giữ encryption key riêng. Reuse logic backup đã kiểm, không chạy lại
   `phase2_restore.py main`: script này cố ý từ chối namespace restore đã tồn tại.
   Cần nhánh backup-only cho checkpoint mới; không reset/import/recreate stores.
5. **Cutover:** chỉ Risk container được thay image/config; giữ cùng owned volumes,
   user10001, cap-drop/read-only/TLS/CRL/JWT, không port mới. Không để hai container
   cùng alias `risk` chạy đồng thời. Giữ maintenance đến health và real lookup
   đạt; kiểm lại DNS/upstream khi thay IP container, chỉ resume các service riêng
   đã pause. Không đổi Keycloak flow/client hoặc chạy bootstrap/migration import.
6. **Verify:** theo mục E; lỗi thì rollback F. Thành công chỉ ghi local promotion
   receipt riêng, không chuyển release lock/G8 sang GO.

**D. Quyết định D-10 cần owner approval**

| Biên đã xác minh | Khuyến nghị để owner chọn | Giới hạn/tiêu chí chấp thuận |
|---|---|---|
| Risk pending nhưng SSO và refresh cũ vẫn cấp token | Giữ Risk đánh giá ở fresh login; sửa reset orchestration để xác nhận native Keycloak logout sớm sau Risk revoke, trước bước sửa credential dễ lỗi; vẫn logout ở cuối và xử lý logout khi partial failure | Giảm cửa sổ, **không bảo đảm zero-window** giữa hai dịch vụ hoặc khi logout lỗi. Pending giữ DENY ở fresh/forced login. Nếu owner yêu cầu mọi token issuance bị chặn ngay từ pending, cần thiết kế enforcement ở Keycloak cho cả SSO/refresh được duyệt riêng; logout ordering chưa đủ |
| Access JWT đã cấp vẫn được API chấp nhận | Đề xuất giữ TTL300s + skew60s cho demo, owner ghi nhận rõ cửa sổ còn hiệu lực tối đa danh nghĩa đến exp+60 (≤360s từ issuance), không gọi là revoked tức thì | Nếu không chấp nhận cửa sổ này, cần thiết kế revocation/session state tại resource server riêng; logout, prompt=login hoặc giảm SSO max không tự thu hồi JWT đã phát |
| Reset API hiện chỉ đòi ADMIN JWT | Đề xuất fresh MFA cho **riêng Reset MFA**, tuổi≤5phút, kiểm chứng context do Keycloak ký ở backend; giữ OTP/Recovery theo contract | Chưa triển khai. Cần approved action-specific ACR/LoA+freshness mapping trên đúng26.8.2/SPI; prompt=login, token iat mới, auth_time đơn lẻ hoặc device cookie không đủ chứng minh MFA mới. Không ép mọi trusted LOW login/refresh phải OTP |
| Session max8h, legacy10h | Đề xuất giữ8h như ngoại lệ hardening theo môi trường; idle30phút và refresh rotation/maxReuse0 giữ nguyên | Owner chọn8h hoặc strict10h; không tự nâng về10h chỉ để gán parity |
| Trusted Device sau reset | Giữ revoke→generation++/pending→reset OTP+Recovery/required actions→logout→completion; stale generation409, pending không register, MFA thật trước trust mới | Đây là invariant bắt buộc, không phải tùy chọn nới lỏng. Không phục hồi trust/cookie cũ để chữa lỗi |
| Partial reset/timeout | Giữ lỗi503 và operation/audit; retry/logout có giới hạn, phân biệt confirmed/unknown outcome; tiếp tục qua operation ledger hợp lệ, không giả rollback remote commit | UI bấm reset hiện tạo operation mới. Resume cùng operation cần support server-side, xác thực subject/requester và supersession; không tự thêm public completion API, không xóa pending hoặc hạ generation |

Evidence: [pending SSO/refresh thật][sessions], [JWT upper bound][jwt-bound],
[UserService orchestration][user-service], [native reset/logout order][kc-reset],
[47 tests][mfa-tests]. Native [Keycloak user logout](https://www.keycloak.org/docs-api/latest/rest-api/index.html#_users_resource)
thu hồi user sessions; không thay validation offline của JWT tại Portal/Gateway.
Fresh-MFA đề xuất dựa trên [Keycloak step-up](https://www.keycloak.org/docs/latest/server_admin/index.html#_step-up-flow)
và [RFC9470](https://www.rfc-editor.org/rfc/rfc9470.html#section-6.1): mức xác thực và
thời điểm xác thực khác thời điểm refresh token. Đây là hướng thiết kế, không là
bằng chứng flow hiện tại đã có mapping đó. Không tự force Risk trên mọi refresh,
không đổi SSO branch/15execution đang duyệt. Không suy kết quả refresh thường
sang offline tokens; nếu cấp offline_access, cần lifecycle acceptance riêng.

Owner cần chọn rõ: **bounded-window reset/logout hay strict pending token block;
JWT window có chấp nhận không; fresh ADMIN MFA≤5phút; SSO8h hay10h**. Các đề xuất
đều PENDING. Policy approval không đồng nghĩa cho phép promote image hoặc mở public.

**E. Minimal targeted acceptance plan — không chạy trong lượt này**

| Nhóm | Evidence reuse | Chỉ chạy khi có thay đổi hoặc sau cutover được duyệt |
|---|---|---|
| GeoIP/N/B0 | Phase2.1A13cases và5PASS gates | Một public-IP service evaluation + trace N/.25N trên runtime mới; một browser thật qua HTTPS để kiểm SPI/MFA. Không tải/verify DB lại; country membership matrix chỉ khi chọn policy mới |
| LOW/MEDIUM/HIGH, mandatory MFA | Existing numeric/browser receipts,26tests; GeoIP high CIDR score25 vẫn STEP_UP | Chỉ rerun case network/policy hoặc guardrail bị tác động; không chạy lại toàn bộ rehearsal |
| Recovery Code/15execution | Flow parity và OTP/recovery valid/invalid/consumed đã PASS | Không rerun nếu Risk-only/config cutover giữ nguyên SPI/flow. Nếu fresh-MFA enhancement sửa flow, test OTP+Recovery và toàn bộ nhánh bị chạm, giữ đủ15execution baseline |
| SSO/refresh pending | Session-boundaries xác nhận residual | Sau D-10 fix mới: reset paused ở từng failure point, thử SSO+refresh/fresh/forced login, áp đúng guarantee được owner duyệt; unchanged sessions không gọi Risk mỗi refresh |
| ADMIN Reset MFA | Real UI reset/enroll/trust/audit +47tests | Sau D-10/backend change: disposable target, ADMIN success/STUDENT403, partial timeout/logout failure, OTP mới, stale cookie không bypass, tài khoản khác nguyên vẹn; fresh-MFA expired/missing/forged claims nếu được chọn |
| Concurrency/deadlock |26tests +4real MySQL/browser cases của exact image | Không rerun nguyên suite cho cùng image. Nếu controller/caller hoặc reset implementation đổi, chỉ same-op/distinct-op và registration-vs-reset race trên disposable subject |
| JWT audiences/RBAC |201exact-bytecode tests, live negatives; dependency bytes không đổi | Risk-only promotion reuse; một STUDENT own grades200/ADMIN403 và ADMIN list200 smoke. Nếu thêm fresh-MFA claims validator, chỉ thêm tests backend enforcement/expiry/refresh claim boundary |
| Persistence/rollback | Restored state witness +GeoIP restart/replacement/rollback | Sau promotion: restart đúng Risk mới, health/lookup, V5661092940 và state continuity; kiểm rollback rehearsal trên state disposable nếu controller mới, không restore state live để làm test |

**Cần môi trường giữ public client IP:** browser→ingress→Keycloak→SPI→real GeoIP
country/ASN→N→decision, cùng forged-header negative và public IPv6 nếu được hỗ trợ.
Local Docker/private peer hoặc IAP/loopback không chứng minh positive public-IP
E2E. Không mở public port để đóng gate này; tiếp tục PARTIAL đến khi có môi
trường mạng được phê duyệt phù hợp. Không gọi service payload public IP là browser E2E.

**F. Rollback**

Trong maintenance, dừng riêng candidate Risk, dùng manifest để trả về **exact old
image** `sha256:3f540f3de29a4ac69ec916a81d153b8d4befd9238c9c06b26b9b9f0f2b843571`
và config trước promotion (GeoIP=false), cùng volumes/schema hiện tại. Nếu chỉ
dataset update lỗi trên image mới, chọn last-good pair rồi restart reader mới.
Health/TLS/Risk và một login smoke đạt mới resume traffic local; giữ private/fail-closed
nếu rollback không đạt. Không chạy lại install/materialize/Flyway bootstrap/import.

**Không restore DB/Redis checkpoint trong rollback image thông thường:** có thể
làm sống lại trust/session đã revoke. Giữ generation, pending operations và audit
hiện tại; không undo Reset MFA. Backup chỉ dùng cho disaster recovery riêng có
review. Risk cũ có lại hạn chế deadlock/GeoIP tắt; rollback là quay về known-good
local baseline, không phải xác nhận đã giữ các cải tiến mới hay đạt public GO.
Không sửa base RC/image receipts để che rollback.

**G. Nhiệm vụ triển khai tiếp theo chính xác**

**Bước implementation kế tiếp đề xuất: bổ sung promotion controller với
`plan/validate` mặc định read-only và manifest/overlay Risk-only riêng**, bao gồm
nhánh checkpoint backup-only và rollback có ownership guard. Descriptor phải
ghi exact from/to image, dataset, source reconciliation, policy P0 và base receipt
hashes; không được làm thay pin/profile hiện hữu khi chỉ chạy plan/validate.
Đây là tooling vận hành, chưa được viết/thực thi trong lượt decision packet này.

Owner review policy P0/D-10 trước; execution `apply` cần authorization riêng cho
cutover local. D-10 fixes, đặc biệt fresh-MFA/strict pending enforcement, chỉ được
implementation sau lựa chọn rõ ràng và đi trong candidate riêng có targeted tests.
Không gộp policy chưa duyệt vào candidate1ec3… đã kiểm. **Full local acceptance
vẫn PARTIAL; promotion đang HOLD; D-17 PENDING; G8 INTERNET_NO_GO.**

[review]: ../../target/full-function-20261111b/phase21/promotion-review.json
[calculator]: ../../risk-scoring-service/src/main/java/com/zerotrust/risk/service/NetworkRiskCalculator.java
[properties]: ../../risk-scoring-service/src/main/java/com/zerotrust/risk/config/NetworkRiskProperties.java
[country-tests]: ../../risk-scoring-service/src/test/java/com/zerotrust/risk/service/NetworkRiskCalculatorTests.java
[policy]: ../../target/full-function-20261111b/phase21a/policy-corrected.json
[network]: ../../target/full-function-20261111b/phase21a/network-evidence.json
[build]: ../../target/full-function-20261111b/phase2/locking-candidate-image.json
[delta]: ../../target/full-function-20261111b/phase2/locking/candidate-acceptance.json
[locking-tests]: ../../target/full-function-20261111b/phase2/locking-source-tests.json
[locking-http]: ../../target/full-function-20261111b/phase2/locking/locking-http.json
[sessions]: ../../target/full-function-20261111b/phase2/session-boundaries.json
[jwt-bound]: ../../target/full-function-20261111b/phase2/jwt-expiry-bound.json
[user-service]: ../../src/main/java/com/zerotrust/zerotrust/service/impl/UserServiceImpl.java
[kc-reset]: ../../src/main/java/com/zerotrust/zerotrust/identity/keycloak/KeycloakUserClient.java
[mfa-tests]: ../../target/full-function-20261111b/phase2/artifact-mfa/results.json
