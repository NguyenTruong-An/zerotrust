# Phase 2.1A — GeoIP thật, nghiệm thu local có giới hạn

11/11/2026. **PARTIAL; chưa promote hoặc deploy Cloud.** GeoIP đã hoạt động trong
Risk candidate cô lập trên checkpoint synthetic `zt-full-function-phase2-restore`.
Profile đang dùng `zt-full-function-20261111b` vẫn giữ image/config cũ, GeoIP=false.
Không sao chép MMDB, account, secrets hoặc volumes từ Lab/DoAn gốc.

**A. Cơ chế legacy.** `MaxMindGeoIpProvider.lookup()` đọc City/ASN MMDB vào bộ nhớ;
`NetworkRiskCalculator.calculate()` ưu tiên CIDR HIGH → ELEVATED → TRUSTED, sau đó
GeoIP cho IP public. Chỉ **country code** chọn nhóm N; city, timezone, radius và ASN
là ngữ cảnh, không có ASN reputation/city scoring. Country lists legacy đều rỗng,
nên country hợp lệ dùng default N=50. Không có previous-IP/country/ASN movement
scoring; H dùng failure counters theo subject/IP, T dùng lịch sử thành công và
timezone cấu hình. [Source calculator](../../risk-scoring-service/src/main/java/com/zerotrust/risk/service/NetworkRiskCalculator.java),
[đối chiếu effective config][policy].

**B. Khoảng trống trước lượt này.** Full-Function tắt GeoIP và chưa có dataset được
phép dùng; thuật toán/provider đã có. CIDR khác theo môi trường. Đính chính receipt
Phase2: parser nhầm `${VAR:}` thành một entry `<UNSET>`; country lists thực tế đều
rỗng ở cả hai bên, elevated CIDRs hiện tại cũng rỗng. Receipt cũ được giữ nguyên;
không thay policy để làm kết quả xanh. [Config đã sửa cách đối chiếu][policy].

**C. Nguồn/license/provenance.** Đã tải chính thức bằng tài khoản MaxMind của owner,
HTTPS xác minh TLS, kiểm checksum archive do MaxMind cung cấp, SHA256 MMDB,
database type/format2 và build date bằng đúng reader trong Risk image. Đây là
HTTPS/checksum provenance, không tuyên bố có chữ ký số vendor cho MMDB.

| Dataset | Build UTC | SHA256 MMDB |
|---|---|---|
| GeoLite2-City | 10/11/2026 07:21:17 | `1ffc2e3e2c0d83a11cb64dfaa318e6f10f74aae131dd18899d5243eaf81c0364` |
| GeoLite2-ASN | 11/11/2026 08:15:07 | `3dceeef0f161aee0b48a3e71dd538798f5d95e9f4c2e0bc35f1c62874e22a4d5` |

[Acquisition/metadata][acquisition]. Credentials chỉ trong vùng private có ACL;
dataset, LICENSE/COPYRIGHT và manifest nằm dưới `target/.../geoip-private`, bị
Git/build-context loại trừ. Runtime chỉ mount release dataset read-only, không
mount AccountID/LicenseKey. Không phân phối dataset. GeoLite EULA yêu cầu cập nhật
và xóa bản cũ trong30ngày kể từ release mới; rollback chỉ giữ trong thời hạn đó.
This product includes GeoLite2 data created by [MaxMind](https://www.maxmind.com/).
City còn ghi attribution [GeoNames](https://www.geonames.org/), CC BY4.0 trong LICENSE.
[Quy định và giới hạn độ chính xác](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/).

**D. Client IP thực.** OIDC: browser → HTTPS ingress → Keycloak → SPI → Risk;
Portal API mới đi qua Gateway. NGINX ghi lại XFF từ peer, xóa Forwarded/X-Real-IP;
Keycloak chỉ tin ingress /32. Native LOGIN event khớp IP thật của browser helper,
không khớp header giả `8.8.8.8`. Trace Risk/SPI được nối bằng evaluation_id.
Docker/NAT ở local cho IP private; chưa chứng minh public browser geolocation.
[Browser/native event/SPI][browser]. Không dùng header giả để tạo public-IP PASS.

**E. Thay đổi.** Chỉ thêm tooling `geoip_data.py`, `GeoIpProbe.java`,
`geoip_lane.py`, `geoip_verify.py`, `geoip_evidence.py` và evidence/tài liệu.
Bật GeoIP bằng override deployment, mount cặp MMDB read-only trên Risk candidate
đã test ở Phase2, ID `sha256:1ec3c4db626d6c232ca9a30c61188d69e883d40eb0005c29bd0d15921258686a`.
Không rebuild app/SPI, sửa B0, V5, flow, release lock hoặc pin profile đang chạy.
Candidate dùng MySQL/Redis/config/realm synthetic restore riêng, không publish port.

**F. Lookup thật.** `8.8.8.8`: country US, ASN15169 Google; city=null,
radius1000km, không suy ra thành phố chính xác. `8.8.4.4` và IPv6
`2001:4860:4860::8888` cũng dùng dữ liệu thật. `1.1.1.1`: ASN13335 nhưng country=null;
không dùng ASN thay cho country bị thiếu. Provider được đối chiếu bằng reader
City/ASN độc lập trên cùng cặp dữ liệu. [Probe nguồn][acquisition], [service trace][network].

**G. Đóng góp B0.** TLS/service JWT đúng caller; payload IP được khai báo là test
ở trust boundary, không phải IP giả của browser. Cùng subject/device và D=T=H=0:

| Ngữ cảnh | N | .25N | S / decision |
|---|---:|---:|---|
| Ba public IP Google, country có dữ liệu |50|12.50|12.50 / ALLOW sau registration fixture |
| Country missing/no record |không có|không có|null / INCOMPLETE, STEP_UP_MFA |
| Private/loopback |50 default|12.50|12.50 / ALLOW với các yếu tố khác đủ, không geolocate |
| CIDR TRUSTED fixture đã có |0|0|0 / ALLOW |
| CIDR HIGH fixture đã có |100|25|25 / STEP_UP_MFA bởi guardrail |

Device mới: D60,N50,T0,H0 →27.50 nhưng vẫn STEP_UP bắt buộc.
Bốn trọng số .25, ngưỡng40/75, HALF_UP2 giữ nguyên. Hai IP cùng nhóm không bị ép
khác điểm. Registration service call là fixture có khai báo; browser bên dưới
chứng minh OTP thật trước registration. [13 trace và phép tính][network].

**H. E2E thật.** HTTPS/PKCE S256, OTP thật, own grades200, STUDENT ADMIN403;
Risk N50 đóng góp12.50, S32.50, quyết định STEP_UP_MFA. Cùng evaluation_id có
SPI STEP_UP_REQUIRED → OTP_EXECUTION_SUCCESS → REGISTERED_204 → LOGIN_SUCCESS.
Header public giả không tạo country/ASN public; thực tế SKIPPED_NON_PUBLIC.
**E2E public GeoIP còn PARTIAL**, không dùng service-boundary lookup thay browser.
[Bằng chứng nối browser/Risk/SPI][browser].

**I. Negative/failure.** Missing country, no record, reserved IPv6 và ULA →
INCOMPLETE/STEP_UP. Private/loopback không gán vị trí Internet. Invalid/mapped
IPv6 bị400. ULA hiện được Java helper phân loại PUBLIC nhưng lookup NOT_FOUND;
giữ hành vi fail-closed này, không tự đổi thành private default để giảm MFA.
Corrupt/type-swapped/future-clock age32ngày bị preflight chặn. Khi cố ý bỏ qua
preflight trên lane thử riêng: City corrupt → health503 và public lookup
INCOMPLETE/STEP_UP, không ALLOW. [Network][network], [lifecycle][lifecycle].
Lần browser giả header đầu bị timeout CORS do test thêm header cả token request;
receipt lỗi được giữ. Đã sửa phạm vi test và chỉ tiếp tục phần chưa hoàn tất;
không nới CORS. So sánh preservation cũng được sửa để không lệ thuộc thứ tự
array mounts do Docker trả về.

**J. Update/restart/rollback.** Updater dùng Basic auth trong bộ nhớ, không trong
URL/argv/log; bỏ Authorization khi redirect tới R2 chính thức, chặn HTTP/host lạ/
userinfo/non443. [Transport test][transport]. `fetch` tải/stage City+ASN, kiểm
checksum/metadata/type/freshness và lookup rồi mới tạo immutable release folder.
`activate` kiểm manifest/hash và đổi `current.json` atomically; **chỉ chọn dữ liệu**,
không tự reload reader. Đường vận hành phải serialize update, preflight/status,
chọn pair → controlled Risk replacement trong maintenance window → health +
lookup; lỗi thì chọn lại last-good và restart reader cũ. Không thay file đang đọc.

Đã kiểm restart, thay release folder cùng vendor build, lookup sau replacement,
rollback và V5 còn661092940; không reset account/schema. **Chưa có bản vendor mới
hơn để nghiệm thu một lần upgrade dữ liệu thật.** Freshness30ngày được kiểm bằng
tool nội bộ, chưa có scheduled monitoring. App health gốc chỉ kiểm City reader,
không phát hiện age/ASN tự động; phải dùng paired preflight/status trước demo và
trước mọi update. Không tạo cloud job. [Lifecycle thực chạy][lifecycle].

**K. Còn chặn/chờ owner.** Chưa promote Risk locking+GeoIP vào profile đang dùng;
CIDR production cần review riêng, không copy CIDR fixture/Lab lên GCP. Cần môi
trường được duyệt giữ được public peer để kiểm public-browser GeoIP; IAP/loopback
không chứng minh được điều này. D-10, D-14 promotion, D-17 PENDING và G8 INTERNET
NO-GO giữ nguyên. Bước owner tiếp: **review candidate GeoIP+Risk này và chốt policy
network cho môi trường đích**; chưa cần đưa thêm key hoặc mở public access.

**L. Acceptance (chỉ trong phạm vi đã thử).** [Machine-readable gates][gates].

| Gate | Trạng thái | Bằng chứng |
|---|---|---|
| GEOIP_DATABASE |PASS|[Acquisition][acquisition], [transport][transport] |
| CLIENT_IP_INTEGRITY |PASS local|[Native peer và header spoof][browser] |
| NETWORK_FEATURE_EXTRACTION |PASS|[Real City/ASN + network fields][network] |
| NETWORK_RISK_CONTRIBUTION |PASS|[13 trường hợp và B0][network] |
| ADAPTIVE_AUTH_GEOIP_E2E |PARTIAL|[Browser network/MFA thật; public lookup chưa quan sát][browser] |
| GEOIP_UPDATE_LIFECYCLE |PASS bounded|[Restart/replacement/rollback/corrupt][lifecycle]; cùng vendor build |
| GEOIP_LEGACY_PARITY |PARTIAL|[Config][policy]; policy/promotion và public peer còn chờ |

164 container hiện hữu giữ ID/image/mount/network/running state;6 protected file
hashes và V5/release locks khớp; Full-Function9/9healthy. Lane GeoIP/restore đã dừng,
stores được giữ. Không chạy full CI/scan, tác động Lab/PD-R19, deploy Cloud hoặc
commit/push. [Preservation][preservation]. **Overall Full-Function vẫn PARTIAL.**

[acquisition]: ../../target/full-function-20261111b/phase21a/acquisition.json
[transport]: ../../target/full-function-20261111b/phase21a/transport-boundary.json
[policy]: ../../target/full-function-20261111b/phase21a/policy-corrected.json
[network]: ../../target/full-function-20261111b/phase21a/network-evidence.json
[browser]: ../../target/full-function-20261111b/phase21a/browser-joined.json
[lifecycle]: ../../target/full-function-20261111b/phase21a/lifecycle.json
[gates]: ../../target/full-function-20261111b/phase21a/acceptance-gates.json
[preservation]: ../../target/full-function-20261111b/phase21a/preservation.json
