[Mục lục tài liệu](../README.md) · [Trang dự án](../../README.md)

> Báo cáo tại thời điểm ghi trong tài liệu; không thay thế kiểm chứng trạng thái hiện tại.

# Geo-IP và Network Risk production hardening

Ngày triển khai mã nguồn: 2026-09-24.

## 1. Phạm vi đã hoàn thành

- Giữ CIDR IPv4/IPv6 làm lớp policy ưu tiên.
- Tích hợp official MaxMind GeoIP2 Java API `5.2.0` để đọc GeoLite City/ASN local.
- Geo-IP mặc định tắt; không làm thay đổi local deployment hiện tại.
- Public IP không khớp CIDR có thể được map country theo policy
  trusted/elevated/high/default.
- Private, loopback, link-local và multicast không gọi Geo-IP.
- CIDR/country band `HIGH` tạo `HIGH_RISK_NETWORK` và mandatory MFA.
- Geo-IP missing/not-found/error tạo fail-safe `INCOMPLETE → STEP_UP_MFA`.
- Thêm `GEOLOCATION_RISK` và `GEOIP_INTELLIGENCE_UNAVAILABLE` cho explainability.
- Đồng bộ enum reason giữa Risk Service và Keycloak extension.
- Geo-IP result chỉ tồn tại trong memory; không thêm cột IP/location vào database.
- Thêm health indicator: Geo-IP enabled nhưng City reader chưa ready làm health DOWN.
- Thêm script tải/cập nhật GeoLite City/ASN; `.mmdb` và `geoip-data/` bị Git ignore.
- `run-risk-local.ps1` đã whitelist toàn bộ biến Geo-IP.
- Thêm `docs/security/DATA_PRIVACY.md` cho data inventory, retention, access và incident handling.

## 2. Cấu hình mới

```text
RISK_GEOIP_ENABLED=false
RISK_GEOIP_CITY_DATABASE_PATH=
RISK_GEOIP_ASN_DATABASE_PATH=
RISK_GEOIP_TRUSTED_COUNTRY_CODES=
RISK_GEOIP_ELEVATED_COUNTRY_CODES=
RISK_GEOIP_HIGH_RISK_COUNTRY_CODES=
```

Country code dùng ISO 3166-1 alpha-2. Khi một country xuất hiện ở nhiều list, thứ
tự high > elevated > trusted. ASN database là tùy chọn; City database bắt buộc khi
`RISK_GEOIP_ENABLED=true`.

## 3. Cách chuẩn bị database

Tại thư mục repository root:

```powershell
$env:MAXMIND_ACCOUNT_ID='account-id'
$env:MAXMIND_LICENSE_KEY='license-key'
.\update-geoip-databases.ps1
```

Script không ghi credential ra log, tải qua HTTPS vào thư mục tạm, kiểm tra `.mmdb`
có tồn tại/kích thước dương rồi thay file đích. License key chỉ dùng cho update job,
không đưa vào Risk Service runtime.

## 4. Trình tự bật an toàn

1. Cấu hình reverse proxy overwrite forwarded headers.
2. Đặt `KC_PROXY_HEADERS` và `KC_PROXY_TRUSTED_ADDRESSES`.
3. Chặn đường truy cập trực tiếp vào Keycloak từ Internet.
4. Xác minh `ClientConnection.getRemoteAddr()` bằng IP kiểm thử kiểm soát được.
5. Chạy script cập nhật GeoLite và dùng absolute path cho hai file.
6. Duyệt policy CIDR/country; không dùng city làm deny rule.
7. Bật `RISK_NETWORK_INTELLIGENCE_ENABLED=true` và `RISK_GEOIP_ENABLED=true`.
8. Kiểm tra `/actuator/health`, sau đó chạy ma trận trusted/elevated/high/not-found.
9. Theo dõi tỷ lệ `INCOMPLETE`, MFA và Geo-IP lookup error trước khi rollout rộng.

## 5. Hành vi quyết định

```text
blocked priority rule        -> DENY
high CIDR/country            -> mandatory STEP_UP_MFA
elevated CIDR/country        -> weighted scoring
trusted CIDR/country         -> network score 0, không tự bỏ qua tín hiệu khác
Geo-IP unavailable/not found -> INCOMPLETE, STEP_UP_MFA
network provider disabled    -> INCOMPLETE, STEP_UP_MFA
```

Guardrail high network không hạ một weighted `DENY` xuống MFA.

## 6. Kiểm thử được bổ sung

- Validation Geo-IP path khi enabled.
- Validation ISO country code.
- Geo-IP disabled/missing database.
- Trusted/high-risk country mapping.
- Geo-IP record missing fail-safe.
- Private IP không gọi Geo-IP.
- CIDR high-risk tạo mandatory MFA.
- Geo-IP reasons được extractor tạo và extension deserialize được.
- Health UP khi disabled và DOWN khi enabled nhưng database unavailable.

## 7. Rollback

Rollback vận hành không cần rollback database:

```text
RISK_GEOIP_ENABLED=false
```

Khởi động lại Risk Service. CIDR provider tiếp tục hoạt động nếu
`RISK_NETWORK_INTELLIGENCE_ENABLED=true`; không có migration schema mới trong thay
đổi này. Không xóa `.mmdb` trong lúc process đang chạy. Nếu cần rollback code, giữ
enum response đồng bộ giữa Risk Service và extension để tránh lỗi deserialize.

## 8. Giới hạn còn lại

- Chưa có location history hoặc phát hiện quốc gia mới theo từng user.
- Chưa có impossible travel.
- Chưa phát hiện VPN/Tor/anonymous proxy; GeoLite City/ASN không thay thế database
  reputation chuyên dụng.
- Chưa tự động schedule update; script phải được gọi bởi scheduler/CI được bảo vệ.
- Production reverse proxy/TLS phải được cấu hình trên hạ tầng thật, không thể được
  suy ra an toàn từ cấu hình local Docker hiện tại.

## 9. Bằng chứng kiểm thử và artifact

Ngày 2026-09-24 đã xác nhận:

- Risk Service: `119` test, `0` failure/error/skip; tạo
  `risk-scoring-service/target/risk-scoring-service-0.0.1-SNAPSHOT.jar`.
- Keycloak extension: `68` test, `0` failure/error/skip; tạo
  `keycloak-risk-extension/target/keycloak-risk-extension.jar`.
- Backend portal: `180` test, `0` failure/error/skip.
- Frontend: lint và production build đều thành công.
- Runtime smoke: MySQL/Redis healthy, Flyway schema ở version `3`, Risk Service
  khởi động thành công và `/actuator/health` trả `UP` khi Geo-IP đang tắt.
- JAR extension mới đã được chép vào
  `keycloak-26.7.0:/opt/keycloak/providers/keycloak-risk-extension.jar`. Container
  dùng `start-dev` và được giữ ở trạng thái dừng như trước khi kiểm tra; lần khởi
  động tiếp theo sẽ nạp JAR mới.

Chưa chạy integration test với database GeoLite thật vì repository không chứa
credential hoặc file `.mmdb`. Đây là bước go-live có chủ đích, không được thay thế
bằng file hoặc country policy giả.

## 10. Tài liệu vận hành chính thức

- MaxMind GeoIP2 Java API: <https://github.com/maxmind/GeoIP2-java>
- GeoLite database: <https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/>
- Cập nhật database: <https://dev.maxmind.com/geoip/updating-databases/>
- Keycloak reverse proxy: <https://www.keycloak.org/server/reverseproxy>
