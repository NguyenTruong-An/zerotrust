# Risk Scoring Service

Spring Boot service độc lập chịu trách nhiệm đánh giá rủi ro đăng nhập cho
ZeroTrust Academic Portal.

**Ngày đối chiếu mã:** 2026-10-05. Phần kết quả local có ngày bên dưới là mốc
lịch sử, không xác nhận runtime hiện tại. Đọc [kiến trúc](../ARCHITECTURE.md),
[giải thích class](../docs/development/CODE_FLOW_WALKTHROUGH.md) và
[reset MFA](../docs/authentication/MFA_RESET_LIFECYCLE.md) trước khi triển khai.

## Yêu cầu

- Java 17
- Maven Wrapper của repository
- MySQL 8 cho runtime local

Project dùng Lombok có chọn lọc để giảm boilerplate: `@RequiredArgsConstructor`
cho constructor injection và `@Getter`/`@Setter` cho configuration properties.
JPA entity không dùng `@Data` để tránh vô tình sinh setter, `equals`, `hashCode`
và `toString` cho toàn bộ trạng thái persistence.

## Cấu hình Risk DB

Risk Service sử dụng database riêng `risk_db`, không dùng Portal DB. Các biến môi
trường hỗ trợ:

```text
RISK_DB_URL
RISK_DB_USERNAME
RISK_DB_PASSWORD
RISK_DEVICE_FINGERPRINT_PEPPER
```

Fallback trong application.properties là MySQL `localhost:3306`, user `root`,
password rỗng. Hướng dẫn Compose dùng `.env` với port 3307 và user `risk_service`;
không dùng fallback này cho production. Có thể cấu hình secret trước khi chạy:

```powershell
$env:RISK_DB_PASSWORD="your-local-mysql-password"
$env:RISK_DEVICE_FINGERPRINT_PEPPER="at-least-32-random-characters-for-local"
```

`RISK_DEVICE_FINGERPRINT_PEPPER` là bí mật phía server, tối thiểu 32 ký tự và
không được commit vào Git. Service dùng HMAC-SHA-256 với pepper này để biến
`subjectId + deviceId` thành fingerprint hash ổn định.

Flyway chịu trách nhiệm quản lý schema và Hibernate chỉ `validate`; không dùng
`ddl-auto=update`. Test tự dùng H2 in-memory nên không tác động dữ liệu MySQL.

Migration đầu tiên `V1__create_known_devices.sql` tạo bảng `known_devices`. Bảng
lưu `device_fingerprint_hash` dạng HMAC-SHA-256 hex, không lưu device ID/fingerprint
thô. Mỗi cặp `(subject_id, device_fingerprint_hash)` là duy nhất và thiết bị có
một trong ba trạng thái `PENDING`, `TRUSTED`, `REVOKED`.

`KnownDeviceEntity` ánh xạ bảng này bằng JPA và dùng trường `version` cho
optimistic locking. `KnownDeviceRepository` hỗ trợ tìm thiết bị theo
`subject_id + device_fingerprint_hash` và kiểm tra thiết bị có trạng thái
`TRUSTED`. `DeviceRecognitionService` đã nối repository vào feature extractor để
phân loại thành MISSING/NEW/PENDING/TRUSTED/REVOKED/REAUTHENTICATION_REQUIRED.
Trạng thái lưu DB vẫn là PENDING/TRUSTED/REVOKED. `trust()` cập nhật `trusted_at`
khi MFA registration thành công lại; server trust hết hạn sau 30 ngày từ mốc này.
Không chấp nhận thời điểm trước first_seen_at và revoked row không tự trust lại.
Revoke do SECURITY dẫn DENY; MFA_RESET dẫn MFA/ID mới khi reset đã completion.

Migration `V2__create_authentication_success_events.sql` tạo bảng
`authentication_success_events`. Bảng lưu `event_id`, subject, client, thời điểm
Keycloak xác thực và thời điểm Risk Service ghi nhận. `event_id` là unique;
repository dùng một câu `INSERT IGNORE` để retry nối tiếp hoặc đồng thời đều không
tạo dòng trùng. Migration `V3__add_temporal_profile_lookup_index.sql` bổ sung index
`(subject_id, client_id, authenticated_at)` cho truy vấn cửa sổ lịch sử của
Temporal Profile.

Migration `V4__device_trust_revocations.sql` thêm revocation_reason,
`subject_device_trust` (generation/pending) và `device_trust_revocations` (audit
operation reset). Đây không phải persistence cho mọi evaluation/decision.

`TrustedDeviceRegistrationService.trustAfterMfa()` hiện thực use case ghi thiết
bị sau MFA trong một transaction: khóa subject/kiểm generation và pending,
tính HMAC từ `subjectId + deviceId`, cập nhật
thiết bị đã biết hoặc tạo bản ghi `TRUSTED` mới bằng thời gian UTC do server cấp.
Raw device ID không được ghi xuống database và device đã `REVOKED` bị từ chối.
Use case này được expose qua `POST /internal/v1/trusted-devices`; endpoint trả
`204 No Content` khi thành công và `409 DEVICE_TRUST_REJECTED` nếu fingerprint đã
bị thu hồi, generation cũ hoặc reset còn pending. Keycloak extension nối sau
conditional MFA; CONFIGURE_TOTP pending không tạo trust và chỉ phát
cookie khi API xác nhận thành công.

## Kiểm thử

Chạy từ thư mục gốc của repository:

```powershell
.\mvnw.cmd -f .\risk-scoring-service\pom.xml clean verify
.\mvnw.cmd -f .\keycloak-risk-extension\pom.xml clean verify
```

Để chạy thử luồng local, mở hai terminal tại thư mục gốc. Terminal thứ nhất:

```powershell
docker compose up -d risk-db risk-redis
docker start keycloak-26.7.0
.\run-risk-local.ps1
```

Terminal thứ hai kiểm tra Risk Service:

```powershell
Invoke-RestMethod http://localhost:8081/actuator/health
```

Kết quả mong đợi là `status = UP`. Gọi endpoint evaluation không có Bearer token
phải nhận `401`. Phép thử tích hợp có token nên đi qua chính extension trong
Keycloak để token có issuer nội bộ `http://localhost:8080/realms/DoAn`, giống môi
trường runtime của extension.

Flow `zerotrust-browser-recovery` đã được bind làm Browser Flow của realm `DoAn`
ngày 2026-09-21; flow `zerotrust-browser` được giữ để rollback. Nhánh step-up cho
phép OTP hoặc Recovery Authentication Code ở hai execution `ALTERNATIVE`. Luồng
login end-to-end đã được xác nhận với tài khoản có OTP. Lần đầu tạo một row
`TRUSTED`; lần đăng nhập thứ hai trên cùng browser vẫn giữ đúng một row, cập nhật
`last_seen_at` và tăng `version` từ 1 lên 2. Fingerprint lưu trong database dài 64
ký tự và không có device ID thô. Kết quả này xác nhận cookie thiết bị được tái sử
dụng và registration là idempotent.

Với cấu hình mặc định tắt Network provider, evaluation thiếu dữ liệu trả
`STEP_UP_MFA`, kể cả khi device TRUSTED (trừ nhánh priority DENY). User có thể
dùng OTP hoặc recovery code chưa dùng. ALLOW cần nguồn bắt buộc COMPLETE, score
LOW và không có mandatory guardrail. Unit test có kiểm nhánh này; deployment
thật cần ma trận E2E riêng, không dùng cookie TRUSTED để suy ra ALLOW.

Mốc lịch sử ngày 2026-09-21: Risk Service đạt `105/105` test và Keycloak
extension đạt `68/68` test. Health local trả `UP` và request evaluation không có
Bearer token bị chặn bằng `401`.

Flyway V3 đã chạy thành công trên MySQL 8.0.46 local, schema lên version 3 và
index `idx_authentication_success_events_subject_client_time` có đúng thứ tự cột
subject/client/authenticated-at. Sau migration, Risk Service health trả `UP`.

Một lần đăng nhập thật bằng password + OTP đã tạo đúng một successful-login row
cho `zerotrust-spa` trong MySQL. Smoke test gửi cùng event hai lần đều nhận `204`
nhưng database chỉ có một row; bản ghi smoke test đã được xóa sau khi xác minh.

## Chạy local

Từ thư mục gốc, tạo `.env` từ file mẫu, thay các placeholder bằng secret local,
khởi động Risk DB và Redis rồi chạy script:

```powershell
Copy-Item .env.example .env
docker compose up -d risk-db risk-redis
.\run-risk-local.ps1
```

Compose dùng MySQL 8.0.46, user ứng dụng `risk_service`, named volume và cổng host
`127.0.0.1:3307`. Redis 7.4.7 dùng password, AOF, named volume và chỉ publish
`127.0.0.1:6379`. Script chỉ nạp các biến cần cho Risk Service và không truyền
MySQL root password vào Java. `RISK_AUTH_HISTORY_PEPPER` phải khác pepper của
device fingerprint.

Khi chạy trực tiếp bằng nút Run của IntelliJ, cấu hình
`RiskScoringApplication` cần hai environment variable sau:

```text
SPRING_PROFILES_ACTIVE=dev
SPRING_CONFIG_IMPORT=optional:file:<repository-root>/.env[.properties]
```

`SPRING_CONFIG_IMPORT` giúp Spring đọc các biến `RISK_*` từ `.env` mà không sao
chép secret vào Run Configuration. Nếu thiếu cấu hình này, placeholder như
`${RISK_JWT_ISSUER_URI}` sẽ không được resolve và ứng dụng chủ động không khởi
động. Đây là hành vi fail-closed của cấu hình bảo mật.

Service mặc định chạy tại `http://localhost:8081`. Kiểm tra trạng thái:

```text
GET http://localhost:8081/actuator/health
```

Có thể đổi cổng bằng biến môi trường `RISK_SERVICE_PORT`.

## Bảo vệ API nội bộ

Risk Service là OAuth2 Resource Server stateless. Bốn endpoint evaluation,
registration và events bắt buộc
Bearer JWT do realm `DoAn` phát hành và kiểm tra đồng thời chữ ký JWKS, issuer,
thời hạn, audience `zerotrust-risk-api` và `azp=zerotrust-risk-caller`. Mỗi thao
tác có client role riêng: `risk:evaluate` cho đánh giá, `risk:device:write` cho
đăng ký thiết bị tin cậy và `risk:events:write` cho ghi event xác thực thành công
hoặc thất bại. Các role
không thay thế cho nhau. Revoke và completion dùng caller riêng
`zerotrust-portal-risk-admin` với `risk:device:revoke`. Realm đích phải cấp role,
scope và audience tương ứng; không suy ra provisioning từ code.

`application.properties` fail-closed: nếu không dùng profile `dev`, issuer và
JWKS phải được truyền bằng `RISK_JWT_ISSUER_URI` và `RISK_JWT_JWK_SET_URI`.
Profile `dev` chỉ nới yêu cầu HTTPS để chạy trên loopback; JWT vẫn bắt buộc.
Profile `prod` bật HTTPS trực tiếp với PKCS12 qua các biến `RISK_TLS_*`.

Service mặc định bind `127.0.0.1`. Khi chạy trong private container network, có
thể đặt `RISK_BIND_ADDRESS=0.0.0.0`, nhưng không publish endpoint `/internal` ra
Internet. Hướng dẫn cấu hình đầy đủ nằm trong `docs/security/RISK_API_SECURITY.md`.

## Phạm vi hiện tại

Service hiện có REST API, validation, pipeline Priority Security Rule, feature
extraction và weighted risk engine cho bốn nhóm đặc trưng đã chốt trong
`ARCHITECTURE.md`.

```text
POST /internal/v1/risk/evaluations
POST /internal/v1/trusted-devices
POST /internal/v1/authentication-failures
POST /internal/v1/authentication-successes
POST /internal/v1/subjects/{subjectId}/trusted-devices/revocations
POST /internal/v1/subjects/{subjectId}/trusted-devices/revocations/completion
```

Request mẫu:

```json
{
  "subjectId": "keycloak-user-id",
  "authenticationSessionId": "authentication-session-id",
  "clientId": "zerotrust-spa",
  "ipAddress": "203.0.113.10",
  "userAgent": "Mozilla/5.0",
  "deviceId": "device-123"
}
```

Caller chỉ được gửi login context thô, không được tự gửi điểm rủi ro hoặc quyết
định `hardDeny`. Thời điểm tiếp nhận được Risk Service lấy từ clock của server,
không tin thời gian do caller cung cấp.

Endpoint thiết bị nhận subject/device ID do Keycloak extension thu sau MFA và
generation đã nhận từ evaluation; không tự chọn generation mới để né 409:

```json
{
  "subjectId": "keycloak-user-id",
  "deviceId": "secure-random-device-identifier",
  "trustGeneration": 0
}
```

Raw device ID chỉ dùng để tính HMAC và không được lưu. API này không tự chứng minh
MFA; ranh giới tin cậy là service account Keycloak với role `risk:device:write`,
TLS và giới hạn mạng nội bộ.

Endpoint authentication failure nhận `eventId`, `subjectId` có thể vắng mặt và
`sourceIp`. Redis dùng `eventId` để chống xử lý trùng và tăng nguyên tử counter
theo subject/IP trong cửa sổ mặc định 15 phút. Tất cả phần động của Redis key đều
được HMAC-SHA-256 bằng pepper riêng; không lưu subject hoặc IP thô trong tên key.
Counter và deduplication marker tự hết hạn. Keycloak listener chỉ gửi lỗi
`invalid_user_credentials` và `user_not_found`; `expired_code`, lỗi session và
`user_temporarily_disabled` không làm tăng counter.

Feature extractor hiện lấy Device Risk và Temporal Risk từ Risk DB,
Authentication History Risk từ Redis và Network Risk từ CIDR + Geo-IP local.
Counter subject và IP được map riêng vào
các dải `0/medium/high`, sau đó
lấy mức cao hơn để tránh tính hai lần cùng một failure event. Baseline development
là subject `3/5`, source IP `10/20`, score `50/100`; tất cả đều có thể cấu hình qua
`RISK_AUTH_*`. Đây là ngưỡng thử nghiệm, không phải con số do NIST hoặc OWASP quy
định. Dải high (`5` theo subject hoặc `20` theo IP theo mặc định) là guardrail bắt
buộc `STEP_UP_MFA` ngay cả khi weighted score chưa đạt 40. Guardrail không hạ một
quyết định weighted `DENY` xuống MFA; khóa tạm thời vẫn do brute-force protection
của Keycloak quản lý.

Temporal Profile đọc tối đa số event cấu hình trong cửa sổ lịch sử theo đúng
subject và client, không lấy event tại hoặc sau thời điểm evaluation. Các event
được đổi sang timezone policy rồi tạo hai tần suất: cùng thứ trong tuần và giờ nằm
trong dung sai vòng 24 giờ. Không có tín hiệu bất thường cho score `0`, một tín
hiệu cho medium, cả hai tín hiệu cho high. Chưa đủ số mẫu tạo
`TEMPORAL_PROFILE_COLD_START`; lỗi database tạo `TEMPORAL_PROFILE_UNAVAILABLE`.
Cả hai đều fail-safe, không được xem như temporal score thấp.

Network Intelligence xét CIDR do operator quản lý trước, hỗ trợ IPv4/IPv6 theo thứ
tự high-risk, elevated-risk, trusted rồi default. Nếu Geo-IP được bật, public IP
không khớp CIDR được tra bằng GeoLite City và tùy chọn GeoLite ASN local, sau đó
phân loại theo country code với cùng thứ tự high/elevated/trusted/default. Private,
loopback, link-local và multicast không được gửi vào Geo-IP provider. City, timezone,
accuracy radius và ASN chỉ tồn tại trong assessment nội bộ; raw IP/location không
được persist hoặc ghi log. Provider không gọi web service Geo-IP theo request.

High-risk CIDR/country tạo `HIGH_RISK_NETWORK` và mandatory `STEP_UP_MFA`, kể cả
khi weighted contribution chỉ là `100 * 0.25 = 25`. Geo-IP bật nhưng database/record
không available tạo `GEOIP_INTELLIGENCE_UNAVAILABLE`; evaluation trở thành
`INCOMPLETE` thay vì rơi về default score. Health chuyển DOWN nếu đã bật Geo-IP mà
City database chưa mở được.

Các giá trị sau là baseline development có thể cấu hình, chưa phải policy chính
thức:

```text
RISK_AUTH_SUBJECT_MEDIUM_MINIMUM=3
RISK_AUTH_SUBJECT_HIGH_MINIMUM=5
RISK_AUTH_IP_MEDIUM_MINIMUM=10
RISK_AUTH_IP_HIGH_MINIMUM=20
RISK_AUTH_HISTORY_MEDIUM_SCORE=50
RISK_AUTH_HISTORY_HIGH_SCORE=100
RISK_NETWORK_INTELLIGENCE_ENABLED=false
RISK_NETWORK_DEFAULT_SCORE=50
RISK_NETWORK_ELEVATED_SCORE=50
RISK_NETWORK_HIGH_SCORE=100
RISK_NETWORK_TRUSTED_CIDRS=
RISK_NETWORK_ELEVATED_CIDRS=
RISK_NETWORK_HIGH_RISK_CIDRS=
RISK_GEOIP_ENABLED=false
RISK_GEOIP_CITY_DATABASE_PATH=
RISK_GEOIP_ASN_DATABASE_PATH=
RISK_GEOIP_TRUSTED_COUNTRY_CODES=
RISK_GEOIP_ELEVATED_COUNTRY_CODES=
RISK_GEOIP_HIGH_RISK_COUNTRY_CODES=
RISK_TEMPORAL_HISTORY_WINDOW=P90D
RISK_TEMPORAL_MINIMUM_EVENTS=5
RISK_TEMPORAL_MAXIMUM_EVENTS=200
RISK_TEMPORAL_ZONE_ID=Asia/Ho_Chi_Minh
RISK_TEMPORAL_HOUR_TOLERANCE=1
RISK_TEMPORAL_MINIMUM_DAY_FREQUENCY=0.10
RISK_TEMPORAL_MINIMUM_HOUR_FREQUENCY=0.20
RISK_TEMPORAL_MEDIUM_SCORE=50
RISK_TEMPORAL_HIGH_SCORE=100
```

Network provider mặc định tắt. Chỉ bật sau khi reverse proxy/Keycloak đã xác định
đúng canonical client IP và policy CIDR đã được duyệt. Ví dụ development:

```text
RISK_NETWORK_INTELLIGENCE_ENABLED=true
RISK_NETWORK_TRUSTED_CIDRS=203.0.113.0/24,2001:db8:100::/48
RISK_NETWORK_ELEVATED_CIDRS=198.51.100.0/24
RISK_NETWORK_HIGH_RISK_CIDRS=192.0.2.128/25
```

Để bật Geo-IP sau khi đã xác minh canonical IP, tải GeoLite City/ASN bằng tài
khoản MaxMind rồi đặt file ngoài Git:

```powershell
$env:MAXMIND_ACCOUNT_ID='account-id'
$env:MAXMIND_LICENSE_KEY='license-key'
.\update-geoip-databases.ps1
```

Sau đó cấu hình:

```text
RISK_GEOIP_ENABLED=true
RISK_GEOIP_CITY_DATABASE_PATH=C:/absolute/path/geoip-data/GeoLite2-City.mmdb
RISK_GEOIP_ASN_DATABASE_PATH=C:/absolute/path/geoip-data/GeoLite2-ASN.mmdb
RISK_GEOIP_TRUSTED_COUNTRY_CODES=
RISK_GEOIP_ELEVATED_COUNTRY_CODES=
RISK_GEOIP_HIGH_RISK_COUNTRY_CODES=
```

Country code phải là ISO 3166-1 alpha-2. High thắng elevated, elevated thắng
trusted nếu policy chồng lấn. Không đưa một quốc gia vào high/deny khi chưa có phê
duyệt policy; city không được dùng làm hard deny vì Geo-IP chỉ là vị trí ước tính.

Không đưa cả dải private, VPN hoặc NAT dùng chung vào `TRUSTED_CIDRS` chỉ vì đó là
mạng nội bộ. Một CIDR là tín hiệu dùng chung cho mọi user đi qua egress đó, không
chứng minh danh tính hay thiết bị. Với production, Keycloak chỉ được tin proxy do
operator kiểm soát, proxy phải ghi đè header chuyển tiếp từ Internet, và extension
tiếp tục lấy địa chỉ đã chuẩn hóa qua `ClientConnection.getRemoteAddr()`.

```json
{
  "evaluationId": "0ea3026d-2f0a-4ab8-a45e-8183e47f52e5",
  "subjectId": "keycloak-user-id",
  "authenticationSessionId": "authentication-session-id",
  "riskScore": null,
  "riskLevel": "MEDIUM",
  "decision": "STEP_UP_MFA",
  "dataStatus": "INCOMPLETE",
  "reasons": [
    "NEW_DEVICE",
    "NETWORK_INTELLIGENCE_UNAVAILABLE",
    "TEMPORAL_PROFILE_COLD_START"
  ],
  "evaluatedAt": "2026-09-04T08:00:00Z",
  "trustGeneration": 0
}
```

Fingerprint REVOKED vì SECURITY (hoặc reason không phải MFA_RESET) trả DENY /
REVOKED_DEVICE trước scoring. REVOKED vì MFA_RESET hoặc trust hết hạn trả
DEVICE_REAUTHENTICATION_REQUIRED, bắt buộc MFA và ID mới. MISSING/NEW/PENDING cũng
có guardrail MFA, không chỉ factor điểm. Snapshot subject reset pending trả
DENY / MFA_RESET_IN_PROGRESS. Evaluation không tự tạo TRUSTED; đăng ký do
post-MFA authenticator thực hiện, không do LOGIN event listener.

Trọng số và ngưỡng trong `application.properties` là baseline phục vụ development,
được đánh dấu `TBD`, không phải chính sách đã được phê duyệt. Có thể ghi đè bằng
các biến môi trường tương ứng. Trọng số bắt buộc có tổng bằng `1.0`, ngưỡng
`medium` phải nhỏ hơn ngưỡng `high`.

### Mức độ hoàn thiện của các đặc trưng

| Nhóm dữ liệu | Nguồn hiện tại | Trạng thái | Ảnh hưởng runtime |
| --- | --- | --- | --- |
| User/session/client | Keycloak `AuthenticationFlowContext` | Thật | Gửi ID của user, authentication session và client sang Risk Service |
| IP/User-Agent | Kết nối và HTTP header mà Keycloak nhận được | Thật, cần cấu hình proxy đúng khi triển khai | Được gửi làm context thô; User-Agent chưa được chấm điểm |
| Device ID | Cookie `ZT_DEVICE_ID` | Thật | Keycloak sinh ID ngẫu nhiên 256 bit sau MFA, API lưu HMAC và cookie được phát sau HTTP 204 |
| Device status | HMAC fingerprint và bảng `known_devices` trong MySQL | Có mã | Phân biệt trust còn hạn, security revoke và MFA-reset/expired; state thiếu/mới/pending bắt buộc MFA |
| Network intelligence | CIDR IPv4/IPv6 + GeoLite City/ASN local | Đã tích hợp, mặc định tắt | CIDR được xét trước; public IP có thể map country; high-risk bắt buộc MFA; Geo-IP lỗi fail-safe; không persist raw IP/location |
| Temporal profile | Keycloak `LOGIN` -> protected Risk API -> `authentication_success_events` trong MySQL | Dữ liệu thật, đã tích hợp | Baseline theo thứ/giờ trong cửa sổ và timezone cấu hình; trả score `0/medium/high`, phân biệt `COLD_START` với `UNAVAILABLE` |
| Authentication history | Keycloak credential-related `LOGIN_ERROR` -> protected Risk API -> Redis counter theo subject/IP, HMAC key, TTL và event deduplication | Dữ liệu thật, đã tích hợp | Bỏ qua lỗi kỹ thuật/lockout; lấy mức cao hơn giữa subject/IP; dải high bắt buộc MFA; Redis lỗi tạo `AUTHENTICATION_HISTORY_UNAVAILABLE` |
| Trọng số/ngưỡng/điểm theo trạng thái device | `application.properties` | Giá trị policy baseline | Là số cấu hình thủ công, chưa được hiệu chỉnh từ dữ liệu thực nghiệm |

Network provider bị tắt, Temporal Profile chưa đủ mẫu/lỗi DB hoặc Redis lỗi đều
không được dùng để tạo một điểm thấp giả. Extractor đánh dấu dữ liệu là
`INCOMPLETE`; `RiskEvaluationService` bỏ qua weighted scoring và trả
`riskScore = null`, `MEDIUM`, `STEP_UP_MFA`. Khi network provider được bật và cả
ba nguồn động đều available, extractor trả `COMPLETE` và runtime đi vào weighted
scoring, vì vậy các nhánh `ALLOW`, `STEP_UP_MFA` và `DENY` đều có thể xảy ra.

Danh sách IP bị chặn có thể cấu hình bằng biến môi trường, phân cách bằng dấu phẩy:

```powershell
$env:RISK_BLOCKED_IP_ADDRESSES="203.0.113.10,198.51.100.20"
```

IP thuộc danh sách này bị `DENY` bởi Priority Security Rule trước khi feature
extraction và weighted scoring chạy.

Risk chuẩn hóa IP literal cho blocklist và khóa HMAC của failure counter: IPv6
rút gọn/đầy đủ, hoa/thường và IPv4 có số 0 ở đầu cùng trỏ về một địa chỉ.
Blocklist được chuẩn hóa khi khởi động; entry sai định dạng khiến service không
khởi động. Hostname, scope ID và IPv4-mapped IPv6 không được chấp nhận; không
tra DNS. Chuỗi rỗng trong cấu hình blocklist tiếp tục được bỏ qua.

Khi nâng cấp từ phiên bản chưa chuẩn hóa, khóa counter của IPv6/IPv4 có số 0 ở
đầu có thể thay đổi. Không thể gộp các khóa HMAC cũ theo mọi cách viết IP mà
không có địa chỉ gốc. Triển khai đồng bộ các instance Risk để tránh chia counter
giữa hai phiên bản; counter cũ hết hạn theo `RISK_AUTH_FAILURE_WINDOW`
(baseline 15 phút). Trong phần cửa sổ còn lại, lịch sử theo IP có thể thiếu;
counter subject và event deduplication giữ nguyên định dạng khóa.

## Giới hạn kiểm chứng

Mốc 2026-10-05: 182 test Risk đạt sau sửa IP normalization; xem
[DEVELOPMENT_CHECKS](../docs/development/DEVELOPMENT_CHECKS.md). H2/mock và JWKS
giả lập không xác nhận MySQL/Redis/Keycloak hoặc TLS production. GeoLite được
nạp vào memory lúc startup, chưa tự reload hoặc kiểm tuổi file. History query
không thay purge/retention job.

Phần dưới là ghi nhận local trước đây, không phải xác nhận rollout hiện tại:

OAuth2 service-to-service đã được triển khai trong code và có test cho token
thiếu, sai chữ ký, sai issuer/audience/caller/role và hết hạn. Endpoint đăng ký
thiết bị đã có kiểm thử phân quyền riêng, validation, persistence và xung đột khi
device bị thu hồi. Role `risk:device:write` đã được tạo, gán vào service account
và dedicated role scope của `zerotrust-risk-caller`; token mới đã được xác minh có
đủ `aud`, `azp` và ba role Risk API hiện hữu. Extension post-MFA và cookie đã
được cài vào flow local và đã qua login end-to-end. Redis local đã healthy; Lua
đã được thử trực tiếp, xác nhận lần ghi đầu tăng counter và cùng `eventId` không
tăng lần hai. Event Listener đã được cài, bật cho realm và thử bằng một lần sai
mật khẩu thật: event marker, counter subject và counter IP đều được tạo đúng một
lần. Listener hiện chỉ đếm `invalid_user_credentials`/`user_not_found` và bỏ qua
`expired_code`/lockout. Counter đã được nối vào feature extractor; phép thử với ba
lần sai mật khẩu trả reason `AUTHENTICATION_HISTORY_RISK`, còn dải high thêm
`EXCESSIVE_AUTHENTICATION_FAILURES` và bắt buộc MFA. Flyway V2/V3, đường ghi
successful-login, truy vấn lịch sử, Temporal Risk và CIDR + GeoLite local Network
Risk calculator đã được triển khai. High-risk network đã có mandatory MFA và
Geo-IP unavailable đã fail-safe. Bước tiếp theo là chạy ma trận runtime end-to-end cho `ALLOW`,
`STEP_UP_MFA`, `DENY`, Redis/Risk Service outage và Keycloak brute-force lockout
trước khi chuyển sang hardening production.
