# Risk Scoring Service

Spring Boot service độc lập chịu trách nhiệm đánh giá rủi ro đăng nhập cho
ZeroTrust Academic Portal.

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

Giá trị local mặc định là MySQL tại `localhost:3306`, user `root` và password
rỗng. Có thể cấu hình password trước khi chạy:

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
phân loại thiết bị thành `MISSING`, `NEW`, `PENDING`, `TRUSTED` hoặc `REVOKED`.
Các chuyển trạng thái trong entity giữ nguyên thời điểm trust/revoke đầu tiên khi
nhận lại cùng sự kiện, không chấp nhận thời điểm trước `first_seen_at` và không
cho phép một thiết bị `REVOKED` tự chuyển lại thành `TRUSTED`. Milestone này mới
khóa invariant của domain.

Migration `V2__create_authentication_success_events.sql` tạo bảng
`authentication_success_events`. Bảng lưu `event_id`, subject, client, thời điểm
Keycloak xác thực và thời điểm Risk Service ghi nhận. `event_id` là unique;
repository dùng một câu `INSERT IGNORE` để retry nối tiếp hoặc đồng thời đều không
tạo dòng trùng. Index `(subject_id, authenticated_at)` phục vụ bước dựng Temporal
Profile tiếp theo.

`TrustedDeviceRegistrationService.trustAfterMfa()` hiện thực use case ghi thiết
bị sau MFA trong một transaction: tính HMAC từ `subjectId + deviceId`, cập nhật
thiết bị đã biết hoặc tạo bản ghi `TRUSTED` mới bằng thời gian UTC do server cấp.
Raw device ID không được ghi xuống database và device đã `REVOKED` bị từ chối.
Use case này được expose qua `POST /internal/v1/trusted-devices`; endpoint trả
`204 No Content` khi thành công và `409 DEVICE_TRUST_REJECTED` nếu fingerprint đã
bị thu hồi. Keycloak extension đã nối lời gọi này sau conditional OTP và chỉ phát
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

Flow `zerotrust-browser` đã được bind làm Browser Flow của realm `DoAn` ngày
2026-09-11. Luồng login end-to-end đã được xác nhận ngày 2026-09-16 với tài khoản
đã cấu hình OTP. Lần đầu tạo một row `TRUSTED`; lần đăng nhập thứ hai trên cùng
browser vẫn giữ đúng một row, cập nhật `last_seen_at` và tăng `version` từ 1 lên
2. Fingerprint lưu trong database dài 64 ký tự và không có device ID thô. Kết quả
này xác nhận cookie thiết bị được tái sử dụng và registration là idempotent.

Với mức hoàn thiện feature hiện tại, kết quả runtime bình thường vẫn là
`STEP_UP_MFA` và màn hình OTP vẫn xuất hiện, kể cả khi device đã `TRUSTED`. Nhánh
`ALLOW` mới chỉ kiểm thử được ở unit test cho weighted engine; runtime chưa thể
trả `ALLOW` cho đến khi các nguồn feature bắt buộc có trạng thái `COMPLETE`.

Xác nhận gần nhất ngày 2026-09-17: Risk Service đạt `69/69` test và Keycloak
extension đạt `66/66` test. Health local trả `UP` và request evaluation không có
Bearer token bị chặn bằng `401`.

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

Risk Service là OAuth2 Resource Server stateless. Cả bốn endpoint nội bộ bắt buộc
Bearer JWT do realm `DoAn` phát hành và kiểm tra đồng thời chữ ký JWKS, issuer,
thời hạn, audience `zerotrust-risk-api` và `azp=zerotrust-risk-caller`. Mỗi thao
tác có client role riêng: `risk:evaluate` cho đánh giá, `risk:device:write` cho
đăng ký thiết bị tin cậy và `risk:events:write` cho ghi event xác thực thành công
hoặc thất bại. Các role
không thay thế cho nhau. Cả ba role đã được tạo/gán trong Keycloak và xuất hiện
trong service token runtime của `zerotrust-risk-caller`.

`application.properties` fail-closed: nếu không dùng profile `dev`, issuer và
JWKS phải được truyền bằng `RISK_JWT_ISSUER_URI` và `RISK_JWT_JWK_SET_URI`.
Profile `dev` chỉ nới yêu cầu HTTPS để chạy trên loopback; JWT vẫn bắt buộc.
Profile `prod` bật HTTPS trực tiếp với PKCS12 qua các biến `RISK_TLS_*`.

Service mặc định bind `127.0.0.1`. Khi chạy trong private container network, có
thể đặt `RISK_BIND_ADDRESS=0.0.0.0`, nhưng không publish endpoint `/internal` ra
Internet. Hướng dẫn cấu hình đầy đủ nằm trong `../RISK_API_SECURITY.md`.

## Phạm vi hiện tại

Service hiện có REST API, validation, pipeline Priority Security Rule, feature
extraction và weighted risk engine cho bốn nhóm đặc trưng đã chốt trong
`ARCHITECTURE.md`.

```text
POST /internal/v1/risk/evaluations
POST /internal/v1/trusted-devices
POST /internal/v1/authentication-failures
POST /internal/v1/authentication-successes
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

Endpoint thiết bị chỉ nhận định danh người dùng và device ID do Keycloak
extension thu được sau MFA:

```json
{
  "subjectId": "keycloak-user-id",
  "deviceId": "secure-random-device-identifier"
}
```

Raw device ID chỉ dùng để tính HMAC và không được lưu. API này không tự chứng minh
MFA; ranh giới tin cậy là service account Keycloak với role `risk:device:write`,
TLS và giới hạn mạng nội bộ.

Endpoint authentication failure nhận `eventId`, `subjectId` có thể vắng mặt và
`sourceIp`. Redis dùng `eventId` để chống xử lý trùng và tăng nguyên tử counter
theo subject/IP trong cửa sổ mặc định 15 phút. Tất cả phần động của Redis key đều
được HMAC-SHA-256 bằng pepper riêng; không lưu subject hoặc IP thô trong tên key.
Counter và deduplication marker tự hết hạn.

Feature extractor hiện lấy Device Risk từ Risk DB và Authentication History Risk
từ Redis. Counter subject và IP được map riêng vào các dải `0/medium/high`, sau đó
lấy mức cao hơn để tránh tính hai lần cùng một failure event. Baseline development
là subject `3/5`, source IP `10/20`, score `50/100`; tất cả đều có thể cấu hình qua
`RISK_AUTH_*`. Đây là ngưỡng thử nghiệm, không phải con số do NIST hoặc OWASP quy
định. Successful-login events đã được thu thập vào MySQL, nhưng phép tính Temporal
Profile và nguồn network intelligence chưa có nên feature data vẫn có trạng thái
`INCOMPLETE`. Hệ thống fail-safe bằng cách yêu cầu MFA:

```text
RISK_AUTH_SUBJECT_MEDIUM_MINIMUM=3
RISK_AUTH_SUBJECT_HIGH_MINIMUM=5
RISK_AUTH_IP_MEDIUM_MINIMUM=10
RISK_AUTH_IP_HIGH_MINIMUM=20
RISK_AUTH_HISTORY_MEDIUM_SCORE=50
RISK_AUTH_HISTORY_HIGH_SCORE=100
```

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
    "TEMPORAL_PROFILE_UNAVAILABLE"
  ],
  "evaluatedAt": "2026-09-04T08:00:00Z"
}
```

Nếu fingerprint có trạng thái `REVOKED`, Risk Service trả `DENY` với lý do
`REVOKED_DEVICE` trước khi weighted scoring. Thiết bị mới chỉ được nhận diện là
`NEW`; service chưa tự ghi hoặc tự chuyển thành `TRUSTED`. Việc đăng ký thiết bị
phải diễn ra sau khi login/MFA thành công ở bước authentication-event tiếp theo.

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
| Device status | HMAC fingerprint và bảng `known_devices` trong MySQL | Thật một phần | Phân loại `MISSING/NEW/PENDING/TRUSTED/REVOKED`; `REVOKED` bị `DENY` |
| Network intelligence | Chưa có provider | Chưa triển khai | Gán factor nội bộ bằng `0`, thêm lý do `NETWORK_INTELLIGENCE_UNAVAILABLE` |
| Temporal profile | Keycloak `LOGIN` -> protected Risk API -> `authentication_success_events` trong MySQL | Thu thập dữ liệu thật; chưa tính profile/score | Mỗi event lưu một lần theo `event_id`; extractor hiện vẫn gán factor nội bộ bằng `0` và thêm `TEMPORAL_PROFILE_UNAVAILABLE` |
| Authentication history | Keycloak `LOGIN_ERROR` -> protected Risk API -> Redis counter theo subject/IP, HMAC key, TTL và event deduplication | Dữ liệu thật, đã tích hợp | Ánh xạ theo dải cấu hình, lấy mức cao hơn giữa subject/IP; thêm `AUTHENTICATION_HISTORY_RISK` khi score dương và `AUTHENTICATION_HISTORY_UNAVAILABLE` nếu Redis lỗi |
| Trọng số/ngưỡng/điểm theo trạng thái device | `application.properties` | Giá trị policy baseline | Là số cấu hình thủ công, chưa được hiệu chỉnh từ dữ liệu thực nghiệm |

Hai factor chưa có provider không được dùng để tạo một điểm thấp giả. Extractor
đánh dấu toàn bộ bộ dữ liệu là `INCOMPLETE`; `RiskEvaluationService` bỏ qua
weighted scoring và trả `riskScore = null`, `MEDIUM`, `STEP_UP_MFA`. Weighted
score chỉ được tính khi mọi nguồn bắt buộc trả về `COMPLETE`.

Danh sách IP bị chặn có thể cấu hình bằng biến môi trường, phân cách bằng dấu phẩy:

```powershell
$env:RISK_BLOCKED_IP_ADDRESSES="203.0.113.10,198.51.100.20"
```

IP thuộc danh sách này bị `DENY` bởi Priority Security Rule trước khi feature
extraction và weighted scoring chạy.

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
lần. Counter đã được nối vào feature extractor; phép thử với ba lần sai mật khẩu
trả reason `AUTHENTICATION_HISTORY_RISK`. Flyway V2 và đường ghi successful-login
đã được triển khai; bước tiếp theo là dựng baseline theo giờ/ngày từ bảng này và
tích hợp Temporal Risk vào extractor, sau đó mới cân nhắc network intelligence.
