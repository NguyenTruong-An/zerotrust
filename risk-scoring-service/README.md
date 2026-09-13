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

## Kiểm thử

Chạy từ thư mục gốc của repository:

```powershell
.\mvnw.cmd -f .\risk-scoring-service\pom.xml clean verify
.\mvnw.cmd -f .\keycloak-risk-extension\pom.xml clean verify
```

Để chạy thử luồng local, mở hai terminal tại thư mục gốc. Terminal thứ nhất:

```powershell
docker compose up -d risk-db
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
2026-09-11. Khi thử login end-to-end, phải đăng xuất phiên frontend/Keycloak cũ
hoặc mở cửa sổ riêng tư vì `check-sso` có thể tiếp tục dùng access token hiện hữu
mà không tạo authentication request mới. Đăng nhập bằng tài khoản đã cấu hình
OTP; với mức hoàn thiện feature hiện tại, kết quả bình thường phải là
`STEP_UP_MFA` và màn hình OTP xuất hiện. Nhánh `ALLOW` mới chỉ kiểm thử được ở
unit test cho weighted engine; runtime chưa thể trả `ALLOW` cho đến khi các nguồn
feature bắt buộc có trạng thái `COMPLETE`.

Xác nhận gần nhất ngày 2026-09-11: Risk Service đạt `37/37` test, Keycloak
extension đạt `40/40` test, health local trả `UP` và request evaluation không có
Bearer token bị chặn bằng `401`.

## Chạy local

Từ thư mục gốc, tạo `.env` từ file mẫu, thay các placeholder bằng secret local,
khởi động Risk DB rồi chạy script:

```powershell
Copy-Item .env.example .env
docker compose up -d risk-db
.\run-risk-local.ps1
```

Compose dùng MySQL 8.0.46, user ứng dụng `risk_service`, named volume và cổng host
`127.0.0.1:3307`. Script chỉ nạp các biến cần cho Risk Service và không truyền
MySQL root password vào Java.

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

Risk Service là OAuth2 Resource Server stateless. Endpoint evaluation bắt buộc
Bearer JWT do realm `DoAn` phát hành và kiểm tra đồng thời chữ ký JWKS, issuer,
thời hạn, audience `zerotrust-risk-api`, `azp=zerotrust-risk-caller` và client
role `risk:evaluate`.

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

Device Risk hiện được lấy từ Risk DB. Vì Redis, temporal profile và nguồn network
intelligence chưa được nối, feature data vẫn có trạng thái `INCOMPLETE`. Hệ thống
fail-safe bằng cách yêu cầu MFA:

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
    "TEMPORAL_PROFILE_UNAVAILABLE",
    "AUTHENTICATION_HISTORY_UNAVAILABLE"
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
| Device ID | Cookie `ZT_DEVICE_ID` | Chỉ đọc được | Chưa có bước phát cookie và đăng ký thiết bị sau MFA |
| Device status | HMAC fingerprint và bảng `known_devices` trong MySQL | Thật một phần | Phân loại `MISSING/NEW/PENDING/TRUSTED/REVOKED`; `REVOKED` bị `DENY` |
| Network intelligence | Chưa có provider | Chưa triển khai | Gán factor nội bộ bằng `0`, thêm lý do `NETWORK_INTELLIGENCE_UNAVAILABLE` |
| Temporal profile | Chưa có lịch sử giờ đăng nhập theo user | Chưa triển khai | Gán factor nội bộ bằng `0`, thêm lý do `TEMPORAL_PROFILE_UNAVAILABLE` |
| Authentication history | Chưa có Redis/counter sự kiện login | Chưa triển khai | Gán factor nội bộ bằng `0`, thêm lý do `AUTHENTICATION_HISTORY_UNAVAILABLE` |
| Trọng số/ngưỡng/điểm theo trạng thái device | `application.properties` | Giá trị policy baseline | Là số cấu hình thủ công, chưa được hiệu chỉnh từ dữ liệu thực nghiệm |

Ba factor chưa có provider không được dùng để tạo một điểm thấp giả. Extractor
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
thiếu, sai chữ ký, sai issuer/audience/caller/role và hết hạn. Extension đã được
cài, cấu hình trong flow riêng và phép thử Client Credentials từ container
Keycloak đến Risk API chạy trên MySQL 8.0.46 đã trả `200`. Flow chưa bind; bước tiếp
theo là kiểm tra login qua flow mới, sau đó ghi authentication event để đăng ký
thiết bị sau login/MFA và nối Redis cho failure counter.
