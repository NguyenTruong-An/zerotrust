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
.\mvnw.cmd -f .\risk-scoring-service\pom.xml test
```

## Chạy local

```powershell
.\mvnw.cmd -f .\risk-scoring-service\pom.xml spring-boot:run
```

Service mặc định chạy tại `http://localhost:8081`. Kiểm tra trạng thái:

```text
GET http://localhost:8081/actuator/health
```

Có thể đổi cổng bằng biến môi trường `RISK_SERVICE_PORT`.

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

Danh sách IP bị chặn có thể cấu hình bằng biến môi trường, phân cách bằng dấu phẩy:

```powershell
$env:RISK_BLOCKED_IP_ADDRESSES="203.0.113.10,198.51.100.20"
```

IP thuộc danh sách này bị `DENY` bởi Priority Security Rule trước khi feature
extraction và weighted scoring chạy.

Hiện tại request từ Postman vẫn có thể giả mạo login context vì OAuth2
service-to-service chưa được thêm. Không expose endpoint `/internal` ra Internet.
Bước tiếp theo là ghi authentication event để đăng ký thiết bị sau login/MFA thành
công, sau đó nối Redis cho failure counter và bảo vệ endpoint trước khi tích hợp
Keycloak extension.
