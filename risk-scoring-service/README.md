# Risk Scoring Service

Spring Boot service độc lập chịu trách nhiệm đánh giá rủi ro đăng nhập cho
ZeroTrust Academic Portal.

## Yêu cầu

- Java 17
- Maven Wrapper của repository

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

Vì Risk DB, Redis và nguồn network intelligence chưa được nối ở milestone này,
feature data có trạng thái `INCOMPLETE`. Hệ thống fail-safe bằng cách yêu cầu MFA:

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
    "DEVICE_HISTORY_UNAVAILABLE",
    "NETWORK_INTELLIGENCE_UNAVAILABLE",
    "TEMPORAL_PROFILE_UNAVAILABLE",
    "AUTHENTICATION_HISTORY_UNAVAILABLE"
  ],
  "evaluatedAt": "2026-09-04T08:00:00Z"
}
```

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
Bước tiếp theo là nối Risk DB cho device history, Redis cho failure counter và bảo
vệ endpoint trước khi tích hợp Keycloak extension.
