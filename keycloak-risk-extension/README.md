# Keycloak Risk Extension

Keycloak Authentication SPI kết nối Browser Authentication Flow với
`risk-scoring-service`.

Module này là thư viện provider chạy bên trong Keycloak, không phải Spring Boot
service và không chạy bằng `java -jar`.

## Phiên bản

Extension compile với Keycloak `26.7.0`, khớp image local hiện tại:

```text
quay.io/keycloak/keycloak:26.7.0
```

Các dependency Keycloak dùng scope `provided`: chúng chỉ phục vụ compile và
không bị đóng gói lặp lại vào provider JAR.

## Build

Chạy từ thư mục gốc repository:

```powershell
.\mvnw.cmd -f .\keycloak-risk-extension\pom.xml clean verify
```

JAR được tạo tại:

```text
keycloak-risk-extension/target/keycloak-risk-extension.jar
```

## Risk Service client

Module hiện đã có HTTP client độc lập để gọi:

```text
POST {risk-service-base-url}/internal/v1/risk/evaluations
```

`RiskEvaluationRequest` chỉ chứa login context thô. Client kiểm tra status HTTP,
content type JSON, timeout, giới hạn response tối đa và bảo đảm `subjectId` cùng
`authenticationSessionId` trong response khớp request. Lỗi kết nối được phân loại
qua `RiskScoringClientException`; Authenticator áp dụng failure mode đã cấu hình.

Client không tự tạo hoặc đóng connection pool. Nó nhận `HttpClientProvider` do
Keycloak quản lý để dùng chung pool, proxy và truststore của server.

Giá trị mặc định riêng cho request đánh giá rủi ro:

```text
connection-pool wait timeout: 500 mili giây
connect timeout: 2 giây
socket timeout: 3 giây
response tối đa: 64 KiB
```

Factory inject provider theo `KeycloakSession`:

```java
var config = RiskScoringClientConfig.defaults(URI.create("http://localhost:8081"));
var httpProvider = session.getProvider(HttpClientProvider.class);
RiskScoringClient client = new HttpRiskScoringClient(httpProvider, config);
```

## Authentication decision flow

`RiskAuthenticator` chạy sau primary authentication, lấy các tín hiệu do
Keycloak quan sát được và gọi Risk Service:

```text
UserModel.id
Root authentication session ID + tab ID
ClientModel.clientId
ClientConnection.remoteAddr
User-Agent
ZT_DEVICE_ID cookie (nếu hợp lệ)
```

Không đọc trực tiếp `X-Forwarded-For`; IP được lấy từ `ClientConnection` để tuân
theo cấu hình proxy tin cậy của Keycloak.

Quyết định được xử lý như sau:

```text
ALLOW       -> hoàn thành execution
STEP_UP_MFA -> ghi auth-note và hoàn thành execution
DENY        -> dừng flow bằng ACCESS_DENIED
```

`RiskStepUpCondition` đọc auth-note để quyết định có chạy conditional subflow OTP
hay không. Risk Authenticator không tự gọi hoặc tự xác minh OTP.

Khi Risk Service lỗi, mặc định `failureMode=DENY` để fail-closed. Có thể cấu hình
`STEP_UP_MFA` cho môi trường chấp nhận fallback sang MFA.

Cookie `ZT_DEVICE_ID` chỉ là tín hiệu nhận diện, không phải bằng chứng xác thực và
không được dùng thay password/MFA. Milestone hiện tại mới đọc cookie; cơ chế cấp
cookie và đăng ký thiết bị tin cậy sau khi MFA thành công chưa được triển khai.

## Trạng thái tích hợp

JAR đã chứa hai factory trong
`META-INF/services/org.keycloak.authentication.AuthenticatorFactory`, nhưng chưa
được chép vào thư mục `providers/`. Browser Authentication Flow và container
Keycloak hiện tại chưa bị thay đổi.

Chưa triển khai production khi endpoint `/internal` của Risk Service chưa có bảo
vệ service-to-service và chưa hoàn thành cơ chế đăng ký thiết bị sau MFA.
