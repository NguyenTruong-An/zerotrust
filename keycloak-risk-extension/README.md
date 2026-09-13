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

## Đóng gói và cài lại vào Keycloak local

Quy trình dưới đây áp dụng cho container development hiện tại
`keycloak-26.7.0`. Chạy các lệnh PowerShell từ thư mục gốc repository.

### 1. Kiểm tra đúng Java và phiên bản Keycloak

```powershell
java -version
.\mvnw.cmd -version
```

Extension compile bằng Java 17 và Keycloak 26.7.0. Phiên bản dependency trong
`pom.xml` phải khớp image Keycloak đang chạy.

### 2. Chạy test và tạo JAR sạch

```powershell
.\mvnw.cmd -f .\keycloak-risk-extension\pom.xml clean verify
```

`clean` xóa artifact cũ, `verify` compile, chạy test và package. Build chỉ thành
công khi lệnh trả exit code 0.

### 3. Kiểm tra artifact trước khi cài

```powershell
Get-Item .\keycloak-risk-extension\target\keycloak-risk-extension.jar
jar tf .\keycloak-risk-extension\target\keycloak-risk-extension.jar |
    Select-String "META-INF/services|RiskAuthenticatorFactory|RiskStepUpConditionFactory"
Get-FileHash .\keycloak-risk-extension\target\keycloak-risk-extension.jar -Algorithm SHA256
```

JAR hợp lệ phải có file ServiceLoader
`META-INF/services/org.keycloak.authentication.AuthenticatorFactory` và class
của cả hai factory. Đây là regular provider JAR; không chạy bằng `java -jar`.

### 4. Xác định chế độ khởi động container

```powershell
docker inspect keycloak-26.7.0 --format '{{json .Config.Cmd}}'
```

Nếu container dùng `start-dev` hoặc `start` không có `--optimized`, có thể dùng
cách copy nhanh ở bước 5. Nếu dùng `start --optimized`, phải build custom image
theo phần tiếp theo; provider mới cần được đưa vào trước `kc.sh build`.

### 5. Copy JAR và restart container development

```powershell
$providerJar = (Resolve-Path .\keycloak-risk-extension\target\keycloak-risk-extension.jar).Path
docker cp $providerJar keycloak-26.7.0:/opt/keycloak/providers/keycloak-risk-extension.jar
docker restart keycloak-26.7.0
docker logs --since 2m keycloak-26.7.0
```

Không hot-deploy provider khi Keycloak đang chạy. Restart cho non-optimized
startup thực hiện lại bước augmentation và nạp provider mới. Log phải hoàn tất
startup mà không có lỗi provider, split-package hoặc `ClassNotFoundException`.

### 6. Xác nhận provider trong Admin Console

Trong realm `DoAn`, vào **Authentication -> Flows** rồi bấm vào tên flow tùy
chỉnh `zerotrust-browser`. Trang danh sách flow chỉ có thao tác tạo/nhân bản nên
không hiện nút `Add step`. Flow built-in `browser` cũng không chỉnh sửa trực
tiếp; nếu chưa có flow tùy chỉnh thì dùng menu ba chấm của `browser` để
`Duplicate` trước.

Trong trang chi tiết `zerotrust-browser`, `Add step` có thể nằm ở hàng nút phía
trên hoặc trong menu dấu `+` ở cuối dòng flow/subflow, tùy vị trí cần thêm và độ
rộng màn hình. Khi mở danh sách authenticator, phải có:

```text
ZeroTrust Risk Evaluation
Condition - ZeroTrust step-up required
```

Hai tên này đến từ `getDisplayType()` của hai factory. Nếu không xuất hiện, kiểm
tra lại JAR, file ServiceLoader, phiên bản Keycloak và log khởi động.

### 7. Tạo hoặc kiểm tra Authentication Flow

Flow `zerotrust-browser` phải có đúng thứ tự:

```text
Username Password Form                         REQUIRED
ZeroTrust Risk Evaluation                     REQUIRED
Risk step-up MFA                              CONDITIONAL
  Condition - ZeroTrust step-up required      REQUIRED
  OTP Form                                    REQUIRED
```

Để thêm execution ở top level, dùng `Add step` của trang chi tiết flow. Để thêm
condition hoặc OTP vào `Risk step-up MFA`, bấm dấu `+` ở cuối chính dòng subflow
đó rồi chọn `Add condition` hoặc `Add step`; nút ở top level sẽ thêm sai cấp.

Cấu hình execution `ZeroTrust Risk Evaluation` cho topology local hiện tại:

```text
Risk Service base URL:
  http://host.docker.internal:8081
Keycloak token endpoint URL:
  http://localhost:8080/realms/DoAn/protocol/openid-connect/token
Risk caller client ID:
  zerotrust-risk-caller
Risk caller client secret:
  secret hiện tại của zerotrust-risk-caller
Token refresh skew:
  30000 ms
Failure mode:
  DENY
```

Sau đó bind `zerotrust-browser` làm Browser Flow của realm `DoAn`. Cấu hình flow
được lưu trong database Keycloak; cập nhật JAR không yêu cầu tạo lại flow nếu
provider ID và các config key không đổi.

### 8. Chạy các service phụ thuộc và thử end-to-end

```powershell
docker compose up -d risk-db
.\run-risk-local.ps1
```

Logout khỏi SPA và Keycloak hoặc mở cửa sổ riêng tư, rồi login lại. Với extractor
hiện tại, kết quả bình thường là `STEP_UP_MFA`, nên OTP Form phải xuất hiện. OTP
đúng thì Keycloak phát token; `DENY` hoặc lỗi Risk Service với
`failureMode=DENY` phải chặn login.

## Đóng gói Keycloak image bền vững

`docker cp` chỉ thay đổi filesystem của một container cụ thể. Xóa rồi tạo lại
container sẽ làm mất JAR. Cách dùng lâu dài là COPY provider vào image trước khi
chạy `kc.sh build`:

```dockerfile
FROM quay.io/keycloak/keycloak:26.7.0 AS builder

COPY --chown=keycloak:keycloak --chmod=644 \
  keycloak-risk-extension/target/keycloak-risk-extension.jar \
  /opt/keycloak/providers/keycloak-risk-extension.jar

RUN touch -m --date=@1743465600 /opt/keycloak/providers/*
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:26.7.0
COPY --from=builder /opt/keycloak/ /opt/keycloak/
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
```

Build image sau khi Maven đã tạo JAR:

```powershell
docker build -t zerotrust-keycloak:26.7.0-with-risk -f .\Dockerfile.keycloak .
```

`compose.yaml` hiện chỉ khai báo Risk DB, chưa khai báo Keycloak. Vì vậy build
image mới chưa tự thay container `keycloak-26.7.0`. Trước khi chuyển container
hiện tại sang image này, cần đưa đầy đủ database/volume, port, hostname và biến
môi trường Keycloak vào Compose; không xóa container đang giữ dữ liệu realm khi
chưa xác nhận dữ liệu đã nằm trong database hoặc volume bền vững.

Container production khởi động image này bằng `start --optimized` cùng cấu hình
database, hostname, TLS và secret của môi trường. Nếu database provider cần build
option riêng, đặt `KC_DB` hoặc truyền option đó trong builder stage trước
`kc.sh build`.

Tài liệu chính thức của Keycloak về provider và container:

- https://www.keycloak.org/server/configuration-provider
- https://www.keycloak.org/server/containers

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

Trước mỗi evaluation, extension dùng confidential client
`zerotrust-risk-caller` và grant `client_credentials` để lấy access token. Token
được cache, làm mới trước hạn 30 giây và gắn vào request bằng
`Authorization: Bearer`. Khi Risk API trả `401`, token hiện tại bị xóa và request
được thử lại đúng một lần với token mới. Client secret, access token và response
lỗi của token endpoint không được ghi log.

Giá trị mặc định riêng cho request đánh giá rủi ro:

```text
connection-pool wait timeout: 500 mili giây
connect timeout: 2 giây
socket timeout: 3 giây
response tối đa: 64 KiB
```

Factory inject HTTP provider và token provider theo `KeycloakSession`:

```java
var httpProvider = session.getProvider(HttpClientProvider.class);
var tokenProvider = new ClientCredentialsTokenProvider(
        httpProvider, tokenConfig, riskConfig, sharedTokenCache);
RiskScoringClient client = new HttpRiskScoringClient(
        httpProvider, riskConfig, tokenProvider);
```

Execution cần cấu hình Risk Service base URL, realm token endpoint, client ID và
client secret của `zerotrust-risk-caller`. Trường secret dùng kiểu Password/secret
trong Keycloak Admin Console. Chi tiết từng giá trị và cấu hình production nằm
trong `../RISK_API_SECURITY.md`.

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

JAR chứa hai factory trong
`META-INF/services/org.keycloak.authentication.AuthenticatorFactory` và đã được
chép vào `/opt/keycloak/providers/` của container local `keycloak-26.7.0` ngày
2026-09-09. Log khởi động xác nhận Keycloak đã nạp cả hai provider. Flow riêng
`zerotrust-browser` đã được tạo, cấu hình Risk Evaluation và conditional OTP đầy
đủ và đã được bind làm Browser Flow của realm `DoAn` ngày 2026-09-11.

Phép thử từ container Keycloak đã lấy token Client Credentials và gọi thành công
Risk API chạy trên host với Risk DB MySQL 8.0.46: token endpoint trả `200`, evaluation
trả `200` với `STEP_UP_MFA / MEDIUM`; request thiếu token bị chặn bằng `401`. Đây
là phép thử kết nối service-to-service. Cần chạy login qua flow mới để xác nhận
toàn bộ nhánh Authenticator và OTP. Phải logout phiên SPA/Keycloak cũ hoặc dùng
cửa sổ riêng tư để tạo authentication request mới; `check-sso` có thể tiếp tục
dùng token hiện hữu mà không chạy lại flow.

Phần bảo vệ service-to-service đã hoàn tất trong code. Chưa triển khai production
cho đến khi luồng đăng nhập end-to-end được kiểm tra, endpoint dùng TLS/mạng nội
bộ và cơ chế đăng ký thiết bị sau MFA được hoàn thành.
