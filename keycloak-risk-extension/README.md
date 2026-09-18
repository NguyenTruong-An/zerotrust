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
    Select-String "META-INF/services|RiskAuthenticatorFactory|RiskStepUpConditionFactory|TrustedDeviceRegistrationAuthenticatorFactory|RiskEventListenerFactory"
Get-FileHash .\keycloak-risk-extension\target\keycloak-risk-extension.jar -Algorithm SHA256
```

JAR hợp lệ phải có file ServiceLoader
`META-INF/services/org.keycloak.authentication.AuthenticatorFactory` và class
của cả ba authenticator factory. JAR cũng phải có
`META-INF/services/org.keycloak.events.EventListenerProviderFactory` và
`RiskEventListenerFactory`. Đây là regular provider JAR; không chạy bằng
`java -jar`.

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
ZeroTrust Remember Device after MFA
```

Ba tên này đến từ `getDisplayType()` của ba factory. Nếu không xuất hiện, kiểm
tra lại JAR, file ServiceLoader, phiên bản Keycloak và log khởi động.

### 7. Tạo hoặc kiểm tra Authentication Flow

Flow `zerotrust-browser` phải có đúng thứ tự:

```text
Username Password Form                         REQUIRED
ZeroTrust Risk Evaluation                     REQUIRED
Risk step-up MFA                              CONDITIONAL
  Condition - ZeroTrust step-up required      REQUIRED
  OTP Form                                    REQUIRED
ZeroTrust Remember Device after MFA           REQUIRED
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
Monitored login client ID:
  zerotrust-spa
```

Sau đó bind `zerotrust-browser` làm Browser Flow của realm `DoAn`. Cấu hình flow
được lưu trong database Keycloak; cập nhật JAR không yêu cầu tạo lại flow nếu
provider ID và các config key không đổi.

### 8. Chạy các service phụ thuộc và thử end-to-end

```powershell
docker compose up -d risk-db risk-redis
.\run-risk-local.ps1
```

Logout khỏi SPA và Keycloak hoặc mở cửa sổ riêng tư, rồi login lại. Với extractor
hiện tại, kết quả bình thường là `STEP_UP_MFA`, nên OTP Form phải xuất hiện. OTP
đúng thì execution sau MFA gọi endpoint trusted-device; chỉ khi API trả `204`,
Keycloak mới phát cookie `ZT_DEVICE_ID`. `DENY` hoặc lỗi Risk Service ở bước đánh
giá với `failureMode=DENY` phải chặn login.

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

`compose.yaml` hiện khai báo Risk DB và Redis, chưa khai báo Keycloak. Vì vậy build
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
POST {risk-service-base-url}/internal/v1/trusted-devices
POST {risk-service-base-url}/internal/v1/authentication-failures
POST {risk-service-base-url}/internal/v1/authentication-successes
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

Khi Risk API thật sự trả `STEP_UP_MFA`, evaluator ghi thêm auth-note cho phép nhớ
thiết bị và ID của chính cấu hình execution evaluator. Sau OTP, execution
`ZeroTrust Remember Device after MFA` dùng ID này để đọc lại URL/client secret,
vì vậy không cần lưu thêm một bản secret trong flow. Nếu chưa có cookie hợp lệ,
extension sinh device ID ngẫu nhiên 256 bit. Nó gọi
`POST /internal/v1/trusted-devices` bằng cùng service token rồi chỉ phát cookie
khi API trả `204`.

Khi Risk Service lỗi, mặc định `failureMode=DENY` để fail-closed. Có thể cấu hình
`STEP_UP_MFA` cho môi trường chấp nhận fallback sang MFA.

Cookie `ZT_DEVICE_ID` có thời hạn 30 ngày, scope theo realm, `HttpOnly`,
`SameSite=Lax` và dùng cờ `Secure` khi Keycloak nhận diện secure context. Cookie
chỉ là định danh ngẫu nhiên; Risk Service lưu HMAC của `subjectId + deviceId`,
không lưu raw device ID. Nó không phải bằng chứng xác thực và không được dùng thay
password/MFA.

Nếu thao tác ghi trusted device lỗi sau khi OTP đã đúng, login hiện tại vẫn được
phép nhưng cookie mới không được phát; lần sau user phải MFA lại. Đây là failure
mode an toàn cho một chức năng ghi nhớ thiết bị: không hạ mức xác thực và không
làm Risk Service trở thành single point of failure sau khi MFA đã hoàn tất. Nếu
API trả `409` vì device đã revoke, extension phát cookie hết hạn để browser bỏ ID
bị từ chối.

## Authentication Event Listener

`RiskEventListenerFactory` đăng ký provider ID `zerotrust-risk-events` qua
`META-INF/services/org.keycloak.events.EventListenerProviderFactory`. Sau khi JAR
được nạp, thêm provider này vào **Realm settings -> Events -> Event listeners**
và giữ lại các listener đã có, ví dụ `jboss-logging`.

Listener chỉ xử lý `LOGIN_ERROR` và `LOGIN` của client cấu hình trong execution `ZeroTrust
Risk Evaluation`; mặc định là `zerotrust-spa`. `BrowserFlowRiskConfigLocator` đi
qua Browser Flow và các subflow để đọc lại chính URL, client ID/secret, timeout
của evaluator, vì vậy không có bản secret thứ hai trong cấu hình realm. Sự kiện
của Admin Console và client khác bị bỏ qua.

Mỗi event hợp lệ gửi `eventId`, `subjectId` nếu Keycloak đã nhận diện được user và
`sourceIp` tới `POST /internal/v1/authentication-failures`. HTTP client dùng cùng
service-token cache và cơ chế refresh/retry 401 với các endpoint còn lại. Risk API
chỉ chấp nhận token có `risk:events:write`.

Với `LOGIN`, listener gửi `eventId`, `subjectId`, `clientId` và thời điểm event do
Keycloak phát tới `POST /internal/v1/authentication-successes`. `Instant` được khóa
thành chuỗi ISO-8601 trong JSON để không phụ thuộc cấu hình serializer của
Keycloak. Event thiếu subject hoặc thời gian hợp lệ bị bỏ qua.

Đây là telemetry sau kết quả xác thực, nên lỗi cấu hình, token, network hoặc Risk
Service chỉ được log bằng loại lỗi/status an toàn và không thay đổi kết quả login.
Failure counter được cập nhật trong Redis bằng Lua/idempotency; success event được
ghi idempotent trong MySQL; listener không kết nối trực tiếp tới hai data store.

## Trạng thái tích hợp

JAR chứa ba authenticator factory trong
`META-INF/services/org.keycloak.authentication.AuthenticatorFactory` và một event
  listener factory trong file ServiceLoader riêng. Bản build 66/66 test đã được
chép vào `/opt/keycloak/providers/` của container local `keycloak-26.7.0` ngày
  2026-09-17. Checksum JAR local và trong container trùng nhau; log khởi động xác
  nhận Keycloak đã nạp cả bốn provider. Flow riêng
`zerotrust-browser` đã được bổ sung execution post-MFA ở đúng cấp sau conditional
OTP và đặt `REQUIRED`; flow vẫn được bind làm Browser Flow của realm `DoAn`.

Phép thử từ container Keycloak đã lấy token Client Credentials và gọi thành công
Risk API chạy trên host với Risk DB MySQL 8.0.46: token endpoint trả `200`,
evaluation trả `200` với `STEP_UP_MFA / MEDIUM`; request thiếu token bị chặn bằng
`401`.

Luồng đăng nhập end-to-end được xác nhận ngày 2026-09-16: Portal chuyển tới
Keycloak, risk evaluation yêu cầu OTP, OTP thành công, post-MFA registration trả
thành công và Portal mở trang `/admin`. Lần đăng nhập thứ hai trên cùng browser
vẫn chỉ có một row `TRUSTED` trong `known_devices`; `last_seen_at` tiến lên và
`version` tăng từ 1 lên 2. Điều này xác nhận browser gửi lại cùng
`ZT_DEVICE_ID` và thao tác đăng ký là idempotent.

Phần bảo vệ service-to-service và cơ chế đăng ký/cookie sau MFA đã hoàn tất trong
code, flow local và phép thử end-to-end. Realm hiện bật đồng thời
`jboss-logging` và `zerotrust-risk-events`; token caller chứa đủ ba role Risk API.
Một lần sai mật khẩu thật đã tạo đúng một event marker, một counter subject và một
counter IP trong Redis. Risk Service hiện đã đọc hai counter, ánh xạ chúng thành
`Authentication History Risk` và lấy mức cao hơn để tránh tính hai lần cùng một
failure event. Phép thử với ba lần sai mật khẩu đã tạo reason
`AUTHENTICATION_HISTORY_RISK`. Listener hiện cũng thu `LOGIN` thành công làm dữ
liệu nguồn cho Temporal Profile. Thiết bị `TRUSTED` vẫn phải OTP vì network và
phép tính temporal chưa hoàn thiện, làm evaluation còn `INCOMPLETE`. Chưa triển khai
production cho đến khi endpoint dùng TLS/mạng nội bộ, Keycloak có canonical
hostname/issuer và các nhánh failure/deny được kiểm thử đầy đủ.

Phép thử runtime ngày 2026-09-17 đăng nhập thật qua Authorization Code + PKCE,
password và OTP, sau đó Portal mở `/admin`. Event Listener đã tạo đúng một row cho
client `zerotrust-spa` trong `authentication_success_events`; `event_id` và subject
đều là UUID 36 ký tự, hai timestamp đều có giá trị và không có lỗi telemetry trong
log Keycloak.
