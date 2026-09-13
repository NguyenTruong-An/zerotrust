# Chạy ZeroTrust Portal trên máy local

Ứng dụng gồm bốn phần cần chạy độc lập:

1. MySQL cho Portal DB.
2. Keycloak tại `http://localhost:8180`.
3. Spring Boot API tại `http://localhost:8080` và frontend SPA tại `http://localhost:3000`.
4. Risk Scoring Service tại `http://localhost:8081` với profile `dev` khi chạy local.

File `compose.yaml` hiện dựng riêng Risk DB; Portal DB, Keycloak, backend và
frontend vẫn được chạy độc lập.

## 1. Chuẩn bị Keycloak

Trong realm `DoAn`, cấu hình client public `zerotrust-spa`, audience mapper
`zerotrust-api`, realm roles `ADMIN`/`STUDENT` và client service account
`zerotrust-provisioner` theo mục 10 của `LOGIN_FLOW.md`. Kết nối Risk API dùng hai
client riêng `zerotrust-risk-api` và `zerotrust-risk-caller` theo
`RISK_API_SECURITY.md`.

## 2. Chạy backend

Yêu cầu Java 17, Maven Wrapper, MySQL và Keycloak đang hoạt động. Trong PowerShell tại thư mục gốc:

```powershell
$env:DB_PASSWORD="mat-khau-mysql"
$env:KEYCLOAK_ADMIN_CLIENT_SECRET="secret-cua-zerotrust-provisioner"
.\mvnw.cmd spring-boot:run
```

Các giá trị local mặc định:

```text
DB_URL=jdbc:mysql://localhost:3306/vip_pro?createDatabaseIfNotExist=true&...
DB_USERNAME=root
KEYCLOAK_URL=http://localhost:8180
KEYCLOAK_ISSUER_URI=http://localhost:8180/realms/DoAn
CORS_ALLOWED_ORIGINS=http://localhost:3000
```

Nếu dùng URL/realm khác, đặt thêm các biến trong `src/main/resources/application.properties` tương ứng.

## 3. Chạy frontend

Yêu cầu Node.js từ 22.13.0. Mở terminal khác:

```powershell
Set-Location frontend
Copy-Item .env.example .env.local
npm install
npm run dev
```

Mở `http://localhost:3000`. Frontend gọi API trực tiếp ở port 8080; không còn proxy `/api`, `/oauth2` hay `/login` qua frontend dev server.

Nếu dependency đã cài xong, các lần sau chỉ cần:

```powershell
Set-Location frontend
npm run dev
```

## 4. Chạy Risk Scoring Service

Với Keycloak chạy trong Docker ở cổng publish `8180` và Risk Service chạy trên
Windows, chuẩn bị lần đầu bằng:

```powershell
Copy-Item .env.example .env
# Thay mọi placeholder trong .env bằng secret ngẫu nhiên riêng cho máy local.
docker compose up -d risk-db
.\run-risk-local.ps1
```

Máy đã được cấu hình trong phiên hiện tại có `.env` sinh ngẫu nhiên và bị Git bỏ
qua, nên các lần sau chỉ cần hai lệnh cuối. Risk DB dùng user `risk_service`, lưu
dữ liệu trong named volume và chỉ publish `127.0.0.1:3307`.

Kiểm tra `GET http://localhost:8081/actuator/health`. Chi tiết vì sao issuer dùng
cổng nội bộ `8080` nhưng JWKS dùng cổng host `8180` nằm trong
`RISK_API_SECURITY.md`.

## 5. Chạy kiểm thử

Backend:

```powershell
.\mvnw.cmd test
```

Frontend:

```powershell
Set-Location frontend
npm run lint
npm run build
```

Risk Service và Keycloak extension:

```powershell
.\mvnw.cmd -f .\risk-scoring-service\pom.xml clean verify
.\mvnw.cmd -f .\keycloak-risk-extension\pom.xml clean verify
```

## 6. Lỗi thường gặp

- Keycloak báo `invalid_redirect_uri`: kiểm tra Valid Redirect URIs và URL trong `.env.local`.
- API trả 401 dù đã login: kiểm tra `iss`, thời gian máy, chữ ký và đặc biệt audience `zerotrust-api` trong access token.
- API trả 403: token hợp lệ nhưng thiếu realm role `ADMIN` hoặc `STUDENT`.
- Browser báo CORS: `CORS_ALLOWED_ORIGINS` backend phải khớp chính xác origin frontend, không có path và không có dấu `/` cuối.
- Reload liên tục hoặc check SSO lỗi: thêm `http://localhost:3000/silent-check-sso.html` vào Valid Redirect URIs.
- Tạo sinh viên lỗi 503/502: kiểm tra client secret và service-account role của `zerotrust-provisioner`; đây là client backend riêng, không phải `zerotrust-spa`.
- Risk Service không kết nối được Risk DB: chạy `docker compose up -d risk-db`,
  kiểm tra `.env` và xác nhận container `zerotrust-risk-db` healthy.
- Extension không gọi được `localhost:8081`: bên trong container, dùng
  `http://host.docker.internal:8081` và đặt `RISK_BIND_ADDRESS=0.0.0.0` cho môi
  trường local.
- Token hợp lệ nhưng Risk API trả 401 do issuer: issuer phải khớp URL token
  endpoint mà extension thực sự gọi; topology Docker local hiện dùng cổng nội bộ
  `8080`.
- Risk Service lỗi `Invalid URI syntax: ${RISK_JWT_ISSUER_URI}` khi bấm Run trong
  IntelliJ: đặt `SPRING_PROFILES_ACTIVE=dev` và
  `SPRING_CONFIG_IMPORT=optional:file:<repository-root>/.env[.properties]` trong
  Run Configuration. Cách đơn giản hơn là chạy `./run-risk-local.ps1` từ thư mục
  gốc.
- Portal Backend lỗi `Port 8080 was already in use`: kiểm tra PID bằng
  `netstat -ano | Select-String ':8080\s+.*LISTENING'`, sau đó dừng đúng instance
  backend cũ bằng `Stop-Process -Id <PID>`. Không đổi cổng tùy ý vì frontend local
  đang gọi API tại `http://localhost:8080`.
- `UnsupportedClassVersionError` với class version `61.0` và runtime `52.0`:
  lệnh `java` đang trỏ tới Java 8. Chạy `java -version` và `mvn -version`, rồi đặt
  `JAVA_HOME`/`PATH` về JDK 17 trước khi khởi động service.

Đọc `CODE_FLOW_WALKTHROUGH.md` trước để đi theo toàn bộ call stack từ frontend,
Keycloak SPI, Risk Service đến API xem điểm. `LOGIN_FLOW.md` tập trung vào PKCE,
refresh token, CORS và logout.
