# Chạy ZeroTrust Portal trên máy local

Ứng dụng gồm ba phần cần chạy độc lập:

1. MySQL cho Portal DB.
2. Keycloak tại `http://localhost:8180`.
3. Spring Boot API tại `http://localhost:8080` và frontend SPA tại `http://localhost:3000`.

File `compose.yaml` hiện chưa khai báo service, vì vậy chưa thể dùng `docker compose up` để dựng toàn bộ hệ thống.

## 1. Chuẩn bị Keycloak

Trong realm `DoAn`, cấu hình client public `zerotrust-spa`, audience mapper `zerotrust-api`, realm roles `ADMIN`/`STUDENT` và client service account `zerotrust-provisioner` theo mục 10 của `LOGIN_FLOW.md`.

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

## 4. Chạy kiểm thử

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

## 5. Lỗi thường gặp

- Keycloak báo `invalid_redirect_uri`: kiểm tra Valid Redirect URIs và URL trong `.env.local`.
- API trả 401 dù đã login: kiểm tra `iss`, thời gian máy, chữ ký và đặc biệt audience `zerotrust-api` trong access token.
- API trả 403: token hợp lệ nhưng thiếu realm role `ADMIN` hoặc `STUDENT`.
- Browser báo CORS: `CORS_ALLOWED_ORIGINS` backend phải khớp chính xác origin frontend, không có path và không có dấu `/` cuối.
- Reload liên tục hoặc check SSO lỗi: thêm `http://localhost:3000/silent-check-sso.html` vào Valid Redirect URIs.
- Tạo sinh viên lỗi 503/502: kiểm tra client secret và service-account role của `zerotrust-provisioner`; đây là client backend riêng, không phải `zerotrust-spa`.

Đọc `LOGIN_FLOW.md` để xem chi tiết code flow, refresh token, CORS và logout.
