[Mục lục tài liệu](../README.md) · [Trang dự án](../../README.md)

# Kiểm tra trước khi tích hợp thay đổi

> Các lệnh bên dưới chạy từ thư mục gốc repository, trừ khi có chỉ dẫn khác.

## Chạy trên Windows

Cần Java 17 và Node.js 22 (từ 22.13.0). Maven Wrapper tải Maven và các phụ thuộc
khi chạy lần đầu. Cài phụ thuộc frontend theo lockfile:

```powershell
Push-Location frontend
npm ci
Pop-Location
```

Chạy toàn bộ kiểm tra từ thư mục gốc:

```powershell
.\verify-project.ps1
```

Có thể chọn `-Scope Backend` hoặc `-Scope Frontend`. Script dừng và trả lỗi
khi một bước thất bại. Không cần secret production, Keycloak, MySQL hoặc Redis
đang chạy cho các bộ test hiện tại: test dùng H2 và các thành phần giả lập.

## Kiểm tra tự động trên GitHub

Workflow `.github/workflows/ci.yml` chạy khi push, mở/cập nhật pull request hoặc
được chạy thủ công. Ba module Java chạy riêng trên Java 17; frontend cài bằng
`npm ci`, chạy ESLint và TypeScript trên Node.js 22. Các job chỉ có quyền đọc
repository và không dùng secret triển khai. Báo cáo Java được giữ bảy ngày,
kể cả khi test thất bại.

Đây là kiểm tra mã và các bài test tự động hiện có. Workflow chưa bao gồm build
frontend, kiểm thử trình duyệt, môi trường Keycloak thật hoặc triển khai.
Một workflow được thêm ở local chỉ bắt đầu chạy trên GitHub sau khi được push.
Branch protection phải được cấu hình riêng nếu muốn bắt buộc các kiểm tra trước merge.

## Mốc kiểm tra ngày 2026-09-30

Script `verify-project.ps1` đã chạy đạt tại local: Portal 180 test, Risk Service 119 test,
Keycloak extension 68 test; ESLint và TypeScript đạt. Workflow đã kiểm tra cú pháp YAML,
chưa chạy trên GitHub. Các số này là mốc tham chiếu,
không phải assertion về số test cố định trong CI.

Các thay đổi MFA recovery, Geo-IP và giao diện đang có trong working tree cần
được rà soát và lưu thành các commit theo chức năng. Không chỉ đưa các file mới
của workflow vào commit rồi giả định rằng CI đang kiểm tra toàn bộ mã local.

## Mốc kiểm tra Risk ngày 2026-10-05

Sau sửa chuẩn hóa IP blocklist/counter, toàn suite Risk chạy đạt **182 test**,
không failure/error/skip. Test mục tiêu đã bắt regression trước khi sửa và đạt
sau sửa. Môi trường Java 17, Maven offline, H2/mock; nhóm JWT dùng JWKS loopback
giả lập. Lệnh thực chạy từ gốc:

```powershell
.\mvnw.cmd --offline --batch-mode --no-transfer-progress -f risk-scoring-service/pom.xml '-DargLine=-javaagent:C:/Users/DELL/.m2/repository/net/bytebuddy/byte-buddy-agent/1.17.8/byte-buddy-agent-1.17.8.jar' test
```

Đường dẫn agent là máy kiểm tra, không phải cấu hình bắt buộc trên máy khác.
Agent được nạp trước để tránh Mockito tự attach bị chặn; sandbox cần cho phép
loopback để test JWKS chạy. Mốc này không xác nhận Portal/SPI suite hoặc
Keycloak/MySQL/Redis production. Lần rà tài liệu tiếp theo không chạy lại backend.

## Thứ tự các đợt tiếp theo

1. Kiểm chứng staging reset MFA/device trust đã có mã: caller riêng, Flyway V4,
   flow post-MFA, partial failure, expiry/rotation và race registration/reset.
2. Kiểm soát token/SSO và yêu cầu MFA còn mới cho thao tác admin.
3. Lưu quyết định rủi ro, phiên bản policy và kiểm chứng các nhánh runtime;
   hiệu chỉnh policy bằng dữ liệu được phê duyệt.
4. Migration Portal DB, cấu hình triển khai, giám sát, backup/restore và retention.
