[Mục lục tài liệu](../README.md) · [Trang dự án](../../README.md)

# Kiểm tra trước khi tích hợp thay đổi

> Các lệnh bên dưới chạy từ thư mục gốc repository, trừ khi có chỉ dẫn khác.

## Mốc kiểm tra ngày 2026-10-27 — hệ thống xem điểm ADMIN/STUDENT

Theo yêu cầu trực tiếp của chủ đồ án, source đã gỡ Teacher, phân công giảng dạy và
lịch học; giữ phần xem/nhập điểm, JWT, Gateway, Keycloak, MFA và Risk. Kết quả chạy
trong lượt thay đổi này:

| Phạm vi | Kết quả |
|---|---|
| Portal `clean test` | **324 test**, 0 failure/error/skip; gồm 7 đường dẫn API đã gỡ trả 404 trong full application context |
| Gateway `clean test` | **20 test**, 0 failure/error/skip; token chỉ có role cũ TEACHER bị từ chối tại Admin API và API điểm Student |
| Demo fixtures | **3 test**; realm chỉ có ADMIN/STUDENT, dữ liệu mẫu chỉ dùng năm bảng học vụ, input Teacher cũ không tạo user/bảng mới |
| Legacy Compose | **3 test**; cấu hình portable và graph khởi động giữ nguyên ranh giới; job School chỉ đọc, không còn migration tạo Teacher |
| Frontend | ESLint 0 lỗi (1 warning có sẵn ở `postcss.config.mjs`), TypeScript và Next production build đạt; không còn route `/teacher` hoặc `/admin/teaching` |
| Tài liệu | Đối chiếu phạm vi và kiểm tra các liên kết local trong tài liệu đã sửa |

Java chạy trong container kiểm thử riêng dùng Temurin **17.0.10**, source tại `/workspace`,
cache Maven riêng của môi trường phát triển; không nối vào database/realm đang chạy.
Hai lệnh thực thi bên trong container, từ gốc source:

```bash
bash ./mvnw --batch-mode --no-transfer-progress -f pom.xml clean test
bash ./mvnw --batch-mode --no-transfer-progress -f gateway/pom.xml clean test
```

Các lệnh Python thực chạy từ root và frontend từ `frontend/`:

```powershell
python -m unittest discover -s scripts/demo -p test_fixtures.py -v
python -m unittest discover -s scripts/legacy -p test_portability.py -v
```

```powershell
npm run check
npm run build
```

Mốc này kiểm chứng source/H2/mock và build; chưa triển khai lại stack đang chạy,
chưa chạy OIDC/OTP/browser acceptance trên source mới. Không sửa MySQL/Redis,
credential/role của live Keycloak, private runtime hoặc migration đã áp dụng.
Các báo cáo ngày 23/10 có Teacher/schedule được giữ là lịch sử, không thay thế kết quả này.

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

### Kiểm thử bảo trì PKI ngày 28/10/2026

Với Python có `cryptography >= 44`, chạy từ canonical source:

```powershell
python -X utf8 scripts/legacy/test_tls_material.py
```

7 tests PASS: bảo toàn revocation entries/CRLNumber, key/SAN/EKU/expiry,
từ chối revoked leaf/khóa sai/CRL sai và check read-only không ghi dữ liệu.
Tests chỉ dùng CA giả trong bộ nhớ/thư mục tạm; không kết nối Docker hoặc ký
bằng CA thật. Chúng không thay thế Windows Schannel/Browser acceptance.
Xem báo cáo tổng hợp và `docs/operations/LEGACY_INTEGRATION.md` cho runtime TLS.

### Các đề xuất lịch sử cần đánh giá riêng

1. Kiểm chứng staging reset MFA/device trust đã có mã: caller riêng, Flyway V4,
   flow post-MFA, partial failure, expiry/rotation và race registration/reset.
2. Kiểm soát token/SSO và yêu cầu MFA còn mới cho thao tác admin.
3. Lưu quyết định rủi ro, phiên bản policy và kiểm chứng các nhánh runtime;
   hiệu chỉnh policy bằng dữ liệu được phê duyệt.
4. Migration Portal DB, cấu hình triển khai, giám sát, backup/restore và retention.
