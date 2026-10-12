[Mục lục](../README.md) · [Theme](../../keycloak-theme/README.md)

# Giao diện xác thực và thời gian khóa — 2026-10-09

## Thay đổi

- CSS/JS của theme `zerotrust`: navy/teal đồng bộ Portal, bố cục hai cột,
  responsive; hướng dẫn riêng cho password, OTP, QR enrollment, recovery.
- Thêm tiếng Việt cho các bước OTP/recovery và footer an toàn.
- `ZeroTrustLoginFormsProvider` kế thừa renderer gốc, bổ sung metadata countdown
  chỉ cho theme zerotrust và thông báo temporary lockout của Keycloak.
- Factory giữ ID freemarker, order 100 theo cơ chế override provider của
  Keycloak 26.7.0. Các form gốc, action URL, hidden fields, MFA validation và
  Browser Flow không bị thay bởi countdown.
- Countdown dùng not-before của login failure thật và giờ server. Không đoán
  từ waitIncrement hay từ chuỗi thông báo. User chưa xác định, khóa vĩnh viễn,
  disabled, failure record thiếu/hết hạn hoặc lookup lỗi không hiển thị thời gian.
- Client chỉ tạm chặn submit khi đang chờ, không mở khóa server hoặc tự gửi
  credential. Server kiểm tra lại ở lần thử sau; khóa thay đổi từ phiên khác
  cần server render lại để có thời gian mới.

## Kiểm chứng mã

29 test mục tiêu đạt, gồm 12 test renderer/lockout mới và các test MFA/reset
registration. Toàn module SPI package đạt **113 test**, không failure/error/skip.
JavaScript qua `node --check`; `git diff --check` cho theme/phần forms đạt.
Sources Keycloak 26.7.0 đã đối chiếu trong Maven cache cho lockout not-before,
renderer và lựa chọn factory theo order. Không đổi policy brute force của DoAn.

## Kiểm chứng runtime

Đã nạp JAR và theme vào container local `keycloak-26.7.0`, khởi động lại và
kiểm tra bằng browser. Discovery của DoAn vẫn trả issuer
`http://localhost:8180/realms/DoAn`.

| Hạng mục | Kết quả |
| --- | --- |
| Đăng nhập DoAn | Theme mới render tiếng Việt, bố cục desktop hai cột; form gốc giữ nguyên |
| OTP | Đăng nhập bằng password tài khoản thử chuyển đến form OTP thật; trường mã dùng inputmode numeric |
| Thiết lập TOTP | Trang QR thật render hướng dẫn từng bước; nhãn OTP/tên thiết bị trỏ đúng input |
| Mã dự phòng | Trang required action thật render mã, nút in/tải/sao chép và nút hoàn tất ban đầu disabled |
| Màn hình nhỏ | Kiểm tra viewport 390 × 844; login, OTP, QR và recovery không tràn ngang; recovery một cột |
| Khóa tạm thời | Gửi sai password cho user thử; Keycloak trả temporary lockout, countdown hiển thị và submit disabled |
| Hết thời gian | Countdown về 00:00, hiện thông báo cho thử lại, submit enabled; không tự submit |

Kiểm tra có thao tác đăng nhập dùng realm riêng
`zerotrust-ui-check-7979d8e3`, policy khóa 15 giây và dữ liệu giả. Realm này dùng
Browser Flow gốc để kiểm chứng renderer; kết quả này không thay thế kiểm thử
end-to-end Risk Service. Không hoàn tất đăng ký factor mới, không đổi credential
hoặc thử khóa user DoAn. Đã xóa realm thử cùng toàn bộ user/failure state sau
kiểm tra.

Ảnh kết quả local lưu tại `target/auth-ui-screenshots/`: `login-desktop.jpg`,
`otp-mobile.jpg`, `temporary-lockout.jpg`. Ảnh khóa dùng tài khoản thử đã xóa.

## Triển khai và giới hạn

- Bản sao trước khi thay đổi nằm trong
  `target/auth-ui-backups/20261009T074912Z/`, gồm JAR và toàn bộ theme cũ.
- JAR đã nạp có SHA-256
  `3978E3615034208ED6E92EFD74FFD9C51767F9249FBFBA02A0464506A38DE09D`.
- Đã kiểm tra CSS cuối được phục vụ sau khi reload. Khi dùng browser có cache
  cũ, tải lại hoàn toàn trang đăng nhập để nhận CSS/JS mới.
- Provider kế thừa FreeMarker của Keycloak 26.7.0; khi nâng phiên bản Keycloak,
  cần kiểm tra lại SPI renderer, template và đăng ký factory.
- Countdown phản ánh mốc khóa khi server render. Nếu một phiên khác kéo dài
  khóa, lần thử tiếp theo vẫn bị server từ chối và nhận mốc mới. Khóa vĩnh viễn
  hoặc user disabled không có thời gian mở khóa tự động.

## Chỉnh căn hàng ứng dụng xác thực

Sau phản hồi giao diện, đã bỏ margin kế thừa của các phần tử danh sách trong
hướng dẫn TOTP; ô Google Authenticator, Microsoft Authenticator và FreeOTP dùng
chung min-height 32px, line-height, padding và gap 8px. Kiểm tra trên trang
CONFIGURE_TOTP thật của realm tạm: desktop cả ba có cùng top và chiều cao;
viewport 390 × 844 xuống dòng đều, không tràn ngang. Đã nạp CSS vào Keycloak
local và xóa realm thử `zerotrust-ui-check-a7997f00`. Ảnh phần đã sửa nằm tại
`target/auth-ui-screenshots/mfa-apps-aligned.jpg`.
