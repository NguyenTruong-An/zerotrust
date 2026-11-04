# Vận hành và bảo trì lab

Mở repository canonical trong IntelliJ và bật Docker Desktop. Dùng
[CURRENT_RUNTIME](CURRENT_RUNTIME.md) để xác định môi trường và chạy các lệnh
dưới đây từ thư mục gốc Git.
Python 3.11+ và Docker Desktop Linux containers phải sẵn sàng. Công cụ TLS dùng
Python/cryptography trong image tools hiện hữu, không cần cài thêm trên Windows.

| Khi cần | Lệnh |
|---|---|
| Xem trạng thái | `scripts\ops\zt.cmd status` |
| Kiểm tra đường dẫn, volume | `scripts\ops\zt.cmd doctor` |
| Đối chiếu Compose với image/mount hiện hữu | `scripts\ops\zt.cmd config-check` |
| Khởi động / dừng đúng thứ tự | `scripts\ops\zt.cmd start` / `scripts\ops\zt.cmd stop` |
| Kiểm tra HTTPS, OIDC, CRL và liên dịch vụ | `scripts\ops\zt.cmd smoke` |
| Xem hạn/chữ ký TLS và CRL | `scripts\ops\zt.cmd tls-check` |
| Gia hạn CRL, lưu bản cũ | `scripts\ops\zt.cmd renew-crl` |
| Sao lưu nhất quán | `scripts\ops\zt.cmd backup` |
| Diễn tập phục hồi | `scripts\ops\zt.cmd restore-check --backup-path ..\backups\lab-20261104T035042Z` |
| Kiểm kê để đề xuất dọn | `scripts\ops\zt.cmd cleanup-report` |
| Đọc log Risk | `scripts\ops\zt.cmd logs --service risk --tail 100` |

Trước demo: `status`, `config-check`, `tls-check`, `smoke`. `tls-check` trả mã 2
khi CRL/chứng chỉ còn tối đa hai ngày. `renew-crl` chỉ gia hạn CRL, không gia hạn
chứng chỉ máy chủ. Nó giữ danh sách thu hồi, lưu bản cũ và kiểm tra hash đầu vào
trước khi thay file. Không tắt TLS, kiểm tra hostname hoặc cài CA vào Windows Root.

## Backup và phục hồi

`backup` yêu cầu toàn bộ lab đang chạy hoặc toàn bộ đã dừng. Nó dừng lab nếu cần,
gắn bốn volume ở chế độ chỉ đọc vào helper không có mạng, tạo archive và khởi động
lại nếu trước đó lab đang chạy. Chọn lúc không có người sử dụng vì có gián đoạn.
Nếu khởi động lại lỗi, chạy `status` rồi xử lý service lỗi; không tạo database mới.

Kết quả ở `../backups/lab-<UTC>/`, ngoài Git, ACL riêng tư: bốn archive dữ liệu,
`runtime.tar.gz`, Compose và manifest chứa SHA-256/image ID. Kiểm tra archive
đọc được **không tương đương** phục hồi MySQL/Redis đã nghiệm thu.

Lệnh `restore-check` xác minh archive rồi tạo volume riêng cho mỗi DB. Nó khởi
động từng DB với đúng image trong manifest, mạng `none` và TLS từ bản backup.
Lệnh in đường dẫn evidence, dừng DB thử và giữ lại volume để rà soát.
[Kết quả phục hồi](RESTORE_VERIFICATION_REPORT.md).
Giữ tối thiểu hai mốc backup đã xác minh và một bản sao ngoài máy, có bảo vệ bí mật.
Không tự xóa backup theo tuổi khi chưa kiểm chứng bản thay thế.

## Build, triển khai và quay lui

1. Chốt revision và chạy test. Dùng `scripts\build\images.cmd --committed`
   để lấy byte từ Git HEAD. Đối chiếu manifest với Git revision, SHA-256 của
   source snapshot và image IDs. [Build pipeline](../development/BUILD_PIPELINE.md).
2. Nếu có nhu cầu nâng cấp Lab, lập một kế hoạch duy nhất gồm service được chọn,
   image ID trước/sau, backup đã kiểm tra, cấu hình Compose, phạm vi nghiệm thu
   và điều kiện quay lui. Sao lưu khóa image hiện hành ở vùng riêng tư. Đưa khóa
   đề xuất vào file riêng để kiểm tra trước khi duyệt.
3. Kiểm tra `docker compose config --quiet` với `compose.lab.yaml`, env riêng
   và khóa đề xuất. Xác nhận project canonical, bốn external volumes, hai
   external networks, đúng mount và đúng image cục bộ. Phạm vi deploy ứng
   dụng chỉ gồm service được duyệt, bỏ qua build/pull và service phụ thuộc.
4. Sau khi duyệt, dùng đúng Compose prefix đã kiểm tra, cập nhật khóa và
   chạy `up -d --no-deps --no-build --pull never <service đã duyệt>`.
   Chạy `config-check`, `status`, `tls-check`, `smoke` và nghiệm thu Browser.
5. Nếu phải quay lui image, dùng khóa trước triển khai và cùng lệnh Compose
   với đúng danh sách service. Chạy lại kiểm tra cấu hình, health, smoke và
   nghiệm thu. Diễn tập rollback được kiểm tra bằng cấu hình. Đổi runtime
   mount thuộc kế hoạch riêng tại [ENVIRONMENTS](ENVIRONMENTS.md).

## Trước buổi demo

Chạy lần lượt `doctor`, `start`, `status`, `tls-check` và `smoke`. Dùng URL
Portal trong [CURRENT_RUNTIME](CURRENT_RUNTIME.md). Mở Risk Observatory từ root:

```powershell
.\scripts\observation\Observe-Risk.cmd --watch-seconds 5 --open
```

Người vận hành tự nhập password/OTP trong trình duyệt. Dùng hai phiên riêng:

1. **ADMIN** mở trang quản trị và xem danh sách học vụ. Logout, rồi mở lại URL
   bảo vệ để xác nhận ứng dụng yêu cầu đăng nhập.
2. **STUDENT** mở hồ sơ/điểm của mình, thử truy cập trang quản trị bằng URL đã
   kiểm tra với ADMIN và xác nhận bị chặn. Logout, kiểm tra lại trang bảo vệ.
3. Ghi giờ, vai trò và kết quả từng bước, kể cả việc có yêu cầu MFA hay không.
   Đối chiếu sự kiện gần thời điểm đó trên Observatory nếu có Risk Evaluation.
   Chỉ ghi dữ liệu quan sát được, tránh chụp token hoặc OTP.

Phạm vi demo dùng thao tác đọc. Khi kết thúc phiên vận hành, dùng `zt.cmd stop`.

## Xử lý lỗi thường gặp

| Dấu hiệu | Cách kiểm tra |
|---|---|
| Docker Engine unavailable | Bật Docker Desktop, đợi engine sẵn sàng rồi chạy lại `doctor`. |
| Container stopped | Đây là trạng thái dự kiến sau `stop`. Chạy `start` để bật lại. |
| Thiếu runtime, file cấu hình hoặc volume | Đối chiếu đúng đường dẫn, tên volume và bản lưu trong CURRENT_RUNTIME trước khi khởi động. |
| Khóa image sai | Chạy `config-check`, đối chiếu image ID với khóa đã duyệt và container. |
| CRL đến hạn | Chạy `tls-check`, dùng `renew-crl` nếu đến hạn CRL và chạy lại `smoke`. |
| Cổng host bị chiếm | Kiểm tra listener của 28443–28445 và xử lý đúng ứng dụng đang giữ cổng. |
| Service exited hoặc unhealthy | Xem `status`, `doctor` và `logs --service <tên>`. Chỉ retry sau khi xử lý nguyên nhân. |

Xem [cấu trúc môi trường](ENVIRONMENTS.md), [runtime hiện hành](CURRENT_RUNTIME.md)
và [đề xuất dọn dẹp](CLEANUP_REVIEW.md).
