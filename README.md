# ZeroTrust Student Score Portal

Hệ thống xem điểm sinh viên với hai role nghiệp vụ **ADMIN** và **STUDENT**. Student xem hồ sơ và điểm của mình; Admin quản lý sinh viên, lớp, môn học, tài khoản và nhập/sửa điểm. Không có chức năng giảng viên, phân công giảng dạy hoặc lịch học. Keycloak sở hữu mật khẩu/MFA/token; Risk đánh giá ngữ cảnh; Gateway và Backend kiểm tra JWT, role và quyền dữ liệu.

## Docker với dữ liệu School / DoAn / Risk đã bảo toàn

Một repository giữ source chính và các Dockerfiles dùng chung. Triển khai legacy dùng
[compose.legacy.yaml](compose.legacy.yaml), private runtime ngoài Git và volumes dữ liệu
đã khôi phục. Xem [hướng dẫn legacy](docs/operations/LEGACY_INTEGRATION.md) cùng
[env example](.env.legacy.example) cho build contexts tương đối, cấu hình và bootstrap riêng.
Clone source không chứa passwords/OTP, database backups hoặc private keys; khôi phục
trên máy khác cần private inputs và một kế hoạch được duyệt.

Với candidate hiện có, từ repository dùng Python3.11+ và Docker:

```powershell
python -X utf8 scripts/legacy/operate.py start
python -X utf8 scripts/legacy/operate.py status
python -X utf8 scripts/legacy/operate.py stop
```

Các lệnh này chỉ dùng existing containers/volumes, không tạo lại database, import realm,
chạy migration hoặc seed. Portal HTTPS28443 và Keycloak HTTPS28444/realm `DoAn` dùng
CA trong truststore/profile QA riêng; không cài Windows Root. Manual Windows browser
và real HIGH vẫn cần bằng chứng xác nhận như hướng dẫn vận hành.

Phạm vi hai role được chủ đồ án xác nhận ngày **27/10/2026**. Khi cập nhật source,
cần rebuild Backend/Gateway/Frontend và triển khai image mới để môi trường đang chạy
nhận thay đổi. Bản sửa source không tự xóa bảng, tài khoản hoặc role cũ trong database/Keycloak;
không chạy migration giảng viên/lịch học để khởi động hệ thống xem điểm.

## Môi trường canonical hiện tại

Canonical source: `C:\Users\DELL\Documents\zerotrust\zerotrust`.
Compose project: `zerotrust-legacy-integration-20261026`. Backend, Frontend và Gateway
đã được đồng bộ với source ADMIN/STUDENT; các application containers QA/Demo cũ đã dọn
đúng danh sách được duyệt. Chỉ canonical project còn ứng dụng đang chạy.

[Báo cáo tổng hợp](ZEROTRUST_FINAL_CONSOLIDATION_REPORT.md) ghi image IDs, source snapshot,
cleanup và các giới hạn nghiệm thu. Windows Schannel hiện lỗi revocation vì CDP nội bộ Docker;
chưa khẳng định toàn hệ thống hoặc Browser Flow PASS, không bỏ qua cảnh báo HTTPS.

Rebuild dùng canonical `compose_prefix` và private env đã chuẩn bị; xem
[hướng dẫn build/start/stop](ZEROTRUST_FINAL_CONSOLIDATION_REPORT.md#12-startstoprebuild-từ-canonical-source).
Không chạy `docker compose up` không chỉ rõ file/project/env: `compose.yaml` và
`scripts/demo` là cấu hình synthetic lịch sử, không phải đường khởi động hiện tại.
Các tài liệu synthetic và dữ liệu/backup được giữ để đối chiếu; không tạo Demo/QA mới.
`deploy/demo` vẫn chứa Dockerfiles dùng chung cho build canonical, không phải source thứ hai.

## Tài liệu

[Kiến trúc](ARCHITECTURE.md) · [Vận hành canonical](docs/operations/LEGACY_INTEGRATION.md) · [Nghiệm thu và cleanup](ZEROTRUST_FINAL_CONSOLIDATION_REPORT.md) · [Mục lục](docs/README.md).

Policy số trong source là development baseline, chưa phải policy production đã hiệu chỉnh. Báo cáo QA lịch sử được giữ trong `docs/qa-*`; kết quả lịch sử không thay thế acceptance của runtime canonical hiện tại.
