# ZeroTrust Student Score Portal

Hệ thống xem điểm sinh viên với hai role nghiệp vụ **ADMIN** và **STUDENT**. Student xem hồ sơ và điểm của mình; Admin quản lý sinh viên, lớp, môn học, tài khoản và nhập/sửa điểm. Không có chức năng giảng viên, phân công giảng dạy hoặc lịch học. Keycloak sở hữu mật khẩu/MFA/token; Risk đánh giá ngữ cảnh; Gateway và Backend kiểm tra JWT, role và quyền dữ liệu.

## Docker với dữ liệu School / DoAn / Risk đã bảo toàn

Một repository giữ source chính và các Dockerfiles dùng chung. Lab hiện hành dùng
[compose.lab.yaml](compose.lab.yaml), private runtime tại `../runtime/lab` ngoài Git
và bốn volume dữ liệu đã bảo toàn. Xem [môi trường và runtime](docs/operations/ENVIRONMENTS.md)
cùng [env example](.env.lab.example) để hiểu cách tách lab, dev và build.
Clone source không chứa passwords/OTP, database backups hoặc private keys; khôi phục
trên máy khác cần private inputs và một kế hoạch được duyệt.

Hướng dẫn hiện hành: [vận hành lab và bản đồ cấu hình/volume](docs/operations/CURRENT_RUNTIME.md).
Lệnh hằng ngày, backup, TLS và dọn dẹp: [RUNBOOK](docs/operations/RUNBOOK.md).
`lab` là tên gọi cho project hiện có, chưa tạo môi trường mới. Từ repository dùng Python3.11+ và Docker:

```powershell
.\scripts\ops\zt.cmd status
.\scripts\ops\zt.cmd doctor
.\scripts\ops\zt.cmd config-check
.\scripts\ops\zt.cmd start
.\scripts\ops\zt.cmd logs --service backend --tail 100
.\scripts\ops\zt.cmd stop
```

`zt.cmd` dùng được cả khi Windows chặn script PowerShell. Có thể dùng trực tiếp
`python -X utf8 scripts/ops/zt.py status` hoặc wrapper `zt.ps1` nếu máy cho phép.
Môi trường mặc định là `lab`; script legacy vẫn tương thích.
Các lệnh này chỉ dùng existing containers/volumes, không tạo lại database, import realm,
chạy migration hoặc seed. Portal HTTPS28443 và Keycloak HTTPS28444/realm `DoAn` dùng
CA trong truststore/profile QA riêng; không cài Windows Root. Manual Windows browser
và real HIGH vẫn cần bằng chứng xác nhận như hướng dẫn vận hành.

Phạm vi hai role được chủ đồ án xác nhận ngày **27/10/2026**. Khi cập nhật source,
cần rebuild Backend/Gateway/Frontend và triển khai image mới để môi trường đang chạy
nhận thay đổi. Bản sửa source không tự xóa bảng, tài khoản hoặc role cũ trong database/Keycloak;
không chạy migration giảng viên/lịch học để khởi động hệ thống xem điểm.

## Môi trường canonical hiện tại

Canonical source: `<repo-root>`.
Compose project: `zerotrust-legacy-integration-20261026`. Backend, Frontend và Gateway
đã được đồng bộ với source ADMIN/STUDENT; các application containers QA/Demo cũ đã dọn
đúng danh sách được duyệt. Ngày 04/11/2026, mười container lab đã chuyển sang runtime
`<lab-runtime-root>`. Sau kiểm tra vận hành và sao lưu,
cả 10 dịch vụ đã chạy healthy; xem kết quả và giới hạn trong RUNBOOK.

[Báo cáo tổng hợp](ZEROTRUST_FINAL_CONSOLIDATION_REPORT.md) ghi image IDs, source snapshot,
cleanup và các giới hạn nghiệm thu. Trạng thái TLS/Browser đọc theo mốc kiểm chứng
trong báo cáo; dùng `status`/`doctor` để kiểm tra vận hành hiện tại. Healthcheck không
thay thế nghiệm thu đăng nhập, MFA hoặc kiểm tra hạn TLS/CRL.

Build chuẩn hóa dùng [quy trình build và manifest phiên bản](docs/development/BUILD_PIPELINE.md):

```powershell
.\scripts\build\images.cmd --service gateway
```

Image mới dùng tag riêng, chưa được triển khai. Runtime đang khóa image hiện hữu
trong `../runtime/lab/images.private.yaml`; quy trình chuyển/quay lui xem
[ENVIRONMENTS](docs/operations/ENVIRONMENTS.md). Giới hạn tài nguyên Risk đã hợp nhất
vào `compose.lab.yaml`, không cần override riêng cho deployment mới.
`compose.yaml` không khai báo service; cần chọn rõ môi trường. `compose.dev.yaml`
và `scripts/demo` dành cho synthetic riêng, không phải đường khởi động lab.
Các tài liệu synthetic và dữ liệu/backup được giữ để đối chiếu; không tạo Demo/QA mới.
Dockerfiles dùng chung nằm tại `deploy/docker`; `deploy/demo` còn helper và fixture
tương thích, không phải source thứ hai.

## Tài liệu

[PUBLIC_DEMO_ROADMAP](docs/production-readiness/PUBLIC_DEMO_ROADMAP.md) là nguồn duy nhất
về phạm vi, task và tiến độ Public Demo Production; đọc trước mọi nhiệm vụ Public Demo.
Quyền CRUD mô tả ở source/Lab không phải quyền ghi trên Public Demo đã chốt read-only.

Xem tín hiệu, điểm D/N/T/H, quyết định và MFA khi test:

```powershell
.\scripts\observation\Observe-Risk.cmd --watch-seconds 5 --open
```

[Hướng dẫn quan sát](docs/testing/RISK_OBSERVATORY.md) giải thích nguồn dữ liệu,
cách ghép từng lần xác thực và phân biệt log thật với dữ liệu minh họa.

[Kiến trúc](ARCHITECTURE.md) · [Vận hành canonical](docs/operations/LEGACY_INTEGRATION.md) · [Nghiệm thu và cleanup](ZEROTRUST_FINAL_CONSOLIDATION_REPORT.md) · [Mục lục](docs/README.md).

Policy số trong source là development baseline, chưa phải policy production đã hiệu chỉnh. Báo cáo QA lịch sử được giữ trong `docs/qa-*`; kết quả lịch sử không thay thế acceptance của runtime canonical hiện tại.
