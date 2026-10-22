# ZeroTrust Academic Portal

Hệ thống học vụ với xác thực thích ứng. Keycloak sở hữu mật khẩu/MFA/token; Risk đánh giá ngữ cảnh; Gateway và Backend kiểm tra JWT, role và ownership. Có giao diện Student, Teacher và Admin.

## Chạy trên Windows 11

Cần Git và Docker Desktop Linux containers. Không cần Java, Node hoặc Python trên host. Khuyến nghị Docker8GB RAM và đủ dung lượng build cache.

Dùng clone mới của branch dưới đây; bản đóng gói đã bao gồm các helpers và Dockerfiles. Xem [setup](docs/setup/DEVELOPMENT_DEMO.md). Không lấy JAR, secret hay volume của QA02C.

```powershell
git clone --branch zerotrust-v4-risk-scoring https://github.com/NguyenTruong-An/zerotrust.git
cd zerotrust
.\scripts\demo\demo.cmd build
.\scripts\demo\demo.cmd start
.\scripts\demo\demo.cmd status
```

- Portal: **https://localhost:8443/**.
- Keycloak: **https://localhost:8444/**, realm `zerotrust-demo`.
- HTTPS8443/8444 và HTTP8445 chỉ bind127.0.0.1. Port8445 chỉ phục vụ CRL đã ký cho Windows; MySQL/Redis/Backend/Risk không publish host ports.
- TLS dùng CA riêng của bản cài đặt. Xem [thiết lập CA](docs/setup/DEVELOPMENT_DEMO.md#tls-trên-windows); không bỏ qua cảnh báo chứng thư.
- Credentials mới tự sinh trong `.local-demo/credentials.json` được Git bỏ qua. Không mở file này khi đang chia sẻ màn hình.

PowerShell chặn `.ps1` vẫn chạy được `demo.cmd`, không cần đổi Execution Policy.

```powershell
.\scripts\demo\demo.cmd build backend
.\scripts\demo\demo.cmd logs risk
.\scripts\demo\demo.cmd stop
```

`start` giữ dữ liệu, `stop` giữ volumes. Không có reset tự động.

## Tài liệu

[Kiến trúc](docs/architecture/SYSTEM.md) · [Setup/Development](docs/setup/DEVELOPMENT_DEMO.md) · [Demo runbook](docs/demo/DEMO_RUNBOOK.md) · [Troubleshooting](docs/setup/TROUBLESHOOTING.md) · [Bảo vệ và giới hạn](docs/security/DEMO_SECURITY.md) · [Mục lục](docs/README.md).

Policy số trong source là development baseline, chưa phải policy production đã hiệu chỉnh. Báo cáo QA lịch sử được giữ trong `docs/qa-*`; kết quả QA02C không thay thế acceptance của Demo mới.
