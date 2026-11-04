# Local setup

Bắt đầu tại [vận hành hiện hành](CURRENT_RUNTIME.md): lệnh start/stop/status/logs,
kiểm tra cấu hình và bản đồ các Docker volume. Môi trường đang dùng có tên `lab`
trong bộ lệnh, trỏ project `zerotrust-legacy-integration-20261026` hiện có.

Tách lab/dev/build và vị trí runtime được mô tả tại [ENVIRONMENTS](ENVIRONMENTS.md).
Quy trình import dữ liệu ban đầu lưu tại [Legacy-data Docker integration](LEGACY_INTEGRATION.md).
Mở cùng một checkout
trong IntelliJ/Codex và chạy các lệnh Docker từ thư mục gốc checkout đó.

[Development/Demo setup](../setup/DEVELOPMENT_DEMO.md) dành cho cấu hình synthetic riêng.
Hướng dẫn chạy IntelliJ và topology cũ được giữ trong
[archive](../archive/LEGACY_LOCAL_SETUP.md); các cổng/schema lịch sử không phải lệnh
khởi động deployment legacy mới.
