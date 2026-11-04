# Nghiệm thu phục hồi Lab ngày 04/11/2026

Đã phục hồi bản `lab-20261104T035042Z` vào bốn Docker named volume mới. Ba
MySQL và Redis đã khởi động, xác thực và đọc dữ liệu qua cấu hình TLS trong
backup. Mỗi container thử dùng `--network none`, không publish cổng, chạy đúng
image ID của manifest và gắn riêng volume thử cùng bản cấu hình đã giải nén.

| Hạng mục | Kết quả | Bằng chứng |
|---|---|---|
| Archive integrity | PASS | Đúng project và manifest đủ năm archive, mười image. Khớp SHA-256, kích thước, số member. Các image ID đều tồn tại cục bộ. |
| Restore execution | PASS | Đã giải nén vào bốn volume rỗng và khởi động đủ bốn container thử. |
| Database readability | PASS | School 9 bảng, 50 hàng. Risk 5 bảng, 143 hàng. Keycloak 100 bảng, 2.048 hàng. Redis trả PONG qua TLS và đọc được keyspace. |
| Data consistency | PARTIAL | School, Risk và Redis đạt các so sánh đã chạy. Keycloak khớp schema, còn hai khác biệt khi đối chiếu với DB đang chạy. |
| Full application recovery | NOT VERIFIED | Phạm vi phục hồi gồm các kho dữ liệu, chưa chạy Gateway, Portal, Risk hoặc Keycloak server trên dữ liệu phục hồi. |

## Đối chiếu dữ liệu

- School và Risk khớp danh sách bảng, metadata cột, số hàng và `CHECKSUM TABLE EXTENDED`
  từng bảng so với Lab. Ledger Flyway của Risk có năm dòng thành công, khớp thứ
  tự, phiên bản và checksum. School có các bảng `students` và `scores` đã kiểm tra.
- Keycloak khớp danh sách bảng và metadata cột. Các bảng realm, user, credential,
  client và ledger migration khớp số hàng và checksum. Trong 100 bảng, chỉ
  `JGROUPS_PING` và `SERVER_CONFIG` lệch checksum. `JGROUPS_PING` có 0 dòng ở
  bản restore và 1 dòng ở Lab đang chạy, phù hợp với chức năng node discovery
  qua JDBC. `SERVER_CONFIG` khớp số dòng nhưng chưa xác định nguyên nhân lệch
  checksum. So sánh này dùng DB đang chạy làm đối chứng, không có checksum dữ
  liệu tại thời điểm backup để chứng minh hai khác biệt đã phát sinh khi nào.
  [Tài liệu Keycloak về node discovery](https://www.keycloak.org/server/caching).
- Redis của bản restore và Lab đều có keyspace rỗng tại thời điểm kiểm tra.
  Kết quả này xác nhận khả năng mở snapshot và đọc keyspace hiện có.

Lần thử đầu dừng ở School do MySQL bỏ qua `server.cnf` khi Docker Desktop trình
bày quyền NTFS dưới dạng world-writable. Lần chạy lại sao chép cấu hình máy chủ
vào filesystem riêng của container với mode 0644, rồi xác thực TLS bằng CA trong
backup. Kiểm tra danh tính Lab được đối chiếu lại theo tập mount và network đã
sắp thứ tự vì Docker có thể trả các mục theo thứ tự khác nhau.

## Tài nguyên giữ lại

Container và volume dùng cùng tên. Mọi container thử đã dừng.

| Prefix | Hậu tố | Mục đích |
|---|---|---|
| `zt-restore-20261104041534-3a74c0` | `-school`, `-risk-db`, `-keycloak-db`, `-redis` | Bốn DB đã phục hồi và kiểm tra |
| `zt-restore-20261104041437-84dafd` | `-school` | Lần thử TLS đầu tiên, giữ cho tới khi duyệt dọn |

Các thư mục tương ứng dưới `../backups/verification/` chứa cấu hình DB riêng tư
và `verification.json`. Giữ quyền truy cập hạn chế. Bản backup gốc vẫn khớp
SHA-256. Đối chiếu Docker sau kiểm tra xác nhận container IDs, image IDs,
volume mounts và network của Lab khớp bản kiểm kê chuyển runtime.

Chữ ký CRL trong archive hợp lệ và `nextUpdate` là **06/11/2026 09:30:48 GMT+7**.
Đây là CRL cũ hơn bản Lab đang phục vụ. Khi phục hồi cả ứng dụng, kiểm tra lại
CA, TLS và hạn CRL trước khi mở Portal.

Lệnh diễn tập lại nằm trong [RUNBOOK](RUNBOOK.md). Mỗi lần chạy tạo volume mới
và giữ bằng chứng để phê duyệt dọn riêng.
