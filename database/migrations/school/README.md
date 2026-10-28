# Lịch sử migration School

Phạm vi hiện tại được chủ đồ án xác nhận ngày **27/10/2026**: hệ thống xem điểm,
chỉ có ADMIN/STUDENT. Không quản lý giảng viên, phân công hoặc lịch học.

`V20261026_01__legacy_teacher_schedule.sql` là migration lịch sử của phần mở rộng
đã loại bỏ. File này từng tạo ba bảng `teachers`, `teaching_assignments`,
`schedule_entries` và bảng ledger `school_schema_history` trên một bản sao legacy.
Giữ nguyên file/checksum để đối chiếu lần triển khai cũ; **không chạy migration này
cho bản cài mới hoặc khi cập nhật hệ thống xem điểm**.

Compose hiện tại không có job `school-migrate`. Job `school-check` dùng
[school_validate.py](../../../scripts/legacy/school_validate.py) chỉ đọc năm bảng
`users`, `student_classes`, `students`, `subjects`, `scores`; đối chiếu schema,
row hash, `scores.version` và liên kết Keycloak với baseline đã duyệt. Không tạo bảng,
seed dữ liệu hoặc ghi ledger. Khởi động thông thường không chạy job này.

Các bảng/ledger cũ nếu đã tồn tại được giữ nguyên; JPA không còn entity sử dụng chúng.
Không DROP bảng, xóa volume hoặc sửa migration đã áp dụng để loại bỏ chức năng.
File fresh-only `database/migrate_teacher_assignment_schedule.sql` cũng chỉ còn
là lịch sử và đã được loại khỏi bootstrap Demo. Bootstrap mới dùng schema
năm bảng và fixtures ADMIN/STUDENT.

Không chạy schema fresh, seed hoặc SQL tính lại điểm trên database legacy đã khôi phục.
Cột `scores.version` của candidate hiện có được giữ nguyên. Kế hoạch cho database
khác phải được đối chiếu riêng; việc gỡ Teacher không yêu cầu thay đổi điểm hoặc credential.
