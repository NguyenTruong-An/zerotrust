# Demo runbook — zerotrust-demo

Phạm vi hiện tại: web xem điểm với ADMIN/STUDENT, không có Teacher, phân công hoặc lịch học. Đây là môi trường build từ source, tách QA02C. Xem [setup](../setup/DEVELOPMENT_DEMO.md) trước lần chạy đầu; browser cần trust CA bằng bước chủ động của người dùng.

```powershell
.\scripts\demo\demo.cmd start
.\scripts\demo\demo.cmd status
```

Mở **https://localhost:8443/**. Credentials ở private `.local-demo/credentials.json`; chỉ copy tài khoản cần dùng, ngoài màn hình trình chiếu. Lần đầu enroll TOTP qua trang Keycloak; password/OTP không nhập vào Portal. Logout trước mỗi lần đổi actor để fresh login đi qua Risk.

| Kịch bản | Thao tác |
|---|---|
| Student | `demo_student`: xem hồ sơ và điểm của mình, lọc môn/kỳ/năm học, rồi logout. |
| Admin | `demo_admin`: xem sinh viên/lớp/môn và bảng điểm; ghi lại điểm cũ, sửa một điểm trong 0–10 trên dữ liệu synthetic, lưu/refresh rồi trả lại điểm cũ. Không đổi role/reset MFA để demo. |
| MEDIUM | Dùng profile browser mới của chính Demo, không có device cookie; đăng nhập/enroll nếu cần, logout rồi đăng nhập với OTP thật. |
| LOW | Sau history fixture và một OTP thật sau enrollment, giữ đúng device cookie của demo_student, logout/login lại: Risk có thể ALLOW không OTP khi context còn bình thường. |
| HIGH | Chạy high tools lane bên dưới để chứng minh numeric HIGH/DENY từ Risk thật và Keycloak403. Đây là peer container riêng, không tuyên bố đó là IP Windows browser. |

```powershell
docker compose --profile tools run --rm --no-deps tools /tools/verify.py normal
docker compose --profile tools run --rm --no-deps high /tools/verify.py high
```

Chỉ chạy verifier có chủ đích: normal gồm enrollment/OTP/login/logout, Student/Admin APIs, Admin sửa rồi trả lại điểm, RBAC/quyền dữ liệu và JWT. HIGH dùng fixture lịch sử synthetic và refresh5 failure events nếu quá10phút để phù hợp TTL15phút; xem reasons thật trong kết quả. Kết quả mới nằm trong `.local-demo/evidence/`, không dùng báo cáo QA02C thay thế. Verifier có giới hạn12 login mỗi installation và không tự tăng budget. Báo cáo bàn giao ngày 23/10 ghi nhận 12 OIDC transactions trên hai bản cài của phiên bản cũ; kết quả đó không xác nhận source sau khi gỡ Teacher. Không tự tăng budget hoặc chạy lại verifier trên dữ liệu legacy.

Security minh họa: Student gọi Admin API nhận 403; Admin không có STUDENT gọi API điểm của Student nhận 403; token sai chữ ký nhận 401. Student chỉ được xem điểm gắn với subject của mình. API Teacher/phân công/lịch học cũ phải không còn được cung cấp. Các kiểm tra này kiểm chứng API, không chỉ việc ẩn nút trên UI.

## Rehearsal thủ công

- [ ] Tự chấp thuận/import CA và mở Portal/Keycloak không cảnh báo TLS.
- [ ] Tự enroll/login OTP và xem đủ Student/Admin UI.
- [ ] Admin sửa điểm synthetic, refresh, trả lại giá trị cũ.
- [ ] Thực hiện logout/login lại, quan sát LOW/MEDIUM theo context thật.
- [ ] Giải thích rõ HIGH lane và các giới hạn của demo.

Chưa đánh dấu manual Windows demo PASS khi chưa có người thao tác và bằng chứng tương ứng. Không reset toàn bộ dữ liệu. Kết thúc bằng `demo.cmd stop`; volumes và credentials được giữ.
