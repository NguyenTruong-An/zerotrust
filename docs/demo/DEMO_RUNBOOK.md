# Demo runbook — zerotrust-demo

Đây là môi trường mới build từ source, tách QA02C. Xem [setup](../setup/DEVELOPMENT_DEMO.md) trước lần chạy đầu; browser cần trust CA bằng bước chủ động của người dùng.

```powershell
.\scripts\demo\demo.cmd start
.\scripts\demo\demo.cmd status
```

Mở **https://localhost:8443/**. Credentials ở private `.local-demo/credentials.json`; chỉ copy tài khoản cần dùng, ngoài màn hình trình chiếu. Lần đầu enroll TOTP qua trang Keycloak; password/OTP không nhập vào Portal. Logout trước mỗi lần đổi actor để fresh login đi qua Risk.

| Kịch bản | Thao tác |
|---|---|
| Student | `demo_student`: xem hồ sơ, điểm và lịch lớp DEMO_A, rồi logout. |
| Teacher | `demo_teacher`: mở assignment DEMO_A, xem roster, ghi lại điểm, sửa điểm trong0–10, lưu/refresh rồi nhập lại giá trị cũ. Assignment DEMO_B thuộc teacher khác. |
| Admin | `demo_admin`: xem giáo viên/sinh viên/môn/lịch, sửa phòng một lịch thành DEMO-CHECK, refresh rồi trả lại phòng cũ. Không đổi role/reset MFA để demo. |
| MEDIUM | Dùng profile browser mới của chính Demo, không có device cookie; đăng nhập/enroll nếu cần, logout rồi đăng nhập với OTP thật. |
| LOW | Sau history fixture và một OTP thật sau enrollment, giữ đúng device cookie của demo_student, logout/login lại: Risk có thể ALLOW không OTP khi context còn bình thường. |
| HIGH | Chạy high tools lane bên dưới để chứng minh numeric HIGH/DENY từ Risk thật và Keycloak403. Đây là peer container riêng, không tuyên bố đó là IP Windows browser. |

```powershell
docker compose --profile tools run --rm --no-deps tools /tools/verify.py normal
docker compose --profile tools run --rm --no-deps high /tools/verify.py high
```

Chỉ chạy verifier có chủ đích: normal gồm enrollment/OTP/login/logout, Student/Teacher/Admin APIs, sửa rồi trả lại điểm/phòng, RBAC/ownership/JWT và A04. HIGH dùng fixture lịch sử synthetic và refresh5 failure events nếu quá10phút để phù hợp TTL15phút; xem reasons thật trong kết quả. Kết quả mới nằm trong `.local-demo/evidence/`, không dùng báo cáo QA02C thay thế. Verifier có giới hạn12 login mỗi installation và không tự tăng budget. Trong đợt bàn giao đã dùng tổng12 OIDC transactions trên hai bản cài Demo mới; không cần chạy lại suite đã PASS.

Security minh họa: Student gọi Teacher/Admin API403; Teacher gọi roster/grade của lớp ngoài quyền404; token sai chữ ký401; Admin xóa assignment còn schedule409. Đây là kiểm tra API thật, không chỉ ẩn UI.

## Rehearsal thủ công

- [ ] Tự chấp thuận/import CA và mở Portal/Keycloak không cảnh báo TLS.
- [ ] Tự enroll/login OTP và xem đủ Student/Teacher/Admin UI.
- [ ] Sửa điểm/phòng, refresh, trả lại giá trị cũ.
- [ ] Thực hiện logout/login lại, quan sát LOW/MEDIUM theo context thật.
- [ ] Giải thích rõ HIGH lane và các giới hạn của demo.

Chưa đánh dấu manual Windows demo PASS khi chưa có người thao tác và bằng chứng tương ứng. Không reset toàn bộ dữ liệu. Kết thúc bằng `demo.cmd stop`; volumes và credentials được giữ.
