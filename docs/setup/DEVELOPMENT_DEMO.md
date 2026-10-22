# Development/Demo setup

Chạy tại root candidate. Cần Docker Desktop Linux containers, Git và mạng để tải Maven/npm/images lần đầu. Khuyến nghị Docker8GB RAM; không cần Java/Node/Python cài riêng trên Windows. Không thay profile/hosts/registry/certificate store tự động.

## Từ GitHub đến bản đóng gói

```powershell
git clone --branch zerotrust-v4-risk-scoring https://github.com/NguyenTruong-An/zerotrust.git
cd zerotrust
git rev-parse HEAD
```

Packaging có parent baseline `894e7fcb1adb960e7c1c057b0d0713fcb2307c26`, giữ ancestry FIX-01–08/POSTFIX03A/03B và source đã dùng cho QA02C. Clone branch mới không cần áp patch hoặc copy private store: Docker builds dùng source, init tự tạo CA/credentials/realm mới. Các lệnh trên chỉ dành cho clone mới; không checkout/pull đè original dirty worktree. Không copy dirty source, private files hoặc QA JAR. Dùng SHA packaging trong báo cáo bàn giao nếu cần pin exact source.

```powershell
.\scripts\demo\demo.cmd build
.\scripts\demo\demo.cmd start
.\scripts\demo\demo.cmd status
```

`build` dựng tất cả artifact từ source. `start` chỉ khởi tạo School/Keycloak trên volume trống, không reset dữ liệu cũ. Realm `zerotrust-demo`; Portal https://localhost:8443/, Keycloak https://localhost:8444/. Issuer `https://localhost:8444/realms/zerotrust-demo`, callbacks Portal `/` và `/silent-check-sso.html`, PKCE S256 bắt buộc. Các cổng cố định đi cùng frontend build, không đổi một cổng riêng lẻ.

`.local-demo/` được Git bỏ qua: credentials, CA/key riêng, role configs, realm import và OTP seed khi dùng verifier. Mỗi service chỉ mount thư mục role của nó; chỉ bootstrap/tools thấy toàn bộ private store. Không in credentials ra logs, Git hay màn hình chia sẻ. Bảo vệ thư mục/backup bằng quyền tài khoản Windows hiện tại; đây là private local store, không phải secret manager production.

## TLS trên Windows

CA mới có SKI/AKI, BasicConstraints/KeyUsage đúng; leaf có SAN localhost/DNS nội bộ và CRL Distribution Point `http://localhost:8445/ca.crl`. CRL có chữ ký CA, chỉ chứa dữ liệu công khai; server không mount private key. Init tạo/refresh CRL7ngày khi start. Nếu để môi trường chạy liên tục hơn7ngày, chạy `demo.cmd start` để init refresh. Java/MySQL/Redis dùng CA với hostname verification. Windows curl/Schannel đã trả200 với CA file và revocation check vẫn bật. Không dùng trust-all, insecure cookie hay bỏ qua lỗi HTTPS.

**Chỉ nếu bạn chấp thuận tin cậy CA local này:** mở `.local-demo/ca.crt`, kiểm tra tên `ZeroTrust Demo Local CA`, rồi tự import vào Trusted Root của Current User bằng Windows certificate UI để Edge/Chrome bình thường nhận chứng thư. Việc này tăng trust trong tài khoản Windows; không phải thao tác script tự thực hiện. Hoặc dùng chức năng import Authorities trong profile Firefox riêng của bạn. Không dùng Firefox/Python của QA02C. Không nhập CA vào máy khác nếu không quản lý private CA tương ứng.

Sau khi import có chủ đích, mở Portal/Keycloak và xác nhận không có cảnh báo TLS. Chưa có bằng chứng người dùng đã thực hiện bước này; báo cáo không ghi manual PASS.

## Phát triển và rebuild

```powershell
.\scripts\demo\demo.cmd build backend
docker compose up -d --no-deps backend
.\scripts\demo\demo.cmd logs backend
```

Tương tự cho frontend/gateway/risk/keycloak. Rebuild Risk không tự cho phép sửa Flyway migration đã áp dụng. Migration mới phải chạy job riêng trước writer, dùng backup phù hợp. Không dùng `ddl-auto=update`.

PowerShell helper tương đương là `scripts/demo/demo.ps1 -Action start|stop|status|logs|build`; `demo.cmd` tránh lỗi Execution Policy mà không chỉnh chính sách hệ thống. Không gọi helper QA02C trong original checkout để quản lý Demo mới.

## Dữ liệu và kiểm chứng

Tài khoản synthetic `demo_student`, `demo_student_b`, `demo_teacher`, `demo_teacher_b`, `demo_admin`, `demo_high`; mật khẩu mới ở trường `users.<actor>.password` trong private credentials. Mỗi tài khoản enroll TOTP qua Keycloak chính thức ở lần đầu, không có OTP seed hardcode/import từ QA. Nếu verifier đã enroll actor, seed Base32 nằm riêng trong `.local-demo/otp-seeds.json`: nhập đúng seed vào Authenticator ngoài màn hình chia sẻ. Dataset có2 lớp,2 môn,3 sinh viên,2 giảng viên,3 điểm,2 phân công,2 lịch; IDs khớp subject Keycloak của lần cài đặt.

Focused acceptance có thể chạy rõ ràng bằng tools profile, không nằm trong startup mặc định:

```powershell
docker compose --profile tools run --rm --no-deps tools /tools/verify.py normal
docker compose --profile tools run --rm --no-deps high /tools/verify.py high
```

Verifier có budget12 OIDC transactions mỗi installation, dùng real OTP và API. Nó chuẩn bị10 synthetic success events,5 failure events qua Risk events API có phân quyền; đây là fixture lịch sử để trình diễn, không phải khẳng định đã có10 người dùng đăng nhập. HIGH lane dùng peer thật172.30.80.200 và CIDR high đã khai báo; không spoof headers hoặc mock response. Failure fixture hết hạn theo Redis TTL15phút; high tool refresh5 failure events có kiểm soát nếu fixture quá10phút. Không chạy lại khi kết quả đã PASS và source không đổi.

```powershell
.\scripts\demo\demo.cmd stop
```

Dừng giữ volume. Không cung cấp reset dữ liệu hoặc volume-delete tự động. Backup MySQL và toàn bộ `.local-demo` phải đi cùng nhau, giữ riêng; không restore lẫn QA/operational. [Troubleshooting](TROUBLESHOOTING.md), [runbook](../demo/DEMO_RUNBOOK.md).
