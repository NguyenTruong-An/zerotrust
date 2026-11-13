# Academic Demo RC hợp nhất

Profile rehearsal Linux amd64 chạy DHI Keycloak 26.8.2 với SPI/theme ZeroTrust, MySQL 8.4.13 và sáu dịch vụ còn lại. Hai hostname `.test` được khóa trong build frontend. Chỉ ingress bind loopback. State synthetic được tạo trong thư mục riêng tại `/tmp` và các volumes mang nhãn project riêng.

## Build và cài mới

Cần Docker Engine Linux amd64, Compose hỗ trợ `!override`, Buildx, Python 3.11+ có `cryptography` và OpenSSL. Chạy từ canonical checkout. Các bước build ứng dụng xuất receipt riêng với SHA source, file hashes và ID image. Build DHI mặc định dùng registry theo exact digest. Khi đã có OCI layout của cùng artifact, có thể truyền `--oci /path/oci`. Driver kiểm manifest, config và từng layer bằng SHA-256.

```bash
mkdir -p target/pd-r22-local
python3 -B deploy/academic-linux/rc/build.py --release rc1 --output target/pd-r22-local/build \
  keycloak backend risk gateway frontend
python3 -B deploy/academic-linux/rc/rc.py lock --build-dir target/pd-r22-local/build \
  --manifest target/pd-r22-local/release-lock.json
python3 -B deploy/academic-linux/rc/rc.py start --manifest target/pd-r22-local/release-lock.json
python3 -B deploy/academic-linux/rc/rc.py status --manifest target/pd-r22-local/release-lock.json
```

Trước `lock`, nạp các registry image theo các tham chiếu trong `REGISTRY` của `rc.py`. MySQL 8.0.46 chỉ chạy trong mạng bootstrap nội bộ, áp dụng V1–V5 trên schema Risk synthetic rồi dừng. MySQL 8.4.13 nhận export logic trong bộ nhớ vào schema Risk trống. Driver so cột/schema và ledger, kiểm School TLS, chờ Keycloak import realm và chỉ đánh dấu installed sau khi tám dịch vụ healthy. Một lần cài lỗi giữ state và volumes để điều tra. Dùng project/state/subnet mới khi thử lại. Một bản cài thành công chỉ được khởi động lại với đúng lock.

## Kiểm thử và phục hồi

```bash
python3 -B deploy/academic-linux/rc/browser.py --manifest /path/release-lock.json --certutil /path/certutil
python3 -B deploy/academic-linux/rc/rc.py exercise --manifest /path/release-lock.json
python3 -B deploy/academic-linux/rc/measure.py --manifest /path/release-lock.json --output /path/capacity.json
```

Chạy browser trên realm mới, trước các bài test đã dùng OTP. Chromium/Playwright cần lib hệ thống tương ứng và `certutil` của NSS. Tool cài CA synthetic vào trust DB riêng cho lần chạy và ánh xạ hostname về loopback. Sau browser, dành một cửa sổ TOTP trước khi chạy lại cùng tài khoản. `exercise` chạy các trường hợp B0/Risk qua HTTPS và private API, bao gồm fault/restart synthetic. `measure.py` chạy tối đa năm worker trên hai phiên STUDENT, ghi số đo local.

Với `age` và `age-keygen`, chạy `recovery.py --manifest … --destination …` trên RC đang chạy. Destination config dùng cùng Portal/Auth URL, subnet riêng và state `/tmp/zerotrust-pd-r22-restore`. Script dừng lane nguồn sau backup và khôi phục SQL, Redis và state cấu hình vào lane mới. Khóa giải mã và archive nằm ở thư mục Linux riêng có quyền hạn chế. Chỉ lane synthetic hỗ trợ rehearsal này. `rollback.py` diễn tập quay lại checkpoint do exact Quay image tạo ra trên MySQL 8.4, trong hai project riêng. Cả hai tool giữ volumes để kiểm chứng.

## Đóng gói

```bash
python3 -B deploy/academic-linux/rc/bundle.py --manifest /path/release-lock.json --output /path/bundle
```

Bundle gồm năm image ứng dụng, deployment inputs, exact lock và danh sách registry pins, có `SHA256SUMS`. Trên Linux nhận gói, kiểm checksum, nạp `app-images.tar`, pull theo `registry-images.txt`, giải nén deployment archive và chạy `rc.py start` với lock đã đi kèm. Gói rehearsal dùng hostname `.test`. Bản hostname/TLS thật cần frontend và lock dành riêng cho host sau D-04. [Master Roadmap](../../../docs/production-readiness/PUBLIC_DEMO_ROADMAP.md)

## Chuẩn bị VPS sau quyết định của owner

**Điều kiện**. Linux amd64, Docker Engine từ 28 và Compose từ 2.24.4, Python 3.11+ bản đã cập nhật với `cryptography` từ 39, OpenSSL, OpenJDK 17 `keytool` và `age`. Tạo `/var/lib/zerotrust` mode 0700 thuộc tài khoản deploy chuyên biệt. Quyền dùng Docker daemon tương đương quyền quản trị máy. Kiểm firewall và đường vào origin trên host thực. Gợi ý bắt đầu **4 vCPU / 8 GiB RAM / 40 GiB disk**. **6 vCPU / 12 GiB / 60 GiB** dành thêm dung lượng cho cài đặt, log và backup. Đo lại trên máy đích. [Capacity PD-R22](../../../docs/production-readiness/evidence/ACADEMIC_DEMO_RELEASE.md#capacity-local) · [Docker port publishing](https://docs.docker.com/engine/network/port-publishing/)

1. Chép [production.example.json](production.example.json) ra ngoài repo. Điền hai FQDN Portal/Auth do owner duyệt, subnet riêng không trùng, và PKI đúng host. Giữ external port 443 và origin loopback 34443. `fullchain.pem` có leaf và intermediate cần thiết. Leaf có SAN cho cả hai hostname, còn hiệu lực và khớp private key. Key mode 0600, đường dẫn tuyệt đối, không dùng symlink. `edge_ca` dùng trust bundle mà client được cấp quyền tin cậy. Các dịch vụ nội bộ dùng CA được sinh riêng khi cài.
2. Từ canonical source đã review, lưu các receipt `builds.<service>` của `backend`, `risk`, `gateway`, `keycloak` trong lock PD-R23 vào thư mục build mới, mỗi service một `<service>.json`. Nạp đúng image ID của chúng và pull bốn registry pins. Dùng tag frontend mới và giữ riêng lock/bundle theo từng hostname. Lock đối chiếu byte nguồn, label nguồn và image ID trước khi chấp nhận dùng lại các build cũ.

```bash
python3 -B deploy/academic-linux/rc/build.py frontend --config /path/demo.json \
  --release rc2302 --output /path/build
python3 -B deploy/academic-linux/rc/rc.py lock --config /path/demo.json \
  --build-dir /path/build --manifest /path/release-lock.json
python3 -B deploy/academic-linux/rc/bundle.py --config /path/demo.json \
  --project zt-academic-prod --manifest /path/release-lock.json --output /path/bundle
```

3. Trên VPS, giữ cổng truy cập giảng viên đóng. Kiểm `sha256sum -c SHA256SUMS` trong thư mục bundle, nạp `app-images.tar`, pull từng dòng `registry-images.txt` với `--platform linux/amd64`, rồi giải nén deployment archive vào thư mục mới. Từ thư mục giải nén, chạy `rc.py validate` với tham số dưới đây. Sau phê duyệt triển khai và preflight đạt, chạy `start`, rồi `smoke` với cùng tham số. `smoke` kiểm TLS và OIDC tại origin, ranh giới đường quản trị, SQL grants và V5.

```bash
args=(--config /var/lib/zerotrust/demo.json --project zt-academic-prod --manifest release-lock.json)
python3 -B deploy/academic-linux/rc/rc.py validate "${args[@]}"
python3 -B deploy/academic-linux/rc/rc.py start "${args[@]}"
python3 -B deploy/academic-linux/rc/rc.py smoke "${args[@]}"
```

### Truy cập và nghiệm thu trên host đích

Origin mặc định giữ `127.0.0.1:34443`. Owner duyệt access model ngày11/11/2026: sau release acceptance, adapter public riêng phục vụ HTTPS443 cho Portal/Auth, Keycloak/MFA/Adaptive Risk và account cá nhân ADMIN/STUDENT; giảng viên không cần GCP/IAP/VPN/IP cố định. Private rehearsal dùng IAP/OS Login cho operator, chưa mở80/443. Giữ OIDC/PKCE/login-actions public đúng chức năng khi được GO, còn Keycloak admin/master/management, MySQL, Redis, Risk và Docker API private. Đo canonical IP qua đường thật, kiểm header giả không được tin; IAP peer IP không thay thế evidence public client IP. [Account/Cloud runbook](../vps/ACCESS_AND_PRIVATE_REHEARSAL.md) · [Keycloak reverse proxy](https://www.keycloak.org/server/reverseproxy)

Trước mở quyền, chạy browser với chứng thư thật. Kiểm STUDENT chỉ đọc điểm của mình (gồm lỗi lần đầu sau enrollment đang theo dõi), ADMIN đọc được và ghi bị chặn, first-login password update/enrollment, OTP sai/đúng, logout, refresh bị từ chối và thu hồi access cho tài khoản thử. Giữ adaptive LOW ALLOW khi đủ điều kiện và sensitive reset D-10 hiện tại. Cấp account synthetic theo danh tính và role, gửi thông tin qua kênh đã duyệt, giữ signup tắt. Xác nhận người xử lý reset/MFA, cảnh báo và sự cố, job expiry và residual JWT lifetime. Đề xuất hết hạn **23/11/2026 lúc 18:00, Asia/Saigon** của runbook cũ vẫn chờ owner đối chiếu lịch bảo vệ, không tự đặt expiry hoặc thời hạn waiver. Khi hết hạn, thu hồi quyền/phiên/trust, vô hiệu hóa tài khoản demo, đóng ingress, lưu backup mã hóa theo chính sách lưu giữ rồi dừng profile. Access model approval không đóng D-17 hoặc G8.

### Backup, restore và fallback

- Đóng quyền truy cập trước bảo trì. Dùng `rc.py stop` với exact lock, rồi kiểm ownership và chỉ khởi động lại container MySQL thuộc đúng project. `vps_backup.py backup` yêu cầu writers, Keycloak installer, MySQL bootstrap và Redis đã dừng. Dùng `--checkpoint` là thư mục backup mới trong vùng lưu trữ được bảo vệ, `--recipients` là tệp public age recipients. Giữ SHA của lock, checkpoint receipt và khóa giải mã theo cơ chế lưu giữ tách biệt. Sau backup, khởi động lại đúng lock và kiểm smoke trước khi mở lại quyền.
- `vps_backup.py restore` nhận `--checkpoint` và `--identity` đã duyệt. Dùng project khác như `zt-academic-prod-restore`, state riêng `/var/lib/zerotrust/zerotrust-academic-prod-restore`, subnet mới, cùng hostname/port/chứng thư và volumes trống. Lượt restore đóng sau origin smoke. Kiểm signing keys, OTP, quyền đọc, trust revoke và dữ liệu trước khi chuyển truy cập. Backup/restore production branch còn phải diễn tập trên host đích.
- Giữ riêng archive Quay exact ID `sha256:e06bec13a903df01c1fd80b590d328db99ecbc4b00ee6ce3baa6f10f5f142615`. PD-R22 đã thử fallback bằng checkpoint **do Quay tạo trên MySQL 8.4**. `rollback.py` chỉ chạy rehearsal. Trên VPS cần checkpoint Quay tương thích với hostname, PKI và schema đích cùng một lượt thử riêng trước khi dùng làm fallback. Nếu chưa có checkpoint tương thích, giữ access đóng và dùng restore cùng exact release. Không gắn database đang chạy DHI vào image Quay.
