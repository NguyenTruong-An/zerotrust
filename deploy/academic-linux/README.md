# Gói Academic Demo cho Linux amd64

Gói dùng tám dịch vụ và các image PD-R19 đã xác minh. Profile `zt-academic-linux` có mạng, volume, realm, tài khoản, CA và secrets mới. Chỉ NGINX bind loopback. MySQL, Redis, Risk và Keycloak management chỉ có đường nội bộ. NGINX xác minh TLS upstream. Các dịch vụ nội bộ dùng CA riêng và Keycloak giữ issuer bên ngoài trong token. Portal dùng School account SELECT-only, ghi security state đi qua realm/Risk.

## Chuẩn bị bản release

Cần Linux amd64, Docker Engine, Compose từ 2.24.4, Python 3.11+ với `cryptography` từ 39, và OpenSSL. Buildx và Git cần khi tạo lock ở canonical source. JDK `keytool` có thể dùng từ image Portal đã khóa. `age` chỉ cần cho backup. [Docker Compose merge](https://docs.docker.com/reference/compose-file/merge/)

1. Chép [production.example.json](production.example.json) thành cấu hình ngoài repo. Đặt hai hostname đã duyệt, release ID mới, port loopback, subnet không trùng, thư mục state riêng và đường dẫn tuyệt đối tới fullchain, key và CA bundle. Fullchain phải hợp lệ cho cả hai hostname. Key có quyền 0600 và thuộc đường dẫn file thực.
2. Từ canonical source, nạp đúng bốn image ứng dụng PD-R19 đã khóa. Build frontend cho đúng Portal/Auth URL, giữ client `zerotrust-spa`, mode Public Demo và cùng origin API. Sau build, đối chiếu digest và duyệt kết quả scan của frontend mới.
3. Tạo manifest và bundle. Gói ảnh có năm app images, còn MySQL/Redis/NGINX được kéo bằng digest trong danh sách đi kèm. Archive không có volume, realm export, PKI, secrets hoặc Git metadata.

```bash
python3 -B deploy/academic-linux/linux_demo.py --config /path/demo.json validate
python3 -B deploy/academic-linux/linux_demo.py --config /path/demo.json --manifest /path/release-lock.json lock
python3 -B deploy/academic-linux/bundle.py --config /path/demo.json --manifest /path/release-lock.json --output /path/new-bundle
```

Chuyển bundle và cấu hình qua kênh đã duyệt. Cung cấp PKI qua kênh secret riêng. `lock` kiểm đủ tám digest và hash đầu vào source. Bên nhận có thể xác minh source đã khóa trực tiếp từ archive.

## Cài, kiểm và triển khai lại trên VPS

Sau khi owner cấp host và phê duyệt triển khai riêng tư, dùng tài khoản deploy được chỉ định. Giữ access gate đóng trong thời gian nghiệm thu.

```bash
cd /path/reviewed-bundle
sha256sum -c SHA256SUMS
docker image load -i app-images.tar
while IFS= read -r image; do docker pull --platform linux/amd64 "$image"; done < registry-images.txt
mkdir -m 700 /path/empty-release
tar -xzf deployment.tar.gz -C /path/empty-release
cd /path/empty-release
python3 -B deploy/academic-linux/linux_demo.py --config /path/demo.json --manifest release-lock.json start
python3 -B deploy/academic-linux/linux_demo.py --config /path/demo.json --manifest release-lock.json status
python3 -B deploy/academic-linux/smoke.py --config /path/demo.json --manifest release-lock.json
```

`start` xác minh project/volume/network, image IDs, input hashes và PKI. Lần đầu tạo credentials/realm/key riêng, migrate V1–V5 khi Risk writers tắt rồi kiểm checksum `661092940`. Lần sau dùng state đã cài và chạy lại cùng lock. App services có giới hạn RAM/CPU và log rotation từ Compose. Ingress kiểm portal qua TLS thật. Chỉ xem log sau khi lọc và chỉ theo đúng project.

Chạy `smoke.py --exercise` trong lane rehearsal riêng trên host thử, với `rehearsal.example.json`, release ID mới, state trống và lock frontend tương ứng. Ca này tạo enrollment, thử token/OTP, B0/trust, dừng Redis/Risk rồi khởi động lại profile. Production-demo chỉ chạy smoke đọc. Trước khi cấp quyền giảng viên, chạy browser thật với hostname và PKI đích, PKCE đúng/sai, OTP, RBAC, direct read-only, logout/refresh, kết quả B0 và trust trên dữ liệu synthetic. Tách ca lỗi/restart khỏi lane giảng viên. Kiểm thêm limits dưới tải nhẹ, edge bypass, Keycloak admin/management, DB/Risk/Redis, raw Observatory và cấp/thu hồi tài khoản. [Keycloak reverse proxy](https://www.keycloak.org/server/reverseproxy)

## Backup, restart và rollback

- Giữ lock, SHA256SUMS, image archive, phiên bản engine, config đã duyệt và checksum backup cùng nhau. Tách Age recipient khỏi identity giải mã và tách khóa khỏi nơi giữ archive.
- Khi bảo trì, đóng access gate, dùng `linux_demo.py ... stop`, rồi kiểm label `com.docker.compose.project=zt-academic-linux` trước khi chạy `docker start zt-academic-linux-mysql-1`. Giữ writers và Redis dừng. Dùng `backup.py --config … --manifest … --recipients /path/recipients --output /path/new-backup` để tạo SQL và Redis AOF tar đã mã hóa. `--rehearse` chỉ dùng cho rehearsal riêng. Script in checksum ciphertext và không ghi file plaintext.
- Giữ state và volumes khi restart. Dùng `linux_demo.py start` để chạy lại đúng lock. Nếu frontend mới hỏng, đưa bundle/config của release cũ trở lại cùng hostname và state đã tương thích, rồi kiểm status và smoke. Đổi DB hoặc Keycloak cần snapshot tương thích. Khôi phục vào DB/volumes mới và kiểm realm, signing key IDs, OTP, V5, RBAC trước chuyển traffic. Giữ volume gốc và evidence để đối chiếu.
- Kiểm restore trên rehearsal. Bản SQL khôi phục qua MySQL 8.4.13 ở PD-R19 chứng minh dữ liệu và ledger. Cần diễn tập restore phù hợp với bản Linux release và engine được duyệt. Backup Redis cần kiểm AOF load trong lane restore trước khi tuyên bố khôi phục toàn bộ.

## Cấp quyền giảng viên

| Phương án | Điều kiện |
|---|---|
| B — HTTPS qua VPN hoặc private access | Khuyến nghị hiện tại. DNS riêng cho cả Portal/Auth. Gateway hoặc VPN đã xác thực chuyển TCP 443 theo hai hostname tới port loopback trên VPS, giữ SNI và TLS của profile. Chỉ định danh giảng viên được cấp quyền. |
| A — HTTPS qua Internet có giới hạn | Chỉ dùng khi owner duyệt artifact/rủi ro và access gate đã được nghiệm thu. Bảo vệ cả hai hostname, bao gồm đường OIDC redirect. Chặn truy cập ngoài danh sách, kiểm người ngoài không vào được và chốt hạn quyền. |

Owner cần cung cấp Linux amd64 host và quyền deploy, Portal/Auth hostname và quyền DNS, fullchain/key/CA bundle hoặc người vận hành PKI, lựa chọn gateway/VPN, danh sách người dùng, giới hạn phiên và thời điểm thu hồi. Giữ signup tắt và MFA bật. Gate phải áp dụng cho cả Portal và Auth, không xuất raw Observatory hoặc management. Test từ một thiết bị được cấp quyền và một thiết bị ngoài phạm vi. Đến hạn, thu hồi access gateway, sessions và tài khoản demo. Cập nhật người phụ trách backup, restart và kênh hỗ trợ giảng viên.

Profile hiện tại chỉ tạo origin loopback. Việc cấu hình access gateway, DNS và mở quyền truy cập thuộc bước owner phê duyệt sau nghiệm thu.
