# Google Cloud VPS — chuẩn bị offline

Chưa triển khai. D-04 PENDING; D-14 technical PASS nhưng chưa promote artifact;
D-17 acceptance DRAFT/PENDING; G8 INTERNET NO-GO.

Owner đã duyệt access model: sau release acceptance, giảng viên dùng account riêng
ADMIN/STUDENT qua public HTTPS + Keycloak/MFA/Adaptive Risk, không cần GCP/IAP/VPN
hoặc IP cố định. IAP chỉ dành cho operator/private rehearsal; hiện ứng dụng chỉ
loopback. Xem [quy trình account và Cloud preflight](ACCESS_AND_PRIVATE_REHEARSAL.md)
và [input Cloud còn trống](cloud.env.example). Đây không là public release approval.
Owner chọn sslip.io + Let's Encrypt HTTP-01 cho demo ngắn hạn. Không đổi quyết định
release hoặc cấu hình PD-R19. Thư mục này là phần bổ sung riêng, không sửa source
đã khóa của RC; giữ nguyên release lock và provenance của các image cũ.

## Hostname và policy

D-04 trong Master Roadmap yêu cầu domain/Portal/Auth và DNS owner. Hợp đồng ingress
yêu cầu hostname/HTTPS hợp lệ, không quy định phải mua hoặc sở hữu apex domain.
Với lựa chọn đã được owner chốt: nhà cung cấp DNS là sslip.io, owner quản lý Static
External IP và ACME endpoint. Không có quyền TXT và không dùng DNS-01. Phụ thuộc
DNS bên thứ ba, rate limit CA và nguy cơ IP được cấp lại phải được ghi vào quyết định
demo có ngày kết thúc. Không tuyên bố D-04 PASS trước khi IP, DNS và TLS thật đạt.

`hostname.env.example` để trống IP. Khi có IP thực, chạy từ checkout/bundle trên Linux:

```bash
python3 -B deploy/academic-linux/vps/prepare.py \
  --ip "$STATIC_EXTERNAL_IP" --output /var/lib/zerotrust/inputs
```

Tool chỉ tạo `demo.json` và `nginx-acme.conf`, từ chối IP private/reserved/placeholder.
Kiểm hai hostname resolve về đúng IP từ ngoài mạng. Không phát hành AAAA nếu chưa
cấu hình IPv6. Mất hoặc đổi static IP đòi hỏi build frontend/issuer/redirect/lock mới.

Generated config sử dụng external HTTPS 443, origin loopback 34443, project
`zt-academic-prod`, state `/var/lib/zerotrust/zerotrust-academic-prod`, subnet
`172.31.243.0/27` (kiểm không trùng VPC/Docker trước khi chốt). RC tự sinh:

- Portal `https://portal.${STATIC_EXTERNAL_IP}.sslip.io`.
- Auth/strict hostname `https://auth.${STATIC_EXTERNAL_IP}.sslip.io`.
- Issuer `${AUTH_URL}/realms/academic-demo`.
- Redirect `${PORTAL_URL}/`, `${PORTAL_URL}/silent-check-sso.html`; logout `/`;
  web origin/CORS `${PORTAL_URL}`; client `zerotrust-spa`, realm `academic-demo`.
- Frontend build: `KEYCLOAK_URL=$AUTH_URL`, `SITE_URL=$PORTAL_URL`,
  `PORTAL_MODE=public-demo`, `API_BASE_URL=`. Không build trước khi có IP.
- ADMIN/STUDENT, synthetic/read-only; không thêm TEACHER.

## D-14/D-17: một lượt triage, 10/11/2026

Receipt gốc: `target/pd-r22/scan-{mysql,bootstrap80,keycloak}.json` và mục PD-R22/23
trong `docs/production-readiness/evidence/ACADEMIC_DEMO_RELEASE.md`. Giữ raw findings.

| Phạm vi | Phân biệt finding và exposure | Hướng xử lý tối thiểu, chưa thực hiện |
|---|---|---|
| MySQL 8.4.13: 2C/33H | 1C/25H trong Go stdlib của gosu; 1C/8H trong Python tooling MySQL Shell. Evidence cũ thấy gosu chỉ chuyển UID, không gọi TLS resumption; không dùng MySQL Shell trong workflow. Đây không phải chứng minh mọi High không thể khai thác. | Tag 8.4.13 live vẫn có amd64 `72c368d8…c86d`, chưa có digest vá mới cùng tag. Ưu tiên vendor refresh; nếu gấp, candidate derived riêng bỏ MySQL Shell không dùng và thay gosu bằng bản build bằng Go đã vá. Giữ mysqld 8.4.13, kiểm startup/TLS/grants/restore trên candidate mới, không thay pin đang duyệt. |
| Bootstrap 8.0.46: 2C/112H | Cùng nhóm tooling và thêm 79 High OS. OpenSSL libraries có mặt trong đường MySQL TLS; không được miễn trừ toàn bộ như tooling. Bootstrap có root startup nhưng chạy mạng recovery internal, không publish, dừng sau chuyển schema. Chưa có exploit được chứng minh trong scope này. | Candidate bootstrap derived vẫn giữ server 8.0.46, cập nhật các RPM có bản vá tương thích, bỏ Shell và thay gosu. Kiểm đúng V1–V5/checksum 661092940 rồi logical transfer. Không sửa applied V5, không đổi engine bằng tag latest. Nếu chưa có candidate verified thì D-14 tiếp tục PENDING, không tự chấp nhận rủi ro. |
| DHI derived cũ: 0C/3H | libsystemd0/CVE-2026-16742 thuộc systemd-homed và libtinfo6/CVE-2025-69720 thuộc infocmp; binary tương ứng vắng theo receipt. libacl1/CVE-2026-54369 vẫn OPEN: caller đặc quyền + pathname do đối tượng khác kiểm soát; chưa thấy đường HTTP khai thác. UID65532/drop ALL/no-new-privileges giảm phơi nhiễm, không phải bản vá. | Catalog live có **cùng 26.8.2**, base amd64 mới `sha256:ba20b9bd0ecd48047240249acaff19aa882db5480a03659fcdf14d4b7bd9d424`, index `255de2e4…c5e`, vendor báo 0C/0H. Registry manifest xác nhận digest/version. Ưu tiên candidate này, kiểm signed SBOM/disposition rồi rebuild riêng derived SPI/theme, scan và kiểm tương thích bị ảnh hưởng. Không đổi runtime/pin hiện có. |

Các bản vá đã đối chiếu: certifi `2026.10.18`; Go Critical TLS resumption từ
`1.24.13/1.25.7` (các High khác đòi hỏi Go mới hơn, receipt cao nhất `1.26.10/1.27.3`);
libacl upstream `2.4.0`. Debian tracker vẫn ghi Trixie vulnerable và thay đổi ABI,
vì vậy không trộn package Sid vào DHI. Vendor 0C/0H chưa là scan độc lập của derived mới.
Không tải layers, build candidate hay miễn trừ CVE trong lượt chuẩn bị này.

Nguồn: [sslip.io](https://sslip.io/), [HTTP-01](https://letsencrypt.org/docs/challenge-types/),
[DHI catalog](https://hub.docker.com/hardened-images/catalog/dhi/keycloak),
[libacl](https://security-tracker.debian.org/tracker/CVE-2026-54369),
[certifi](https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2),
[Go TLS](https://pkg.go.dev/vuln/GO-2026-4337), [MySQL tags](https://hub.docker.com/_/mysql).

## Trình tự một VM, chưa chạy

1. Sau quyền tạo tài nguyên riêng: Ubuntu 24.04 LTS amd64, E2 custom 4 vCPU/8 GiB,
   disk 40 GiB, một Static External IPv4, không Spot cho buổi bảo vệ. Dùng project
   và VPC riêng hoặc kiểm toàn bộ firewall kế thừa. Không tạo GKE/Cloud SQL/LB/NAT.
   Trial có hạn; đặt budget alert, chốt lịch tắt VM và ngày thu hồi.
2. SSH chỉ qua IAP TCP forwarding + OS Login: allow TCP22 từ `35.235.240.0/20`
   tới VM tag riêng; quyền IAP tunnel/OS Login theo người quản trị. Không allow SSH
   0.0.0.0/0. Chặn 443 ban đầu, không mở 34443, 3306, 6379, 8443, 9000, 2375/2376.
   Docker API chỉ Unix socket. VPC firewall là biên chính, không chỉ dựa UFW.
3. Cài Docker/Compose và dependencies theo RC README; tạo `/var/lib/zerotrust`
   0700 và `pki` 0700. Volumes riêng được RC tạo; không restore/copy local Lab hay
   PD-R19. Build/scan frontend và lock **production-demo** theo hostname thực;
   tái sử dụng app receipt phù hợp, không sửa lock rehearsal thành production.
4. Chạy NGINX host bằng **config ACME riêng** đã sinh, không dùng default site.
   Webroot `/var/www/zerotrust-acme` và các thư mục cha mode0755, challenge file0644.
   Lệnh service: `/usr/sbin/nginx -c /var/lib/zerotrust/inputs/nginx-acme.conf -g 'daemon off;'`.
   Tạo systemd unit cho đúng lệnh này khi triển khai. NGINX này chỉ bind80; không proxy
   ứng dụng. Allow TCP80 để CA truy cập; mọi route ngoài challenge, cả `/`, trả404.
   Không redirect sang ứng dụng chưa duyệt. Không dùng allowlist IP của CA.
5. Certbot host `certonly --webroot -w /var/www/zerotrust-acme --cert-name zerotrust-demo
   -d "$PORTAL_HOST" -d "$AUTH_HOST"` (cấp email/đồng ý điều khoản bởi operator).
   Kiểm staging challenge trước, sau đó dùng production CA. Copy fullchain/key từ
   Certbot vào hai đường `pki` trong demo.json, file thường0600, không symlink.
   Dùng system CA bundle `/etc/ssl/certs/ca-certificates.crt`.
6. Kiểm bundle checksum, nạp đúng images, `rc.py validate/start/smoke` theo README RC.
   Đây là origin loopback. Kiểm TLS/issuer/browser qua đường quản trị trước khi
   cho phép listener public. Giữ Docker Compose restart policy/named volumes/log limits.
7. Chép thư mục `vps/` cạnh `rc/` trong deployment tree, kiểm checksum khi chuyển.
   Tạo seal riêng bằng lệnh dưới. Seal là ràng buộc bytes, **không phải release approval**.
   Quyết định D-04/D-14/D-17/G8 phải có owner/reference/thời hạn cụ thể.
8. Sau GO đúng phạm vi: publish listener; giai đoạn nghiệm thu operator có thể
   tạm giới hạn nguồn443 theo quyết định riêng. Đây không là yêu cầu IP cố định
   cho giảng viên ở public demo. Từ thiết bị ngoài VM: xác minh CA/SAN, PKCE/MFA, OTP sai/đúng,
   ADMIN/STUDENT read-only, logout/revoke, và client IP trực tiếp qua Keycloak SPI→Risk.
   Gửi XFF/Forwarded giả để xác nhận bị thay thế; không xuất token/raw IP vào báo cáo.
   Nếu IP là bridge/proxy hoặc sai bất kỳ gate nào, đóng ingress/firewall ngay;
   chưa mở rộng access. Không coi IAP tunnel là bằng chứng client IP đường public.
   Việc cho phép kiểm thử ngoài VM khi G8 còn NO-GO cần quyết định phạm vi riêng;
   adapter này không có cờ bypass G8 để tự thực hiện bước đó.
9. Sau public release approval, cho browser truy cập HTTPS/OIDC và chỉ cấp dữ liệu
   cho account riêng trong roster đã duyệt. Không bắt giảng viên dùng IAP/VPN/IP allowlist.
   Thu hồi phiên/tài khoản/trust và
   đóng firewall khi kết thúc; giữ IP cho đến khi đã ngừng phát hành/thu hồi access.

[IAP](https://docs.cloud.google.com/iap/docs/using-tcp-forwarding) ·
[Docker firewall](https://docs.docker.com/engine/network/packet-filtering-firewalls/)

## Listener public và khóa riêng cho adapter

```bash
python3 -B deploy/academic-linux/vps/operate.py seal \
  --config /var/lib/zerotrust/inputs/demo.json --manifest /opt/zerotrust/release-lock.json \
  --seal /var/lib/zerotrust/vps-lock.json
```

`publish` dùng cùng ba tham số, thêm `--approval /var/lib/zerotrust/owner-decision.json`.
Receipt do operator lập từ quyết định thật, không tự tạo APPROVED. Các trường bắt buộc:
`vps_lock_sha256`, `owner`, `decision_reference`, `expires_at` (ISO8601 có timezone),
`D-04`, `D-14`, `D-17`, `G8` đều APPROVED. Adapter không tự chứng minh firewall hoặc
thay thế policy review. Receipt và seal đặt ngoài Git, quyền0600.

Adapter kiểm base RC và installed lock, sau đó kiểm mô hình Compose chỉ khác đúng
mapping `0.0.0.0:443:8443`; giữ origin `127.0.0.1:34443`. Không thêm mount/network hay
publish dịch vụ khác. NGINX ứng dụng vẫn dùng renderer đã kiểm: upstream TLS verified,
Host/Proto/Port cố định, XFF bị thay bằng `$remote_addr`, bỏ Forwarded/X-Real-IP.
Gateway/Keycloak chỉ tin ingress `172.31.243.9/32` theo subnet đã chọn. Không đặt thêm
CDN/proxy TCP hoặc bật trust-all. Giữ network Docker NAT Linux thông thường; IP thật
còn phải nghiệm thu trên GCE, không suy từ Docker Desktop.

`close` dừng riêng ingress và không cần G8 approval. Firewall vẫn cần operator đóng.
`rc.py start` sau bảo trì có thể đưa ingress về loopback; muốn public lại dùng adapter,
không chạy raw Compose override để bỏ qua kiểm tra. Sao lưu VPS dùng `vps_backup.py`
theo RC README với writers đã dừng, encrypted checkpoint riêng và bản offsite; không
đụng backup local. Restore vào project/state/volumes riêng, nghiệm thu trước chuyển.
Quay fallback chỉ dùng checkpoint Quay tương thích, không gắn DB DHI vào Quay.

## Gia hạn TLS, không đổi release lock

Certbot timer chỉ quản lý lineage riêng của VPS. Deploy hook gọi:

```bash
python3 -B /opt/zerotrust/deploy/academic-linux/vps/operate.py renew-tls \
  --config /var/lib/zerotrust/inputs/demo.json --manifest /opt/zerotrust/release-lock.json \
  --seal /var/lib/zerotrust/vps-lock.json --approval /var/lib/zerotrust/owner-decision.json \
  --fullchain "$RENEWED_LINEAGE/fullchain.pem" --key "$RENEWED_LINEAGE/privkey.pem"
```

Không copy đè `pki` trước hook. Hook snapshot Certbot files, kiểm key/chain/SAN/expiry,
khóa thao tác đồng thời, lưu journal0700, dừng riêng ingress, cập nhật file0600 ở
`pki`, RC state và đúng ingress-config volume. Helper dùng image Redis đã khóa,
UID101, no-network/drop ALL, không có Docker socket. Khởi động và kiểm chứng chỉ
được phục vụ cho cả hai hostname qua TLS loopback. Không chạm internal CA, Keycloak
signing key, DB hoặc release/VPS lock. Có gián đoạn ngắn lúc restart ingress.

Lỗi cập nhật: khôi phục TLS cũ và giữ ingress dừng; journal vẫn còn. Chạy `recover-tls`
với config/manifest/seal để phục hồi, rồi review và `publish` lại. Nếu tiến trình bị
ngắt, không chạy raw `rc.py start`; adapter từ chối khi có journal. Journal chưa có
marker `ready` nghĩa là chưa đổi TLS và cần operator kiểm tra trước khi dọn journal.
Renewal từ chối ingress đang dừng/loopback hoặc approval hết hạn, không tự mở lại demo.
Đặt cảnh báo thất bại Certbot/expiry, không chỉ dựa vào timer. Diễn tập hook trên VPS
vẫn còn bắt buộc trước tuyên bố vận hành đã verified.

## Kiểm tra phần mới

`python3 -B -m unittest discover -s deploy/academic-linux/vps -p test_vps.py -v`
chạy offline, bao gồm SAN/key/chain/expiry bằng OpenSSL và journal rollback trên Linux.
`VPS_NATIVE_CHECKS=1 ... -p test_native.py` kiểm Compose merge và NGINX ACME bằng
image đã có: network none, không publish port, không mount volume hiện có, không pull.
Không thay thế host acceptance, scan candidate mới hoặc quyết định G8.
