# Academic Demo local

Triển khai Compose cô lập dùng canonical source và dữ liệu synthetic. Chỉ NGINX bind `127.0.0.1:19443`. Ingress giữ hostname/issuer riêng, giới hạn request và chặn đường management/Observatory. Compose dùng project `zt-academic-demo`, bridge nội bộ, named volumes riêng và config read-only theo từng process. Quay và MySQL 8.0.46 là baseline staging. Quyết định release và tình trạng nghiệm thu nằm tại [Master Roadmap](../../docs/production-readiness/PUBLIC_DEMO_ROADMAP.md).

## Dựng và kiểm tại máy staging

Cần Docker Engine Linux/amd64, Docker Compose v2/v5, Python 3 với `cryptography`, JDK 17 `keytool` và bốn image staging đã pin trong `academic_demo.py`. Dùng `playwright` với Chromium hoặc Chrome để chạy browser smoke. `age` và `age-keygen` chỉ cần cho diễn tập backup. Tại checkout hiện hành có thể dùng Python venv của candidate từ PD-R11.

```text
docker buildx build --platform linux/amd64 --load -f deploy/docker/Dockerfile.frontend --build-arg NODE_IMAGE=node:24.22.2-alpine@sha256:ec318aabf188af4e5488847eea4b24452650b9917140563e140762526a37f1df --build-arg KEYCLOAK_URL=https://auth.academic-demo.test:19443 --build-arg KEYCLOAK_REALM=academic-demo --build-arg PORTAL_MODE=public-demo --build-arg SITE_URL=https://portal.academic-demo.test:19443 --build-arg RUN_CHECKS=true -t zt-academic-demo/frontend:alpine .
python deploy/academic-demo/academic_demo.py start
python deploy/academic-demo/academic_demo.py status
python deploy/academic-demo/smoke.py
python deploy/academic-demo/risk_smoke.py
```

Chạy từng ca `smoke.py --risk-outage`, `risk_smoke.py --redis-outage` và backup rehearsal khi không có người đang demo. Các ca này dừng service synthetic trong scope rồi khôi phục lại.

App dùng realm `academic-demo` và CA tự sinh. Lệnh smoke tự ánh xạ hai hostname vào loopback bằng browser profile riêng và xác minh CA/SAN bằng HTTP client. Với trình duyệt tương tác, dùng cùng ánh xạ tên trong cấu hình trình duyệt hoặc DNS staging riêng, rồi cấu hình trust cho **CA staging** theo quy trình máy thử. URL Portal là `https://portal.academic-demo.test:19443`. Lấy thông tin account từ tệp riêng `target/academic-demo/private/accounts.json` qua kênh được bảo vệ. Tạo mới secrets ở máy đích bằng bootstrap.

Trên Linux staging, dùng daemon local. Chuyển các image app đã kiểm bằng `docker image save`/`docker image load` với các tag trong Compose, đối chiếu ID trong manifest trước khi chạy. Giữ nguyên project/hostnames cho lane loopback. Để chuyển sang Linux VPS có truy cập giảng viên, cần owner chốt D-04 và cung cấp hostname/DNS, chứng thư hợp lệ và kênh truy cập. Tạo bản phát hành với issuer/redirect/CORS và `NEXT_PUBLIC` build args của hostname đó, sau đó kiểm TLS, browser, proxy và giới hạn tài khoản trên chính host đích. [Hợp đồng ingress](../public-demo/INGRESS_CONTRACT.md) · [Hợp đồng config và dữ liệu](../public-demo/README.md)

## Vận hành và khôi phục

- `status` kiểm trạng thái container và health. Ingress kiểm HTTP qua Gateway; Gateway tự kiểm HTTPS và từ chối peer đi thẳng. Cảnh báo khi ingress, Keycloak, Risk hoặc MySQL không healthy.
- `docker stats --no-stream` để xem CPU/RAM của service và `docker system df` để xem dung lượng trên máy staging. Profile có cap RAM/CPU, restart policy và log local giới hạn 3 tệp × 10 MB. Chỉ đọc log service thuộc project và lọc payload/credentials trước khi chia sẻ.
- `python deploy/academic-demo/backup_rehearsal.py` quiesce writers, xuất ba schema synthetic, mã hóa age và thử import vào MySQL 8.4.13 riêng qua Unix socket. Identity để tách khỏi archive. Recovery volume giữ lại để kiểm chứng, lệnh dừng nếu schema đích đã có dữ liệu.
- `python deploy/academic-demo/academic_demo.py stop` dừng service của profile. `start` tái sử dụng realm và dữ liệu. Khi redeploy, giữ cặp image digest và snapshot tương thích, thử restore vào schema mới trước khi chuyển traffic. Profile có Redis AOF, backup SQL bao gồm School, Risk và Keycloak.
- Kết thúc demo, ngừng cấp account, thu hồi phiên/tài khoản và access gate, đóng ingress theo quyết định owner, lưu archive mã hóa và xử lý dữ liệu theo thời hạn đã duyệt. Lab có quy trình riêng.
