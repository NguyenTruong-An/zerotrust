# GCP Fast-track Academic Deploy

**Owner decision 13/11/2026 (chat):** Hướng B — đưa full-function + D-10 strict lên Google Cloud theo **fast-track**, không theo đủ 39 task còn lại của [roadmap](PUBLIC_DEMO_ROADMAP.md). Hạn: buổi bảo vệ **trong vòng 1 tuần**. Ngày chính xác cần owner ghi vào D-07 bên dưới.

## Quyết định owner trong lượt này

| ID | Quyết định | Điều kiện |
|---|---|---|
| FT-01 | Fast-track Academic thay cho 8 phase đầy đủ | Giữ nguyên MFA, B0 (0,25×4; 40/75), Priority DENY, Missing Data, fail-closed, RBAC/ownership, TLS/CRL nội bộ, strict revocation D-10, secret/realm/store mới. Không copy dữ liệu/secret Lab hay local. |
| D-17 | **ACCEPTED, có thời hạn** cho Keycloak DHI 26.8.2 (3 High, gồm CVE-2026-54369) | Keycloak admin/master/management chỉ private; chỉ dữ liệu synthetic; tắt dịch vụ sau bảo vệ (D-07). Không tuyên bố FIXED. |
| D-07 | Tắt dịch vụ sau bảo vệ | **Owner điền ngày bảo vệ: `____`**. Expiry = ngày bảo vệ + 3 ngày. |
| EXEC | Owner tự cài Google Cloud SDK và đăng nhập trên máy Windows này | Claude chỉ chạy lệnh qua IAP; **hỏi trước mỗi thao tác thay đổi** (IP, firewall, upload, start). |

Những quyết định còn treo nhưng fast-track dùng mặc định đề xuất, owner xác nhận ở checkpoint T3: D-04 `portal.35.253.233.81.sslip.io` / `auth.35.253.233.81.sslip.io` + Let's Encrypt HTTP-01; D-05 1 ADMIN + 2 STUDENT synthetic cho giảng viên; D-08 RPO 24h / RTO 4h bằng snapshot đĩa GCE; D-12 xóa toàn bộ VM/disk/snapshot khi hết hạn.

## Kiến trúc triển khai

- 1 VM `zt-academic-private` (us-central1-a, Ubuntu 24.04, 4 vCPU/8 GiB), Docker Compose, mọi service không host port trừ ingress.
- **Fresh install V1→V9**: không cần cutover V7→V9 như local; migrator chạy một lần trên schema trống, cùng 5 image D-10 đã seal (`binding.phase3.json`), riêng frontend build lại cho hostname GCP.
- Edge: ingress NGINX nhận 443 với chứng chỉ Let's Encrypt cho Portal/Auth; phía sau giữ PKI/CRL nội bộ mới sinh trên VM. Cổng 80 chỉ mở cho ACME HTTP-01 và redirect.
- Keycloak admin/master/management không route ra edge; operator vào qua IAP SSH tunnel.
- Network Risk v2 giữ **SHADOW**, retention=false; B0 là policy live. GCP cho public peer thật nên có thể thu Network Context (gate GeoIP 2/7 còn lại).

## Các bước (checkpoint owner ở mỗi dấu ⛔)

| Bước | Việc | Ai | Kết quả cần có |
|---|---|---|---|
| T0 | Cài gcloud, `gcloud auth login`, chọn project/zone; preflight read-only VM qua IAP (OS, Docker, disk, RAM, firewall) | Owner cài · Claude chạy read-only | Receipt preflight |
| T1 | ⛔ Reserve Static External IP cho VM (tránh đổi IP → hỏng sslip/TLS) | Claude, sau khi owner OK | IP tĩnh khớp hostname |
| T2 | Tạo profile `deploy/gcp-fast-track`: compose Linux + config generator (từ `full-function/operate.py` + strict config `d10_isolated.py`), hostname sslip, frontend build GCP, fresh V1–V9, bootstrap service clients | Claude (local) | Profile + unit check |
| T3 | Rehearsal profile trên Docker local với hostname GCP (mạng riêng, không host port): login ADMIN/STUDENT + MFA, B0 LOW/MFA/DENY, RBAC 200/403/401, strict revoke/reset MFA, fail-closed | Claude (local, disposable) | Acceptance receipt |
| T4 | ⛔ Upload bundle (image tar + profile, **không** secret) qua IAP, `docker load`, so image ID | Claude, sau khi owner OK | ID khớp seal |
| T5 | ⛔ Sinh secret/CA/realm **trên VM**, start private (chỉ loopback), acceptance qua IAP tunnel | Claude, sau khi owner OK | Private acceptance PASS |
| T6 | ⛔ Snapshot đĩa (backup tối thiểu); mở firewall 80/443; xin chứng chỉ LE; mở public | Claude, sau khi owner OK | HTTPS hợp lệ, admin console không truy cập được từ Internet |
| T7 | Tạo tài khoản giảng viên (UPDATE_PASSWORD + CONFIGURE_TOTP lần đầu), giao qua kênh riêng của owner; smoke public từ trình duyệt owner | Owner giao credential · Claude tạo account | Teacher guide + public smoke |
| T8 | Sau bảo vệ: disable accounts, đóng firewall, xóa VM/disk/snapshot theo D-07/D-12 | ⛔ Owner duyệt xóa | Offboarding receipt |

## Rủi ro còn lại được chấp nhận (chỉ cho bản demo có thời hạn)

- D-17: 3 CVE High của Keycloak DHI chưa có bản vá.
- Không có CI đúng release SHA, SBOM/scan mới cho frontend GCP, load/soak test; chỉ smoke và acceptance chức năng.
- Một VM (SPOF), backup = snapshot thủ công, monitoring = health check thủ công/cron; không on-call.
- sslip.io là DNS bên thứ ba; rate limit Let's Encrypt.
- Network v2 chưa calibration (SHADOW, không ảnh hưởng quyết định).

Fast-track **không** đổi các mốc của roadmap: G1–G8 không được ghi PASS từ tài liệu này; đây là bản demo học thuật có thời hạn được owner chấp nhận rủi ro.
## Kết quả 13/11/2026

- Profile `deploy/gcp-fast-track`: cài mới V1→V9 D-10 strict, CA/realm/secret sinh trên VM, ingress loopback-only.
- Rehearsal local (hostname GCP): install PASS, 14/14 native strict PASS.
- VM `zt-academic-private` (owner đổi sang e2-highcpu-8 sau khi 4 vCPU = 2 lõi vật lý trượt ngân sách p95 Gateway 250 ms): install PASS, **14/14 native strict PASS** gồm performance smoke. Evidence: `target/gcp-fast-track/vm-evidence-20261113/`.
- Chưa mở 80/443, chưa có chứng chỉ Let's Encrypt, chưa tạo tài khoản giảng viên. CRL nội bộ hết hạn sau 7 ngày kể từ lúc cài.

