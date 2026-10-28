# Bàn giao Development/Demo — 2026-10-23

> **Báo cáo lịch sử.** Ngày 27/10/2026, chủ đồ án xác nhận chỉ làm hệ thống xem điểm
> với ADMIN/STUDENT và yêu cầu gỡ Teacher, phân công, lịch học. Các kết quả Teacher,
> schedule và A04 bên dưới chỉ áp dụng cho bản build ngày 23/10, không còn là yêu cầu
> nghiệm thu hiện tại và không được dùng làm PASS cho source mới. Xem
> [kiến trúc hiện tại](../../ARCHITECTURE.md), [runbook đã cập nhật](DEMO_RUNBOOK.md)
> và [kiểm tra phát triển](../development/DEVELOPMENT_CHECKS.md).

Môi trường `zerotrust-demo` hoạt động độc lập QA02C, build từ parent baseline GitHub **894e7fcb1adb960e7c1c057b0d0713fcb2307c26** và35 paths packaging. Đã xác minh ancestry FIX-01–08/POSTFIX03A/03B, source dùng cho QA02C và A04 trong committed Backend. Commit packaging là commit chứa tài liệu này trên branch `zerotrust-v4-risk-scoring`; exact SHA có thể đọc bằng `git log -1 --format=%H`. [GitHub branch](https://github.com/NguyenTruong-An/zerotrust/tree/zerotrust-v4-risk-scoring).

Candidate: `output/development-demo/workspace` trong original checkout. Bộ evidence ở thư mục cha `output/development-demo`; không đưa secret hoặc private backups vào patch. Original HEAD/index và43 tracked dirty paths được giữ nguyên. Tất cả22 container cũ giữ nguyên ID/image/state; chưa cleanup lịch sử.

## Đã triển khai

- Một Compose, network riêng, hai volume mới `zerotrust-demo-mysql-final`/`zerotrust-demo-redis-final`; bảy dịch vụ ứng dụng cộng static signed-CRL server và hai job init/migrate. Tools là profile tùy chọn, không chạy mặc định.
- Multi-stage source builds cho Backend/Gateway/Risk/SPI/Next. Không dùng QA JAR, DB/Redis volume, browser hay fault proxy. Version/digest upstream được pin.
- CA/keys/passwords/service identities/realm mới, lưu riêng trong `.local-demo` bị Git bỏ qua. Runtime chỉ mount role config riêng. Browser OIDC Code+PKCE S256, official TOTP enrollment; JWT/MFA/ownership/Risk policy giữ nguyên.
- Risk Flyway V1–V5 nguyên vẹn, V5=**661092940**; bootstrap initial0900_ai_ci, xác minh writers quiesced trước V5. Năm cột identity0900_bin/NO PAD. Risk runtime không có CREATE/ALTER/DROP; School validate schema.
- Helpers `.cmd`/`.ps1` start/stop/status/logs/build. `.cmd` không thay PowerShell Execution Policy. Stop/start giữ dữ liệu.
- README và đường setup chính đã chuẩn hóa; giữ tài liệu học thuật/QA/evidence. Chỉ xóa hai tracked config cũ `frontend/vite.config.ts`, `frontend/.openai/hosting.json`, bỏ dependency Vinext/Vite/Cloudflare/Sites không còn dùng. [Phân loại file](../archive/README.md); exact danh sách/hash trong `file-changes.json` của bộ bàn giao.

## Kiểm chứng trên Demo mới

| Phạm vi | Kết quả và evidence trong bộ bàn giao |
|---|---|
| Source build | PASS; Backend focused21 tests,0failure; frontend lint/typecheck/Next build PASS. `build.log`, `build-final-package.log`, `build-release-candidate.log`. |
| Startup | PASS;8 dịch vụ lâu dài healthy, init/migrate exit0. `fresh-install-final.log`, `final-health.log`, `docker-after.json`. |
| LOW | PASS; Risk0/LOW/COMPLETE/ALLOW, OIDC token được cấp, không OTP. `acceptance-evidence/smoke-normal.json`. |
| MEDIUM | PASS; real Risk INCOMPLETE/MEDIUM/STEP_UP_MFA và real Keycloak OTP. `acceptance-evidence/medium.json`, `medium-proof.log`, smoke-normal. |
| HIGH | PASS; real peer172.30.80.200, Risk95/HIGH/COMPLETE/DENY, Keycloak403, không code/token. `acceptance-evidence/smoke-high.json`. |
| Student | PASS; profile/grades/schedules200, role khác403. |
| Teacher | PASS; roster, grade update9.5 rồi restore; foreign assignment/student404. |
| Admin/A04 | PASS; đổi phòng rồi restore; xóa assignment còn schedule409 bằng Backend source, không JAR override. |
| JWT/logout | PASS; tampered token401, RBAC/ownership, logout rồi fresh login/OTP. Smoke normal và verifier source. |
| Database | PASS; đúng schema, FK/identity và Flyway/grants. `schema-security.json`. |
| Persistence | PASS; School rows, Keycloak users/credentials/clients/flows, Flyway và MySQL UUID giữ nguyên; Redis authenticated TLS/AOF marker còn sau stop/start. `persistence-result.json`. |
| Windows HTTPS | PASS qua native curl/Schannel, CA file và revocation verification; Portal8443 và discovery8444 trả200. `windows-https.json`. Không sửa global trust/hosts/registry. |
| Fresh reproduction | PASS; sau sửa template, dùng private store và volume rỗng độc lập: bootstrap/migration, official enrollment, OIDC subject, Student APIs và HIGH engine. `fresh-source-oidc-proof.log`, `fresh-high-engine.log`. |
| Bảo toàn | PASS; `preservation.json`, inventory trước/sau. |

Full functional suite chạy trên bản cài Demo mới thứ nhất. Bản cài độc lập cuối từ template đã sửa chỉ chạy startup, một Student OIDC/enrollment/API proof, HIGH engine và persistence; không lặp lại toàn bộ suite. Tổng thực tế12 SPA OIDC transactions,10 OTP submissions trên hai bản cài (gồm chẩn đoán), không chạy frozen55. Test history gồm10 synthetic success/5 failure events qua Risk API có phân quyền; không sửa weights/thresholds hoặc hardcode quyết định.

Lỗi packaging đã sửa: UID file permissions; initial Risk collation; realm import basename; client scope `basic` để token có subject; OTP counter reuse trong verifier; CRL Distribution Point để Windows Schannel kiểm tra revocation. Không nới JWT/MFA/assertion. Các helper chẩn đoán/khôi phục một lần được giữ ngoài candidate; bản cài cuối không cần chúng.

Exact JAR SHA256 (image/container IDs và frontend BUILD_ID trong `artifact-provenance.json`):

| Artifact | SHA256 |
|---|---|
| Backend | `db96121e7da45fc1234f679dc45ae8f1056fe8fd8b5814ec2b3c00ed9016ff37` |
| Gateway | `eae8f291f528f5d15588d4c4ff974f48ffd2e2bc869f94a54d09e935f9ca0428` |
| Risk | `c85a499855a7b6c512986f79c507f6ce8d77d29e51a7013a301c53583a7cfe7a` |
| SPI | `d7808ea21d644745cd147f9570b062da6ede5972a14e73d8841f49bade96ef19` |

## Giới hạn còn lại

**Chưa manual Windows browser PASS.** Người trình bày cần tự chấp thuận CA và diễn tập Student/Teacher/Admin UI theo [setup](../setup/DEVELOPMENT_DEMO.md#tls-trên-windows) và [runbook](DEMO_RUNBOOK.md). HTTPS Windows đã được kiểm tra bằng native client, không thay thế tương tác browser thực tế. HIGH lane là peer container, không phải IP Windows browser. CRL có hạn7ngày và refresh khi start. Access token stateless có thể còn hiệu lực tới expiry sau logout; SSO có thể bỏ fresh Risk evaluation. P05/W02/F03 giữ FAIL lịch sử. Đây là local Development/Demo, không phải chứng nhận production security.

## Controlled cleanup — đã được phê duyệt, chỉ chạy sau push PASS

Owner đã phê duyệt một lần commit/push và cleanup ngày23/10/2026. Exact full IDs/image allowlist trong `cleanup-proposal.json` của bộ bàn giao local. Chỉ sau push và Demo health PASS mới stop/remove các container dưới đây, rồi xóa tối đa9 image riêng không còn container tham chiếu; identity mismatch/shared image được skip. Không force/prune, không xóa network, volume, DB hoặc backup. Tài liệu trong commit ghi checkpoint trước cleanup; snapshot cuối với SHA và kết quả thực tế được cập nhật local sau cleanup, không tạo commit thứ hai.

| Container | ID prefix |
|---|---|
| qa02c-5a51c51a-frontend | 625501b74fa2 |
| qa02c-5a51c51a-backend | 20b9da501c32 |
| qa02c-5a51c51a-risk | dede7be86cd1 |
| qa02c-5a51c51a-gateway | 3cebb891695d |
| qa02c-5a51c51a-keycloak | 84e010ab2424 |
| qa02c-5a51c51a-browser | 83f750d9c015 |
| qa02c-5a51c51a-high-browser | 581f0ab4e271 |
| qa02b-899effc1-harness | 45d00b1f35af |
| qa02b-899effc1-high-browser | 3b7c2cd25372 |
| qa02b-899effc1-keycloak | aaa01ed021f4 |
| qa02b-899effc1-risk | 5d6a2fe4011f |

Giữ tất cả historical MySQL/Redis containers/volumes, operational Keycloak/Risk DB/Redis, tài nguyên không rõ owner, toàn bộ evidence/academic docs/private backups. Demo mới không tham chiếu bất cứ image/volume/network QA nào. Việc dọn các container QA này sẽ ngừng khả năng mở trực tiếp stack QA cũ; dữ liệu và image backup vẫn được bảo toàn.

Đã backup config container riêng tư và Docker-save9 images vào `cleanup-private/retired-qa-images.private.tar.gz` (2290921487bytes; SHA256 `59951c336224e58c414ec73527254a2435e68b8483575840d32a6d43ffc6f165`). QA database/volumes/backups hiện có được giữ nguyên; không cần tháo/xóa DB để dọn stateless containers.

## Lệnh chính thức từ clone GitHub mới

```powershell
git clone --branch zerotrust-v4-risk-scoring https://github.com/NguyenTruong-An/zerotrust.git
cd zerotrust
.\scripts\demo\demo.cmd build
.\scripts\demo\demo.cmd start
.\scripts\demo\demo.cmd status
.\scripts\demo\demo.cmd stop
```

`stop` giữ dữ liệu. Nếu Demo đang chạy từ candidate trên cùng máy, quản lý instance đó từ candidate; không start một private store mới lên các volume đang dùng. Cài CA và rehearsal thủ công theo [setup](../setup/DEVELOPMENT_DEMO.md), [checklist](DEMO_RUNBOOK.md#rehearsal-thủ-công). Manual Windows browser: **NOT_VERIFIED**.
