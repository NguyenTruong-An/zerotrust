# D-10 — packet cho một controlled deployment

**OFFLINE ONLY.** Owner đã chọn B cho engineering. Packet này không cho phép APPLY/deploy/restart hoặc reset tài khoản thật. [Thiết kế và evidence](../../../docs/authentication/D10_STRICT_PHASE2.md). Không dùng binding, controller hoặc request Network v2.

`contract.json` định nghĩa TLS, roles, schema và flow delta. `binding.offline.json` chỉ được seal sau targeted/native tests PASS, pin năm image ID, JAR/source/evidence hashes và baseline active. `validate.py` chỉ đọc file và Docker image metadata, không có action triển khai. Không đưa compose/CA/secrets/fault proxy/accounts của fixture vào release. Đây là local image ID binding, chưa là registry publication/signature.

## Phê duyệt và checkpoint bắt buộc cho Phase3

Owner phê duyệt một maintenance window, gián đoạn bảo vệ API, force fresh login của sessions cũ, fail-closed503 khi authority lỗi và native acceptance bằng tài khoản test được chỉ định riêng. B đã được duyệt, không yêu cầu chốt lại chính sách. Không dùng tài khoản owner cho reset/revoke phá hủy.

Trước mutation cần bind exact live inventory/config/flow delta và kiểm tra local JPA, reserved receipt attributes không thể sửa qua Account Profile, TLS/CRL, service role scopes, authority DB writer grants, schema V7 và trạng thái pending hiện hữu. Không nhập full fixture realm. Chưa có executor active hoặc authorization ở packet này.

## Trình tự cutover đề xuất

1. Đóng protected ingress và direct Backend paths cho human traffic; quiesce Portal mutations/native identity writers. Giữ health/JWKS/machine bootstrap qua đường nội bộ đã kiểm soát. Không cho writer cũ và mới chạy song song.
2. Tạo checkpoint nhất quán MySQL School/Risk/Keycloak, realm/flow/client config, current MFA/device/revocation state, image/volume inventory. Backup mã hóa bằng công cụ đã duyệt, khóa/retention/access control do owner quản lý; chỉ ghi receipt/hash, không export token/password/OTP vào evidence. Xác minh khả năng restore trên disposable lane, không restore active để diễn tập.
3. Apply V8/V9 additive bằng migrator một lần; kiểm checksum V1–V7, không drop/downgrade. Nếu V7 pending chưa giải quyết: giữ pending và dừng cutover, không xóa. Provision ba service clients/roles và TLS/secret mounts mới, không reuse credentials fixture.
4. Install Risk authority, native issuer/global mutation gate và reviewed browser flow; rồi Backend/Gateway gates và frontend candidate dưới maintenance. Health/JWKS machine bootstrap phải hoạt động trước human issuance. Thiếu gate/claim/service credential là fail-closed, không có khoảng bearer-only; legacy JWT/SSO/refresh thiếu epoch không được upgrade.
5. Kiểm exact images/config, V9 single writer, TLS/CRL và issuer; dùng tài khoản acceptance mới để kiểm MFA, API200/403/401/ownership, oldJWT/paused-code/SSO/refresh deny, native password/disable/logout, proof/UNKNOWN/reset recovery, other-subject isolation và B0/SHADOW. Kiểm UI challenge→reauth→confirm, timeout, user-visible pending, SSO policy effective; không cần lặp full integration đã PASS nếu không đổi scope.
6. Chỉ mở human traffic sau mọi gate và acceptance bắt buộc PASS. Giữ Network v2 SHADOW/retention=false. Native acceptance runtime đích mới cho phép xét đóng D-10.

## Rollback và UNKNOWN

- Không chạy rollback security state. V8/V9, epoch/tombstones, device generation, pending, native receipts, credentials và required actions hiện tại phải giữ nguyên; không hồi sinh trust/session/token từ checkpoint.
- Chỉ đổi artifact/flow sang bản **còn strict-compatible** đã kiểm. Hiện chưa có old strict pin được nghiệm thu; nếu candidate lỗi, giữ maintenance fail-closed và sửa candidate. Old V7 bearer-only images không phải rollback đón human traffic hợp lệ.
- Timeout/remote UNKNOWN giữ operation/effect hiện hành; resume theo receipt dưới native row lock. Không replay mutation bằng UUID mới, clear pending thủ công hoặc supersede để vượt lỗi.
- Backup/restore là kế hoạch disaster recovery riêng, không là rollback D10: trước khi restore cần authorization mới, fence toàn bộ traffic và bảo toàn/merge monotonic security state bằng thủ tục được kiểm. Nếu chưa chứng minh merge an toàn, tiếp tục fail-closed. Không tự restore snapshot cũ.

## Điều kiện Go/No-Go

Offline PASS cho phép chuẩn bị Phase3; không tự cấp quyền thực thi. Phase3 NO-GO nếu thiếu owner authorization, checkpoint/restore rehearsal phù hợp, executor maintenance riêng đã review, reserved-attribute check, current pending reconciliation hoặc exact runtime acceptance. Public-network calibration, D-17 và G8 là gate riêng; không suy từ D10 offline.
