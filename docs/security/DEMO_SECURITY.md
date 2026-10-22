# Bảo vệ và giới hạn Development/Demo

Giữ nguyên security contract của baseline894e7fc: JWT issuer/audience/expiry/signature, mandatory subject và RBAC/ownership; Risk LOW/STEP_UP_MFA/DENY, cold-start/incomplete guard, priority deny; OTP thực do Keycloak xác thực. A04 mapping native FK-conflict đã có trong committed Backend, không dùng QA JAR override.

Secrets và TLS keys sinh mới cho từng private store, không đặt trong Docker image/Git/Env inspect. Ứng dụng chỉ mount role config của mình. MySQL require secure transport, Redis authenticated TLS, Java trust CA/hostname. Chỉ HTTPS loopback8443/8444 và HTTP8445 phục vụ signed CRL công khai; CRL service không có secret và không phục vụ API đăng nhập. Windows Schannel verification đã PASS mà không tắt revocation. Runtime Risk không có DDL; migration job riêng dùng account khác và guard writers-quiesced thật. Flyway V1–V5 không sửa; V5=661092940, subject/client columns0900_bin/NO PAD.

PKCE S256 bắt buộc; SPA default client scopes có `basic` để phát sub. Keycloak quản lý enrollment bằng CONFIGURE_TOTP, không seed OTP credential bằng SQL. `basic` cung cấp subject mapper theo [Keycloak upgrade guide](https://github.com/keycloak/keycloak/blob/main/docs/documentation/upgrading/topics/changes/changes-25_0_0.adoc); không bỏ subject validation để chữa401.

Đây là local Development/Demo: tài khoản bootstrap/admin, CA private và service secrets cùng private store cần được bảo vệ bằng Windows account/backup. CA chưa tự cài vào trust store. Network CIDR synthetic và history fixtures chỉ dành Demo; weights/thresholds không đổi. Không coi local service identities, static dataset hoặc health checks là production hardening.

Stateless access tokens có thể còn hợp lệ tới expiry sau logout/trust revoke. SSO có thể bỏ Risk khi không thực hiện fresh password login. Redis outage có thể khiến Keycloak timeout rồi fail-closed DENY; không khẳng định luôn ra OTP. Ba frozen cases P05/W02/F03 vẫn là FAIL lịch sử trong báo cáo `docs/qa-postfix/QA02C_PORTAL_GATEWAY_FULL_E2E_REPORT.md` được giữ tại original checkout, không được đổi assertion. Thư mục QA đó là evidence local chưa có trong baseline clone; không copy dirty evidence vào candidate.

Fresh acceptance và giới hạn Windows manual được ghi riêng trong [completion report](../demo/COMPLETION_REPORT.md). Không dùng kết quả QA02C làm PASS cho môi trường mới. Không tuyên bố security certification toàn hệ thống.
