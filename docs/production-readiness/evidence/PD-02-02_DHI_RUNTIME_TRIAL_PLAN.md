# PD-02-02 — Kế hoạch thử nghiệm runtime Keycloak DHI

**PD-R18 · 08/11/2026 (Asia/Saigon) · Kế hoạch sẵn sàng · D-17 PENDING**

Kế hoạch chỉ áp dụng khi owner duyệt D-17 trên exact base digest đã qua triage. Candidate đang dùng là Quay 26.8.2, image ZeroTrust `sha256:e06bec13a903df01c1fd80b590d328db99ecbc4b00ee6ce3baa6f10f5f142615`. Phương án thử DHI dùng Linux amd64 `sha256:44b3665b60304cb4448e3ab9943ab02727ee793c2ec4b954d2de2ee84f28b892` hoặc digest thay thế được xác minh và owner duyệt riêng. Kết quả runtime cũ chỉ dùng làm đối chứng. [Rootfs và triage](PD-02-02_DHI_ROOTFS_SECURITY_VERIFICATION.md) · [Chữ ký OCI](PD-02-02_DHI_EXACT_ARTIFACT_VERIFICATION.md#16-pd-r17) · [Candidate Quay](PD-02-02_CANDIDATE_RUNTIME_CLOSEOUT.md)

## 1. Khác biệt và phạm vi thay đổi dự kiến

| Điểm kiểm | Phân loại | Hành động sau approval |
|---|---|---|
| Server/API và Java | **Compatible by inspection.** Cùng Keycloak 26.8.2. SPI profile candidate compile Java 17 với API provided 26.8.2; DHI Temurin 21. | Giữ API profile và bytecode target. Chạy provider discovery và startup để kiểm linkage thật, kiểm server chỉ có một bộ Guava hiệu lực. |
| OS và ownership | **Requires adjustment.** Quay dùng layout/ownership `keycloak:keycloak`. DHI OCI config dùng UID 65532; user/group DHI là `nonroot`. | Thử thay `COPY --chown` bằng UID/GID đã xác minh, giữ process nonroot. Kiểm rootless mapping và quyền owner trên Linux host thực. |
| Provider, theme và augmentation | **Requires adjustment.** Recipe hiện copy provider vào `/opt/keycloak/providers` và theme vào `/opt/keycloak/themes`, rồi chạy `kc.sh build --db=mysql --health-enabled=true`. | Pin DHI cho cả stage augmentation và final stage. Cài SPI/theme trước `build`. Chép output tối ưu đúng ownership. Chạy `start --optimized` trên artifact derived, kiểm providers và theme bằng readback/browser. |
| Entrypoint và health | **Needs runtime verification.** DHI OCI config dùng `/opt/keycloak/bin/kc.sh`, CMD `start --optimized`, workdir `/`, expose 8080/8443/9000 và không khai báo Docker Healthcheck. | Giữ command/profile rõ ràng. Kiểm health/readiness ở management interface private và kiểm OIDC discovery, DB-ready riêng. Kiểm temp/data cần ghi với read-only rootfs trước khi bật guard vận hành. |
| DB và schema | **Compatible by inspection**, MySQL Connector/J 9.7.0 trong DHI. | Giữ MySQL 8.0.46 fixture, TLS verify hostname, thử realm import/readback trên schema riêng. V5 `661092940` chỉ kiểm invariant bên Risk, giữ engine và Flyway hiện có. |
| TLS/CA và crypto | **Needs runtime verification.** Rootfs DHI có CA bundle `/etc/ssl/certs/ca-certificates.crt` và Temurin truststore `/usr/lib/jvm/temurin-21/lib/security/cacerts`. | Kiểm truststore thực tế được JVM và Connector/J dùng. Kiểm HTTPS/TLS và certificate hostname giữa SPI/Risk và MySQL, cùng ca từ chối chứng thư sai. |
| Config và secret-file | **Requires adjustment / needs runtime verification.** Private Keycloak config và SPI đọc file theo contract. | Tạo secret/config synthetic riêng, mount chỉ đọc, quyền tối thiểu cho UID mới; kiểm readback quyền và fail-fast khi file thiếu. Giữ issuer/redirect/caller bindings. |

Các tệp dự kiến thay đổi sau approval là [Dockerfile Keycloak Public Demo](../../../deploy/public-demo/Dockerfile.keycloak) và cấu hình/harness candidate synthetic phục vụ UID, truststore và startup. [SPI POM](../../../keycloak-risk-extension/pom.xml) là nguồn kiểm profile, thay đổi chỉ khi có lỗi API được chứng minh. [Secret contract](../../../deploy/public-demo/SECRETS_IDENTITY_CONTRACT.md) và [configuration contract](../../../deploy/public-demo/configuration-contract.json) là tiêu chuẩn kiểm. Phân tích tĩnh PD-R18 chưa xác nhận điểm không tương thích chặn startup.

## 2. Cổng bắt đầu thử nghiệm

1. Owner duyệt D-17 cho base digest và scope tài nguyên, sau khi Critical/High được triage và SQLite/Guava disposition đủ evidence. Ghi expected derived digest sau build và liên kết source snapshot, SBOM, scanner DB.
2. Tạo project/bridge private và candidate volumes riêng được gắn ownership label. Dùng tên/alias distinct, dữ liệu synthetic, issuer riêng, MySQL schema riêng, TLS/CA, signing keys, realm/accounts, mật khẩu và history riêng. Không expose public, không lấy bất kỳ tài nguyên Lab nào. Giữ base Quay và image ZeroTrust gốc để rollback.
3. Kiểm preflight trước khi chạy gồm metadata Lab/candidate, inventory image/volume/network, hash các file, secret ACL, expected 10 Lab Exited theo mốc đối chiếu. So sánh sau theo identity/status và dữ liệu cần bảo toàn. Định lượng CPU/RAM/disk sau thử có giới hạn; PD-R18 chưa có số đo runtime DHI.

## 3. Ma trận regression sau approval

Các lane dưới đây tái sử dụng logic của [runtime harness](../../../target/pd-02-02-runtime/harness.py), [readback/logout](../../../target/pd-02-02-runtime/readback.py), [Browser](../../../target/pd-02-02-runtime/browser_suite.py), [API B0/RBAC](../../../target/pd-02-02-runtime/api.py), [fault cases](../../../target/pd-02-02-runtime/faults.py) và [logical restore](../../../target/pd-02-02-runtime/rollback.py). Các script cũ gắn với candidate cũ. Tách resource prefix, fixture/schema, digests và preflight theo scope được duyệt trước khi tái sử dụng. Tái dùng assertion, fixture synthetic và cấu trúc receipt, ghi kết quả DHI mới.

| Ca | Hành vi cần thấy | Evidence |
|---|---|---|
| 1. Startup | Optimized startup hoàn tất, readiness/management private, discovery đúng issuer. | Startup/readiness + exact digest/config. |
| 2. Custom SPI | Provider factory, listener và theme được load. | Readback provider/JAR digest, browser theme. |
| 3. Browser Flow | Password → Risk → conditional OTP → trust registration theo execution chain. | Realm REST readback và một fresh browser flow. |
| 4. Authorization Code + PKCE | S256 đúng thì exchange thành công, verifier sai bị từ chối. | Browser/token endpoint, dữ liệu đã lọc. |
| 5. MFA enrollment | Required action enroll TOTP, không coi enroll là OTP đã hoàn tất hay đã cấp trust. | Execution receipt và trust state trước/sau. |
| 6. Correct/wrong OTP | OTP đúng mới hoàn tất login, OTP sai không phát token/cookie trust. | Hai kết quả và state. |
| 7. Trusted Device register/revoke | OTP proof và subject/session đúng mới register; revoke làm lần login kế tiếp step-up khi có yêu cầu. | Generation/state và browser evidence. |
| 8. B0 LOW/MEDIUM/HIGH | Đo ba ca numeric tách riêng, xác nhận ngưỡng và ALLOW/STEP_UP_MFA/DENY. | API response và enforcement cùng evaluation. |
| 9. Mandatory MFA | LOW numeric vẫn lên MEDIUM/STEP_UP_MFA khi guard yêu cầu. HIGH vẫn DENY. | Effective band, score và decision. |
| 10. Priority DENY | DENY trước scoring, score null, NOT_EVALUATED. | Priority reason và deny không có code/token. |
| 11. Missing Data | INCOMPLETE, score null, STEP_UP_MFA khi Risk trả kết quả hợp lệ. | Score/status và challenge. |
| 12. Fail-closed | Timeout, TLS/token/payload lỗi theo fault harness tạo deny đúng config. | Evidence không phát token và reason kỹ thuật. |
| 13. JWT/service identity | Caller đúng role/audience/azp được phép, token sai issuer/audience/caller bị từ chối. | JWT/Risk API matrix và routing private. |
| 14. ADMIN/STUDENT RBAC | Student xem dữ liệu của mình, không có quyền Admin. Admin dùng đúng lane Admin. | Hai actor, positive/negative API. |
| 15. Academic read-only | GET hợp lệ; ghi học vụ bị deny ở direct backend, School grants SELECT-only. | HTTP response + kiểm DB state không đổi. |
| 16. MySQL/realm | Schema synthetic tách riêng, import/readback realm/client/flow/session policy, V5 ledger invariant của Risk. | Snapshot/readback và checksum. |
| 17. TLS | Chuỗi CA/hostname đúng từ browser, SPI và MySQL; lỗi chứng thư bị chặn. | Positive/negative TLS, chưa public PKI. |
| 18. Session/logout/refresh | RP logout invalidates refresh, session/cookie không được tái dùng sai. | Browser logout + refresh denial. |
| 19. Security rescan | Exact derived artifact có signed/provenance chain, SBOM, scan và dispositions Critical/High được review. | Raw scan và per-finding decision. |
| 20. Rollback | Quay gốc khôi phục được với schema snapshot riêng, không mở DB sau trial bằng binary cũ. | Restore receipt, realm/key IDs, PKCE/OTP, logout/trust smoke. |

## 4. Rollback và acceptance

Trước trial, lưu metadata/digests của Quay candidate và snapshot logic có checksum cho candidate data, realm, config và ledger; giữ secrets/keys private đúng scope. Tách schema/volumes thử DHI khỏi snapshot gốc. Khi DHI lỗi startup, vi phạm policy hoặc không qua triage, dừng các trial writers, giữ evidence, loại trial khỏi lane và chỉ khôi phục snapshot vào schema riêng bằng image gốc theo scope được duyệt. Kiểm realm, issuer, key IDs, browser PKCE/OTP, trust/revoke, logout, TLS và V5 trước khi coi rollback đạt. Không restore lên Lab và không hạ phiên bản trên schema đã migrate. [Kết quả logical restore cũ](../../../target/pd-02-02-runtime/rollback-results.txt)

**Tiêu chí:** đủ 20 lane theo digest/config thật, không còn Critical/High applicable chưa xử lý hoặc chưa có quyết định được owner duyệt, rollback đã diễn tập, Lab/source được bảo toàn. PD-R18 hoàn thành kế hoạch, toàn bộ runtime DHI vẫn **NOT_VERIFIED**.
