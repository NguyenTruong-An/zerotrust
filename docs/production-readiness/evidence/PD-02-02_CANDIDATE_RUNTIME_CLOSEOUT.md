# PD-02-02 — Candidate image, runtime cô lập và security closeout

**EV-PD-02-02-04 · PD-R11 · 07/11/2026 (Asia/Saigon) · PARTIAL · NO-GO FOR PUBLIC ACCESS**

## 1. Baseline PD-R10

Canonical branch **zerotrust-v4-risk-scoring**, HEAD **c401e17029d64f9a96738d845b8c0ad0f03fc164**, ahead 3, working tree có thay đổi từ các checkpoint trước. D-15 duyệt Boot 4.1.2, Cloud 2025.1.4, Gateway 5.0.4 trên Java 17. D-16 duyệt Keycloak 26.8.2 và provided API tương ứng. D-16-RUNTIME cho phép thử nghiệm synthetic cô lập. D-10/D-13 vẫn PENDING. PD-R10 đã có source migration, 1.800 Java PASS/123 SKIP và 98 frontend/viewer/Python PASS. [EV-PD-02-02-01](PD-02-02_DEPENDENCY_REMEDIATION.md) · [EV-PD-02-02-02](PD-02-02_PLATFORM_DECISION_AND_CLOSEOUT.md) · [EV-PD-02-02-03](PD-02-02_CONTROLLED_PLATFORM_MIGRATION.md)

## 2. Docker daemon preflight

Docker Desktop context **desktop-linux**, Engine **29.4.1**, linux/amd64, overlayfs, Compose **5.1.3**, Buildx **0.33.0**. Engine có 12 CPU và 7,62 GiB RAM. Đĩa C còn khoảng 97 GB lúc preflight. Baseline có 24 container, 8 network, 30 volume và 57 image. Mười container thuộc Lab `zerotrust-legacy-integration-20261026` đang chạy, dùng các cổng loopback 28443–28445. Chỉ thu metadata được chọn từ Docker, gồm state, image, cổng, mount reference, restart policy và network.

## 3. Xác minh ranh giới cô lập

Bridge `zt-pd02-candidate-core` có `Internal=true`, subnet `172.31.228.0/24` và ID `78f328bf12240fb026921d60d63b2b8f3e101364a4a04545f4ae35fe0dd768a4`. Subnet tách khỏi các network Docker hiện có. Chỉ các container mang nhãn `com.zerotrust.purpose=pd-02-02` tham gia. MySQL, Redis và Keycloak management không có cổng host. Host truy cập HTTPS bằng relay TCP chỉ bind `127.0.0.1:38441–38444`, đi qua probe trên bridge và giữ nguyên TLS tới dịch vụ. Installer ban đầu yêu cầu Docker publish loopback trên internal bridge, nhưng Docker không công bố cổng thực tế. Installer đã dừng trước khi runtime dùng relay. Test Python xác minh CA synthetic và hostname, với cờ X.509 strict riêng được tắt do fixture thiếu Authority Key Identifier. Chrome pin SPKI của leaf Keycloak cho phiên kiểm thử. [Docker bridge driver](https://docs.docker.com/engine/network/drivers/bridge/)

Các ứng dụng dùng marker cấu hình `staging` để kích hoạt kiểm tra schema `pd_staging_*`. Đây là candidate cục bộ dưới D-16-RUNTIME. CA, chứng thư, signing keys, realm và tài khoản được tạo mới cho lượt thử nghiệm. Config được nạp vào volumes riêng bằng helper chạy `--network none`, sau đó mount read-only vào các dịch vụ.

## 4. Inventory tài nguyên candidate

Mọi tên sau dùng tiền tố `zt-pd02-candidate-`. Tất cả container đã dừng sau kiểm chứng và được giữ lại cùng dữ liệu synthetic.

| Thành phần | Tên container | Volumes hoặc địa chỉ |
|---|---|---|
| MySQL 8.0.46 | `mysql` | `mysql-cfg`, `mysql-data`, IP .10. Schemas `pd_staging_school`, `pd_staging_risk`, `pd_staging_keycloak`, `pd_staging_keycloak_restore` |
| Redis 7.4.7 | `redis` | `redis-cfg`, `redis-data`, IP .11. TLS 6379 và user ACL riêng |
| Keycloak | `kc`, `kc-install`, `kc-restore` | `kc-cfg`, `kc-install-cfg`, `realm-cfg`, `kc-restore-cfg`, IP .12/.17/.18. Realm `pd02-candidate-r11` |
| Ứng dụng | `risk`, `portal`, `gateway` | `risk-cfg`, `portal-cfg`, `gateway-cfg`, IP .13/.14/.15 |
| Kiểm thử | `probe`, `migrate`, `risk-fault` | `probe-cfg`, `migrate-cfg`, `risk-fault-cfg`, IP .9/.16/.19 |

Tổng cộng 11 container, 14 named volume và một bridge. Các fixture secret nằm trong volumes và thư mục ignored riêng của candidate. Bản báo cáo và các receipt không chứa giá trị secret.

## 5. Kết quả build image

Năm image local **PASS** với `docker buildx build --platform linux/amd64 --load`. Build dùng root canonical, `.dockerignore` và tag `pd-r11-c401e17`. OCI label gắn HEAD cùng SHA-256 inventory snapshot `59a6af25b41dea37338d5282600775ba2221f4e393e98c882fd503570e9b92dd` của 715 file. Không truyền secret build arg hay nạp fixture runtime vào context.

| Image dưới `zt-pd02-candidate/` | Recipe và cấu hình | Hoàn tất UTC |
|---|---|---|
| `keycloak` | `deploy/public-demo/Dockerfile.keycloak`, profile `public-demo-candidate`, Maven verify và `kc.sh build --db=mysql --health-enabled=true` | 12:17:20 |
| `risk` | `deploy/docker/Dockerfile.java`, `MODULE=risk-scoring-service`, `RUN_CHECKS=false` | 12:18:06 |
| `portal` | Cùng Java recipe, `MODULE=.`, `RUN_CHECKS=false` | 12:18:23 |
| `gateway` | Cùng Java recipe, `MODULE=gateway`, `RUN_CHECKS=false` | 12:18:39 |
| `tools` | `deploy/docker/Dockerfile.tools`, Python venv để relay và fault fixture | 12:19:11 |

Ba Java app build dùng suite source đã chạy tại PD-R10 và được kiểm lại bằng HTTP/runtime mới ở PD-R11. Frontend/Node không cần thiết cho các ca OIDC/API này. Gateway dùng Portal cho fixture fallback, chỉ các route API được nghiệm thu.

## 6. Image IDs, digests và base pins

Docker Desktop báo OCI index digest dưới đây đồng thời là local image ID. Build logs ghi child manifest, config digest và provenance của từng image. Các digest là artifact cục bộ.

| Image | OCI index digest / local ID |
|---|---|
| Keycloak | `sha256:e06bec13a903df01c1fd80b590d328db99ecbc4b00ee6ce3baa6f10f5f142615` |
| Risk | `sha256:2d276a161e7edea74ef082a2c8157025d37f12046cbcc458462809c3b9fd77de` |
| Portal | `sha256:e268a00ef8375fea37c5cd322f656ef424312aae78dc44ab589bc376336dbf45` |
| Gateway | `sha256:bf4491e134669996e6d1baaa9cf68e6f1c1b077433d7cee37ccf2add69b9e05f` |
| Tools | `sha256:a56de95082e6ecce308422324e8c4ea56b2ff5752a5b7f277b585bdad7d0884c` |
| MySQL fixture | `sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b` |
| Redis fixture | `sha256:02f2cc4882f8bf87c79a220ac958f58c700bdec0dfb9b9ea61b62fb0e8f1bfcf` |

Linux/amd64 child manifest của 5 build theo thứ tự bảng là `641648092d3d599bba8f324db0974caee3153e0f8b32c29348b18f016dbaa0b6`, `eaa29a1b42539153901aa752f13a83d1216d2af4d057be841bf54edd024d6de5`, `110df8b7d72685baf28d61a0010a5974235e0ec4c455911cd56d3860db46faaf`, `181559eeda5f7057e613b3d6db341488c4a22e33eb7a99db4f9a1a0edb5512ef` và `d0043ad926212966affe9dd0ee70d3c77ab655f0a4aecc370341f1dc43d639d0`, đều SHA-256.

Base pins theo recipe. Keycloak Quay linux/amd64 child `sha256:4340d05ee7d15be34293868d495ac772d61f1a4d0e43d53bae2e75e2f05de185`. Temurin 17.0.21+9 JDK Jammy builder/tools `sha256:057a0daec60e87c96571bf5c9c7792065bcb19e804d584cd37d4144038a35717`. Temurin 17.0.21+9 JRE Resolute apps `sha256:d532593b4d17f9455bcc74b4b45046fd0f9799db3b50b3486091e3e33ad99a26`. [Keycloak recipe](../../../deploy/public-demo/Dockerfile.keycloak) · [Java recipe](../../../deploy/docker/Dockerfile.java) · [Tools recipe](../../../deploy/docker/Dockerfile.tools)

## 7. SBOM và kết quả scan

Trivy **0.76.2**, DB update **07/11 06:54Z**, Java DB **07/11 01:07Z**. Quét `--image-src docker --scanners vuln --pkg-types os,library --list-all-pkgs`, tạo JSON và CycloneDX từ từng kết quả. Mỗi scan gắn đúng ImageID trong mục 6. Bảng đếm package/advisory records, gồm các record lặp theo binary hoặc package. Trivy kiểm kê OS, Java, Python và Go nơi tìm thấy metadata. Phạm vi là filesystem cuối của image cùng layer attribution do scanner cung cấp. Intermediate builder/cache chưa được scan độc lập.

| Artifact | Critical | High | Medium | Low | Unknown |
|---|---:|---:|---:|---:|---:|
| Keycloak | 0 | 4 | 38 | 28 | 0 |
| Risk | 0 | 0 | 53 | 4 | 0 |
| Portal | 0 | 0 | 53 | 4 | 0 |
| Gateway | 0 | 0 | 53 | 4 | 0 |
| Tools | 0 | 1 | 57 | 49 | 0 |
| MySQL fixture | 2 | 112 | 178 | 10 | 1 |
| Redis fixture | 6 | 74 | 92 | 21 | 1 |

Ứng dụng có 241 Risk, 132 Portal và 92 Gateway Java package records, 0 Java vulnerability match. Keycloak có 516 Java package records và giữ mức raw **0 Critical/4 High** của base PD-R10. OS Java image đã dùng apt/libapt và Brotli bản pin đã vá trong recipe. Node Bookworm 1 Critical/34 High và npm CLI 6 High của checkpoint trước không thuộc image build PD-R11. Application npm audit 0 tại PD-R10 vẫn là bằng chứng riêng. [Scan/SBOM và receipt cục bộ](../../../target/pd-02-02-runtime/) · [Ma trận Critical/High theo package và layer](../../../target/pd-02-02-runtime/critical-high.csv)

## 8. Keycloak native runtime

**PASS** cho khởi động tối ưu Keycloak 26.8.2, import realm trên MySQL 8.0.46 qua TLS, discovery HTTPS đúng issuer, restart dùng schema đã tồn tại. Installer dùng user schema riêng để khởi tạo. Runtime dùng user DML riêng, `migration-strategy=validate`, `initialize-empty=false`, không mount realm import. Truststore synthetic được load từ đường dẫn riêng. Fixture image startup với env trỏ sai file secret từ chối với exit 1. File hiệu lực của runtime là regular file Linux mode 0600, thuộc UID 1000, mount read-only.

## 9. SPI provider discovery

Provider JAR lấy từ container có SHA-256 `67090903551ffcc183de7c3df24c484dd82608325243fa5885c8c149511634ef`. Service descriptors ghi Risk authenticator, điều kiện step-up, device registration, event listener và login forms factory. Admin REST readback bằng operator synthetic xác nhận browser flow có các execution trên cùng `auth-otp-form`, realm bật `zerotrust-risk-events` và SPA đặt PKCE S256. Browser OTP, device rows và success events chứng minh các provider liên quan thực sự được gọi. Build profile SPI ghi **251 PASS / 27 SKIP / 0 lỗi** trong 278 test.

## 10. Realm, PKCE, MFA và Trusted Device

Chrome headless dùng authorization code và verifier S256. Probe thu authorization redirect tại callback synthetic và đổi code qua token endpoint HTTPS. Verifier sai bị `invalid_grant`. RP-initiated logout làm refresh token bị từ chối. Direct password grant của SPA tắt theo realm readback. Required Action enroll TOTP tự nó không tạo trusted row. OTP sai không có code và không đổi trust. OTP hợp lệ trong browser execution tạo `TRUSTED` đúng subject. Lần đăng nhập LOW với cookie đã trust bỏ step-up. Sau revoke và completion bằng service riêng, cookie cũ buộc OTP mới. OTP của các lần đăng nhập được dùng qua các cửa sổ TOTP khác nhau. [Keycloak 26.8.2 TOTP template](https://github.com/keycloak/keycloak/blob/26.8.2/themes/src/main/resources/theme/base/login/login-config-totp.ftl)

## 11. Tích hợp Risk Service

Candidate Risk chạy HTTPS với MySQL và Redis TLS. Authenticator lấy token bằng client credentials từ file secret và gọi Risk với issuer/JWKS thực. Correlation echo đúng ở ca HTTP thành công. Nonce đầu vào sai trả 400. Browser không nhận code khi Risk dừng, và Risk lên lại với health 200. Fault fixture HTTPS độc lập trả từng lỗi malformed JSON, duplicate field, sai nonce echo, lệch subject, lệch session. Cả năm lần có hit đúng fixture và Keycloak không cấp authorization code. Real Risk được khôi phục sau các ca fault.

## 12. Ma trận service identity

`400` trong ma trận là request rỗng đã qua kiểm tra quyền và bị validation. Payload hợp lệ của success/failure/device/revoke chạy riêng và trả `204`.

| Caller | Evaluate | Device write | Success/failure event | Revoke/complete |
|---|---:|---:|---:|---:|
| `zerotrust-risk-caller` | 400 | 400 | 400/400 | 403/403 |
| `zerotrust-portal-risk-admin` | 403 | 403 | 403/403 | 400/400 |
| `zerotrust-provisioner`, chỉ `query-users` | 403 | 403 | 403/403 | 403/403 |
| Anonymous hoặc JWT sai định dạng | 401 | 401 | 401/401 | 401/401 |
| SPA access token | 401, audience sai | Chưa lặp riêng | Chưa lặp riêng | Chưa lặp riêng |

Ba service account nhận token với issuer, azp và audience mong đợi. Keycloak từ chối client secret sai và client credentials grant của SPA. Quyền ADMIN reset/FGAP theo D-10 chưa nghiệm thu.

## 13. Adaptive Authentication B0

| Ca | Kết quả thực tế | Lớp bằng chứng |
|---|---|---|
| Thiết bị trusted, mạng và lịch sử phù hợp | LOW 0 → ALLOW | Risk HTTPS và Chrome password-only |
| Thiết bị mới, tổng thấp | 15, mandatory MFA → MEDIUM/STEP_UP_MFA | Risk HTTPS và Chrome OTP |
| Chạm ngưỡng medium | 40 → MEDIUM/STEP_UP_MFA | Risk HTTPS |
| Lịch sử thất bại và mạng rủi ro | 82,5 → HIGH/DENY | Risk HTTPS, Redis Lua native |
| IP blocked chính xác | DENY, `riskScore=null` | Risk HTTPS |
| Thiếu dữ liệu | INCOMPLETE → STEP_UP_MFA | Risk HTTPS |
| Risk outage | Không cấp code | Chrome và candidate Risk được dừng có kiểm soát |
| Malformed, duplicate, nonce, subject/session mismatch | Không cấp code trong 5 ca | Chrome và TLS fault fixture |
| Trust sau OTP và revoke | Trust chỉ tăng sau OTP thành công, cookie revoked buộc OTP | Chrome và readback MySQL |
| Stable event ID và subject binding | Lặp payload/cross-subject cùng ID giữ đúng một row, thuộc subject ban đầu. Browser success events ghi cho đúng subject, subject đối chứng giữ nguyên. | MySQL/Redis/Risk HTTPS và Chrome |


## 14. Rollback rehearsal

**PASS cho logical restore cùng phiên bản.** Dừng Keycloak candidate writer, lấy consistent logical snapshot bằng `mysqldump --single-transaction` và restore qua stdin vào `pd_staging_keycloak_restore` bằng tài khoản riêng. Snapshot SHA-256 `5e78e66c3c9d64767212d0af39798d79132d643d65bbe16c80b6ca6805a55497`. Đối chiếu counts realm, user, credential, changelog. Keycloak **cùng image 26.8.2** khởi động trên schema restore ở validate-only, discovery/JWKS giữ key IDs và service client đăng nhập được. Sau đó dừng restore instance, khởi động lại candidate gốc và lặp discovery/JWKS/service login. Snapshot được giữ trong bộ nhớ khi restore. Phạm vi là Keycloak MySQL synthetic trên cùng engine host. Rehearsal chưa xác minh downgrade, cross-version compatibility, restore toàn stack, RTO/RPO hay offsite. [Keycloak upgrading guide](https://www.keycloak.org/docs/26.8.2/upgrading/)

## 15. Advisory còn lại

| Advisory / lớp | Phiên bản và điều kiện tiếp cận | Xử lý và trạng thái |
|---|---|---|
| CVE-2026-102554, Guava Keycloak bundled JAR | 33.6.0-jre. Trigger cần Java native deserialization từ đầu vào không tin cậy. Có JAR trong image, chưa chứng minh hay loại trừ call path trên các bề mặt Keycloak được bật. | **OPEN**. Upstream Guava 33.7.2 có fix. Dùng Keycloak vendor artifact tương thích, cần owner duyệt nếu phải đổi khỏi phiên bản D-16. [Guava release](https://github.com/google/guava/releases/tag/v33.7.2) |
| CVE-2026-91403, OpenJDK Keycloak base | RPM `21.0.13.0.9-1.2.el9`. Cacerts của Java resolve tới `/etc/pki/ca-trust/extracted/java/cacerts`. SBOM có `ca-certificates-2026.2.92_v9.0.319-90.3.el9_8`. | **MITIGATED trên candidate** theo cách xử lý cho OpenJDK RPM của vendor. Giữ raw scanner match và xác minh lại bundle trên digest release. [Red Hat CVE](https://access.redhat.com/security/cve/cve-2026-91403) |
| CVE-2026-119373, SQLite Keycloak base | `sqlite-libs 3.34.1-11.el9_8`, trigger FTS5. Config dùng MySQL. Chưa kiểm tra đầy đủ bề mặt native sử dụng thư viện. | **OPEN, reachability chưa xác minh**. Theo dõi fix cho Keycloak base tương thích. [Red Hat CVE](https://access.redhat.com/security/cve/cve-2026-119373) |
| CVE-2026-119586, SQLite Keycloak base | Cùng library. Trigger qua `.recover` CLI trên dữ liệu DB attacker kiểm soát. `sqlite3` CLI không có trong candidate và backend là MySQL. | Đường CLI không có trên candidate. Giữ raw match và chờ disposition chính thức trên release artifact. [Red Hat bug](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2026-119586) |
| CVE-2025-47273, Tools Python package | Trivy ghi setuptools 70.3.0, trong khi venv đang chạy là 84.2.1. Trigger là `PackageIndex.download` xử lý package index/URL không tin cậy. Relay và TLS fixture dùng stdlib, không chạy PackageIndex. | **OPEN trên Tools fixture**, fix từ 78.1.1. Xác định và loại hoặc cập nhật bản dư trước khi chọn Tools cho release. [Setuptools advisory](https://github.com/pypa/setuptools/security/advisories/GHSA-5rjg-fvgr-3xxf) |
| GHSA-6q48-6c7w-9gw2, MySQL Shell Python | certifi 2026.2.25. Cần luồng TLS dùng public trust của MySQL Shell. Ca fixture chỉ dùng mysqld/mysql/mysqldump với CA riêng. | **OPEN trên image**, fix 2026.10.18. Chọn artifact MySQL tương thích hoặc loại operator component khỏi release và quét lại. [Certifi advisory](https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2) |
| CVE-2026-31789, Redis Alpine OpenSSL | `libssl3/libcrypto3 3.3.6-r0`, hai raw Critical records. Vendor xác định trigger overflow thuộc nền tảng 32-bit. Image/runtime là linux/amd64. | **Điều kiện kiến trúc loại trừ trigger này trên candidate**. Alpine fix 3.3.7-r0. Các OpenSSL High khác vẫn cần triage vì Redis TLS có nạp thư viện. [OpenSSL advisory](https://openssl-library.org/news/secadv/20260407.txt) |
| Go stdlib trong `/usr/local/bin/gosu` | MySQL Go v1.24.6, Redis v1.18.2. Critical CVE-2025-68121 ở cả hai, thêm CVE-2023-24538, CVE-2023-24540 và CVE-2024-24790 ở Redis. Binary thực thi lúc đổi UID trong entrypoint. Không quan sát TLS session resumption, template execution hoặc address-policy path trong cách dùng này. | **OPEN trên fixture images**, chưa kết luận từng High hết reachable. Thay binary hoặc chọn vendor image đã rebuild và kiểm tra tương thích. [Go TLS report](https://pkg.go.dev/vuln/GO-2026-4337) · [Go release history](https://go.dev/doc/devel/release) |

Ma trận cục bộ có từng dòng Critical/High của cả bảy image, kèm target, package/version, layer digest khi có, fix theo scanner và trạng thái. Với 186 High records của hai fixture DB, phân loại theo đường TLS, thư viện native chưa xác minh, Go startup helper hoặc MySQL Shell operator. Đây là triage ban đầu theo component và inventory, chưa xác minh độc lập vendor fix hoặc reachability cho từng dòng. Critical/High vẫn là blocker trên mọi artifact dự định phát hành có match áp dụng. Không có waiver. [Ma trận đầy đủ](../../../target/pd-02-02-runtime/critical-high.csv)

Bundled protobuf-java **4.35.0** và Netty DNS **4.1.139.Final** thay cho version provided trong graph SPI. Hai bản bundled này không match advisory High tương ứng trong scan. OpenTelemetry API **1.62.0** còn Medium CVE-2026-118259, Trivy ghi fix **1.67.0**. Giữ riêng record provided và runtime, không thay JAR Keycloak.

## 16. Blockers để đóng PD-02-02

- Keycloak còn Guava và SQLite dispositions chưa đóng. Nếu cần vendor artifact ngoài D-16, trình owner quyết định trên đúng digest.
- MySQL và Redis ở đây là fixture pin để kiểm chứng contract. Nếu các artifact này được chọn cho release, cần xử lý Critical/High áp dụng, tái quét exact images và chạy migration/TLS/rollback trên artifact thay thế. Tools residual phải xử lý nếu được đóng gói.
- Redis ACL nguồn không gồm `INFO`, nhưng Spring Boot Redis health indicator của Risk gọi lệnh đó. Native health trả lỗi permission với allowlist thiếu `INFO`. Fixture mở đúng lệnh `INFO` để chạy probe, giữ TLS và giới hạn key. Cần chốt cách kiểm health và ACL tương thích cho cấu hình release trước khi đóng PR-016/G3. [ACL contract](../../../deploy/public-demo/redis-acl-contract.conf)
- Node/Frontend chưa được build hoặc quét lại ở PD-R11, nên giữ residual theo artifact từ PD-R10. Final release SBOM, secret scan, hardening và CI cùng SHA/digest còn thiếu.

## 17. Security regression và kết quả test

**Build 5/5 PASS, SPI 251 PASS / 27 SKIP / 0 lỗi.** Receipt API ghi 23 checkpoint PASS, gồm ma trận gộp nhiều status assertions. Browser ghi 25 nhãn PASS khác nhau qua hai lượt, gồm enrollment và chuỗi MFA/trust hoàn chỉnh. Fault fixture ghi 5 ca từ chối và 1 health recovery PASS. Có thêm receipt cho event idempotency, fail-fast, readback/logout và rollback. Portal và Gateway trả 200 với ADMIN đọc và STUDENT đọc đúng dữ liệu, trả 403 khi ADMIN gửi academic write và khi STUDENT gọi admin path. Tài khoản School bị DB từ chối UPDATE và cross-schema read. Gateway trả 403 cho peer không trusted, 400 cho forwarded header thiếu hoặc có chuỗi IP, 404 cho operator path và 413 cho body vượt giới hạn sau xác thực. Risk container từ chối threshold B0 sai. Keycloak container từ chối secret path sai. [API](../../../target/pd-02-02-runtime/api-results.txt) · [Chrome](../../../target/pd-02-02-runtime/browser-suite-results.txt) · [TLS faults](../../../target/pd-02-02-runtime/fault-results.txt) · [Logout](../../../target/pd-02-02-runtime/readback-results.txt) · [Rollback](../../../target/pd-02-02-runtime/rollback-results.txt)

Các lần chạy thử ban đầu gặp lỗi harness về localhost publish, kiểm chứng chứng thư Python, diễn giải mandatory MFA, callback browser và dùng lại TOTP trong cùng cửa sổ. Đã chỉnh harness và chạy lại những ca liên quan. Redis health với ACL thiếu `INFO` là kết quả cấu hình thực cần theo dõi ở mục 16. Những bước chưa chạy gồm browser HIGH/priority DENY bằng IP browser thật, ma trận wrong issuer/expired token native đầy đủ, tải đồng thời native, kiểm thử FGAP/reset cuối, signed release secret scan và full-stack recovery. HIGH và priority DENY có bằng chứng HTTP. Các suites source PD-R10 giữ nguyên phạm vi, không cộng lại vào test mới.

## 18. Flyway V5

**PASS, checksum 661092940.** Candidate Risk image dùng packaged `Migrate` trên MySQL 8.0.46 với TLS VERIFY_IDENTITY. Kiểm tra trước migration cho thấy không có candidate Risk runtime/writer session. Flyway migrate/validate V1–V5 thành công. Row V5 của schema riêng có `checksum=661092940, success=1`. V5 class lấy từ candidate JAR có SHA-256 `24449acbaab162df24350998c0e8c889140ddc404594738f2f8d8dc2713d77a1`. Không có chỉnh sửa V5, guard engine hoặc Flyway history. [Checksum test](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/migration/V5ChecksumContractTest.java)

## 19. Bảo toàn Lab và source

Đối chiếu trước/sau 24 container hiện có, gồm 10 Lab. ID, image, status, started-at, restart count, cổng, membership, mount references sau khi chuẩn hóa thứ tự và restart policy khớp. Tám network và 30 volume cũ giữ inventory. Candidate không mount nguồn Lab, không dùng realm/DB/secret Lab và không thay đổi Lab. HEAD và branch khớp. 714/715 file baseline byte-identical, chỉ Master Roadmap cập nhật và báo cáo này được thêm. [Receipt kiểm tra metadata](../../../target/pd-02-02-runtime/preservation-results.txt)

## 20. Điều kiện dành cho Phase 03–06

| Phase | Bằng chứng cần cho artifact/môi trường chính thức |
|---|---|
| 03 | Reviewed source SHA, CI, immutable signed/published RC và N-1, SBOM/secret scans toàn bộ image gồm frontend và dependency services được chọn, package/advisory dispositions, container hardening và MySQL version/migration plan |
| 04 | Staging riêng với selected images, proxy/CA/grants/ACL/TLS native, realm/account/FGAP và quyết định D-10/D-13, rollback cùng compatible snapshot |
| 05 | Cấu hình host riêng đã duyệt, TLS/ingress/egress và service permissions, resource/logging control, secret delivery và storage policies |
| 06 | Acceptance trên đúng release config, đầy đủ weighted/browser/policy/security cases, giới hạn theo tải đã duyệt, backup/restore và release review |

**PD-02-02 PARTIAL. PR-001 và PR-016 OPEN. G1/G3 PARTIAL. D-16-RUNTIME đã thực thi trong phạm vi được duyệt. Việc đủ điều kiện tiếp theo là tiếp tục xử lý residual và cấu hình của PD-02-02. PD-02-08 chờ PD-02-02 PASS.**
