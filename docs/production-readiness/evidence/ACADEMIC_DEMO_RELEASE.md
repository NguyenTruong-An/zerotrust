# Academic Demo — staging, baseline và quyết định release

**PD-R19 · 08/11/2026 · Local staging · Internet NO-GO**

Owner giao phạm vi Academic Demo 14 ngày, mục tiêu trước khoảng 22/11/2026. Profile dùng dữ liệu synthetic và quyền ADMIN/STUDENT. Kiến trúc HTTPS, MFA, role/ownership, học vụ chỉ đọc, service identity, secrets riêng, rollback và thu hồi access là điều kiện bắt buộc. Các yêu cầu CI công khai, HA, vận hành dài hạn và DR cấp production tiếp tục được theo dõi ở Master Roadmap. Bản release và mức rủi ro còn lại cần owner quyết định theo đúng digest và thời hạn. [Master Roadmap](../PUBLIC_DEMO_ROADMAP.md) · [Compose và vận hành](../../../deploy/academic-demo/README.md)

## Baseline và freeze dự kiến

Git HEAD `c401e17029d64f9a96738d845b8c0ad0f03fc164`, branch `zerotrust-v4-risk-scoring`. Working tree có thay đổi trước PD-R19. Các image Java bên dưới lấy từ staging candidate đã có receipt. Frontend build trong PD-R19 có 34 test PASS. Các ID thuộc Linux amd64. Đây là snapshot của staging local để review. Registry publication, public host args và source freeze cần quyết định riêng.

| Thành phần | Version / OCI digest hoặc local image ID | Phạm vi |
|---|---|---|
| Keycloak + SPI | Quay 26.8.2 / OpenJDK 21 · `e06bec13a903df01c1fd80b590d328db99ecbc4b00ee6ce3baa6f10f5f142615` | Baseline staging, **PROPOSED** cho so sánh D-17. |
| DHI Keycloak | Temurin 21 / amd64 `44b3665b60304cb4448e3ab9943ab02727ee793c2ec4b954d2de2ee84f28b892` | **PROPOSED** cho trial, runtime **NOT_VERIFIED**. |
| School Backend | Java 17 / Spring Boot 4.1.2 · `e268a00ef8375fea37c5cd322f656ef424312aae78dc44ab589bc376336dbf45` | Staging. |
| Risk Service | Java 17 / Spring Boot 4.1.2 · `122237b9480449be28aa55f717747d3f2cc00cd3e3a45cbeae66d83ee60e202a` | Staging, Redis ACL/readiness từ PD-R12. |
| Gateway | Java 17 / Spring Cloud 2025.1.4, Gateway 5.0.4 · `bf4491e134669996e6d1baaa9cf68e6f1c1b077433d7cee37ccf2add69b9e05f` | Staging. |
| Frontend | Node 24.22.2 Alpine, Next.js theo lockfile · amd64 `d75858ebd462feba75f1d51d677066fab46597f168eda4a98ac8fe866dddd60d`, index local `6b664c9b3cc32f40aa7f74a65e312216fde55d6f2ad8b281dd66cd79855563e8` | Build local, chỉ dùng issuer/URL staging. |
| MySQL | 8.0.46 · `7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b` | Installer V5 và baseline staging. |
| MySQL LTS | 8.4.13 · `72c368d898861f3b3a07af0e6d690400f44f048799ed46822783d9224cc2c86d` | Engine recovery cô lập, **PROPOSED** cho D-14. |
| Redis | 7.4.12 Alpine · `ec1c2d3603c3d7d65b153bedda0248b641aa3bd7684503406b27b9e870ac0796` | Staging. |
| Ingress | NGINX 1.30.6 Alpine · `bb8f722b4be005fcd7827816a136ab779fd40185d85b5171be915cc7fc0575c7` | Staging TLS qua 127.0.0.1:19443. |

## Scan và quyết định owner

Trivy 0.76.2, vulnerability DB cập nhật 08/11 lúc 00:37 UTC và Java DB 00:58 UTC. Các số là **raw rows**. [Tất cả Critical/High theo image](../../../target/academic-demo/critical-high.csv)

| Image | Critical / High raw | Disposition |
|---|---|---|
| Frontend Debian staging ban đầu | 1 / 34 | Thay bằng Node Alpine 24.22.2 trong profile local. Giữ raw findings của bản đầu. |
| Frontend Alpine, Gateway, School, Risk, Redis, NGINX | 0 / 0 mỗi image | Theo snapshot DB trên, còn cần quét exact release image sau rebuild hostname. |
| Quay Keycloak 26.8.2 | 0 / 4 | Guava CVE-2026-102554, SQLite CVE-2026-119373 và CVE-2026-119586, JVM CVE-2026-91403. Giữ OPEN theo từng finding. [Triage PD-R13](PD-02-02_KEYCLOAK_D17_SECURITY_REVIEW.md) |
| DHI Keycloak base | 0 / 3 | Guava/zlib đã vá, SQLite FTS5 không áp dụng cho base. Hai raw High không áp dụng, `libacl1` CVE-2026-54369 OPEN. [Triage PD-R18](PD-02-02_DHI_ROOTFS_SECURITY_VERIFICATION.md) |
| MySQL 8.0.46 | 2 / 112 | `gosu` CVE-2025-68121 và certifi GHSA-6q48-6c7w-9gw2. High gồm thư viện TLS của OS và tooling. Giữ baseline bootstrap synthetic. |
| MySQL 8.4.13 | 2 / 33 | Cùng hai Critical theo package scanner, ít High hơn. Recovery chạy cô lập qua Unix socket. Còn triage trước khi dùng làm DB phục vụ demo. |

Hai `gosu` khớp SHA-256 với binary PD-R12. Trong đường startup đã kiểm, helper chỉ chuyển UID. Tìm ký hiệu không thấy đường gọi `crypto/tls` hoặc `net/http` cần cho CVE-2025-68121. Với certifi trong MySQL Shell, staging dùng `mysqld`, `mysql` và `mysqldump` qua CA riêng. Giữ finding certifi cho mọi đường dùng mysqlsh và giữ raw rows của cả hai CVE. Chưa có waiver cho release, đặc biệt với các thư viện mà `mysqld` nạp trực tiếp. [Go advisory](https://pkg.go.dev/vuln/GO-2026-4337) · [Certifi advisory](https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2) · [Phân tích PD-R12](PD-02-02_RESIDUAL_SECURITY_CLOSEOUT.md)

**D-17 PENDING.** Tag chính thức DHI `26` được kiểm lại vẫn trả về digest PD-R18. Chưa thấy bản đã vá `libacl1` trong phạm vi kiểm tra. Khuyến nghị owner duyệt trial DHI có giới hạn trên synthetic để thu bằng chứng tương thích, giữ Quay làm mốc hồi quy. Trước release, yêu cầu patch/disposition exact digest và kiểm derived image. Giới hạn ingress theo danh tính, private DB/Risk/management, process nonroot, volume tối thiểu và theo dõi cảnh báo là biện pháp giảm phơi nhiễm cho trial. Việc phê duyệt artifact và rủi ro Internet vẫn cần quyết định riêng. [Debian libacl](https://security-tracker.debian.org/tracker/CVE-2026-54369) · [Kế hoạch DHI](PD-02-02_DHI_RUNTIME_TRIAL_PLAN.md)

**D-14 PENDING.** MySQL xác nhận 8.0 đã EOL từ 8.0.46. Giữ phiên bản đó để chạy V5 với checksum `661092940` trong installer synthetic. Đề xuất hướng 8.4 LTS, preserve ledger qua logical migration, triage các finding theo binary/package và kiểm lại full app/runtime trên 8.4. Không chỉnh V5 hoặc dùng Flyway repair. [MySQL 8.0 release notes](https://dev.mysql.com/doc/relnotes/mysql/8.0/en/) · [MySQL 8.4 release notes](https://dev.mysql.com/doc/relnotes/mysql/8.4/en/)

**D-04 và quyền Internet PENDING.** Cần Linux host, DNS/hostname Portal và Auth, chứng thư hợp lệ, access gate cho người được cấp quyền, giới hạn concurrent sessions, thời điểm thu hồi và owner ký GO theo digest. Khi residual risk chưa phù hợp cho public Internet, xét VPN hoặc cổng truy cập riêng có xác thực.

## Staging acceptance

| Ca | Kết quả đã quan sát |
|---|---|
| Local startup và HTTPS | 8/8 service healthy. Ingress TLS xác minh CA/SAN, issuer OIDC đúng. Chặn Keycloak admin, actuator và Observatory. Gateway trực tiếp trả 403. Installer Keycloak đã import realm nhưng timeout dừng lần đầu và để lại exit 137. Đã tăng grace period lên 35 giây. Keycloak runtime dừng và khởi động lại thành công trong rehearsal. |
| Browser | STUDENT PKCE S256, OTP đúng/sai, chỉ xem điểm của mình, ADMIN route bị từ chối. ADMIN đọc được, ghi bị chặn cả ở API qua ingress và backend trực tiếp. Logout và từ chối refresh sau logout. Một ca score read lỗi ở lượt chạy xen kẽ kiểm Redis. Lượt xác minh sau khi toàn stack ổn định và sau restore đã PASS. [Receipt](../../../target/academic-demo/browser-after-restore.log) |
| Risk API | LOW 0, MEDIUM 40, HIGH 82,5, Mandatory MFA 15, Priority DENY trước scoring, Missing Data, service identity, trusted-device register/revoke và Redis AOF qua restart. [Receipt](../../../target/academic-demo/risk-final.log) |
| Risk Service outage | Keycloak từ chối login trong browser khi Risk Service dừng. Risk đã khởi động lại. [Receipt](../../../target/academic-demo/risk-outage.log) |
| Redis outage | Risk readiness trả HTTP 503. B0 trả `INCOMPLETE/STEP_UP_MFA`, score null khi mất history. Sau khi Redis trở lại, data status trở về `COMPLETE`. [Receipt](../../../target/academic-demo/redis-outage.log) |
| Dữ liệu và recovery | School account SELECT-only, SQL write deny, V5 `661092940`. Backup age của School/Risk/Keycloak giải mã và import vào MySQL 8.4.13 cô lập. Đối chiếu số dòng và Flyway checksum. Stack gốc healthy và browser smoke PASS sau rehearsal. Chưa chạy Keycloak/Risk trỏ vào MySQL 8.4. [Receipt](../../../target/academic-demo/backup-rehearsal.log) |

Gói đề nghị commit gồm `deploy/academic-demo/`, phần thêm `NODE_IMAGE` trong Dockerfile frontend, runbook, hướng dẫn giảng viên, docs index và Master Roadmap. Scan secrets riêng `deploy/academic-demo/` ghi 0 findings. State, CA, tài khoản và archive nằm dưới `target/academic-demo/private/` được Git ignore. [Manifest local và hashes](../../../target/academic-demo/staging-manifest.json) · [Secret scan](../../../target/academic-demo/source-secret-scan.json)

Một mẫu vận hành có khoảng 1,72 GiB RAM cộng gộp cho tám service. Đây là mẫu local sau recovery, chưa đo tải đồng thời trên VPS. [RAM](../../../target/academic-demo/memory-snapshot.txt) · [Dung lượng Docker](../../../target/academic-demo/disk-snapshot.txt)

## Nghiệm thu và phát hành

- [x] Tách network, volumes, schema, realm, keys và dữ liệu synthetic. Chỉ NGINX publish trên loopback.
- [x] Baseline local boot, backend direct access và rule chỉ đọc được kiểm theo receipt thực tế.
- [ ] Chốt D-17/D-14 và chạy các ca bị ảnh hưởng trên candidate đích.
- [ ] Rà cùng nguồn build, pin digest, quét CVE và secrets theo scope release, kiểm rollback trên bản Linux đích.
- [ ] Chốt D-04 và giới hạn truy cập/phiên, kiểm TLS PKI thật, retire bootstrap admin, diễn tập cấp và thu hồi account.
- [ ] Owner ký quyết định có ngày hết hạn và cho phép mở access. Chốt riêng file manifest, source diff và quyền commit/push.

[Hướng dẫn giảng viên](../../demo/ACADEMIC_DEMO_TEACHER_GUIDE.md) · [Runbook bảo vệ](../../DEFENSE_DEMO_RUNBOOK_DRAFT.md)

## PD-R20 · Gói Linux và quyết định còn mở

Giữ nguyên `zt-academic-demo` và `https://portal.academic-demo.test:19443` của PD-R19. Đối chiếu ID image của container, hash tệp runtime và raw scans theo staging manifest. Kiểm đọc trên PD-R19 xác nhận còn realm, signing keys, MFA enrollment, Risk device rows và Flyway V5 `661092940`. Receipt PD-R19 chứng minh restart trước đó. PD-R20 kiểm lại restart trong project `zt-academic-linux` cô lập với cùng Keycloak/School/Risk/Gateway/MySQL/Redis/NGINX, frontend build cho hostname rehearsal mới. [State PD-R19](../../../target/pd-r20/pd-r19-state-readonly.json) · [Gói Linux](../../../deploy/academic-linux/README.md)

| Hạng mục | Bằng chứng PD-R20 |
|---|---|
| Compose Linux | Ubuntu WSL chạy Linux amd64 qua Docker Engine 29.4.1. Tám service healthy, ingress chỉ loopback, DB/Risk/Redis và Keycloak management giữ private. Installer Keycloak dừng với exit 143 sau import, V5 giữ checksum. [Startup](../../../target/pd-r20/linux-start.log) |
| Hostname và TLS | Lock build riêng Portal/Auth, issuer và PKCE đúng hostname. Smoke kiểm CA/SAN và từ chối hostname sai. Mẫu production qua kiểm cấu hình, verifier từ chối sai SAN hoặc sai key với PKI synthetic. [Preflight](../../../target/pd-r20/production-preflight-final.log) |
| Hồi quy | OIDC/PKCE đúng và sai, OTP, RBAC, ownership, direct write deny, logout và refresh. B0 0/40/82,5, Mandatory MFA, Priority DENY, Missing Data, trust revoke và fail-closed. Redis mất kết nối làm readiness 503 và trả `INCOMPLETE/STEP_UP_MFA`. [Smoke](../../../target/pd-r20/linux-smoke.log) |
| Recovery | Restart rehearsal giữ JWKS, enrollment OTP, Risk device state và V5. Redeploy frontend theo lock mới, giữ state rehearsal. Trình khởi động từ chối tạo state mới nếu project đã có volumes. Backup SQL và Redis mã hóa bằng age, kiểm giải mã và inventory ba schema/AOF. Full restore trên VPS còn cần nghiệm thu. [Backup](../../../target/pd-r20/linux-backup.log) · [Guard](../../../target/pd-r20/linux-wrong-state.log) |
| Release | Lock tám digest, frontend hostname và SHA-256 đầu vào. Bundle có năm app images, deployment archive và ba registry pins. Đã kiểm checksum và chạy smoke từ bundle giải nén không có `.git` với các image đã nạp trên local. Scan frontend exact mới 0 Critical/High và secret scan phạm vi package source 0 findings. Rehearsal dùng hostname `.test`. Build frontend đích sau D-04. [Release lock](../../../target/pd-r20/linux-release-reviewed.json) · [SHA256SUMS](../../../target/pd-r20/linux-bundle-reviewed/SHA256SUMS) · [Transfer smoke](../../../target/pd-r20/linux-transfer-reviewed.log) |

Sau redeploy và backup, tài khoản STUDENT đã enroll OTP vẫn đăng nhập và đọc đúng dữ liệu. Realm xác nhận signup tắt. Dừng riêng rehearsal khi bàn giao và giữ 11 volumes. Metadata Lab và PD-R19 khớp trước/sau, tám service PD-R19 vẫn healthy. [OTP và signup](../../../target/pd-r20/linux-persistence-reviewed.log)

### D-17 · Keycloak

| Option | Bằng chứng, thay đổi và điều kiện |
|---|---|
| A — Quay PD-R19 | Khuyến nghị cho rehearsal và phương án demo qua private access nếu owner chấp nhận rủi ro cụ thể. Quay 26.8.2 cùng SPI đã qua startup, PKCE, OTP, RBAC, B0 và rollback cùng engine. Guava, hai SQLite findings và JVM High vẫn OPEN. Dùng quyền giới hạn theo danh tính, mạng private, không signup và log cảnh báo đã lọc. Giữ image Quay và snapshot cùng engine làm phương án quay lại. |
| B — DHI | Base PD-R18 đã xử lý Guava/zlib, SQLite FTS5 không áp dụng cho base. `libacl1` CVE-2026-54369 OPEN. Cần owner duyệt trial riêng. Trial dùng project, ports, volumes, realm/keys mới, chỉnh UID 65532, provider/theme augmentation, CA/truststore và startup. Chạy ma trận SPI, PKCE, OTP, trust, B0, role/ownership, TLS, realm/MySQL, rescan exact derived digest và restore trước khi chọn. [Kế hoạch DHI](PD-02-02_DHI_RUNTIME_TRIAL_PLAN.md) |

D-17 giữ **PENDING**. PD-R20 giữ Quay và không thử DHI khi chưa có quyết định.

### D-14 · MySQL

- 8.0.46 giữ cho baseline cô lập và bước cài V5. Tập rủi ro image và tình trạng hết hỗ trợ đã ghi ở PD-R19.
- 8.4.13 LTS là hướng ưu tiên cho release sau khi kiểm đủ ứng dụng. Logical restore PD-R19 khớp realm/credentials và V5, còn thiếu startup Keycloak/School/Risk trên 8.4, TLS/grants, browser/Risk và exact image disposition. Thử trên bản restore riêng rồi chuyển bằng snapshot tương thích. D-14 giữ **PENDING**.

**Quyết định truy cập**. Khuyến nghị HTTPS qua VPN/private access. Owner cung cấp VPS Linux amd64 và quyền deploy, hai hostname/DNS, PKI, access gate, người dùng, hạn phiên/ngày thu hồi và phê duyệt artifact/rủi ro. Rehearsal và cấu hình mẫu đã sẵn sàng. Trên VPS còn phải kiểm TLS qua đường truy cập thật, browser, app regression, limits, backup/restore, rollback và thu hồi quyền. **Internet NO-GO**. [Checklist deploy và access](../../../deploy/academic-linux/README.md)

## PD-R21 · Thử nghiệm synthetic D-14 và D-17

Owner duyệt thử nghiệm hai phương án trong chat ngày 08/11/2026. Mỗi phương án dùng Compose project, volumes, subnet và state synthetic riêng trên Docker Linux amd64. Chỉ ingress thử nghiệm có cổng loopback. D-14 giữ Keycloak Quay và D-17 giữ MySQL 8.0.46 để tách tác động của từng thay đổi. Mã chạy thử và cấu hình bổ sung nằm trong `target/pd-r21/`. [Trial driver](../../../target/pd-r21/trial.py)

**D-14 · Cài trực tiếp trên 8.4.13 thất bại ở V5.** Exact MySQL 8.4.13 `sha256:72c368d898861f3b3a07af0e6d690400f44f048799ed46822783d9224cc2c86d` khởi động và chạy V1–V4. Ledger ghi V5 checksum `661092940`, success `0`. Preflight V5 chỉ chấp nhận MySQL 8.0.46 và trả `UNREVIEWED_MYSQL_VERSION` trước DDL của V5. Lượt kiểm tiếp theo bị Flyway từ chối do ledger đã ghi lỗi. Lần cài lỗi được giữ riêng. Đường chuyển logic dùng một MySQL 8.0.46 synthetic mới để áp dụng V5, truyền dump schema Risk qua bộ nhớ vào schema trống trên MySQL 8.4.13 ở project `zt-pd-r21-d14restore`, và xác nhận ledger `661092940 / success=1`. [Ledger lần cài trực tiếp](../../../target/pd-r21/d14-diagnose.log) · [Guard V5](../../../risk-scoring-service/src/main/java/com/zerotrust/risk/migration/SubjectIdentityMigrationPreflight.java#L53) · [Receipt chuyển logic](../../../target/pd-r21/d14-logical-transfer.log) · [MySQL upgrade paths](https://dev.mysql.com/doc/refman/8.4/en/upgrade-paths.html)

**D-17 · Derived image được build từ exact OCI base.** Manifest và toàn bộ blob config/layers được kiểm SHA-256 trước build. BuildKit ghi nhận DHI amd64 `44b3665b…b892` và Quay app image `e06bec13…2615` làm materials. Chỉ copy provider/theme ZeroTrust từ Quay, đặt ownership 65532 và chạy Keycloak augmentation với mạng build tắt. Local image ID `sha256:17daa7bddecd0f25a812e9e29d178a9f4cbf3d5f5aef4057d8eb535bc9dfe985`. Provenance BuildKit và CycloneDX của derived image là evidence local. Chữ ký vendor PD-R17 áp dụng cho DHI base. [Build recipe](../../../target/pd-r21/Dockerfile.dhi-trial) · [Build metadata](../../../target/pd-r21/dhi-build-metadata.json) · [Exact image lock](../../../target/pd-r21/d17-image-lock.json) · [Keycloak container guide](https://www.keycloak.org/server/containers)

| Exact image | Raw Critical / High | Disposition |
|---|---:|---|
| MySQL 8.4.13 | 2 / 33 | Hai Critical vẫn là Go stdlib trong `gosu` và `certifi` trong MySQL Shell. Evidence PD-R19 về đường chạy của hai thành phần vẫn áp dụng cho cùng image ID. Giữ raw rows và tiếp tục triage High theo đường nạp của `mysqld`. [Raw scan](../../../target/pd-r21/mysql84-trivy-raw.json) · [Go advisory](https://pkg.go.dev/vuln/GO-2026-4337) · [Certifi advisory](https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2) |
| DHI Keycloak + SPI/theme | 0 / 3 | CycloneDX local ghi một Guava 33.7.2-jre và zlib bản đã đối chiếu ở PD-R18. Scanner không báo SQLite. Kết luận SQLite FTS5 NOT_APPLICABLE của kiểm kê native đầy đủ có phạm vi exact base PD-R18. Hai High `libsystemd0` và `libtinfo6` khớp findings đã triage trên base. `libacl1` CVE-2026-54369 **OPEN**. Quyền hạn container thử giảm điều kiện có caller đặc quyền, chưa đủ để kết luận vá hoặc miễn trừ phát hành. [Raw scan](../../../target/pd-r21/dhi-trivy-raw.json) · [CycloneDX](../../../target/pd-r21/dhi-derived.cdx.json) · [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-54369) |

Trivy 0.76.2 quét image local theo đúng ID, dùng snapshot vulnerability DB 08/11/2026 00:37 UTC và Java DB 00:58 UTC để đối chiếu với PD-R18/PD-R19.

**D-14 · Hồi quy stack trên 8.4.13 đạt sau chuyển logic.** Tám dịch vụ healthy, TLS/CA/SAN và OIDC issuer đúng. Các ca PKCE đúng/sai, OTP, ADMIN/STUDENT, ownership, SQL SELECT-only, chặn ghi trực tiếp và logout/refresh đạt qua HTTPS. Risk đạt B0 0/40/82,5, Mandatory MFA, Priority DENY, Missing Data, đăng ký và revoke thiết bị. Redis outage trả readiness 503 và `INCOMPLETE/STEP_UP_MFA`, history/AOF trở lại sau restart. Khi Risk dừng, Keycloak từ chối đăng nhập. Restart toàn stack giữ JWKS, enrollment OTP, Risk state và V5. Trial chỉ chuyển schema Risk vừa cài trên 8.0.46. School và realm thử được tạo mới trên 8.4.13. [Image lock](../../../target/pd-r21/d14restore-image-lock.json) · [Startup](../../../target/pd-r21/d14restore-start.log) · [Hồi quy](../../../target/pd-r21/d14restore-smoke.log)

**Đối chiếu DHI.** Registry tag `26` vẫn trỏ tới index `50a09844…2f1c` và Linux amd64 `44b3665b…b892` tại PD-R21. Chín diff IDs đầu của derived image trùng base, derived có 12 layers. SHA-256 provider JAR trong DHI và Quay đều là `67090903551ffcc183de7c3df24c484dd82608325243fa5885c8c149511634ef`. [Registry manifest](../../../target/pd-r21/dhi-registry-index.json) · [Derived diff IDs](../../../target/pd-r21/dhi-derived-diffids.json)

**D-17 · Hồi quy runtime trên MySQL 8.0.46.** Tám dịch vụ healthy, realm được import, installer dừng graceful. PID 1 chạy với UID/GID 65532, `CapEff=0` và `NoNewPrivs=1`. HTML đăng nhập có asset của theme ZeroTrust. Guava runtime 33.7.2-jre có SHA-256 trùng PD-R18. Kiểm các đường cài đặt chuẩn của `systemd-homed`, `homectl` và `infocmp` trên derived container đều vắng mặt. Hồi quy HTTPS kiểm PKCE, OTP, RBAC/ownership, chỉ đọc, logout/refresh, B0, Trusted Device, Risk fail-closed và phục hồi Redis. Lượt đầu bị dừng ở lệnh kiểm kê JAR do utility trong image tối giản không có. Lượt sau dùng shell builtins và đọc JAR từ host. [Startup](../../../target/pd-r21/d17-start.log) · [Hồi quy](../../../target/pd-r21/d17-smoke-retry.log) · [Kiểm kê các utility](../../../target/pd-r21/dhi-utility-check.txt)

**Recovery và phạm vi nghiệm thu.** Cả hai trial chính qua restart toàn stack và đối chiếu JWKS, enrollment OTP, Risk state, ledger V5. Hai frontend build đều chạy 34 test PASS. Hồi quy runtime dùng harness giao thức HTTPS, chưa kiểm hiển thị bằng trình duyệt thật trong PD-R21. Rollback từ snapshot DHI sang Quay, khôi phục đầy đủ trên phiên bản phát hành và cấu hình kết hợp DHI + MySQL 8.4 còn NOT_VERIFIED.

**Bàn giao.** 21 container thử đã Exited và 43 volume synthetic còn lưu. So sánh sau chuẩn hóa thứ tự mounts cho thấy metadata của 57 container có trước trùng baseline. Lab có 10 container Exited và PD-R19 còn 8 healthy. 70 volume cũ, inventory image và tên/ID network giữ nguyên. HEAD, branch và hash V5 khớp. D-14 và D-17 giữ PENDING ở quyết định phát hành. PD-02-02 PARTIAL, PD-02-08 TODO, Internet NO-GO. [Đối chiếu bảo toàn](../../../target/pd-r21/preservation.json)
