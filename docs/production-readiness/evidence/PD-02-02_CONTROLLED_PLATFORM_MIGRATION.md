# PD-02-02 — Controlled platform migration

**EV-PD-02-02-03 · PD-R10 · 07/11/2026, Asia/Saigon (GMT+7)**

**PARTIAL.** Portal, Risk và Gateway đã migrate và build trên Spring Boot 4.1.2. Keycloak 26.8.2 đã qua compile, SPI tests và augmentation cục bộ. Build image và runtime ứng viên còn bị chặn do Docker daemon không khả dụng. PR-001/PR-016 OPEN, G1/G3 PARTIAL. **NO-GO FOR PUBLIC ACCESS.** [Master Roadmap](../PUBLIC_DEMO_ROADMAP.md) · [Decision packet PD-R9](PD-02-02_PLATFORM_DECISION_AND_CLOSEOUT.md)

## 1. Phê duyệt và phạm vi

| Quyết định | Trạng thái và phạm vi đã dùng |
|---|---|
| D-15 | **APPROVED** theo yêu cầu owner ngày 07/11. Di trú ba Spring modules sang Boot 4.1.2, Cloud 2025.1.4/Gateway 5.0.4, giữ Java 17. Cho phép thay đổi BOM, source/build/test compatibility. |
| D-16 | **APPROVED** cho server và SPI provided API 26.8.2 của ứng viên Public Demo. Tách recipe/profile ứng viên khỏi đường build Keycloak Lab. |
| D-16-RUNTIME | **APPROVED WITH RESTRICTIONS** cho runtime mạng private với realm, DB, tài khoản synthetic, secrets, signing keys và volumes tách biệt. **BLOCKED thực thi** ở lượt này vì không xác minh được môi trường Docker cô lập. |
| D-10 và D-13 | **PENDING**. Giữ quyền reset MFA và biên operator-private hiện hành. |

Xác minh các bản GA với upstream tại mốc thực thi. Boot 4.2 và Cloud 2026.0 đang ở RC. Giữ các version đã duyệt. [Spring releases](https://spring.io/blog/category/releases/) · [Ma trận Cloud/Boot](https://spring.io/projects/spring-cloud/) · [Keycloak 26.8.2](https://www.keycloak.org/2026/11/keycloak-2682-released)

## 2. Baseline và kiểm soát thay đổi

Canonical branch `zerotrust-v4-risk-scoring`, HEAD `c401e17029d64f9a96738d845b8c0ad0f03fc164`, ahead 3 theo local upstream. Chụp inventory và SHA-256 của 713 file tracked/untracked trước thay đổi, gồm ba POM, cấu hình Spring profiles, CI, Lab manifests và migration sources. Dùng effective graphs từ PD-R9 làm baseline phiên bản.

| Scope | PD-R9 | PD-R10 |
|---|---|---|
| Java application toolchain | Temurin 17.0.21+9, release 17 | Giữ nguyên |
| Portal, Risk, Gateway | Boot 3.5.16 / Framework 6.2.19 / Security 6.5.11 | Boot **4.1.2** / Framework **7.0.10** / Security **7.1.2** |
| Gateway | Cloud 2025.0.3 / Gateway 4.3.5 / Netty 4.1.140.Final | Cloud **2025.1.4** / Gateway **5.0.4** / Reactor Netty **1.3.8** / Netty **4.2.19.Final** |
| Servlet/JPA | Tomcat 10.1.61 / Hibernate 6.6.53.Final | Tomcat **11.0.27**, Servlet 6.1 / Hibernate **7.4.13.Final**. Connector/J vẫn 9.7.0 |
| JSON | Jackson 2.21.8 trong Spring apps | Jackson **3.1.7** trong Spring HTTP/API. Jackson 2.21.8 vẫn là dependency riêng của Keycloak admin client/GeoIP2 |
| Risk Flyway và H2 | Flyway 11.7.2, H2 2.3.232 test-only | Flyway **12.4.0**, H2 **2.5.252** test-only. Portal test H2 2.4.240 từ BOM |
| Keycloak | Server và provided APIs 26.7.0 | Ứng viên **26.8.2**. Lab/default SPI build vẫn 26.7.0. Admin Client 26.0.12 và SPA 26.2.5 giữ nguyên |
| Frontend | Node 24.22.2, npm 11.21.2, Next 16.4.5, lock PD-R9 | Giữ nguyên |

[Baseline PD-R9](PD-02-02_PLATFORM_DECISION_AND_CLOSEOUT.md) · [Boot requirements](https://docs.spring.io/spring-boot/system-requirements.html)

## 3. Di trú Spring theo module

1. **Portal.** Dùng Boot 4 MVC/resource-server starters và các test modules MVC/JPA. Chuyển các mapper của lỗi bảo mật và Risk admin HTTP client sang Jackson 3. Giữ strict trailing-token validation, bearer/TLS và Keycloak RESTEasy Jackson 2 provider. Cập nhật import `BasicErrorController` của read-only guard. Targeted 217 tests đạt trước khi chạy full verify, gồm synthetic School reads, direct write denial, RBAC/ownership, JPA và error handling. [Portal POM](../../../pom.xml)
2. **Risk.** Dùng Boot 4 MVC/resource-server/Flyway starters và test modules mới. Chuyển mapper của security responses và trace sang Jackson 3. Điều chỉnh Actuator/Redis/JPA test package names. V5 bytecode gate chạy trước regression JPA. H2 2.4.240 tái hiện lỗi CHECK predicate qua hai connection của upstream. Nâng riêng H2 test dependency lên 2.5.252, giữ nguyên SQL constraint và toàn bộ assertions. Bổ sung starter Security test của Boot 4 để `@WebMvcTest` nạp `HttpSecurity`. Targeted retry 184 PASS. [Risk POM](../../../risk-scoring-service/pom.xml) · [H2 issue #4302](https://github.com/h2database/h2database/issues/4302) · [H2 releases](https://github.com/h2database/h2database/releases)
3. **Gateway.** Nhập Cloud BOM 2025.1.4 và đổi sang API `HttpHeaders.headerNames()` của Spring 7. Giữ danh sách loại forwarded/identity headers, thứ tự filter và route authorization. Chuyển codec/error properties sang tên Boot 4, thêm assertion effective codec 1 MiB. Các HTTP tests dùng `@AutoConfigureWebTestClient`, địa chỉ loopback và cổng ngẫu nhiên. Targeted retry 75 PASS, gồm timeout, proxy spoofing, quotas, body/header limits và operator routes. [Gateway POM](../../../gateway/pom.xml) · [Boot migration guide](https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-4.0-Migration-Guide) · [WebTestClient auto-configuration](https://docs.spring.io/spring-boot/reference/testing/spring-boot-applications.html)

BOM giữ các dependency được hỗ trợ. Giữ các override bảo mật còn cần thiết như Log4j2, Bouncy Castle ở Gateway và Jackson 2 cho thư viện dùng riêng. Không đổi B0, thresholds, Mandatory MFA, Priority DENY, fail-closed, JWT issuer/aud/azp/algorithm requirements, trust generation, nonce/echo, strict Risk response hoặc stable Event ID.

## 4. Keycloak candidate và provider packaging

- Thêm Maven profile `public-demo-candidate` với provided APIs 26.8.2. Default version 26.7.0, Dockerfile đang dùng cho Lab và Compose Lab giữ nguyên. CI có matrix job riêng cho profile ứng viên. [SPI POM](../../../keycloak-risk-extension/pom.xml) · [CI](../../../.github/workflows/ci.yml)
- Hai server stages của recipe ứng viên pin Quay **linux/amd64** child manifest `sha256:4340d05ee7d15be34293868d495ac772d61f1a4d0e43d53bae2e75e2f05de185`. Đối chiếu OCI index digest `sha256:3879c623248408de29a5303178b5816c77e8dfef3890c361f8c0bbeaa979ba3b` với body hash và trường platform. Dùng vendor `kc.sh` entrypoint cùng command và config riêng của Public Demo. [Candidate Dockerfile](../../../deploy/public-demo/Dockerfile.keycloak) · [Build notes](../../../deploy/public-demo/README.md)
- JAR provider đóng gói 3 ServiceLoader descriptors cho 5 factory implementations. Không có nested JAR hay bundled Keycloak classes. SHA-256 JAR thử là `7eed70d71f78506244b2f8f7c8d250bc44ce7c5cca8b1bcead5a4d93c6ebd980`.
- Tải Keycloak ZIP 26.8.2, xác minh SHA-256 `321ffee62ec28fab18fe885d8cd62cc814edce72a35cd062dc81b504c1a406b3` theo GitHub release metadata. Chạy **`kc.bat build --db=mysql --health-enabled=true`** trong thư mục build riêng, JDK 17. Quarkus augmentation thành công và ghi nhận ba authenticator factories, event listener và login forms provider. Vendor cảnh báo dùng internal SPI và một số feature defaults deprecated. Lượt này không gọi `kc start` hay nối DB. [Keycloak release assets](https://github.com/keycloak/keycloak/releases/tag/26.8.2)

## 5. Keycloak runtime compatibility

| Kiểm chứng | Kết quả |
|---|---|
| Java/Jakarta/provider linkage | Maven verify với 26.8.2, JAR descriptor check và Quarkus augmentation PASS. OpenJDK 21 trong image đã xác minh qua inventory RPM, chưa boot image. |
| Secret-file/startup | 18 config tests và 1 HTTP token fixture PASS trong SPI suite, gồm require file và tách inline secret khỏi Public Demo. Chưa xác minh Linux mounts/permissions và startup trên container thật. |
| Auth/Risk, nonce, strict JSON, MFA/trust và events | SPI fixtures, signed HTTP/JWT và backend regression đạt. 28 response invariant tests và 8 adaptive contract tests chạy với provided 26.8.2. |
| Realm import/readback, Client Credentials/FGAP, Browser Flow, PKCE/OTP, LOW/MEDIUM/HIGH, mandatory/priority/fail-closed, trust register/revoke, session/logout, event delivery | **BLOCKED** ở native candidate. Docker daemon không khả dụng, không xác nhận được isolated network, realm, DB, secrets, keys hoặc ports. |
| Candidate image build/scan và runtime rollback | **BLOCKED**. Quét upstream base và augmentation ZIP cục bộ có scope riêng. |

## 6. Thay đổi source/configuration

Ba Spring POM và các import/API có thay đổi do Boot 4, Jackson 3, Servlet/JPA test modules và Spring 7 HTTP headers. Gateway giữ các proxy/security limits thông qua property names mới. CI thêm candidate SPI job và giữ job mặc định. Candidate Dockerfile riêng, không thay file Lab. Bảng SHA-256 cuối báo cáo liệt kê từng input trước/sau. Những test sửa vì migration vẫn giữ assertions, profiles và opt-in gates. Trường `JsonNode.fieldNames()` chuyển sang `propertyNames()` với cùng phép so sánh tập trường.

## 7. Regression

| Lượt chạy cuối | PASS | FAIL/ERROR | SKIPPED |
|---|---:|---:|---:|
| Portal Maven verify | 534 | 0 | 0 |
| Risk Maven verify | 903 | 0 | 96 |
| Gateway Maven verify | 112 | 0 | 0 |
| Keycloak SPI Maven verify, profile candidate | 251 | 0 | 27 |
| **Java tổng** | **1.800** | **0** | **123** |
| Frontend `npm test` | 34 | 0 | 0 |
| Public Demo Python | 42 | 0 | 0 |
| Observatory Python và viewer JS | 22 | 0 | 0 |

Java có **1.923 test được báo cáo**. Conditional skip liên quan native MySQL/Redis và opt-in SPI/HTTP audits, không được tính là PASS. Các lỗi build/test ban đầu từ relocation, H2 và web test auto-configuration đã được tái kiểm trên module cuối. Có 90 test PD-02-01, fail-fast/grants mock, JWT/RBAC, B0, MFA/trust và service identity trong suites. Python gồm NGINX TLS và age native loopback/synthetic. Frontend lint/typecheck đạt với một warning PostCSS có trước. Hai production build Standard và Public Demo đạt. Build Public Demo dùng auth localhost bị từ chối theo contract.

## 8. Security rescan

| Artifact/scope | Trước → sau |
|---|---|
| Maven OSV, bốn effective graphs | **368 → 419** tọa độ, **49 → 4** advisory ID. Ba Spring app graphs hiện không match. Cả bốn match sau migration là Keycloak SPI provided. Maven plugin graph nằm ngoài scope. |
| Packaged JAR, Trivy rootfs | Quét bốn JAR đã build trong thư mục artifact riêng, **346 package records, 0 match**. SPI JAR không chứa provided dependencies. Kết quả này khác server JAR inventory. |
| Frontend npm audit | **0 → 0** trong app/lockfile. Hai Moderate của tarball npm CLI ghi ở PD-R9 vẫn là residual riêng. |
| Keycloak upstream base Linux amd64 | PD-R9 26.7.0 **6 Critical / 41 High**. Lượt này 26.8.2 child digest **0 / 4**, gồm **0 / 3 OS** và **0 / 1 bundled JAR**. CVE-2026-18963 không còn match ở base ứng viên. |
| Temurin builder / Java runtime base | Jammy **0 / 2** và Resolute **0 / 2** ở OS scan. Các match APT/libapt là CVE-2026-109518. Dockerfile đã pin fixed distro package. Linux final layer chưa build lại. |
| Node Bookworm base | OS **1 / 34**, npm bundled trước lớp patch **0 / 6**. CVE-2023-45853 liên quan MiniZip, Debian ghi contrib/minizip không được build trong gói zlib Bookworm. Các mục OS khác giữ triage theo từng CVE của PD-R9. |
| Candidate/full release images | **NOT VERIFIED**. Không có image app/candidate mới để quét. |

Trivy 0.76.2 dùng DB 07/11 `06:54:25Z`, Java DB 07/11 `01:07:52Z`. Registry scans chỉ đọc image gốc theo digest. Native JDK/Node giữ pin đã đối chiếu vendor ở PD-R9, lần này chạy build/tests trên đúng binaries đó. Không suy ra Windows OS hay Linux native runtime sạch từ scan dependency. [PD-R9 advisory crosswalk](PD-02-02_PLATFORM_DECISION_AND_CLOSEOUT.md) · [Ubuntu APT CVE](https://ubuntu.com/security/CVE-2026-109518) · [Debian MiniZip](https://security-tracker.debian.org/tracker/CVE-2023-45853)

## 9. Advisory còn lại

| Scope và advisory | Bằng chứng, xử lý còn thiếu |
|---|---|
| SPI provided Guava 32.1.2-jre và base Guava 33.6.0-jre, **CVE-2026-102554** | Match cả hai scope, fix upstream 33.7.2. Điều kiện là attacker-controlled native Java deserialization của Guava collections. Trivy/OSV High, vendor Moderate. Giữ chờ vendor fix hoặc reachability proof cho exact image. Không override server library. [Guava advisory](https://github.com/google/guava/security/advisories/GHSA-xxph-c9ww-hj94) |
| SPI provided protobuf 3.25.1, **CVE-2024-7254** | Fix 3.25.5 trong line 3.25. Trivy inventory của base ghi protobuf 4.35.0, JAR provider không bundle protobuf. Cần xác nhận effective runtime classpath sau khi build. [Advisory](https://osv.dev/vulnerability/GHSA-735f-pc8j-v9w8) |
| SPI provided Netty DNS 4.1.135.Final, **CVE-2026-73508** | Fix 4.1.136.Final. Base ghi 4.1.139.Final. Cần xác nhận packaged/runtime resolver và malformed-DNS reachability. [Advisory](https://osv.dev/vulnerability/GHSA-mfg7-5gfp-c4w3) |
| SPI/base OpenTelemetry API 1.62.0, **CVE-2026-118259** | Moderate OSV, fix 1.67.0. Cần kiểm đường xử lý W3C tracestate không tin cậy và vendor patch. [Advisory](https://osv.dev/vulnerability/GHSA-ccrj-gw8r-854m) |
| Keycloak base OpenJDK RPM, **CVE-2026-91403** | Base có ca-certificates fixed RPM cho CVE-2026-114406. Red Hat dùng system trust store để xử lý eMudhra. Còn phải kiểm effective CA path trong container. [Red Hat](https://access.redhat.com/security/cve/cve-2026-91403) |
| Keycloak base sqlite-libs, **CVE-2026-119373** và **CVE-2026-119586** | Lần lượt cần FTS5 với query/dữ liệu đặc thù hoặc CLI `.recover` với DB do attacker tạo. Base không thấy RPM sqlite CLI, candidate chọn MySQL. Chưa có fixed RPM trong feed. Còn xác minh binary/call path hoặc cập nhật vendor. [FTS5](https://www.cve.org/CVERecord?id=CVE-2026-119373) · [SQLite recovery](https://www.cve.org/CVERecord?id=CVE-2026-119586) |

Registry raw High/Critical Node/Temurin cùng digest và danh sách như PD-R9. Sáu High của bundled npm base khác tarball 11.21.2 được pin trong Dockerfile. Đóng từng residual theo artifact và khả năng tiếp cận. Scope approval D-15/D-16 không phải risk waiver.

## 10. Flyway V5

**Checksum 661092940 giữ nguyên.** Gate chạy với Flyway 12.4.0 trên Java 17 trước regression Risk. So bốn SHA-256 của V5 và helper/nested classes trước/sau, cả trong `target/classes` và `BOOT-INF/classes` của JAR. H2 chạy Flyway với các migrations hiện có. `Health.java`, `Migrate.java`, `InspectRisk.java` và `MigrateLegacyRisk.java` compile cùng classpath của Risk JAR mới. Không sửa migration V1–V5 hay applied history. Không dùng H2 để suy ra MySQL validate/upgrade hay snapshot rollback đã đạt. [V5 checksum contract](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/migration/V5ChecksumContractTest.java)

## 11. Rollback

Không có DB schema migration trên môi trường thật để rollback. Không revert module nào vì regression cuối đạt. Bốn nhóm thay đổi tách được theo Portal, Risk, Gateway và profile/recipe Keycloak. Nếu cần hoàn tác source, đảo riêng hunks của nhóm và đối chiếu baseline SHA, giữ nguyên thay đổi của các checkpoint trước. Nếu candidate DB đã migrate trong lượt được phép sau này, rollback cần restore snapshot nhất quán với Keycloak version trước và kiểm schema trước khi mở writers. Không chạy image cũ trên schema mới. [Keycloak upgrading guide](https://www.keycloak.org/docs/26.8.2/upgrading/)

## 12. Lab và repository

Baseline và cuối lượt Docker daemon unavailable. Metadata container hiện tại **NOT_VERIFIED**. Lab Compose, Dockerfile Keycloak mặc định, default SPI version, volumes và dữ liệu không bị thao tác. Không đọc secrets, OTP, DB hoặc signing keys Lab. Không tạo worktree/clone, commit, push, mở public port hoặc triển khai Staging/Production. Đối chiếu tất cả source và 48 file readiness lịch sử qua SHA-256. HEAD/branch và các thay đổi có trước được bảo toàn ngoài các extension migration được liệt kê.

## 13. Production acceptance còn thiếu

Cần exact image build và digest, Linux package scan/SBOM, container runtime hardening, quyền file/secrets, issuer/JWKS/TLS, MySQL engine/schema/grants và Redis thật. Candidate Keycloak cần realm readback, native Browser Flow và retry/rollback tests có synthetic witness. Nghiệm thu Staging/Production, D-10/D-13 và owner GO vẫn là các bước riêng.

## 14. Blockers và gate

- **PR-001 OPEN, G1 PARTIAL.** Spring app source graphs và packaged JAR scan đã đạt, còn residual theo base/server/provided, candidate image và final release verification.
- **PR-016 OPEN, G3 PARTIAL.** Recipe và augmentation đã có. Docker daemon không khả dụng nên chưa chứng minh container build/run, native realm/PKCE/MFA/trust, Linux permissions và hardening.
- **PD-02-02 PARTIAL.** D-15 và D-16 đã được áp dụng ở source/config. D-16-RUNTIME được duyệt có điều kiện và đang bị chặn thực thi. Không coi 123 skip, scan base hay augmentation là acceptance còn thiếu.

## 15. Bước tiếp theo

Khi Docker daemon có thể truy cập và xác nhận được isolation, tiếp tục đúng **PD-02-02** với build/scan image ứng viên, Keycloak integration và rollback trên dữ liệu synthetic. Đóng các advisory còn áp dụng theo từng artifact hoặc quyết định được owner duyệt. **PD-02-08** đứng kế tiếp khi PD-02-02 PASS. Tại PD-R10, chưa có task TODO đủ dependencies.

### Manifest SHA-256 và provenance

Đối chiếu **645/713** file hiện hữu giữ nguyên byte, 68 file thay đổi gồm roadmap, hai file thêm gồm báo cáo và candidate Dockerfile, không có file bị xóa. Cả 48 file readiness lịch sử giữ nguyên.

| Đầu vào migration | PD-R9 | PD-R10 |
|---|---|---|
| [.github/workflows/ci.yml](../../../.github/workflows/ci.yml) | `a8c11d7cc7035295ea3ef88ce0798fb9ef723fe0129341af1c5a12dda1b546b7` | `eaf4eea9730b0d8a72cb23d7a22063213c4aec7d9dec557505be051786d5ed5b` |
| [deploy/public-demo/Dockerfile.keycloak](../../../deploy/public-demo/Dockerfile.keycloak) | Mới | `d76854c2dd14cba26b1487436a9e7950f5e381e6a16a7a915a30e32158df7a8b` |
| [deploy/public-demo/README.md](../../../deploy/public-demo/README.md) | `282a340aedd8d90261c5a002331b47ac065c925cc7a5385e7c89769c7befec5d` | `29717ae2d46ab0fdb79776adb2b50734034c777948e8a3fbdc3fdccb03ef9530` |
| [gateway/pom.xml](../../../gateway/pom.xml) | `96b3f829a0ca8d0ec2e819e73330114548f6a09011de670ab054221f0c58852e` | `88453eccb7b6d38585537d2b5d003d4168aa9f8394d170790945b7fc26fc49f6` |
| [gateway/src/main/java/com/zerotrust/gateway/CanonicalRequestFilter.java](../../../gateway/src/main/java/com/zerotrust/gateway/CanonicalRequestFilter.java) | `d053ad245e89895d286e552e004d15203a3621f349b6bd22927061b3f13805eb` | `6c5924dcc8e5516f0c46a9a5c450924941c90a0aa20b34d3115cab6ecaff2798` |
| [gateway/src/main/java/com/zerotrust/gateway/GatewayRoutesConfig.java](../../../gateway/src/main/java/com/zerotrust/gateway/GatewayRoutesConfig.java) | `74b019e9f821a3a3dd7baf92bbcd165a6142032dd1dd70a5970b310c1525fbfc` | `94c1a6eec61f4cb3b9cfc333770404911f2493e56bb792d183ae95a6fb558fd9` |
| [gateway/src/main/resources/application.properties](../../../gateway/src/main/resources/application.properties) | `88a155195e54818fc22f014a05ccc10442757e7782968f7aadded16c7953ed8c` | `9f5f3d44f96cada2db0a894f091357947f362a3176d2142ea5e087fc3ef21d4a` |
| [gateway/src/test/java/com/zerotrust/gateway/GatewayAbuseHttpTest.java](../../../gateway/src/test/java/com/zerotrust/gateway/GatewayAbuseHttpTest.java) | `c1262974005dfb4c7bb2f723792be6b18d10ef2bacf08e05b4c74c011da4b3b2` | `8c9036214958774680fc8340d7597f1265215026b5bf5f298f8adee306f63585` |
| [gateway/src/test/java/com/zerotrust/gateway/GatewayRouteTests.java](../../../gateway/src/test/java/com/zerotrust/gateway/GatewayRouteTests.java) | `c0ec5615714176c9ab5f56937fc8d52e3173503a7dfd92bd157ee4a1d0f9f76c` | `93e762ea2642306d0c6bf1c8befa216a026aeced607c7d53cadd6bb614e81596` |
| [gateway/src/test/java/com/zerotrust/gateway/GatewaySecurityTests.java](../../../gateway/src/test/java/com/zerotrust/gateway/GatewaySecurityTests.java) | `9d3d93ad92bba0b11f703d9d4c9a76eca035b6fab885d08bcad7f0389004a611` | `037cb314fb37a23b57645a4914bdfe9445c4f4e5af2683ec4ad53925b6b0b933` |
| [keycloak-risk-extension/pom.xml](../../../keycloak-risk-extension/pom.xml) | `718fd18628510fc1545fe9d6134b181bcdbc9e3adb18836bfa239a47bee4c839` | `9a4c9fa04ee9050bdf38791047344a3d49de2ca7566b5dfcb23450ae27ea9564` |
| [pom.xml](../../../pom.xml) | `f8cbc823f9e34b1ca8fd6376439bae4c0866ea409bc5c64464ec9253cf68744d` | `d5b561490158cc4e9d260bd989819b100a600a1713c000120864880b14b1cb63` |
| [risk-scoring-service/pom.xml](../../../risk-scoring-service/pom.xml) | `f10a90e9b31b1e84ac5aaecb08261eb3cef5df644b5d78a03f1b38f4adbfa29d` | `caf548e37d54d8dc753562ddd0149614d50f53d6402bf95d3da99dd6142035dc` |
| [risk-scoring-service/src/main/java/com/zerotrust/risk/config/GeoIpHealthIndicator.java](../../../risk-scoring-service/src/main/java/com/zerotrust/risk/config/GeoIpHealthIndicator.java) | `d23d4273bb6263d8caf3f1044321940a20b7863a87de7fade1ab8cb48580fb1e` | `d42b58f2c383fa45c199db2b8aa590c075e8987ae0a9ebedcc803b7c5cf230fd` |
| [risk-scoring-service/src/main/java/com/zerotrust/risk/config/RiskApiSecurityConfig.java](../../../risk-scoring-service/src/main/java/com/zerotrust/risk/config/RiskApiSecurityConfig.java) | `9cb97e72d57d41f5e9331de35da6f84a8205356392f2582aabbf37c7308ca3aa` | `5425eeb69b12cc49f963c0af0dcd3c13701d9eca86e1c759ada5db6cd684c26c` |
| [risk-scoring-service/src/main/java/com/zerotrust/risk/trace/RiskScoreTrace.java](../../../risk-scoring-service/src/main/java/com/zerotrust/risk/trace/RiskScoreTrace.java) | `b56acd81eaf263eb70dedd2469ffb4254cc4572b532dab00554c1a70e4016e6d` | `cd07ed2da4d3b80f6fb334cc63e59e9f7dd22e4097b184f6464e76f1c8b38fee` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/audit/B1ImplementationTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/audit/B1ImplementationTests.java) | `625509dc297289e6357ff11b321107b537b284ca21d5cb0a696c25c95aae5f67` | `816ae55eed38207686e87e53d5f86ca32e9b53fb42956b33426b148060145c6e` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/audit/ControlledStudyExperiment.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/audit/ControlledStudyExperiment.java) | `38ba866e185716a084a74d1f2c7cc45a294e7a2484ded86a7d135dfb12c9fcc0` | `4f208aafd2f0628acafc483b5a9751071d3c2a86941ff49c0807c511fc0d9b62` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/audit/RiskObservationTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/audit/RiskObservationTests.java) | `a6610ecfe8621ae1c918b233533feb897f197b21c02cf31f27388694a8358d79` | `f735f7e0b9c30a0b796d2f5d1ae453c8aa43a9d089b9694c8f45f02a4f5cd359` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/audit/TrustScoreResearchTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/audit/TrustScoreResearchTests.java) | `8337feb8479cc6cd759e4cbe74169d873dfb68d3fa33b2e9f35ad0f868327402` | `ab7cff1e990a28dbbe047efea14427060a202b1bdbe0baf92b8d7c2b9b80b1be` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/audit/http/HttpAuditSupport.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/audit/http/HttpAuditSupport.java) | `5c21163cc7b0bf36272d6fb46a7cbccf4bcd475c4a0ac37992a4ae48b482c2e5` | `14b2c014c1badf98315728b9c979104d81df74ecb5aedfdcbb839079ec8153cb` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/audit/mysql/DeviceTrustSnapshotMySqlRegressionTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/audit/mysql/DeviceTrustSnapshotMySqlRegressionTests.java) | `08e31fc54d32c56f561c3e865b2dd3a38ca7931c15f8817673fc51e92b33876a` | `d0ee813b8475dd9d7245e2041232a750c01b0f45e088ba6de787f972e2ab3132` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/audit/mysql/SubjectDeviceLifecycleRegressionTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/audit/mysql/SubjectDeviceLifecycleRegressionTests.java) | `3611a791b9e37c0cf13be385d7a2a036c89d6d8fcd856d012c194194bd80f4d6` | `523b3f2753972ad97e183a9f1cbdb91f2d26539955f2aee3754e763910ae2476` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/config/GeoIpHealthIndicatorTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/config/GeoIpHealthIndicatorTests.java) | `074274a9878fd30d689ffa91f26a516dd0ddf14386ef361e0c3c9f7fed3bf67e` | `56e863db52dd553297610d69e7ef103267b80bffc0d5953e561075bc080ca2d6` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/config/PublicDemoB0ContractTest.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/config/PublicDemoB0ContractTest.java) | `6507a46f8ca8f3d3b30299db870a15c35a1a313e3dae7ce484521616e1386a44` | `58fe3ac2abd594ce9c01eccfee4de56dded70c8bfc1b03ea3f90659937ba4e54` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/config/PublicDemoStartupConfigurationTest.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/config/PublicDemoStartupConfigurationTest.java) | `9ce72887d318c73311a65b84982836aed4b824af6ae166ab7ebd5bcf1bda4c81` | `64ecf9859473dc47c7975d653303ae5a313fcbe1d63c77e44eb7272bb5aab064` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/controller/B1RiskEvaluationControllerTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/controller/B1RiskEvaluationControllerTests.java) | `d9690f3a5b9e57d94c3095a49b7dbc3419b1f502dfe00b783c0012a5bcfd1768` | `7311b0c0fb98831330c7f35be11f60f52a0a015cfcb6ba0ea817c0054ebff2ca` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/controller/RiskEvaluationControllerTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/controller/RiskEvaluationControllerTests.java) | `8a6350460518c19b0fb3a6b97e617feff06eb3c1a70f30b2a048c6dbfa40986d` | `4ff4e34df4ad232c6400e3be08cfc1b89d7cea4d8b9bf19e16992b98483b8eff` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/controller/TrustedDeviceControllerTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/controller/TrustedDeviceControllerTests.java) | `a335a521adfe38a8bfb5e7173473176ac3894034cadddfc1bab3b7a673a3e657` | `e28190ea446279d01fe35d485351381329b5f48e576c949a74d6acbe88a51c07` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/controller/TrustedDeviceRevocationControllerTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/controller/TrustedDeviceRevocationControllerTests.java) | `fe89f2126ea57cfbc4876358e29a5793c84d00453226d219ebf769b76b30006c` | `f27c01eafff8763c9b42e1a7b042b160fad0c08a286281fc6da3a6931001617d` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/diagnostic/SubjectIdentityMySqlInvestigationTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/diagnostic/SubjectIdentityMySqlInvestigationTests.java) | `80ab2fbcda4c806e06e9aaa230bc0f44ae91843323f861c59a8aae056e871535` | `ad59b8c3af8742ac6e28152fc4f0828175122e078cc706be9a1edcb4f416b608` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/diagnostic/SubjectIdentityMySqlSupport.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/diagnostic/SubjectIdentityMySqlSupport.java) | `b16aecccd4d7828d456b2cb11c7b19690076f32efa2637bdbb64964bd701c9e2` | `7f12200bd0e5375f300afeccb20d86b711f3e6d40919a02ec62f4ca1c4b43245` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/migration/SubjectIdentityMigrationMySqlTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/migration/SubjectIdentityMigrationMySqlTests.java) | `5d6e5425f4941a49e03d2c4f6cd750a381a041f9d5b3938789d4a3b4d0b7349d` | `eee10d7f569532cd2c33a259ef0e27e5b162e23a6278a5ea2b4d7781a8161787` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/repository/AuthenticationSuccessEventRepositoryTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/repository/AuthenticationSuccessEventRepositoryTests.java) | `17fa5de40baf3614d555e4af272e2c953c935f73c1ab39a65270c69917ff9c2a` | `4c9bfe989a75c353648abab6d79000448d84e940fda00d0c91c7be27e4e60796` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/repository/KnownDeviceRepositoryTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/repository/KnownDeviceRepositoryTests.java) | `5168594e5939d0b1615c9168ea08b023a770e31ec2dc095449fe60afbbe1e3f6` | `44ebe178786cf30c4b7e72bb3d62c105e44ed3f4865aa8a27789ea3f4a6b5bef` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/security/RiskApiHttpsSecurityTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/security/RiskApiHttpsSecurityTests.java) | `97cdcc038f7ec8bb845ac22b1c6ca680d24c1e4008d0db2c6e0f8f4e5fbff1ab` | `368f8652c1b7d7690243db8fcf9886e15ddfe0a1a29a029aa21303f17db4ba88` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/security/RiskApiSecurityTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/security/RiskApiSecurityTests.java) | `92f3924f9a2a80f234634440f48b91310004e510873a29f5e5cfba27667683c5` | `a71c921b1b1cb40225f8ab8aa52d1449f894d0581b2876e2ae4436c3ea6469e4` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/service/TimestampLifecycleBaselineMySqlTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/service/TimestampLifecycleBaselineMySqlTests.java) | `6491d4f8b130adf6e02bf0d548528b9be9636868ae477d71b5a5f2d33d214754` | `5711ee258d5a49e790876da7d58cf08e32312311cd651e2da8bd42ba6a7897a1` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/service/TimestampLifecyclePrecisionContract.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/service/TimestampLifecyclePrecisionContract.java) | `60380f85bd6ca1f4fa3a24145c93e54f184e5eb10a7eda2b57ecddf61aec2541` | `5c801d8265135b3ca92867443f0e8d111bd77e6fe16f81dfaf796f344f3a5721` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/service/TimestampLifecyclePrecisionH2Tests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/service/TimestampLifecyclePrecisionH2Tests.java) | `777cc15a16ec1c1e14c0ae803e059fae8e41823783fea595f7fdb699afecfad6` | `f8c00d7de073229003e083ab1ce5ed0576b23d470f0a1b6283be0ef5f4aacf35` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/service/TimestampLifecyclePrecisionMySqlTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/service/TimestampLifecyclePrecisionMySqlTests.java) | `c56ffa03a036ef8728271d1a791cd14a58320ee5e18883f13712f04f77d9c466` | `3f2ca557f5eef208c64ce165495d14ba40dffbf058162fcb5cb80e005c48b951` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/service/TimestampMySqlSupport.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/service/TimestampMySqlSupport.java) | `94ae95a38ee9f647549099ed686a12c6cfc3dd254f0612a79276531bcefc86ce` | `70945e66db0b7ea01f65fc54fe59354421611d0de94520c0bbb164a9af93bfa5` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/service/TimestampMySqlSupportTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/service/TimestampMySqlSupportTests.java) | `a9f6513f4b951a9184fdffc6b2d58beda1d022c70ef10dc16d933527a5c44870` | `46d4c8cd370fa48229ed369fc782b25b584bf0b1a32f42ed2f824b67f2ce7f6a` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/service/TimestampSubjectIsolationMySqlTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/service/TimestampSubjectIsolationMySqlTests.java) | `af407bf5791b6719e67eec283b69e89aded2cd3ffacebb99bcf6a6cc2480b53e` | `0236c95456985d755c13a54008dbddd7fd11e1832d5ff3c4e28f8c84947b268e` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/service/TrustedDeviceRegistrationServiceTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/service/TrustedDeviceRegistrationServiceTests.java) | `e5c1fb366dcc2a6a4ec0c3fdb0d49701daac9ec9ad69a8f49b870213c6158e6c` | `75bb0accb4076928df4965cf9ad9c137927236a2657dcebb64888d68340c2fc1` |
| [src/main/java/com/zerotrust/zerotrust/exception/CustomAccessDeniedHandler.java](../../../src/main/java/com/zerotrust/zerotrust/exception/CustomAccessDeniedHandler.java) | `c2916e4d85592d5a6f22773d6f4db2c974cffd1429d3e95ce18332cbbe4362c2` | `0ce6eab575f2f662718c7286e0d5abc7d19cc662bf19b060670f19ec7c9b9721` |
| [src/main/java/com/zerotrust/zerotrust/exception/CustomAuthenticationEntryPoint.java](../../../src/main/java/com/zerotrust/zerotrust/exception/CustomAuthenticationEntryPoint.java) | `0fd26f9fd0b5727367959907efce06039bf91d7048a8d55608b3890cb3d4be06` | `3c00ddc26ce03e0fc167ebd8c3f1c25be31345f47d2ce94ae461bbebe0b05394` |
| [src/main/java/com/zerotrust/zerotrust/risk/RiskDeviceAdminClient.java](../../../src/main/java/com/zerotrust/zerotrust/risk/RiskDeviceAdminClient.java) | `d42d5900f17fc53bd818d1b8923be3c1890133f8bc043052ac579edef23b5d4a` | `eb46c13f204c44814d7145d2fc725e325894d03f837f2d9f26b0327625c2601b` |
| [src/main/java/com/zerotrust/zerotrust/security/PublicDemoAcademicReadOnlyFilter.java](../../../src/main/java/com/zerotrust/zerotrust/security/PublicDemoAcademicReadOnlyFilter.java) | `5bb61f394415b1b233c4790eb13a94098e7811472d9aad1ed0e27342e5f75b2d` | `2b18693b82f1046b6c92e2c558614af4fdc6c002a8de3c9dc7b204656698df47` |
| [src/test/java/com/zerotrust/zerotrust/ZerotrustApplicationTests.java](../../../src/test/java/com/zerotrust/zerotrust/ZerotrustApplicationTests.java) | `4be660eb98c93c787cb3b4b13a81ea8fc718d71d813d3174d5a4216b2aa94cc5` | `98120ff9765432ddc10fcae1d2488f8078c54eec1a5a155b49f916920dc30612` |
| [src/test/java/com/zerotrust/zerotrust/config/FrameworkResponseHeadersTest.java](../../../src/test/java/com/zerotrust/zerotrust/config/FrameworkResponseHeadersTest.java) | `710909c82e642b0427dacfb9729b6f5054c1306bf88c7ff38eff102ce1208491` | `60b029ec3e46efebf3105e1e50640533415d258d93be0bd1fb13e8921e3c64a2` |
| [src/test/java/com/zerotrust/zerotrust/config/KeycloakAdminPropertiesTest.java](../../../src/test/java/com/zerotrust/zerotrust/config/KeycloakAdminPropertiesTest.java) | `81191663e577d97a8e1521aec3690d867d4159d1b2f46ff3bdce2a57f0dd1349` | `35b6ca8ed73941dc47a6daae128de8f311199ced5aca129a719778261f67b7a5` |
| [src/test/java/com/zerotrust/zerotrust/config/PublicDemoConfigurationTest.java](../../../src/test/java/com/zerotrust/zerotrust/config/PublicDemoConfigurationTest.java) | `be84ed779e02fba66ca72c18df4c3d48ff2104f44a56ddc6c078870a176605d5` | `460fea59b849ae431197d566d46ea9247bd037c6fa1c2e5b5ddb1aaeaf4ea169` |
| [src/test/java/com/zerotrust/zerotrust/config/PublicDemoStartupConfigurationTest.java](../../../src/test/java/com/zerotrust/zerotrust/config/PublicDemoStartupConfigurationTest.java) | `b14461179060cca1266399819abd7d830a84b902978af6b97bc404e53e03981d` | `ea720ad4676a389374d48bc16a25899832358d5b81f87b5c3f63a8fe7c8c3734` |
| [src/test/java/com/zerotrust/zerotrust/controller/AdminControllerSecurityTest.java](../../../src/test/java/com/zerotrust/zerotrust/controller/AdminControllerSecurityTest.java) | `30446da25657717c41e0bc7f0a27b1efc209e83068c22a1475bccd4e8bea7269` | `dbf8293f4c90bffeeec3465e637361fdc03c9313f1f869f5edb50fcbfd836ab9` |
| [src/test/java/com/zerotrust/zerotrust/controller/PublicDemoAcademicReadOnlyTest.java](../../../src/test/java/com/zerotrust/zerotrust/controller/PublicDemoAcademicReadOnlyTest.java) | `1cd4bc784732395cc7ce9f5bd9dcddc21d4a3b1dccb8935f78f4db76a64981fb` | `8c475554c087fb3967f6bea6b6a675530cd13e0dd63229e43fef19c97b2ae7b2` |
| [src/test/java/com/zerotrust/zerotrust/controller/SchoolPortalPersistenceAcceptanceTest.java](../../../src/test/java/com/zerotrust/zerotrust/controller/SchoolPortalPersistenceAcceptanceTest.java) | `7697fb30f3c2c36f150319de500b7a5effea12b6f12006c7302448cdc53d7c74` | `ea63208f6e7178b3efa15f509896747547d7edc7155e97b9ea823d6e9d3369e2` |
| [src/test/java/com/zerotrust/zerotrust/controller/StudentControllerSecurityTest.java](../../../src/test/java/com/zerotrust/zerotrust/controller/StudentControllerSecurityTest.java) | `0845982694b25c41bed3acdb7ebd526798556feea5c6e24a70745f436244bc33` | `a89934b01b2db06bb454177428ab56a5440e43ec91612eb1f2e33b82d8d6217a` |
| [src/test/java/com/zerotrust/zerotrust/entity/ScoreEntityMappingTest.java](../../../src/test/java/com/zerotrust/zerotrust/entity/ScoreEntityMappingTest.java) | `e5bbac2cc70b323685f2ae72236346b346d128f9db7b827d4dbea1d9a8a90d2b` | `6aa8892e47283e5c76957dfa95938e5c2e9895dd6899438da7b857315ea7471a` |
| [src/test/java/com/zerotrust/zerotrust/repository/StudentClassRepositoryTest.java](../../../src/test/java/com/zerotrust/zerotrust/repository/StudentClassRepositoryTest.java) | `8ce613f7fa1d4a75fe6c8b2a1e1160ac3dd77644d1cee64b5aa4e49762009ba7` | `536d947299082323f127144833da5c531c3ce0878ef6107ceb1d4b1908e9d00b` |
| [src/test/java/com/zerotrust/zerotrust/repository/StudentRepositoryTest.java](../../../src/test/java/com/zerotrust/zerotrust/repository/StudentRepositoryTest.java) | `f5313821ee22df745f57724c620cdc8ce43921f8dd1c7b4c308ffb7bf252db40` | `edb4cb7e8bebe563da09a4b20cd8d51c308497631637f0ad0498f8893ab8daa3` |
| [src/test/java/com/zerotrust/zerotrust/repository/SubjectRepositoryTest.java](../../../src/test/java/com/zerotrust/zerotrust/repository/SubjectRepositoryTest.java) | `364841c318e106d98f7b3c219e2485e16429d0e80d414c7b3f942507e6029bbf` | `0aac430c91c9659d6624de4c7b7f15f27fce9aaef3b09a572da21df62a3660e4` |
| [src/test/java/com/zerotrust/zerotrust/risk/RiskAdminPropertiesTest.java](../../../src/test/java/com/zerotrust/zerotrust/risk/RiskAdminPropertiesTest.java) | `3efe389dc1f4a40bac8d8b2457460639647215b4a806c924c0bb54785c12c48b` | `4facad5205471a01858a31bc624d72ca0c90b5c921bce4635805fcdb613ca2d8` |
| [src/test/java/com/zerotrust/zerotrust/risk/RiskDeviceAdminClientHttpTest.java](../../../src/test/java/com/zerotrust/zerotrust/risk/RiskDeviceAdminClientHttpTest.java) | `459deef50a22c769b4f670344de12f2e4937da5c9dfd79729d5ac35498e34038` | `d945fb4dfbde0c3032a0edca808117b1fdd1486ae76e57419413834736157962` |
| [src/test/java/com/zerotrust/zerotrust/risk/RiskDeviceAdminClientTest.java](../../../src/test/java/com/zerotrust/zerotrust/risk/RiskDeviceAdminClientTest.java) | `da313ca0e67fb36e6915f15cf75553d88656f9c86bec1110ebfd4d44e3a7b5db` | `6a8e9a85611a948c0a607de2920f8fab9ca85fd8cbb8763bfd9bb7e41e75c73b` |
| [src/test/java/com/zerotrust/zerotrust/security/CredentialExposureTest.java](../../../src/test/java/com/zerotrust/zerotrust/security/CredentialExposureTest.java) | `c83ff5f4d49a5031159ac391093b4aa6ded534a928711b5085b7839e167d52cc` | `051d083c241e46e2ff5693c42d4d91e8ae3f6f01eb44ce79b8016cfb144db587` |
| [src/test/java/com/zerotrust/zerotrust/service/impl/ScoreUpdateConcurrencyTest.java](../../../src/test/java/com/zerotrust/zerotrust/service/impl/ScoreUpdateConcurrencyTest.java) | `0cad74ddcb8507d0b226ceeba1522699d6ce6cdd72cfed67fe7715f44beafa6f` | `e051d4db31f05a228847e27265fd541b796b3a01f66421e876fa46f92d91b616` |
| [src/test/java/com/zerotrust/zerotrust/service/impl/SubjectCreationTransactionTest.java](../../../src/test/java/com/zerotrust/zerotrust/service/impl/SubjectCreationTransactionTest.java) | `dc81a6cf25b2882e402a090971f95cfd1e20a230a240146f74fc08bf7dad612e` | `f1d903aa21d5747b5deaf5ca93b31f856ebb74d96d4c5979cc795e6f50cea945` |

| JAR được quét cục bộ | SHA-256 |
|---|---|
| `keycloak-risk-extension.jar` | `7eed70d71f78506244b2f8f7c8d250bc44ce7c5cca8b1bcead5a4d93c6ebd980` |
| `risk-scoring-service-0.0.1-SNAPSHOT.jar` | `72eef2074248cd356f549671f42a5d74568ee66f7c0a01d44a6ef38588125678` |
| `zerotrust-0.0.1-SNAPSHOT.jar` | `84dd5d85ded311b11156cdc80222d54543cdef20fff7c298fb8860d393fe793a` |
| `zerotrust-gateway-0.0.1-SNAPSHOT.jar` | `ed8dfc4c416b661b4398654b74568eeb1daec95b65fc0c8e263cd77d39a58826` |

Logs và raw inventory nằm trong ignored `target/pd-02-02-migration/`. Maven verify dùng `mvnw.cmd --batch-mode --no-transfer-progress -f <pom> verify dependency:tree -DoutputType=json`, thêm `-Ppublic-demo-candidate` cho SPI. Npm audit và OSV querybatch dùng registry công khai. Trivy dùng `image --image-src remote --platform linux/amd64` cho upstream base và `rootfs --pkg-types library` cho thư mục bốn JAR. Lượt `fs` không nhận dạng JAR và không được tính vào kết quả.
