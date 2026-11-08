# PD-02-02 — Xác minh bản vá từ nhà cung cấp và quyết định D-17

**EV-PD-02-02-07 · PD-R15 · 08/11/2026 (Asia/Saigon) · PARTIAL · NO-GO FOR PUBLIC ACCESS**

## 1. Baseline PD-R13 và PD-R14

- PD-R10–R12 đã xác minh Spring Boot 4.1.2, Spring Cloud 2025.1.4/Gateway 5.0.4, Custom SPI trên Keycloak 26.8.2 và Redis 7.4.12 Alpine trong phạm vi candidate. Redis đạt TLS/ACL/readiness/AOF và scan 0 Critical / 0 High. Evidence native trên candidate cũ gồm realm, OIDC/PKCE, OTP, trusted device, B0, Risk integration và logical restore cùng phiên bản. V5 ledger ghi `661092940`. [Migration](PD-02-02_CONTROLLED_PLATFORM_MIGRATION.md) · [Runtime](PD-02-02_CANDIDATE_RUNTIME_CLOSEOUT.md) · [Redis và residuals](PD-02-02_RESIDUAL_SECURITY_CLOSEOUT.md)
- PD-R13 ghi **0 Critical / 4 High** theo scan exact image. Guava và SQLite FTS5 còn OPEN. Disposition đã có cho CA truststore và trigger SQLite CLI giữ nguyên trong phạm vi digest cũ. [PD-R13](PD-02-02_KEYCLOAK_D17_SECURITY_REVIEW.md) · [Ma trận 199 records](PD-02-02_RESIDUAL_ADVISORIES.csv)
- PD-R14 có receipt hồi quy trên cùng image với cấu hình thử nghiệm riêng. Filter cho kết quả khác giữa đường mặc định và stream đặt filter riêng. NSS sampling chỉ phản ánh cửa sổ đã quan sát. Shutdown dừng ở bước chờ `probe`; lần đọc Docker trong PD-R15 ghi 7 Running / 7 Exited, gồm `kc-filter-r14` Running và `kc` gốc Exited. Hai trạng thái cấu hình và dữ liệu có evidence riêng. [Filter receipt](../../../target/pd-02-02-mitigation/filter-live-receipt.txt) · [NSS sampling](../../../target/pd-02-02-mitigation/nss-live-samples.txt) · [Hồi quy](../../../target/pd-02-02-mitigation/regression-receipt.txt) · [Shutdown receipt](../../../target/pd-02-02-mitigation/shutdown-receipt.txt)

## 2. Exact Keycloak artifact hiện tại

| Thành phần | Evidence |
|---|---|
| Candidate ZeroTrust | `zt-pd02-candidate/keycloak:pd-r11-c401e17` · `sha256:e06bec13a903df01c1fd80b590d328db99ecbc4b00ee6ce3baa6f10f5f142615`. ID và repo digest khớp qua Docker inspect chỉ đọc. |
| Quay 26.8.2 | OCI index `sha256:3879c623248408de29a5303178b5816c77e8dfef3890c361f8c0bbeaa979ba3b`. Linux amd64 child `sha256:4340d05ee7d15be34293868d495ac772d61f1a4d0e43d53bae2e75e2f05de185` khớp pin trong recipe. SHA-256 trên byte manifest và `Docker-Content-Digest` khớp ở cả hai cấp. |
| Runtime đã lưu | Guava `33.6.0-jre`, JAR SHA-256 `dc573e1fca4fd5454f4a5fd3d7da2df03002876a4175bafc14a95980dd7713b3`. SQLite RPM `3.34.1-11.el9_8`, thư viện SHA-256 `007322505ff5177c820251b31612a9e4c2e6e4c78a5ad62df81d92ba329d65ff`. Red Hat OpenJDK 21.0.13+9, NSS softoken `3.124.0-5.el9_6`. Package inventory lấy từ CycloneDX PD-R13. Hai SHA-256 được tính lại trên JAR/ELF đã lưu. |

Tại thời điểm đối chiếu, Keycloak Downloads và GitHub latest cùng ghi **26.8.2**. Quay trả 200 cho `26.8.2`, `26.8.2-0`, `26.8` và `latest` trên cùng index theo tag API, còn lookup `26.8.3` trả 404. Docker Hub metadata cho cùng index và amd64 child của các tag 26.8.2. Quay có `nightly` riêng ngoài phạm vi release ổn định. [Downloads](https://www.keycloak.org/downloads) · [Release 26.8.2](https://github.com/keycloak/keycloak/releases/tag/26.8.2) · [Quay tag API](https://quay.io/api/v1/repository/keycloak/keycloak/tag/?onlyActiveTags=true&limit=20) · [Quay manifest](https://quay.io/v2/keycloak/keycloak/manifests/26.8.2) · [Docker Hub tag API](https://hub.docker.com/v2/repositories/keycloak/keycloak/tags/?page_size=8) · [Recipe](../../../deploy/public-demo/Dockerfile.keycloak) · [SBOM PD-R13](../../../target/pd-02-02-keycloak-d17/keycloak-rescan.cdx.json)

## 3. Guava — CVE-2026-102554

Google đã vá ở Guava **33.7.2**. CNA chấm 8.2 High và Google GHSA xếp Moderate. Rủi ro là cấp phát bộ nhớ quá mức khi ứng dụng giải tuần tự hóa dữ liệu Java native không tin cậy qua các kiểu dữ liệu bị ảnh hưởng. Issue upstream Keycloak **#54110** còn Open, có nhãn `status/blocked-external` và chưa có milestone. Issue để mở việc xác định reachability. Candidate 26.8.2 vẫn chứa `33.6.0-jre`, do đó disposition của candidate hiện tại là **OPEN**. [Google advisory](https://github.com/google/guava/security/advisories/GHSA-xxph-c9ww-hj94) · [Guava release](https://github.com/google/guava/releases/tag/v33.7.2) · [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-102554) · [Keycloak #54110](https://github.com/keycloak/keycloak/issues/54110)

## 4. Artifact có bằng chứng bản vá Guava

- **Docker Hardened Images (DHI)** cung cấp Keycloak **26.8.2** trên Debian 13. Tag definition `keycloak/debian-13/26` trỏ đến index `sha256:50a09844dc6063ee54cb99259ffbc070ac53ded09a6d1c0075ccaff9e5032f1c` và Linux amd64 manifest **`sha256:44b3665b60304cb4448e3ab9943ab02727ee793c2ec4b954d2de2ee84f28b892`**, push ngày 07/11/2026 16:31:47 UTC. Indexed SBOM của chính manifest có `pkg:maven/com.google.guava/guava@33.7.2-jre` và `org.keycloak:keycloak-services:26.8.2`. Đây là **VERIFIED theo SBOM vendor trên exact digest**. Bản dựng `945fd489…9477` cũng có Guava 33.7.2-jre nhưng dùng gói zlib khác. [Catalog DHI](https://hub.docker.com/hardened-images/catalog/dhi/keycloak/images/keycloak%2Fdebian-13%2F26/sha256-44b3665b60304cb4448e3ab9943ab02727ee793c2ec4b954d2de2ee84f28b892) · [Docker DHI MCP](https://docs.docker.com/dhi/tools/mcp/)
- **Chainguard** đánh dấu fix cho APK `keycloak-26.8` từ **26.8.1-r3** trên x86_64 và aarch64. Trường `component_version=33.6.0-jre` trong record mô tả component được theo dõi. Chưa xác minh JAR thực tế, phương thức patch hay digest của image 26.8.2. Public manifest trả 401 và anonymous token trả 403. [Advisory x86_64](https://advisories.cgr.dev/chainguard/v3/osv/CGA-6jh6-g9rj-r7cq.json) · [Advisory aarch64](https://advisories.cgr.dev/chainguard/v3/osv/CGA-g2hw-fm5h-jgwv.json) · [Catalog](https://images.chainguard.dev/directory/image/keycloak/versions)
- **Red Hat** ghi `guava` và `rhbk/keycloak-rhel9` của RHBK là **Affected**. Bản `33.7.2.jre-redhat-00002` trong RHSA-2026:95622 áp dụng cho Red Hat Build of Apache Camel. Pyxis RPM manifest của RHBK 26.6.9 không định danh JAR Guava. Anonymous registry lookup của exact digest trả 401. **Guava fix trên RHBK NOT VERIFIED.** [Red Hat Security Data API](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-102554.json) · [RPM manifest RHBK](https://catalog.redhat.com/api/containers/v1/images/id/6aee13ddc3762db5db4d47ef/rpm-manifest)

## 5. SQLite FTS5 — CVE-2026-119373

SQLite upstream xác nhận phạm vi trước **3.54.0** khi bật FTS5. Bản sửa có trong release 3.54.0. Red Hat xếp Important. Trên candidate cũ, FTS5 được xác nhận bật và NSS softoken liên kết SQLite. Cấu hình MySQL và cửa sổ JVM sampling PD-R13/R14 chưa đủ để loại trừ đường native trong release. **OPEN trên candidate hiện tại.** [SQLite release](https://sqlite.org/releaselog/3_54_0.html) · [Upstream fix](https://sqlite.org/src/info/a7f8c92f62) · [Red Hat CVE](https://access.redhat.com/security/cve/cve-2026-119373) · [PD-R13 native inventory](PD-02-02_KEYCLOAK_D17_SECURITY_REVIEW.md#7-sqlite-nativeruntime-assessment)

## 6. Artifact và gói có bằng chứng SQLite

| Nguồn | Kết quả đối chiếu |
|---|---|
| **Red Hat Hardened Images** | RHSA-2026:86202 xác nhận `sqlite-main-3.54.1-1.hum1` cho Hardened Images/Hummingbird. RHEL 9 `sqlite` vẫn **Affected** trong Security Data API. UBI/RHEL9 và Hummingbird có nhánh package riêng. |
| **RHBK 26.6.9, build 26.6-25** | Catalog và CSAF xác nhận amd64 manifest `sha256:0de6b0a3bfe5135725e33bb1da8fd22c1fc94e754814d6c3ddef92105a094116`, index `sha256:91937e38d3507d29a4bc5898a77abda62a204b508c77c730cd0bc745dcdb0d03`. Pyxis record `6aee13ddc3762db5db4d47ef` có 44 RPM, gồm đúng `sqlite-libs-3.34.1-11.el9_8.x86_64` và `nss-softokn-3.124.0-5.el9_6.x86_64`. Chưa có erratum áp dụng cho hai gói này trên digest. |
| **DHI 26.8.2, amd64 44b3665b…b892** | Truy vấn đủ **2.733 package** (`INDEXED`, `truncated=false`, gồm package có exception) không có tên hoặc purl chứa SQLite, `libsqlite3` hay `sqlite-jdbc`. Cũng không có package `libnss3`. **Không có package SQLite trong SBOM công khai.** Còn thiếu xác minh chữ ký và danh mục file native của rootfs, gồm thư viện có thể được nhúng. Disposition FTS5 ở mức exact filesystem vẫn **NOT VERIFIED**. |
| **Chainguard 26.8.2** | Chưa có SBOM gắn với digest của Keycloak. Record `CGA-3466-5x3q-qphw` trỏ đến CVE-2026-119586 của SQLite CLI; mục FTS5 cần bằng chứng riêng. |

[Red Hat Security Data API](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-119373.json) · [RHSA-2026:86202 CSAF](https://access.redhat.com/hydra/rest/securitydata/csaf/RHSA-2026:86202.json) · [Pyxis theo digest](https://catalog.redhat.com/api/containers/v1/images/registry/registry.access.redhat.com/repository/rhbk/keycloak-rhel9/manifest_digest/sha256:0de6b0a3bfe5135725e33bb1da8fd22c1fc94e754814d6c3ddef92105a094116) · [RPM manifest RHBK](https://catalog.redhat.com/api/containers/v1/images/id/6aee13ddc3762db5db4d47ef/rpm-manifest) · [DHI MCP](https://docs.docker.com/dhi/tools/mcp/) · [CGA record](https://advisories.cgr.dev/chainguard/v3/osv/CGA-3466-5x3q-qphw.json)

## 7. So sánh các phương án

| Phương án | Vendor, version, digest và support | Guava, SQLite và Critical/High | Compatibility, migration, rollback và khuyến nghị |
|---|---|---|---|
| **A — upstream patched release** | Keycloak community Apache-2.0. Stable 26.8.2 amd64 `4340d05e…185`. | Candidate derived digest có 0C/4H ở PD-R13, trong đó hai mục đang xét OPEN. Chưa có release stable mới hơn trong lần kiểm tra. | Ưu tiên khi upstream có digest đã vá. Với release mới, build lại SPI theo API đúng phiên bản, kiểm realm/MySQL và diễn tập quay về snapshot trước nâng cấp. |
| **B — Docker Hardened Images** | Docker DHI Community, Apache-2.0, Debian 13, Keycloak 26.8.2, amd64 `44b3665b…b892`. Registry yêu cầu xác thực. | Guava 33.7.2-jre có trong exact SBOM; không thấy package SQLite. Docker catalog 0C/2H duy nhất trên zlib, Debian xác nhận bản package tương ứng đã vá cả hai. Còn phải đối chiếu scan và native content. | **Ưu tiên xác minh tĩnh tiếp.** Cùng Keycloak API line và Java major, đổi OS/JRE/UID. Cần xác minh augmentation, TLS, restore và rollback về baseline cũ. Chưa đề xuất thay server. |
| **B — Chainguard** | Chainguard Keycloak 26.8.2, vendor catalog; digest chưa xác minh, truy cập artifact theo entitlement. | Guava APK có fix; SQLite và Critical/High theo exact artifact chưa xác minh. | Cần kiểm entrypoint, UID, JRE/CA, provider layout, MySQL và restore. Giữ làm phương án khi có digest và SBOM. |
| **B — Red Hat Build of Keycloak** | Red Hat RHBK 26.6.9, amd64 `0de6b0a3…4116`, hỗ trợ theo subscription và ma trận vendor. | Guava sản phẩm còn Affected; SQLite RPM vẫn là bản candidate cũ. Endpoint vulnerability trả 0 record; chưa có scan đầy đủ để suy ra tổng Critical/High. | Khác stream. Cần BOM RHBK, build SPI và thẩm định đường chuyển realm/schema. Giữ riêng snapshot của từng distribution. Loại build này khỏi danh sách thay thế cho hai CVE. |
| **C — mitigation vendor hỗ trợ** | Chưa có mitigation Keycloak gắn với digest được vendor xác nhận cho hai mục. Java có cơ chế serialization filter. | PD-R14 chỉ có kết quả có giới hạn. Filter riêng của stream làm thay đổi kết quả, chưa có coverage release; filter Java không xử lý SQLite native. | Cần vendor support, coverage và rollback config trước khi xem xét. Giữ thử nghiệm đã lưu làm evidence lịch sử. |
| **D — giữ candidate** | Quay 26.8.2 + SPI trên local digest `e06bec13…2615`, scope D-16. | 0C/4H lịch sử, hai Category A còn OPEN. | **Phương án hiện tại.** Giữ candidate và dữ liệu theo scope cũ. Cần proof cho cả hai mục trước khi xét release. |

[Keycloak container guide](https://www.keycloak.org/server/containers) · [Docker DHI và licensing](https://docs.docker.com/dhi/) · [DHI registry authentication](https://docs.docker.com/dhi/how-to/use/) · [RHBK supported configurations](https://access.redhat.com/articles/7033107) · [RHBK BOM](https://access.redhat.com/articles/7027683) · [Oracle Java serialization filtering](https://docs.oracle.com/en/java/javase/21/core/serialization-filtering1.html)

## 8. Đánh giá tương thích

DHI tag definition ghi entrypoint `/opt/keycloak/bin/kc.sh`, command `start --optimized`, user **65532** và Eclipse Temurin 21.0.13+9. SBOM có MySQL Connector/J **9.7.0**. Cùng Keycloak 26.8.2 và Java 21 là căn cứ để đề xuất kiểm chứng. SPI hiện dùng API provided 26.8.2 và build target Java 17. Cần kiểm quyền file secret chỉ đọc theo UID/GID mới, CA/truststore, TLS hostname verification, crypto providers, thư mục ghi và bước `kc.sh build --db=mysql` sau khi cài provider. Cần realm import/readback và logical restore riêng để kiểm tra schema và dữ liệu xác thực. D-14/MySQL 8.4 LTS vẫn là đầu vào riêng của PD-03-06. **Tất cả runtime compatibility trên DHI vẫn NOT VERIFIED.** [DHI catalog](https://hub.docker.com/hardened-images/catalog/dhi/keycloak/images) · [SPI POM](../../../keycloak-risk-extension/pom.xml) · [Recipe hiện tại](../../../deploy/public-demo/Dockerfile.keycloak) · [Keycloak upgrading guide](https://www.keycloak.org/docs/latest/upgrading/index.html)

## 9. Advisory delta và provenance

- Docker DHI ghi **0 Critical / 2 High** duy nhất trên manifest hiện tại. Tool CVE trả bốn dòng High do lặp tọa độ zlib chung và amd64. Hai CVE là **CVE-2026-76844** và **CVE-2026-85091**. SBOM ghi zlib/zlib1g `1:1.3.dfsg+really1.3.1-1+deb13u1`; Debian DSA-6613-1 và cả hai tracker cùng xác nhận đúng phiên bản này đã vá trên Trixie. **Package fix verified theo Debian, scanner reconciliation còn mở.** Giữ cả raw matches. Digest DHI cũ `945fd489…9477` có 0C/0H theo Docker và dùng `deb13u0+dhi4`; chưa có proof backport cho hai mục zlib để chọn digest cũ dựa trên số đếm. [DSA-6613-1](https://lists.debian.org/debian-security-announce/2026/msg00532.html) · [Debian 76844](https://security-tracker.debian.org/tracker/CVE-2026-76844) · [Debian 85091](https://security-tracker.debian.org/tracker/CVE-2026-85091) · [DHI digest cũ](https://hub.docker.com/hardened-images/catalog/dhi/keycloak/images/keycloak%2Fdebian-13%2F26/sha256-945fd4896b7ec3e5572011a94441bda4d4f6bb7374951add9e91fde4b6b39477/vulnerabilities)
- **CVE-2026-117691** nằm trong security fixes của Keycloak 26.8.2. Red Hat CSAF RHSA-2026:96039 cũng định danh fix này trên exact RHBK amd64 `0de6b0a3…4116`. Fix SAML đó có advisory riêng với hai mục đang theo dõi. [Keycloak 26.8.2 release notes](https://www.keycloak.org/2026/11/keycloak-2682-released) · [Keycloak Security Advisories](https://github.com/keycloak/keycloak/security/advisories) · [Red Hat CSAF](https://security.access.redhat.com/data/csaf/v2/advisories/2026/rhsa-2026_96039.json)
- **Cách tái lập đối chiếu DHI.** Qua MCP công khai `https://dhi.io/mcp`, dùng `dhi_get_tag_definition` với `repoName=dhi/keycloak`, `tagDefinitionId=keycloak/debian-13/26`. Gọi `dhi_get_image_packages` với exact amd64 digest, `limit=0`, `includeExcepted=true`, rồi đối chiếu `dhi_get_image_cves` và `dhi_get_image_attestations` trên cùng digest. Catalog liệt kê CycloneDX attestation `sha256:51273473cdf310a6b915364d83c558c930e6e4e046872d234e3806fe50a78619` và VEX `sha256:d2f10bfc319de7f953a8d4fd38ce681eeaf5a6af6a69bb97ae38a8abda85f5ae`. Anonymous request tới manifest, referrers và token của registry trả 401; kiểm chứng chữ ký và nội dung attestation **NOT VERIFIED**. [MCP và tool schema](https://docs.docker.com/dhi/tools/mcp/) · [Xác minh attestation](https://docs.docker.com/dhi/how-to/verify/)

## 10. D-17 — NO VERIFIED PATCHED ARTIFACT

**D-17 giữ PENDING.** Chưa đủ evidence cho một artifact đáp ứng toàn bộ điều kiện của D-17. DHI `44b3665b…b892` là đầu mối ưu tiên, với Guava đã xác minh theo SBOM và bằng chứng package ban đầu cho SQLite/zlib. Bảng dưới đây là packet chuẩn bị cho lần trình owner sau khi đủ evidence.

| Mục | Phương án có điều kiện |
|---|---|
| Vendor, version, digest | Docker DHI Community, Keycloak 26.8.2 trên Debian 13, pin Linux amd64 `sha256:44b3665b60304cb4448e3ab9943ab02727ee793c2ec4b954d2de2ee84f28b892` hoặc một digest vendor mới đã được kiểm chứng lại. |
| Security evidence | Verify chữ ký và subject của SBOM/provenance/VEX. Đối chiếu Guava JAR thực tế, kiểm native rootfs và JAR nhúng để xác nhận SQLite/FTS5 vắng mặt hoặc đã vá. Tái quét theo digest, đối chiếu các match zlib bằng Debian DSA. |
| Support/licensing | DHI Community Apache-2.0, truy cập registry qua tài khoản được phép. Xác nhận điều khoản và phạm vi hỗ trợ cần cho demo trước khi chọn. |
| Thay đổi sau phê duyệt | Chỉ điều chỉnh recipe/pin và cấu hình tương thích của Keycloak Public Demo. Build SPI đúng API, cài provider, thực hiện augmentation MySQL; kiểm UID/GID, mount quyền tối thiểu và TLS/truststore. Dùng candidate cô lập và synthetic data nếu được duyệt. |
| Rollback | Giữ baseline image, provider, config và snapshot logic có checksum/ledger. Dùng schema candidate riêng. Nếu thất bại, dừng candidate mới và khôi phục snapshot trước chuyển đổi vào schema riêng bằng image cũ. Tránh mở schema đã nâng cấp bằng image cũ. Xác minh realm, key IDs, login/MFA, logout và trust trên bản khôi phục trước khi tiếp tục. |
| Rủi ro và quyền | DHI native inventory, provenance, compatibility và runtime regression chưa nghiệm thu. Chuyển server, tạo runtime thử nghiệm và dùng quyền registry cần owner cấp đúng phạm vi. |

## 11. Blockers còn lại

Hai Category A còn **OPEN trên candidate đang dùng**. Với DHI, blocker cụ thể là **bằng chứng đã xác minh chữ ký và native content cho exact amd64 digest**, đồng thời cần đối chiếu scanner với fixed zlib version. PR-001 và PR-016 OPEN. G1/G3 PARTIAL. PD-02-08 tiếp tục chờ PD-02-02 PASS.

## 12. Tiêu chí nghiệm thu sau khi được giao thử artifact

| Nhóm | Candidate cũ | Artifact DHI |
|---|---|---|
| Startup, SPI và realm | Startup, provider discovery, augmentation, realm import/readback đã có trong PD-R10/R11/R14 theo từng cấu hình. | **NOT VERIFIED.** Kiểm startup/health, Custom Authenticator, provider discovery, realm import/readback, quyền đọc file và TLS/CA. |
| OIDC và Adaptive Authentication | Có native candidate evidence về PKCE, OTP, trust, caller, B0 và fault handling. | **NOT VERIFIED.** Chạy Authorization Code + PKCE, JWT negative cases, OTP, Trusted Device, session/logout, Risk integration, B0 LOW/MEDIUM/HIGH, Mandatory MFA, Priority DENY, Missing Data, fail-closed và caller authorization. |
| School và RBAC | Có scoped evidence read-only và ADMIN/STUDENT từ các lượt đã lưu. | **NOT VERIFIED.** Kiểm academic read-only, SQL SELECT-only, RBAC và giữ dữ liệu School qua test. |
| Supply chain và dữ liệu | Scan exact image PD-R13, MySQL 8.0.46 same-version logical restore, V5 `661092940`. | **NOT VERIFIED.** Scan exact base và image sau augmentation; xác minh SBOM, chữ ký, SQLite/native, zlib, migration/restore compatibility và rollback rehearsal. D-14 MySQL migration không áp dụng cho scope này. |

PD-02-02 chỉ đủ điều kiện PASS khi hai advisory có disposition được chứng minh trên artifact đã duyệt, tất cả Critical/High applicable được xử lý theo tiêu chí hiện hành và hồi quy bắt buộc trên đúng cấu hình đạt. Phiên này chỉ đối chiếu nguồn công khai, metadata Docker chỉ đọc và evidence đã lưu. Các thử nghiệm PD-R14 không được chạy lại.

Đối chiếu bàn giao xác nhận 720/721 tệp baseline khớp SHA-256. Chênh lệch gồm cập nhật Master Roadmap và thêm báo cáo này. HEAD, branch và Git index giữ nguyên. Metadata của 10/10 Lab Exited và 24/24 container ngoài candidate khớp baseline. Trạng thái candidate vẫn 7 Running / 7 Exited.

## 13. Một bước tiếp theo

**Xác minh tĩnh đúng DHI amd64 digest `44b3665b…b892` khi có quyền đọc registry hoặc vendor cung cấp gói evidence đã ký.** Kiểm subject/signature và native inventory để chốt SQLite FTS5, đồng thời đối chiếu zlib trên cùng digest. Kết quả đó là đầu vào để quyết định có trình D-17 cho thử nghiệm candidate cô lập hay không.
