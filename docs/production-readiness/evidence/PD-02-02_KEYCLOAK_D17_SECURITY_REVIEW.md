# PD-02-02 — Keycloak security review và quyết định D-17

**EV-PD-02-02-06 · PD-R13 · 07/11/2026 (Asia/Saigon) · PARTIAL · NO-GO FOR PUBLIC ACCESS**

## 1. Baseline PD-R12

Canonical branch `zerotrust-v4-risk-scoring`, HEAD `c401e17029d64f9a96738d845b8c0ad0f03fc164`, ahead 3, dirty tree. Đối chiếu acceptance PD-02-02, PR-001/012/016, G1/G3, D-14/15/16/16-RUNTIME/17 và ma trận 199 dòng. PD-R12 đã đóng Redis ACL/health ở candidate với Redis 7.4.12 Alpine. Hai residual Keycloak Guava và FTS5 là Category A còn mở. D-14, D-17, D-10 và D-13 vẫn PENDING. [Roadmap](../PUBLIC_DEMO_ROADMAP.md) · [PD-R3](PD-02-02_DEPENDENCY_REMEDIATION.md) · [PD-R9](PD-02-02_PLATFORM_DECISION_AND_CLOSEOUT.md) · [PD-R10](PD-02-02_CONTROLLED_PLATFORM_MIGRATION.md) · [PD-R11](PD-02-02_CANDIDATE_RUNTIME_CLOSEOUT.md) · [PD-R12](PD-02-02_RESIDUAL_SECURITY_CLOSEOUT.md) · [Advisory inventory](PD-02-02_RESIDUAL_ADVISORIES.csv)

## 2. Keycloak candidate hiện tại

| Lớp | Exact artifact hoặc phiên bản |
|---|---|
| Candidate local | `zt-pd02-candidate/keycloak:pd-r11-c401e17`, OCI index `sha256:e06bec13a903df01c1fd80b590d328db99ecbc4b00ee6ce3baa6f10f5f142615` |
| Upstream Quay 26.8.2 | Index `sha256:3879c623248408de29a5303178b5816c77e8dfef3890c361f8c0bbeaa979ba3b`, amd64 child `sha256:4340d05ee7d15be34293868d495ac772d61f1a4d0e43d53bae2e75e2f05de185` |
| Server JVM/OS | Red Hat OpenJDK 21.0.13+9, RPM 21.0.13.0.9-1.2.el9, Red Hat 9.8. D-15 Java 17 dùng cho Spring và SPI build target. |
| Custom SPI | Provided Keycloak API 26.8.2, Java release 17. SHA-256 của provider trong exact image `67090903551ffcc183de7c3df24c484dd82608325243fa5885c8c149511634ef`. |
| Guava | Server runtime `33.6.0-jre` tại `/opt/keycloak/lib/lib/main`, SHA-256 `dc573e1fca4fd5454f4a5fd3d7da2df03002876a4175bafc14a95980dd7713b3`. SPI graph có Guava `32.1.2-jre` scope provided, không thay bản runtime. |
| SQLite | RPM `sqlite-libs 3.34.1-11.el9_8`, `/usr/lib64/libsqlite3.so.0.8.6`, SHA-256 `007322505ff5177c820251b31612a9e4c2e6e4c78a5ad62df81d92ba329d65ff`. |

Trivy 0.76.2 quét lại image local với cùng DB PD-R12 để đối chiếu, kết quả **0 Critical / 4 High / 38 Medium / 28 Low**. Bốn High gồm Guava, hai SQLite CVE riêng và OpenJDK CA. Giữ disposition CA đã mitigated trên exact image và SQLite `.recover` loại trừ trigger CLI. [Dockerfile candidate](../../../deploy/public-demo/Dockerfile.keycloak) · [SPI POM](../../../keycloak-risk-extension/pom.xml) · [Rescan](../../../target/pd-02-02-keycloak-d17/keycloak-rescan.json) · [CycloneDX](../../../target/pd-02-02-keycloak-d17/keycloak-rescan.cdx.json)

## 3. Xác minh advisory chính thức

| Advisory | Affected, fix và mức độ |
|---|---|
| **CVE-2026-102554 / GHSA-xxph-c9ww-hj94** | Guava từ 4.0 đến trước 33.7.2. Google GHSA đánh Moderate, CNA CVSS v4 **8.2 High** và Trivy High. Điều kiện là ứng dụng nhận Java native serialized objects không tin cậy, cho phép stream điều khiển số phần tử của compact map/set hoặc serialization proxy của MapMaker. Tác động là cấp phát sớm quá mức và DoS. Bản 33.7.2 phát hành 29/09/2026, CVE công bố 09/10 và OSV GHSA ghi fix 33.7.2. [Google GHSA](https://github.com/google/guava/security/advisories/GHSA-xxph-c9ww-hj94) · [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-102554) · [OSV](https://osv.dev/vulnerability/GHSA-xxph-c9ww-hj94) |
| **CVE-2026-119373** | SQLite trước 3.54.0 ở builds bật FTS5. Heap out-of-bounds write khi merge prefix doclists với điều kiện FTS5 cụ thể. CNA CVSS v3.1 **7.8 High** và v4 **8.5 High**, Red Hat Important. Upstream sửa tại check-in `a7f8c92f62`, phát hành 3.54.0 ngày 09/10/2026, CVE công bố 30/10. Red Hat ghi package RHEL 9 sqlite Affected. [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-119373) · [SQLite patch](https://sqlite.org/src/info/a7f8c92f62) · [SQLite 3.54.0](https://sqlite.org/releaselog/3_54_0.html) · [Red Hat advisory](https://access.redhat.com/security/cve/cve-2026-119373) |

Scoring mô tả component và preconditions. Ảnh hưởng trong Keycloak phụ thuộc đường đi thực tế, được đánh giá riêng ở mục 4–7. Đã kiểm Keycloak advisories/release notes. NVD không trả nội dung CVE đọc được trong lượt này, nên đối chiếu scoring từ CNA và nguồn vendor. [Keycloak advisories](https://github.com/keycloak/keycloak/security/advisories)

## 4. Guava vulnerability analysis

Vendor patch bỏ việc tin số phần tử từ stream để preallocate ngay. Các collection tăng kích thước theo phần tử thực đọc. So sánh exact Guava trong candidate với Guava 33.7.2-jre lấy từ Maven Central và xác minh SHA-256 publisher `b530942257fb935f8b2cfaa5f8eb5bd59c555fd8e8d01b8ce98912e077ea606c`. Hai JAR được chạy riêng trong JVM offline, heap cap 128 MiB, một phần tử hợp lệ và declared count giới hạn 8.192. Hai bản đều roundtrip object hợp lệ và từ chối stream thiếu dữ liệu. Median thread allocations giảm từ **136.128 → 9.136 bytes** cho CompactHashMap và **103.208 → 7.976 bytes** cho CompactHashSet. Đây là bằng chứng differential ở thư viện, không phải test exploit Keycloak. [Guava patch](https://github.com/google/guava/commit/b931fe9d6d5cf00bc55714ad3308d086f71850fe) · [Guava 33.7.2](https://github.com/google/guava/releases/tag/v33.7.2) · [Offline receipt](../../../target/pd-02-02-keycloak-d17/guava-offline-receipt.txt)

Runtime Guava thuộc server distribution. SPI nhận Risk/token responses bằng JSON và không đóng gói Guava. Một bản vá thư viện giữ API trong patch train vẫn cần nhà cung cấp server xác nhận tương thích classpath, Quarkus augmentation và bundled modules trước khi dùng cho Keycloak. [Risk HTTP client](../../../keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/client/HttpRiskScoringClient.java) · [Token provider](../../../keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/client/ClientCredentialsTokenProvider.java)

## 5. Guava runtime reachability

Phân tích method references trong constant pool của **484 JAR** trong rootfs exact image, gồm main, boot, deployment và provider. Có 430 records tham chiếu native stream hoặc wrapper theo bộ lọc tĩnh, trong đó 5 records Keycloak/SPI namespace, gồm một bản transformed trùng lớp Kerberos. Kiểm source và bytecode các điểm dưới đây. [Static receipt](../../../target/pd-02-02-keycloak-d17/static-receipt.json)

| Boundary | Đường dữ liệu và quan sát |
|---|---|
| Token, UserInfo, realm import | Token nhận form, UserInfo kiểm bearer token, partial import được authorize và nhận JSON. Các mẫu Java serialization vô hại bị từ chối, không có đường deserialize Guava từ ba probe này. [Token endpoint](https://github.com/keycloak/keycloak/blob/26.8.2/services/src/main/java/org/keycloak/protocol/oidc/endpoints/TokenEndpoint.java) · [Realm admin](https://github.com/keycloak/keycloak/blob/26.8.2/services/src/main/java/org/keycloak/services/resources/admin/RealmAdminResource.java) |
| Twitter identity broker | Có `ObjectInputStream.readObject` trước cast. Dữ liệu được lấy từ auth-session note của RequestToken do server ghi khi bắt đầu broker flow. Candidate có 0 IdP và endpoint broker không cấu hình trả 404. Twitter class xuất hiện trong snapshot sau probe, sự hiện diện của class chưa chứng minh deserialize đã được gọi. [Twitter source](https://github.com/keycloak/keycloak/blob/26.8.2/services/src/main/java/org/keycloak/social/twitter/TwitterIdentityProvider.java) |
| Kerberos | Helper có sink deserialize trước khi kiểm kiểu ticket. Không thấy caller ngoài helper trong static Keycloak records của image. Candidate không có external user-storage và không có SPNEGO execution trong browser flow đã đọc. [Kerberos source](https://github.com/keycloak/keycloak/blob/26.8.2/common/src/main/java/org/keycloak/common/util/KerberosSerializationUtils.java) |
| Core principal/context, sessions và caches | Core có callback `defaultReadObject`. JVM có `ObjectInputStream` và Infinispan JavaSerializationMarshaller loaded cả trước và sau test. Effective `cache=local`, DB MySQL. Callback và class loading là khả năng xử lý object, chưa phải đường từ request vào affected type. [Core context](https://github.com/keycloak/keycloak/blob/26.8.2/core/src/main/java/org/keycloak/KeycloakSecurityContext.java) · [Cache source](https://github.com/keycloak/keycloak/blob/26.8.2/model/infinispan/src/main/java/org/keycloak/connections/infinispan/DefaultInfinispanConnectionProviderFactory.java) |
| Custom Authenticator SPI | Provider dùng OIDC client credentials, strict JSON, correlation và response policy. Static method-reference pass không thấy native Java input stream trong SPI. Snapshot sau browser login ghi nhận Risk authenticator và device registration authenticator trên exact candidate. |

Hai snapshot `jcmd VM.class_hierarchy` từ JVM Quarkus thật không thấy ba affected Guava base classes đã theo dõi. Native request set có giới hạn, static pass có thể bỏ qua reflection, runtime generated code, nested gadget chains và cấu hình/extension khác. **Guava OPEN**. [JVM trước](../../../target/pd-02-02-keycloak-d17/jvm-before.json) · [JVM sau](../../../target/pd-02-02-keycloak-d17/jvm-after.json)

## 6. SQLite FTS5 analysis

Trigger cần FTS5 được compile và luồng dùng prefix doclist merge với `detail=none` cùng rowid/đầu vào phù hợp. Vendor sửa sizing và arithmetic khi xử lý rowid âm. Dữ liệu nguy hại cần tới luồng SQLite đó. Điều này khác với CVE-2026-119586, vốn yêu cầu `.recover` của CLI. [SQLite patch](https://sqlite.org/src/info/a7f8c92f62) · [Red Hat advisory](https://access.redhat.com/security/cve/cve-2026-119373) · [SQLite CLI advisory](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2026-119586)

Load đúng thư viện của candidate trong helper **network none**, DB in-memory. `sqlite3_libversion=3.34.1`, `ENABLE_FTS5=true`. Query prefix nhỏ với rowid dương trả đúng một kết quả. Phép thử xác minh feature có mặt và chạy được, không tái hiện heap corruption. [Offline SQLite receipt](../../../target/pd-02-02-keycloak-d17/sqlite-offline-receipt.json)

## 7. SQLite native/runtime assessment

- Rootfs có libsqlite3 và symlink SONAME. Không có executable `sqlite3`. Ba marker Java thuộc Liquibase SQLite support và H2 metadata, không thấy SQLite JDBC driver trong 484 JAR.
- Phân tích **149 ELF** xác nhận `libsoftokn3.so` và bốn NSS unsupported tools `bltest`, `dbtool`, `ecperf`, `fipstest` liên kết `libsqlite3.so.0`. Không thấy DT_NEEDED chain tới SQLite từ `java` hoặc `libjvm.so`. Đây là phát hiện về đường gián tiếp mà cấu hình MySQL riêng không loại trừ.
- Đối chiếu NSS softoken upstream 3.124, đường SDB dùng `nssPublic` và `nssPrivate` cho certificate/key stores, chưa thấy FTS5 ở đường này. RPM candidate là `nss-softokn 3.124.0-5.el9_6`, source vendor có thể có patch downstream. [NSS SDB source](https://github.com/nss-dev/nss/blob/NSS_3_124_RTM/lib/softoken/sdb.c)
- Hai snapshot của **PID Java thật** trước/sau OIDC test thấy `libnss3.so` và `libnssutil3.so`, không thấy `libsoftokn3.so` hoặc SQLite mapped. Lần kiểm đầu dùng PID 1 của launcher `kc.sh` đã được thay bằng PID tìm từ `jcmd -l`. Quan sát có giới hạn, không kiểm các mode PKCS#11/FIPS, alternate providers hay công cụ operator trong cấu hình release.

**FTS5 OPEN.** Feature khả dụng trong library, đường tới FTS5 không quan sát trên candidate MySQL/OIDC đã thử, vẫn thiếu bằng chứng loại trừ đường gián tiếp trên release hoặc vendor fix. [Static receipt](../../../target/pd-02-02-keycloak-d17/static-receipt.json) · [JVM snapshot](../../../target/pd-02-02-keycloak-d17/jvm-after.json)

## 8. Vendor patch availability

- **Keycloak upstream.** Downloads và release notes công bố 26.8.2 ngày 05/11/2026. Registry lookup xác nhận exact Quay index/child ở mục 2 và chưa resolve tag 26.8.3. Keycloak 26.8.2 có các security fixes khác trong release notes. Hai residual trong SBOM candidate vẫn match. [Keycloak downloads](https://www.keycloak.org/downloads) · [26.8.2 release notes](https://www.keycloak.org/2026/11/keycloak-2682-released)
- **Chainguard.** Advisory công khai xác nhận fixed package `keycloak-26.8 26.8.1-r3` cho Guava. OSV x86_64 còn ghi locator/version component 33.6.0-jre trong bản ghi lịch sử, còn fix event áp dụng theo package release. Catalog liệt kê tag 26.8.2, nhưng anonymous registry lookup bị 403. Không có verified digest/SBOM của tag để chứng minh hai CVE cùng được xử lý, cũng chưa xác minh cơ chế backport tại binary. [Chainguard advisory](https://images.chainguard.dev/security/CGA-6jh6-g9rj-r7cq) · [OSV x86_64](https://osv.dev/vulnerability/CGA-6jh6-g9rj-r7cq) · [Vendor tags](https://images.chainguard.dev/directory/image/keycloak/versions)
- **Red Hat.** Security Data API ghi fix `sqlite-main-3.54.1-1.hum1` ngày 20/10 cho **Red Hat Hardened Images**, RHSA-2026:86202. RHEL 9 sqlite vẫn Affected trong dữ liệu được đọc. Package Hardened Images thuộc distribution khác, chưa có căn cứ áp sang RPM UBI9 hiện tại. RHBK 26.6 catalog chính thức, tra cứu manifest công khai cho kết quả 403/401 và chưa có exact SBOM xác nhận Guava/FTS5. [Red Hat Security Data API](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-119373.json) · [RHBK catalog](https://catalog.redhat.com/software/containers/rhbk/keycloak-rhel9/64f0add883a29ec473d40906)

**NO VERIFIED PATCHED VENDOR ARTIFACT FOUND**

## 9. Candidate artifact comparison

| Vendor và repository | Version, digest, kiến trúc | Security và support | Tác động và điều kiện tương thích |
|---|---|---|---|
| Keycloak upstream Quay | 26.8.2, 05/11/2026. Exact amd64 child `4340d05e…185`, candidate `e06bec13…615`, đầy đủ ở mục 2. | Community Apache-2.0. OS Red Hat 9.8, Java 21, Guava 33.6.0, SQLite 3.34.1 RPM. Raw 0C/4H. | SPI 26.8.2, realm/MySQL, JVM và same-version restore đã kiểm. Giữ candidate để test. |
| Chainguard Keycloak | Catalog 26.8.2 amd64/arm64, package Guava fix từ 26.8.1-r3. Ngày build và digest của image cần quyền vendor. | Guava package fix được vendor công bố, SQLite/OS/java và tổng Critical/High trên exact image chưa xác minh. Entitlement và terms vendor cần owner. | Catalog cho thấy khác UID và entrypoint. Cần đối chiếu provider path, secret permissions, Java/CA, augmentation, realm, MySQL và rollback. |
| Red Hat build of Keycloak | `registry.redhat.io/rhbk/keycloak-rhel9`, stream 26.6 catalog amd64. Chưa resolve digest/build date bằng anonymous lookup. | Supported downstream theo subscription. UBI9 Micro và OpenJDK theo catalog. Hai package versions, fixes và C/H exact image chưa xác minh. | Khác stream với SPI 26.8.2. Cần rebuild và test API/realm/schema, kiểm supported configurations và khả năng restore phù hợp. |
| Red Hat Hardened Images SQLite package | 3.54.1-1.hum1, 20/10/2026. Package evidence riêng. | Fixed SQLite advisory theo vendor, chưa xác nhận tích hợp vào Keycloak distribution. | Dùng để đối chiếu bản vá vendor, chưa đủ làm phương án thay server. |

## 10. Safe security test results

| Loại | Kết quả PD-R13 |
|---|---|
| **VENDOR PATCH VERIFIED** | Guava 33.7.2 Maven Central hash khớp, differential hai collection PASS. SQLite upstream patch/release và errata đúng product được xác minh. |
| **CONTROLLED OFFLINE VERIFIED** | Guava 4 differential checkpoints PASS. Pattern filter thử riêng trên JDK17 từ chối CompactHashMap, CompactHashSet và MapMakerInternalMap, HashMap control PASS. SQLite exact library FTS5 prefix benign PASS trong network-none. |
| **CONTROLLED NATIVE VERIFIED** | Exact Keycloak và Risk readiness lên. 11 checkpoint PASS gồm realm IdP/user-storage/browser-flow readback, token 400, partial import 415, UserInfo 401, broker 404, realm readback sau probe, Chrome PKCE + OTP + UserInfo 200 và V5 ledger. Receipt ghi riêng các bước và snapshot. |
| **STATIC ANALYSIS VERIFIED** | Exact-image export, SPI/JAR method references, ELF DT_NEEDED và Guava/NSS/SQLite source đối chiếu. |

Token endpoint thực tế trả 400 `invalid_request`, thay cho dự kiến ban đầu 415. Harness được sửa để kiểm đúng semantic từ chối. Browser dùng callback synthetic, loopback và TLS pin của candidate. Các regression rộng hơn đã PASS PD-R11/R12 được dùng đúng phạm vi vì artifact và code giữ nguyên. [Native receipt](../../../target/pd-02-02-keycloak-d17/native-receipt.txt) · [Filter receipt](../../../target/pd-02-02-keycloak-d17/guava-filter-offline-receipt.txt)


## 11. Remaining unknowns

- Chưa có whole-program reachability proof cho Java object deserialization qua reflection, marshaller wrappers hoặc extension/config ngoài candidate. Hai JVM snapshot là quan sát thời điểm.
- Candidate có NSS consumer gián tiếp và FTS5 được compile. Chưa kiểm chứng đường NSS/PKCS#11/FIPS hoặc DB file import trong topology release. Static linkage không đo `dlopen` theo mọi cấu hình.
- Chưa xác minh exact digest, SBOM, signing và disposition của cả hai CVE trên Chainguard/RHBK. Chưa có trial ngoài D-16.
- Snapshot restore PD-R11 xác nhận same-version Keycloak. Cross-version hoặc cross-distribution schema/restore còn cần kiểm sau khi chọn artifact.

## 12. Security remediation options

| Ưu tiên | Phương án | Kết luận ở PD-R13 |
|---|---|---|
| A | Official Keycloak patched release | Ưu tiên khi có exact digest cùng support và đủ fix evidence. Quay hiện mới xác nhận 26.8.2, còn hai residual. |
| B | Vendor-supported patched distribution | Chainguard có Guava package advisory. RHBK là downstream có hỗ trợ. Thiếu digest và evidence đóng cả hai mục, chưa đủ trình owner duyệt thay image. |
| C | Mitigation có kiểm chứng | Offline JDK17 chứng minh pattern filter có thể từ chối các lớp Guava thử nghiệm. Cần đánh giá trên JVM 21, global/filter-factory behavior, per-stream filters, hợp đồng support và regression của mọi flow dùng serialization trước khi cân nhắc áp dụng. Giới hạn array đơn thuần không đủ để kết luận chặn allocation nội bộ của collection. Với FTS5 cần vendor build/feature policy có thể kiểm chứng, cùng ràng buộc NSS và operator boundary. |
| D | Giữ residual OPEN | Áp dụng hiện tại. Giữ candidate để kiểm thử. Không có risk waiver hay server library override. |

Source không thay đổi security policy. [Java serialization filtering](https://docs.oracle.com/en/java/javase/21/core/serialization-filtering1.html) · [Offline filter receipt](../../../target/pd-02-02-keycloak-d17/guava-filter-offline-receipt.txt)

## 13. D-17 decision packet

**D-17: REJECT** là khuyến nghị đối với việc đổi image tại checkpoint này. **Owner decision vẫn PENDING.** Exact Quay 26.8.2 tại mục 2 được giữ theo D-16 cho candidate test. Chưa có artifact thay thế đáp ứng ngưỡng để đưa ra yêu cầu APPROVE.

Khi có lựa chọn cụ thể, trình lại D-17 với vendor, exact amd64 digest, release date, support và license, package paths/versions, SBOM, provenance, Guava fix/backport, SQLite FTS5 fix hoặc disposition có bằng chứng, cùng các Critical/High mới. Tác động cần xem gồm JDK/CA, UID/mount, provider ABI, launcher, Quarkus augmentation và DB/schema. Sau owner approval, chạy isolated candidate regression ở mục 15. Dừng writers trước snapshot. Duy trì digest hiện tại cùng DB snapshot tương thích và thử restore, realm readback, token issuance và SPI boot trước khi chấp nhận switch. Mọi rollback phải ghép image với schema/snapshot tương thích.

## 14. D-14 MySQL decision analysis

**Khuyến nghị hướng B, lập plan logical migration sang MySQL 8.4 LTS.** Vendor đưa 8.0 vào Sustaining Support từ 21/04/2026. Hướng A giữ tương thích V5 và giảm thay đổi, nhưng hai artifact 8.0.46 đã quét còn 2C/112H và 1C/77H. Vá OS cho cùng engine chỉ giải quyết một phần, còn cần disposition MySQL Shell, entrypoint, OpenSSL và lifecycle. Giữ 8.0.46 làm bootstrap fixture có kiểm soát. [MySQL lifecycle](https://www.mysql.com/support/eol-notice.html) · [Exact 8.0.46 scan comparison](PD-02-02_RESIDUAL_SECURITY_CLOSEOUT.md)

**Metadata shortlist** Docker Official `mysql:8.4.13-oraclelinux9`, release 20/10/2026, index `sha256:a81d043930e51745522bd5c430961cf8286f0a23f0a9a2a6e0108f7ea71b0902`, linux/amd64 child `sha256:72c368d898861f3b3a07af0e6d690400f44f048799ed46822783d9224cc2c86d`. Registry metadata được xác minh. Runtime, scan và migration trên digest này thuộc task sau. Vendor hỗ trợ logical dump/load từ 8.0 sang 8.4. Keycloak liệt kê MySQL 8.4 là phiên bản hỗ trợ, compatibility của realm/SPI và DB restore dự án vẫn cần test. [Registry receipt](../../../target/pd-02-02-keycloak-d17/registry-mysql8413.txt) · [MySQL 8.4.13](https://dev.mysql.com/doc/relnotes/mysql/8.4/en/news-8-4-13.html) · [Upgrade paths](https://dev.mysql.com/doc/refman/8.4/en/upgrade-paths.html) · [Keycloak DB support](https://www.keycloak.org/server/db)

1. **PD-03-06** lập ADR và review exact 8.4 digest, scan OS/runtime, TLS, shell và entrypoint. Pin plan theo artifact và chọn tool dump/load đã vá. Trên 8.0.46 fresh, quiesce writers, chạy và validate V1–V5 với checksum **661092940**. Export application schemas và Flyway ledger từ cùng snapshot. Tạo lại account/grants đích theo contract, tránh chuyển MySQL system schemas.
2. **PD-04-02** restore logical snapshot vào MySQL 8.4 synthetic riêng. Giữ row V5 và checksum từ snapshot, Flyway validate và JPA validate. V5 preflight chỉ nhận 8.0.46 nên không replay V5 trực tiếp trên schema LTS rỗng. Kiểm index/FK/CHECK, collation `utf8mb4_0900_bin` NO PAD, case/space isolation, timestamp precision, SQL modes và locking. Kiểm Connector/J 9.7.0, Hibernate 7.4.13.Final, Flyway 12.4.0, TLS VERIFY_IDENTITY, roles DDL/DML và Keycloak/School grants.
3. **PD-04-02/PD-05-05** thử thất bại giữa chừng, reopen source snapshot bằng image tương thích và giữ write fence đến khi xác nhận cutover. Định nghĩa cách xử lý dữ liệu mới nếu rollback sau khi mở writers. Không dùng raw downgrade datadir.
4. **Owner D-14 PENDING** cho phép chọn lộ trình và runtime trial theo scope riêng. Snapshot/checksum, security scan, compatibility và rollback là điều kiện trước release selection.

Native baseline PD-R13 đọc được MySQL 8.0.46, năm target columns có collation exact, `NO PAD`, ba runtime users dùng `caching_sha2_password` và ledger V5 `661092940/1`. Đây là dữ liệu đối chiếu 8.0.46. [V5 guard](../../../risk-scoring-service/src/main/java/com/zerotrust/risk/migration/SubjectIdentityMigrationPreflight.java) · [MySQL authentication](https://dev.mysql.com/doc/refman/8.4/en/pluggable-authentication.html)

## 15. Regression requirements

- **Khi có Keycloak artifact được duyệt:** scan/signature/SBOM theo exact digest, rebuild SPI và augmentation, provider discovery, realm/grants/account readback, PKCE và JWT issuer/audience/role. Kiểm OTP, trust registration/revoke, session/logout, strict JSON, wrong nonce, caller matrix và event IDs. Tách weighted LOW/MEDIUM/HIGH với Mandatory MFA, Priority DENY, incomplete và outage. Kiểm Portal academic read-only/ADMIN/STUDENT RBAC qua normal entry points.
- **Khi thay JVM hoặc native dependencies:** kiểm PKCS#11/FIPS trong phạm vi sử dụng, CA trust path, SQLite compile options/runtime consumers, Red Hat backport hoặc version fix. Nếu định áp filter, kiểm per-stream/factory behavior và startup/cache/realm/import/backchannel compatibility, rồi thử rollback config.
- **Khi thay MySQL artifact:** thực hiện migration/restore matrix ở mục 14. Test chính xác R12 Redis readiness/health nếu thay topology/config dependency.

PD-R13 chạy targeted probes do không thay code, dependency artifact hoặc cấu hình release. PD-R11/R12 giữ evidence cho B0, MFA/trust, Redis/ACL, caller, fault contract và rollback. Full release/Phase 04–07 có acceptance riêng.

## 16. Residual risks

| Category | Residual | Trạng thái |
|---|---|---|
| A | Guava server bundled, native serialization sinks và release surface chưa có disposition đủ chặt | OPEN, PD-02-02 / D-17 |
| A | FTS5 build bật, NSS indirect consumer, vendor UBI9 fix chưa xác minh | OPEN, PD-02-02 / D-17 |
| B | Exact release image supply chain, MySQL selection, signed RC/N-1, frontend và secret scans | PD-03-01–06 / D-14 |
| C | Realm/FGAP, workload, CA/permissions, monitoring và full backup/restore | PD-04–07 / D-10, D-13 |

Redis ACL/health đã verified ở candidate. SQLite CLI và OpenJDK CA giữ disposition theo exact digest ở mục 2. Không chuyển hai Category A sang downstream để đóng task.

## 17. PD-02-02 acceptance assessment

**PARTIAL.** Có patch evidence cấp thư viện, static/native/offline receipts và điều kiện owner cụ thể. Hai advisory Category A còn OPEN vì chưa có vendor Keycloak artifact đã vá được xác minh và mitigation trên candidate hiện tại chưa đạt ngưỡng. PR-001, PR-012 và PR-016 **OPEN**. G1/G3 **PARTIAL**. Phase 02 còn PARTIAL. D-17 và D-14 giữ PENDING.

## 18. Lab preservation

Docker Engine 29.4.1 `desktop-linux`, internal bridge `zt-pd02-candidate-core` giữ nguyên. Chỉ khởi động lại năm candidate services có sẵn với owned mounts, dùng loopback 127.0.0.1 cho probe. Helper inspect rootfs chưa chạy và SQLite helper network-none đã thoát, không thêm project/volume. Trạng thái metadata của 24 container ngoài candidate khớp trước/sau. Mười container Lab Exited tại hai mốc. Candidate services và relay đã dừng. HEAD/branch giữ nguyên, 719/720 file baseline byte-identical. Diff hiện tại chỉ sửa Master Roadmap và thêm báo cáo này. V5 source và checksum bảo toàn. [Preservation receipt](../../../target/pd-02-02-keycloak-d17/preservation-results.txt)

## 19. Next recommended action

Tiếp tục PD-02-02 khi có exact vendor digest với proof cho Guava/FTS5 hoặc mitigation có thể nghiệm thu. Trình D-17 trên artifact cụ thể trước mọi thử nghiệm vượt D-16. D-14 chuyển vào bước quyết định lộ trình tương thích PD-03-06/PD-04-02 theo scope. PD-02-08 chờ PD-02-02 PASS. **NO-GO FOR PUBLIC ACCESS**.
