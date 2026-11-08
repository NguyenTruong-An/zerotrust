# PD-02-02 — Xác minh exact artifact Docker Hardened Images Keycloak

**EV-PD-02-02-08 · PD-R16 · 08/11/2026 (Asia/Saigon) · PARTIAL · NO-GO FOR PUBLIC ACCESS**

**Cập nhật PD-R17**. Xem [kết quả xác minh sau đăng nhập](#16-pd-r17).

## 1. Baseline PD-R15

PD-R15 xác định DHI Keycloak 26.8.2 có Guava 33.7.2-jre trong SBOM công khai theo digest. Inventory chưa liệt kê SQLite. Hai High zlib có phiên bản khớp bản vá Debian. PD-R16 kiểm tra quyền đọc registry, chạy lệnh xác minh chính thức của Docker Scout và đối chiếu inventory theo đúng digest đó. [PD-R15](PD-02-02_VENDOR_PATCH_VERIFICATION.md)

Candidate ZeroTrust dùng Keycloak Quay 26.8.2 kèm Custom SPI. Exact local digest `sha256:e06bec13a903df01c1fd80b590d328db99ecbc4b00ee6ce3baa6f10f5f142615` giữ Guava và FTS5 OPEN theo PD-R13. Receipt PD-R14 lưu trạng thái tại thời điểm shutdown dừng ở `probe`. Trạng thái hiện tại được đối chiếu riêng ở mục 13. [PD-R13](PD-02-02_KEYCLOAK_D17_SECURITY_REVIEW.md) · [PD-R14 shutdown](../../../target/pd-02-02-mitigation/shutdown-receipt.txt)

## 2. DHI identity và digest

| Hạng mục | Giá trị |
|---|---|
| Official registry | `dhi.io/keycloak` |
| Distribution | Docker Hardened Images, Keycloak 26.8.2, Debian 13 |
| Tag definition | `keycloak/debian-13/26`, dùng để tra metadata công khai |
| OCI index | `sha256:50a09844dc6063ee54cb99259ffbc070ac53ded09a6d1c0075ccaff9e5032f1c` |
| Manifest Linux amd64 | `sha256:44b3665b60304cb4448e3ab9943ab02727ee793c2ec4b954d2de2ee84f28b892` |
| Metadata vendor | Index cập nhật 07/11/2026 16:32:39 UTC. Vendor ghi amd64 manifest push 07/11/2026 16:31:47 UTC. Mapping khớp PD-R15. |
| Registry verification | **NOT_VERIFIED — ACCESS RESTRICTED.** Docker CLI chưa nhận được byte index/manifest để băm và đối chiếu platform descriptor. Catalog không ghi thay đổi digest trong lần đọc này. |

Truy vấn public DHI MCP bằng `dhi_get_tag_definition` với `repoName=dhi/keycloak`, rồi dùng amd64 digest khi gọi `dhi_get_image_packages`, `dhi_get_image_cves` và `dhi_get_image_attestations`. [Docker DHI MCP](https://docs.docker.com/dhi/tools/mcp/) · [Catalog theo amd64 digest](https://hub.docker.com/hardened-images/catalog/dhi/keycloak/images/keycloak%2Fdebian-13%2F26/sha256-44b3665b60304cb4448e3ab9943ab02727ee793c2ec4b954d2de2ee84f28b892)

## 3. Quyền registry và chữ ký

| Phép kiểm | Kết quả |
|---|---|
| `docker buildx imagetools inspect --raw` trên hai reference immutable | Exit 1 cho cả index và amd64. Docker báo `failed to authorize`, `failed to fetch anonymous token`, `401 Unauthorized` tại `dhi.io/token`, scope `repository:keycloak:pull`. Docker CLI hiện tại chưa có quyền đọc hiệu lực. |
| Docker Scout v1.20.4, `attest get --verify --platform linux/amd64` trên exact amd64 | CycloneDX, SLSA v1 và OpenVEX đều exit 1. Scout dừng ở yêu cầu đăng nhập Docker ID trước khi trả attestation. Hai lượt đọc chẩn đoán CycloneDX/SLSA cho cùng thông báo. |
| Key công khai của signer | Endpoint chính thức trả HTTP 200. SHA-256 của PEM `1d02bbccf149283ae6288d96264dcad3fb23ee1911d90324a48eab28e4cb8a5f`. SHA-256 của SubjectPublicKeyInfo DER `118ba556dd52f4aec67018efd316c285c783cd3e54cc0f4527605715c643887c`. |
| Image signature và attestation signature | **NOT_VERIFIED.** Lỗi truy cập xảy ra trước bước kiểm chữ ký. Cosign không có trong PATH. Lượt kiểm Scout dùng `--verify` và giữ kiểm tra transparency log mặc định. |

Docker hướng dẫn xác thực bằng Docker ID có quyền đọc DHI Community. Docker Scout yêu cầu phiên Docker ID hiệu lực. Owner có thể dùng `docker login` và `docker login dhi.io` tương tác ngoài chat. Nếu tổ chức dùng token, áp dụng quyền đọc/pull theo hướng dẫn Docker. Quyền tải layers để phân tích rootfs cần được giao riêng. [Cách đăng nhập registry](https://docs.docker.com/dhi/how-to/use/) · [Quy trình xác minh chữ ký](https://docs.docker.com/dhi/how-to/verify/) · [Public key Docker](https://registry.scout.docker.com/keyring/dhi/latest.pub)

## 4. CycloneDX SBOM và subject binding

Vendor liệt kê CycloneDX v1.6 attestation reference `sha256:51273473cdf310a6b915364d83c558c930e6e4e046872d234e3806fe50a78619` và OpenVEX `sha256:d2f10bfc319de7f953a8d4fd38ce681eeaf5a6af6a69bb97ae38a8abda85f5ae` cho amd64 manifest. Truy vấn inventory với `limit=0` và `includeExcepted=true` trả **2.733 package**, `INDEXED`, `truncated=false`, kèm digest và package locations. **Signed SBOM và VEX NOT_VERIFIED.** Chưa có in-toto envelope để kiểm chữ ký và `subject[].digest.sha256` với amd64 manifest. [Docker DHI MCP](https://docs.docker.com/dhi/tools/mcp/) · [Docker attestation verification](https://docs.docker.com/dhi/how-to/verify/)

## 5. SLSA provenance

Vendor liệt kê SLSA v1 attestation `sha256:b881b95d1e0fbd95bc21078161bfdb7065e7fb1c033bcc0bdcd9d192180ed015` và v0.2 `sha256:3c40ee40bebd06c44d20cbf62d36c12fc769063b582ebc4073acde3c6adea5dc`. Metadata push là mốc registry do catalog công bố. **Provenance NOT_VERIFIED.** Signed envelope, subject binding, builder identity, build inputs và materials còn thiếu. [Docker attestation verification](https://docs.docker.com/dhi/how-to/verify/)

## 6. Guava — CVE-2026-102554

- Inventory công khai theo exact digest trả **một** mục Guava từ name, purl và indexed locations. Bản ghi là Maven `com.google.guava:guava:33.7.2-jre` tại `/opt/keycloak/lib/lib/main/com.google.guava.guava-33.7.2-jre.jar`, trong layer có diff ID `sha256:5a38b5d34514749b7a9eacf7e13278d7693d9ff240e34849051460b5d055a58b`. Google công bố fix 33.7.2. [Docker DHI MCP](https://docs.docker.com/dhi/tools/mcp/) · [Guava advisory](https://github.com/google/guava/security/advisories/GHSA-xxph-c9ww-hj94) · [Guava release](https://github.com/google/guava/releases/tag/v33.7.2)
- Guava trên thuộc server distribution. Custom SPI của dự án là artifact cài thêm, build Java release 17 với Keycloak provided API 26.8.2. PD-R13 ghi Guava 32.1.2-jre ở graph provided và JAR SPI cũ không đóng gói Guava. Bằng chứng SPI cũ dùng cho phạm vi build đó. [SPI POM](../../../keycloak-risk-extension/pom.xml) · [PD-R13](PD-02-02_KEYCLOAK_D17_SECURITY_REVIEW.md)
- **GUAVA — NOT_VERIFIED trên signed artifact.** Có bằng chứng version đã vá trong public inventory. Việc loại trừ Guava cũ trong merged filesystem, server/application layers và JAR nhúng còn thiếu. Candidate Quay hiện tại giữ OPEN.

## 7. SQLite FTS5 — native inventory

**NOT VERIFIED — ACCESS RESTRICTED.** SQLite upstream sửa CVE-2026-119373 từ 3.54.0 cho build bật FTS5. Public inventory đã kiểm tên package, purl và indexed locations. Không thấy `sqlite`, `libnss`, `softokn`, `freebl`, `pkcs11` hoặc `p11-kit` trong các trường được đối chiếu. Kết quả giới hạn ở dữ liệu catalog. Chưa đọc được manifest/layers hoặc signed SBOM/VEX để phân loại `ABSENT`, `PRESENT — PATCHED` hay `PRESENT — UNPATCHED`. [SQLite 3.54.0](https://sqlite.org/releaselog/3_54_0.html) · [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-119373) · [Docker DHI MCP](https://docs.docker.com/dhi/tools/mcp/)

Sau khi có quyền tải để phân tích tĩnh, bước kiểm native cần dựng merged filesystem theo OCI layer order và whiteouts, đối chiếu dpkg inventory, file và symlink `libsqlite3.so*`, SQLite CLI, ELF `DT_NEEDED` và các đường tải native của NSS/PKCS#11. Kiểm JAR lồng, native resource và dấu hiệu SQLite được link tĩnh. Nếu tìm được thành phần, truy về version/patch và bằng chứng FTS5 trước khi quyết định disposition. Các bước này chưa thực hiện. Candidate Quay có NSS linkage theo PD-R13 và giữ **OPEN**. [PD-R13 native inventory](PD-02-02_KEYCLOAK_D17_SECURITY_REVIEW.md#7-sqlite-nativeruntime-assessment)

## 8. zlib — VENDOR-FIXED PACKAGE VERIFIED

Public inventory của DHI amd64 có Debian 13 Trixie `zlib`/`zlib1g` phiên bản **`1:1.3.dfsg+really1.3.1-1+deb13u1`**. Package binary amd64 có indexed location `/var/lib/dpkg/status.d/zlib1g`. DSA-6613-1 và hai Debian tracker xác nhận chính version này đã vá **CVE-2026-76844** và **CVE-2026-85091**. Đây là bản vá Debian security cho stable, với version backport rõ ràng. Scout catalog vẫn báo High và trường `fixedBy` rỗng. Giữ raw results để reconcile khi rescan. Kết luận **PASS ở cấp phiên bản package công khai**. Ràng buộc vào signed artifact vẫn NOT_VERIFIED. [DSA-6613-1](https://lists.debian.org/debian-security-announce/2026/msg00532.html) · [Debian 76844](https://security-tracker.debian.org/tracker/CVE-2026-76844) · [Debian 85091](https://security-tracker.debian.org/tracker/CVE-2026-85091)

## 9. Critical/High còn lại và raw inventory

Tag definition ghi **0 Critical / 2 High duy nhất** cho amd64. `dhi_get_image_cves(limit=0)` trên exact digest trả **0 Critical, 4 dòng High, 5 Medium, 1 Low**. Hai CVE High xuất hiện ở tọa độ Debian chung và tọa độ amd64. Không có Critical/High khác trong feed công khai lần này. Phạm vi image đầy đủ vẫn cần signed inventory và rescan. [DHI MCP](https://docs.docker.com/dhi/tools/mcp/) · [DHI catalog](https://hub.docker.com/hardened-images/catalog/dhi/keycloak/images/keycloak%2Fdebian-13%2F26/sha256-44b3665b60304cb4448e3ab9943ab02727ee793c2ec4b954d2de2ee84f28b892)

| Advisory | Package | Version | Fixed version | Exact artifact evidence | Disposition |
|---|---|---|---|---|---|
| CVE-2026-76844 | zlib, Debian Trixie chung | `1:1.3.dfsg+really1.3.1-1+deb13u1` | `1:1.3.dfsg+really1.3.1-1+deb13u1` | Public catalog amd64, raw HIGH, `fixedBy=null` | VENDOR-FIXED PACKAGE VERIFIED, giữ raw match |
| CVE-2026-76844 | zlib, Debian Trixie amd64 | `1:1.3.dfsg+really1.3.1-1+deb13u1` | `1:1.3.dfsg+really1.3.1-1+deb13u1` | Public catalog amd64, raw HIGH, `fixedBy=null` | VENDOR-FIXED PACKAGE VERIFIED, giữ raw match |
| CVE-2026-85091 | zlib, Debian Trixie chung | `1:1.3.dfsg+really1.3.1-1+deb13u1` | `1:1.3.dfsg+really1.3.1-1+deb13u1` | Public catalog amd64, raw HIGH, `fixedBy=null` | VENDOR-FIXED PACKAGE VERIFIED, giữ raw match |
| CVE-2026-85091 | zlib, Debian Trixie amd64 | `1:1.3.dfsg+really1.3.1-1+deb13u1` | `1:1.3.dfsg+really1.3.1-1+deb13u1` | Public catalog amd64, raw HIGH, `fixedBy=null` | VENDOR-FIXED PACKAGE VERIFIED, giữ raw match |
| CVE-2026-102554 | Guava server | `33.7.2-jre` theo catalog | `33.7.2` | Một bản ghi trong public SBOM, chưa kiểm chữ ký | NOT_VERIFIED trên signed artifact |
| CVE-2026-119373 | SQLite FTS5 | Chưa xác định trên rootfs | `3.54.0` upstream | Public inventory không có match | NOT VERIFIED — ACCESS RESTRICTED |

## 10. Compatibility preflight — PARTIAL

| Phạm vi | Đối chiếu tĩnh và việc còn cần kiểm |
|---|---|
| Server, Java, API và JDBC | DHI catalog ghi Keycloak 26.8.2, Temurin 21.0.13+9 và MySQL Connector/J 9.7.0 trong server layer. SPI hiện compile Java release 17 và Keycloak provided API 26.8.2. Cần kiểm SPI load, classpath/API và khả năng đọc realm/schema MySQL trên exact image. |
| Entrypoint và filesystem | DHI dùng `/opt/keycloak/bin/kc.sh`, mặc định `start --optimized`, workdir `/`. Vendor inventory có server JAR dưới `/opt/keycloak/lib/lib/main`. Cần xác minh provider/theme path và quyền ghi khi build. |
| Build-time và runtime | Recipe Quay hiện copy provider vào `/opt/keycloak/providers`, theme vào `/opt/keycloak/themes` rồi chạy `kc.sh build --db=mysql --health-enabled=true`. Phương án DHI sau phê duyệt phải cài provider/theme trước augmentation và kiểm health trên runtime optimized. Hostname, JDBC URL, TLS và đường dẫn secret là cấu hình runtime. |
| UID/GID, rootless và rootfs read-only | Catalog DHI ghi `nonroot` UID/GID **65532**. Recipe hiện dùng `--chown=keycloak:keycloak`; cần xác minh cách đặt owner trong image thay thế. Kiểm mount chỉ đọc và quyền truy cập của UID thực tế, writable data/temp, quyền ownership khi build và hành vi rootless/read-only rootfs trên Linux. |
| CA, TLS, crypto và secrets | DHI dùng Temurin/Debian CA; baseline là Red Hat OpenJDK/UBI. Kiểm CA path, truststore, TLS hostname verification, provider crypto, private config và file secret mount chỉ đọc trước khi thử. |
| Chức năng | OIDC/PKCE, OTP, Trusted Device, Risk/B0, Mandatory MFA, Priority DENY, Missing Data và fail-closed giữ nguyên yêu cầu. DHI runtime và health endpoints chưa được chạy hoặc xác minh. |

[DHI catalog](https://hub.docker.com/hardened-images/catalog/dhi/keycloak/images) · [Keycloak container guide](https://www.keycloak.org/server/containers) · [Dockerfile hiện tại](../../../deploy/public-demo/Dockerfile.keycloak) · [SPI POM](../../../keycloak-risk-extension/pom.xml) · [Secret và identity contract](../../../deploy/public-demo/SECRETS_IDENTITY_CONTRACT.md)

## 11. D-17 — PENDING

Áp dụng **trường hợp B — Verification incomplete**. Exact DHI amd64 vẫn là artifact đang xem xét. Chưa trình approval cho runtime trial khi chữ ký, signed subject binding và native inventory chưa xác minh được. Giữ packet compatibility/rollback tại PD-R15 làm đầu vào nếu sau này đủ điều kiện. [Packet PD-R15](PD-02-02_VENDOR_PATCH_VERIFICATION.md#10-d-17--no-verified-patched-artifact)

## 12. Điều còn chưa xác minh

- Byte OCI index/manifest/config, platform descriptor và binding giữa digest, subject của SBOM/VEX/provenance và Docker signer.
- Exact JAR/ELF native inventory, Guava copy cũ hoặc JAR nhúng, SQLite/FTS5, NSS/PKCS#11 và static-link evidence.
- Rescan độc lập, đối chiếu raw zlib với signed package evidence và các Critical/High applicable trên exact image. Runtime SPI, realm, TLS, MySQL và rollback là công việc sau khi được phê duyệt.

## 13. Bảo toàn Lab, source và evidence

Snapshot trước và sau dùng Git read-only, SHA-256 các tệp hiện có và Docker metadata chọn lọc. Cả **10 Lab Exited** khớp baseline. Candidate đã ở **1 Running / 13 Exited** ngay khi bắt đầu PD-R16, chỉ MySQL còn Running. Đây là trạng thái đã quan sát ở đầu phiên, khác receipt PD-R14/PD-R15. Hai snapshot PD-R16 khớp về container, image, network và volume. Branch `zerotrust-v4-risk-scoring`, HEAD `c401e17`, Git index và 32 tệp evidence PD-R14 giữ nguyên. Chỉ cập nhật Master Roadmap và thêm báo cáo này.

## 14. PD-02-02 acceptance status

| Hạng mục | Kết quả |
|---|---|
| Exact DHI manifest từ registry | **NOT_VERIFIED**, metadata vendor khớp |
| Image signature / signed SBOM / provenance | **NOT_VERIFIED**, registry/Scout access |
| Guava 33.7.2 trên signed artifact | **NOT_VERIFIED**, version đã vá có trong public inventory |
| SQLite FTS5 disposition | **NOT_VERIFIED — ACCESS RESTRICTED** |
| zlib advisories | **PASS** ở cấp Debian package/version, raw High còn lưu |
| Remaining Critical/High | Feed DHI công khai có hai High duy nhất đã đối chiếu DSA. Exact signed-artifact inventory còn mở. |
| Compatibility preflight | **PARTIAL**, phạm vi tĩnh |
| D-17 / D-14 | **PENDING / PENDING** |
| PD-02-02 / Phase 02 | **PARTIAL / PARTIAL** |
| Release gates | **PR-001/016 OPEN, G1/G3 PARTIAL, PD-02-08 TODO, NO-GO FOR PUBLIC ACCESS** |

## 15. Một bước tiếp theo

**Owner xác thực Docker CLI và Scout bằng Docker ID có quyền đọc `dhi.io/keycloak` theo luồng đăng nhập chính thức.** Quyền đó mở bước lấy manifest và signed attestations trên đúng digest PD-R15. Quyền tải layers để phân tích tĩnh vẫn tách riêng với quyền chạy runtime. [Docker registry login](https://docs.docker.com/dhi/how-to/use/) · [Docker Scout verification](https://docs.docker.com/dhi/how-to/verify/)

## 16. PD-R17

Kết quả xác minh sau khi owner đăng nhập, ngày 08/11/2026 (Asia/Saigon). Phần này cập nhật những mục bị chặn ở PD-R16. Các mục 1–15 giữ kết quả lịch sử. Phạm vi PD-R17 gồm registry manifests, chữ ký và attestation blobs. Layers của image Keycloak chưa được tải để kiểm kê rootfs.

### 16.1. Registry, image signature và platform binding

| Phép kiểm | Kết quả PD-R17 |
|---|---|
| Registry access | **PASS.** Buildx dùng phiên Docker hiện có đọc hai immutable reference trên `dhi.io/keycloak`, exit 0. |
| OCI index | **VERIFIED.** SHA-256 của **2.146 byte** trả về là `50a09844dc6063ee54cb99259ffbc070ac53ded09a6d1c0075ccaff9e5032f1c`. |
| OCI Linux amd64 manifest | **VERIFIED.** Có đúng một descriptor Linux amd64 trong index. SHA-256 của **3.513 byte** manifest khớp descriptor `44b3665b60304cb4448e3ab9943ab02727ee793c2ec4b954d2de2ee84f28b892`. Manifest khai báo chín layer và config digest `sha256:c93b23dcbfc187c87b189d023f3bd610430e8f73670db11b0363b29bfeccd603`. |
| Image signature | **VERIFIED qua signed OCI index.** Cosign v2.6.5 với `--experimental-oci11` và public key chính thức trả exit 0. OCI signature referrer của index là `sha256:e3366aa14c1ffe13c5329cb7f69a0f169d6d164222e26bb478bfbe54aec976fb`. Cosign xác minh claims, chữ ký và transparency log offline. Payload khai báo `docker-reference=index.docker.io/dhi/keycloak` và đúng index digest. Manifest amd64 được ràng buộc qua descriptor trong index đã ký và SHA-256 đã kiểm. Lookup chữ ký trực tiếp trên manifest con không tìm thấy chữ ký riêng. |
| Signer | **VERIFIED bằng Docker DHI public key.** SPKI SHA-256 `118ba556dd52f4aec67018efd316c285c783cd3e54cc0f4527605715c643887c`, khớp fingerprint PD-R16. |

Docker Scout dùng để xác minh chữ ký attestation. Cosign dùng riêng cho chữ ký image index. Cosign v3.1.4 theo chế độ mặc định không tìm thấy signature referrer. Lượt v2.6.5 dùng tùy chọn OCI 1.1 mà Scout chỉ ra. regctl chỉ đọc OCI referrers và payload của attestation. Binary tạm của regctl/Cosign được đối chiếu SHA-256 từ metadata release chính thức trước khi chạy và được dọn sau kiểm tra. [Quy trình xác minh DHI](https://docs.docker.com/dhi/how-to/verify/) · [Docker DHI public key](https://registry.scout.docker.com/keyring/dhi/latest.pub) · [Cosign v2.6.5](https://github.com/sigstore/cosign/releases/tag/v2.6.5) · [regctl v0.11.7](https://github.com/regclient/regclient/releases/tag/v0.11.7)

### 16.2. Signed SBOM, provenance và scanner evidence

Docker Scout v1.20.4 xác minh chữ ký và claims cho CycloneDX và SLSA v1 với Docker DHI key, exit 0. Cả hai lượt giữ kiểm tra transparency log mặc định và Scout báo đã xác minh log offline. OCI attestation manifest và in-toto statement đều trỏ đúng Linux amd64 digest `44b3665b…b892`. Raw payload lấy bằng regctl khớp SHA-256 trong OCI descriptor. [Docker Scout attestation verification](https://docs.docker.com/dhi/how-to/verify/)

| Attestation | OCI manifest SHA-256 | Kết quả |
|---|---|---|
| CycloneDX v1.6 | `51273473cdf310a6b915364d83c558c930e6e4e046872d234e3806fe50a78619` | **VERIFIED.** 2.719 components. Raw payload SHA-256 `4f784b688b7623a826369b0fa67dce1521c69164963ace1e1a24669142bed8b0`. Đây là số từ signed CycloneDX; public catalog ở PD-R16 đếm theo inventory riêng. |
| SLSA provenance v1 | `b881b95d1e0fbd95bc21078161bfdb7065e7fb1c033bcc0bdcd9d192180ed015` | **VERIFIED.** Builder ID `https://github.com/docker-hardened-images/definitions/actions/runs/42389894233/attempts/1`, build type BuildKit và 354 resolved dependencies. Raw payload SHA-256 `c2954c9dea77517d76fe6a6d442eee2c877220419407fa7ce5a05f619d427572`. |
| CVE report v0.2 | `ced66c7375ff4f764fa9a4209720d47079a411944b1b941236dd8aff501967cd` | **VERIFIED chữ ký và subject.** Scout báo thiếu entry transparency log ở lượt mặc định. Lượt `--skip-tlog` theo hướng dẫn Docker xác minh chữ ký/claims và trả exit 0. Payload SHA-256 `0767df5ce1dff06cc09f67930714c678d2056e903a0bf93341cc92354721d12c`. |
| OpenVEX exceptions | `b670c741b8bcacd106122cdfa85e5232c248f0696742149b5016312275b7162c` | **VERIFIED chữ ký và subject bằng hai bước.** Lượt mặc định báo thiếu entry transparency log. Lượt `--skip-tlog` báo chữ ký/claims hợp lệ rồi lỗi ở VEX export, exit 2. Regctl đọc raw payload của đúng attestation, khớp SHA-256 descriptor `801c25b305164c146e4a449e46deb0ed321bb087d1ea6e1e40aa1fe6113ca756` và subject amd64. Trong 127 statements không có mục khớp bốn CVE đang đối chiếu. |

### 16.3. Disposition theo exact artifact

| Hạng mục | Kết quả PD-R17 |
|---|---|
| Guava CVE-2026-102554 | **VERIFIED trong signed SBOM.** CycloneDX có đúng một component Guava, `com.google.guava:guava:33.7.2-jre`, và không khai báo phiên bản Guava khác. Đây là version đã vá theo upstream. Kiểm tra bản nhúng hoặc JAR ngoài inventory còn **PARTIAL** ở mức rootfs. |
| SQLite FTS5 CVE-2026-119373 | **NOT_VERIFIED.** Không tìm thấy component SQLite, NSS softoken hay PKCS#11 trong các trường định danh của signed CycloneDX. OpenVEX đã đọc không có disposition cho CVE này. Còn thiếu kiểm kê file ELF/JAR native, linkage và SQLite nhúng trên rootfs. Chưa đủ điều kiện ghi **NOT_APPLICABLE**. |
| zlib CVE-2026-76844 và CVE-2026-85091 | **VERIFIED bản vá package.** Signed CycloneDX khai báo Debian Trixie `zlib` và `zlib1g` phiên bản `1:1.3.dfsg+really1.3.1-1+deb13u1`, khớp exact fixed version trong DSA-6613-1. |
| Critical/High còn lại | Signed CVE report có **0 Critical / 4 dòng High**, chỉ gồm hai CVE zlib, mỗi CVE xuất hiện hai lần và có CVSS 8.3. Giữ nguyên raw findings. Chưa có High khác trong attestation đã đọc. Phạm vi rootfs và rescan độc lập còn mở. |

[Guava advisory](https://github.com/google/guava/security/advisories/GHSA-xxph-c9ww-hj94) · [Debian DSA-6613-1](https://lists.debian.org/debian-security-announce/2026/msg00532.html) · [Debian CVE-2026-76844](https://security-tracker.debian.org/tracker/CVE-2026-76844) · [Debian CVE-2026-85091](https://security-tracker.debian.org/tracker/CVE-2026-85091)

### 16.4. D-17 và một bước tiếp theo

**D-17 PENDING, chưa đủ điều kiện trình phê duyệt runtime trial.** Chữ ký và exact subject đã được xác minh. SQLite native disposition, kiểm JAR nhúng và rescan trên rootfs chưa hoàn tất. PD-02-02 và Phase 02 giữ **PARTIAL**, PR-001/016 **OPEN**, PD-02-08 **TODO**, Public Demo **NO-GO**. Các disposition này áp dụng cho DHI, còn Guava/FTS5 trên candidate Quay giữ OPEN.

**Bước tiếp theo duy nhất:** Owner phê duyệt tải layers của đúng DHI manifest Linux amd64 `sha256:44b3665b60304cb4448e3ab9943ab02727ee793c2ec4b954d2de2ee84f28b892` để kiểm tra tĩnh trong thư mục cô lập. Phạm vi là dựng merged rootfs để kiểm SQLite/FTS5, NSS/PKCS#11, ELF/JAR nhúng và quét lại. Quyền này chỉ dành cho phân tích tĩnh, không bao gồm tạo hoặc chạy container.

PD-R17 bắt đầu với 10 Lab Exited và không có candidate đang chạy. Lúc bàn giao 14 candidate đều Exited, metadata 10/10 Lab và 24/24 container ngoài candidate khớp baseline. Docker không ghi sự kiện container trong 30 phút trước lúc đối chiếu. Snapshot trước/sau giữ nguyên danh mục image/network/volume, Git HEAD/branch/status, 721 tệp ngoài hai tài liệu và 32 evidence PD-R14.
