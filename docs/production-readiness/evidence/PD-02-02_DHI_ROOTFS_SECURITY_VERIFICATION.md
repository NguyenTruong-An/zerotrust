# PD-02-02 — Xác minh bảo mật rootfs Keycloak DHI

**PD-R18 · 08/11/2026 (Asia/Saigon) · PARTIAL**

Kiểm tra tĩnh đã hoàn tất trên DHI Keycloak 26.8.2 Linux amd64. **Guava PATCHED, SQLite FTS5 NOT_APPLICABLE, zlib PATCHED** trong phạm vi base digest bên dưới. Trivy ghi 0 Critical và 3 High. Hai High được phân loại NOT_APPLICABLE theo thành phần có trong rootfs. Một High của `libacl1` còn OPEN vì chưa đủ bằng chứng về bản vá hoặc đường gọi có đặc quyền. D-17 giữ PENDING và PD-02-02 giữ PARTIAL. [Xác minh chữ ký PD-R17](PD-02-02_DHI_EXACT_ARTIFACT_VERIFICATION.md) · [Kế hoạch thử nghiệm runtime](PD-02-02_DHI_RUNTIME_TRIAL_PLAN.md)

## 1. OCI integrity và phạm vi

| Mục | Kết quả |
|---|---|
| Registry | **PASS**. Đọc index/manifest theo digest và tải trực tiếp blobs từ `dhi.io/keycloak` vào OCI layout riêng. |
| Signed parent index | `sha256:50a09844dc6063ee54cb99259ffbc070ac53ded09a6d1c0075ccaff9e5032f1c`. SHA-256 của raw index khớp. Tái sử dụng xác minh chữ ký PD-R17 và descriptor Linux amd64 duy nhất. |
| Linux amd64 manifest | `sha256:44b3665b60304cb4448e3ab9943ab02727ee793c2ec4b954d2de2ee84f28b892`. SHA-256 của raw manifest khớp digest trong index. |
| Config và layers | Config `sha256:c93b23dcbfc187c87b189d023f3bd610430e8f73670db11b0363b29bfeccd603`, `linux/amd64`. Đủ 9 blobs zstd (226.067.442 byte nén). Size, SHA-256 nén và 9 SHA-256 diff ID sau giải nén khớp descriptor/config theo thứ tự. |
| Merged rootfs | Kiểm tra member path và hardlink trước khi dùng `umoci 0.6.0 unpack --rootless` trên Ubuntu WSL, UID 1000. Bundle nằm trong thư mục tạm riêng trên filesystem Linux. OCI layout Windows chỉ chứa blobs. Công cụ áp dụng layer order và whiteout semantics. Không có whiteout trong 9 layer hoặc rootfs. |
| Signed CycloneDX | Raw predicate truy xuất lại khớp SHA-256 `4f784b688b7623a826369b0fa67dce1521c69164963ace1e1a24669142bed8b0`, subject là exact manifest. Dùng receipt xác minh PD-R17 cho chữ ký, signer và provenance. |
| Independent scan | Trivy **0.76.2**, vulnerability DB **2026-11-08 00:37:11 UTC**, Java DB **2026-11-08 00:58:16 UTC**. Quét trực tiếp OCI layout có một manifest platform, với offline analysis và hai DB đã nạp. Raw scan ghi Debian 13.7, 30 OS packages, 517 Java components. Tổng **0 Critical / 3 High / 41 Medium / 25 Low**. |

Unpack tĩnh và scan không thực thi binary trong image. Không dùng image store của Docker cho artifact DHI. [OCI image layer spec](https://github.com/opencontainers/image-spec/blob/main/layer.md) · [umoci rootless](https://umo.ci/quick-start/rootless/) · [Trivy image input](https://trivy.dev/docs/latest/target/container_image/) · [Docker DHI attestations](https://docs.docker.com/dhi/how-to/verify/)

## 2. Guava và SQLite/FTS5

**CVE-2026-102554 — PATCHED.** Signed CycloneDX khai báo đúng một tọa độ `pkg:maven/com.google.guava/guava@33.7.2-jre`. JAR thực tế `/opt/keycloak/lib/lib/main/com.google.guava.guava-33.7.2-jre.jar` có Maven `pom.properties` khớp group, artifact và version. SHA-256 của JAR `b530942257fb935f8b2cfaa5f8eb5bd59c555fd8e8d01b8ce98912e077ea606c` khớp JAR upstream đã đối chiếu ở PD-R13. Kiểm 486 JAR trong 487 ZIP cấp rootfs, một archive lồng và 112.011 entries. Maven metadata và các tên lớp `CompactHashMap`, `CompactHashSet`, `MapMakerInternalMap` cùng hai linked variants chỉ xuất hiện trong JAR đã vá khi tìm theo basename, kể cả package relocation. Hash cả năm lớp khớp JAR tham chiếu. Không thấy Guava cũ hay bản nhúng mang các lớp liên quan trong inventory đã kiểm. [Guava upstream advisory](https://github.com/google/guava/security/advisories/GHSA-xxph-c9ww-hj94) · [Evidence PD-R13](PD-02-02_KEYCLOAK_D17_SECURITY_REVIEW.md)

**CVE-2026-119373 — NOT_APPLICABLE trên exact base Linux amd64.** Upstream sửa lỗi FTS5 trong SQLite 3.54.0. Kết luận cho digest này dựa trên các lớp bằng chứng sau:

- Rootfs gồm 2.454 file thường, 264 thư mục, 386 symlink. Inventory tên/path, 30 package Debian, symlink và signed CycloneDX không có SQLite CLI, thư viện SQLite hoặc Mozilla NSS softoken.
- Kiểm 454 ELF rootfs và 22 ELF trong archive bằng `readelf -dW -sW`, không lỗi đọc. Không có SQLite/Mozilla NSS trong DT_NEEDED, hoặc ký hiệu hay byte markers như `sqlite3_open`, `sqlite3_prepare`, `SQLite format 3`, `ENABLE_FTS5`, `fts5_api`. Không thấy static archive ở cấp rootfs. Kiểm marker trên cả 30 native resources trong archive, bao gồm 8 resource khác ELF, và không thấy SQLite JNI hay lớp `org/sqlite`. Không phát hiện archive gói khác và không có lỗi đọc ZIP.
- Bốn `libnss_{files,dns,compat,hesiod}` thuộc glibc Name Service Switch. JDK có `SunPKCS11` và wrapper `libj2pkcs11.so`, với DT_NEEDED chỉ `libdl.so.2` và `libc.so.6`. Không thấy Mozilla `libnss3`, `libsoftokn3`, `libfreebl` hay module PKCS#11 riêng để tạo chuỗi linkage FTS5 như trên candidate Quay. Vì không xác định được SQLite trong artifact, version và tình trạng bản vá SQLite không có đối tượng để đối chiếu.

Phạm vi gồm dữ liệu có sẵn trong merged rootfs. Disposition phải được đối chiếu lại trên derived image với provider/theme, truststore, native module và mount thực tế. [SQLite 3.54.0](https://sqlite.org/releaselog/3_54_0.html) · [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-119373)

## 3. Đối chiếu toàn bộ Critical/High quan sát được

| CVE | Raw finding và version cài | Disposition cho exact base amd64 |
|---|---|---|
| CVE-2026-76844 | DHI signed scanner PD-R17 có 2 dòng High (Debian chung/amd64), Trivy không match. `zlib1g 1:1.3.dfsg+really1.3.1-1+deb13u1`. | **PATCHED.** Bản cài trong dpkg khớp signed SBOM và fixed version Debian Trixie. [DSA-6613-1](https://lists.debian.org/debian-security-announce/2026/msg00532.html) |
| CVE-2026-85091 | DHI signed scanner PD-R17 có 2 dòng High (Debian chung/amd64), Trivy không match. Cùng package/version. | **PATCHED.** Cùng exact Debian backport. Bốn raw High zlib giữ nguyên trong evidence PD-R17. [DSA-6613-1](https://lists.debian.org/debian-security-announce/2026/msg00532.html) |
| CVE-2026-16742 | Trivy High/affected, `libsystemd0 257.13-1~deb13u1+dhi2`, không fixed version trong raw. | **NOT_APPLICABLE.** Advisory của systemd giới hạn vào authenticate path của `systemd-homed`. Rootfs chỉ có `libsystemd0` từ source package systemd, không có `systemd-homed` hoặc `homectl`. Exact signed VEX cũng ghi `not_affected`. [Systemd advisory](https://github.com/systemd/systemd/security/advisories/GHSA-jm29-p7hh-vjhv) |
| CVE-2025-69720 | Trivy High/affected, `libtinfo6 6.5+20250216-2+deb13u0+dhi5`, không fixed version trong raw. | **NOT_APPLICABLE.** Advisory áp dụng cho `analyze_string` của lệnh `infocmp`. Rootfs có thư viện `libtinfo6`, không có lệnh `infocmp`. Exact signed VEX cũng ghi `not_affected`. [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2025-69720) |
| CVE-2026-54369 | Trivy High/affected, `libacl1 2.3.2-2+deb13u0+dhi2`, không fixed version trong raw. | **OPEN — khả năng áp dụng runtime chưa xác minh.** Bốn API pathname nêu trong advisory được export bởi `libacl.so.1.1.2302`. `cp`, `mv`, `sed` và `install` thực sự import một số API này. Debian vẫn ghi source Trixie vulnerable và dự kiến cập nhật qua point release. [CNA advisory](https://www.vulncheck.com/advisories/acl-symlink-traversal-privilege-escalation-via-libacl-functions) · [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-54369) |

OpenVEX PD-R17 có hai statements cho mỗi High mới, theo package chung/amd64, cùng ràng buộc exact product digest và component. Tất cả ghi `not_affected` với lý do bên tấn công không thể kiểm soát mã lỗi, còn phần diễn giải chỉ dẫn đến quyết định `no-dsa` của Debian. PD-R17 đã xác minh chữ ký/claims với `--skip-tlog` và digest/subject payload qua registry sau khi Scout gặp lỗi export. PD-R18 dùng thêm bằng chứng vắng thành phần đối với systemd-homed và infocmp. Với libacl, manifest OCI xác định user 65532 và kiểm tĩnh không thấy file setuid/setgid trong bundle rootless. Chưa có chứng cứ cụ thể về patch hoặc khả năng kiểm soát pathname qua privileged caller ở startup, thao tác vận hành hay mount của variant dự kiến. Do đó giữ High này mở và giữ cả ba raw matches. [OpenVEX receipt PD-R17](PD-02-02_DHI_EXACT_ARTIFACT_VERIFICATION.md#16-pd-r17)

## 4. Quyết định và điều kiện nghiệm thu

**D-17 PENDING.** Chưa đủ căn cứ để đề nghị phê duyệt chạy digest này. Yêu cầu vendor làm rõ CVE-2026-54369 theo exact digest bằng patch receipt hoặc VEX có giải thích cụ thể về privileged caller và untrusted path, hoặc chọn DHI Keycloak 26 compatible do vendor phát hành với `acl` đã vá (2.4.0 hoặc bản distro có chứng cứ backport). Digest thay thế phải được kiểm chữ ký, platform, SBOM và dispositions trên chính digest mới. Candidate Quay giữ nguyên làm mốc so sánh và rollback, với hai disposition Guava/FTS5 OPEN như trước.

Khi đã xử lý High còn mở, owner xét D-17 cho thử nghiệm synthetic tách biệt. Để PD-02-02 PASS, thực thi regression và rollback theo kế hoạch đã chuẩn bị, scan exact derived candidate sau augmentation, xử lý từng Critical/High theo tiêu chí roadmap và đối chiếu Lab, source, V5. Bằng chứng runtime, kiểm truststore/mount và tương thích realm/MySQL hiện **NOT_VERIFIED**. D-14 là quyết định MySQL cho đường release tiếp theo. [Master Roadmap](../PUBLIC_DEMO_ROADMAP.md) · [Ma trận 20 ca và rollback](PD-02-02_DHI_RUNTIME_TRIAL_PLAN.md)

## 5. Evidence tái lập

Đối chiếu trước/sau PD-R18 ghi nhận cùng Git HEAD `c401e17029d64f9a96738d845b8c0ad0f03fc164`, branch `zerotrust-v4-risk-scoring` và SHA-256 tổng hợp của 721 tệp ngoài sáu tài liệu bàn giao. Metadata 10 Lab Exited khớp baseline. Metadata 14 candidate Exited, inventory Docker images/volumes/networks và hash evidence PD-R14 khớp trước/sau.

Receipts cục bộ nằm trong `target/pd-r18-dhi/` (Git ignore). Giữ nguyên scanner output và các dữ liệu lịch sử.

| Receipt | SHA-256 |
|---|---|
| [OCI unpack receipt](../../../target/pd-r18-dhi/unpack-receipt.json) | `3758506b7fe4fa0fe20f38684efa63a1a9fc3e70b695ff210440dedcf4cf50e0` |
| [Rootfs inventory](../../../target/pd-r18-dhi/rootfs-inventory.json) | `2beec135f3e2e990be121fef257b1b8b1c12d427b4f56b861c982f996258799b` |
| [Raw Trivy scan](../../../target/pd-r18-dhi/trivy-image-raw.json) | `30c7f503dda65523daad6361734babad62567b2c44e5e6f955cffcd3eb51f943` |
| [Signed OpenVEX payload](../../../target/pd-r18-dhi/signed-openvex-payload.json) | `801c25b305164c146e4a449e46deb0ed321bb087d1ea6e1e40aa1fe6113ca756` |
| [Signed CycloneDX payload](../../../target/pd-r18-dhi/signed-cyclonedx-payload.json) | `4f784b688b7623a826369b0fa67dce1521c69164963ace1e1a24669142bed8b0` |
