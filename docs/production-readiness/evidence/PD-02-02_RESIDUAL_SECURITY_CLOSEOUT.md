# PD-02-02 — Residual security và Redis health closeout

**EV-PD-02-02-05 · PD-R12 · 07/11/2026 (Asia/Saigon) · PARTIAL · NO-GO FOR PUBLIC ACCESS**

## 1. Baseline PD-R11

Canonical branch `zerotrust-v4-risk-scoring`, HEAD `c401e17029d64f9a96738d845b8c0ad0f03fc164`, ahead 3, dirty tree. D-15 và D-16 đã duyệt. D-16-RUNTIME cho phép candidate synthetic cô lập. D-10 và D-13 còn PENDING. PD-R11 đã nghiệm thu image build, Keycloak 26.8.2/SPI, PKCE/MFA/trust, B0, MySQL/Redis TLS, V5 và logical restore cùng phiên bản. PD-R12 giữ phạm vi bằng chứng đó và chạy lại những phần bị tác động bởi Risk health và Redis image mới. [PD-R11](PD-02-02_CANDIDATE_RUNTIME_CLOSEOUT.md) · [Migration](PD-02-02_CONTROLLED_PLATFORM_MIGRATION.md) · [Platform decision](PD-02-02_PLATFORM_DECISION_AND_CLOSEOUT.md) · [Remediation trước đó](PD-02-02_DEPENDENCY_REMEDIATION.md) · [Security audit](../SECURITY_AUDIT.md)

## 2. Tóm tắt raw scanner findings

Số dòng Critical/High theo package và artifact. Đây là version matches, có advisory lặp ở nhiều package hoặc binary. So sánh dùng Trivy 0.76.2 với DB 07/11 06:54Z và Java DB 07/11 01:07Z để giữ cùng dữ liệu PD-R11.

| Artifact | PD-R11 C/H | PD-R12 C/H | Phạm vi |
|---|---:|---:|---|
| Keycloak 26.8.2 | 0/4 | 0/4 | Candidate digest giữ nguyên, đối chiếu Quay và kiểm tra exact runtime |
| Risk | 0/0 | 0/0 | Build và scan image mới |
| Portal, Gateway | 0/0 mỗi image | 0/0 baseline | Image giữ nguyên, dùng scan PD-R11 |
| Tools | 0/1 | 0/1 baseline | TEST-ONLY, kiểm thêm nguồn record trong image |
| MySQL Docker Official 8.0.46 | 2/112 | 2/112 | Cùng rootfs ở amd64 child digest mới đối chiếu |
| MySQL Oracle Registry 8.0.46 | — | 1/77 | Artifact thay thế khảo sát, không chọn |
| Redis 7.4.7 Alpine → 7.4.12 Alpine | 6/74 | **0/0** | Chọn 7.4.12 Alpine cho candidate PD-R12 |
| Redis 7.4.12 Bookworm | — | 1/34 | Artifact khảo sát, không chọn |

## 3. Normalized advisory inventory

Đọc đủ **199 dòng gốc** gồm 8 Critical và 191 High. CSV mới liên kết theo số dòng gốc, digest, target, package, version và layer. Theo từng artifact có 4 advisory Keycloak, 96 MySQL, 71 Redis và 1 Tools sau gộp theo advisory ID. CSV giữ toàn bộ bản ghi package, điều kiện hoặc mô tả trigger từ scanner, đường thực thi đã quan sát, nguồn vendor, hướng xử lý, residual, task và owner scope. Với các record còn mở, nguồn vendor được đính kèm để truy xuất. Các version/fix từ scanner chưa được xác nhận độc lập từng dòng ngoài các nhóm được phân tích sâu. [Ma trận PD-R12](PD-02-02_RESIDUAL_ADVISORIES.csv) · [CSV gốc PD-R11](../../../target/pd-02-02-runtime/critical-high.csv)

## 4. Keycloak residual dispositions

Candidate `sha256:e06bec13a903df01c1fd80b590d328db99ecbc4b00ee6ce3baa6f10f5f142615`. Quay 26.8.2 vẫn resolve tới amd64 child `sha256:4340d05ee7d15be34293868d495ac772d61f1a4d0e43d53bae2e75e2f05de185` của base hiện tại.

| Advisory | Bằng chứng và disposition |
|---|---|
| **CVE-2026-102554, Guava 33.6.0-jre** | Quét constant-pool signatures của 351 server JAR và SPI JAR. Năm class records vừa có native deserialization signature vừa có affected type nằm trong Guava. Kiểm bytecode thấy `KerberosSerializationUtils` và `TwitterIdentityProvider` có `ObjectInputStream.readObject`; các core principal/context cũng có hooks serialization. Realm fixture không có identity broker config, cache local, SPI dùng JSON cho token và Risk response. Chưa chứng minh đường từ untrusted serialized stream tới affected Guava classes trên các surface đã bật, cũng chưa chứng minh loại trừ toàn bộ đường gián tiếp. **OPEN, Category A**. Guava 33.7.2 đã vá, chưa xác minh artifact Keycloak chính thức trong D-16 chứa fix. [Guava release](https://github.com/google/guava/releases/tag/v33.7.2) · [Keycloak downloads](https://www.keycloak.org/downloads) |
| **CVE-2026-119373, SQLite FTS5** | Có `/usr/lib64/libsqlite3.so.0`, RPM 3.34.1-11.el9_8. Keycloak dùng MySQL. Không thấy SQLite JDBC driver trong JAR inventory hoặc SQLite được map vào Java tại thời điểm sample. Các SQLite signatures ở Liquibase và H2 là code/config hỗ trợ nhiều DB, không xác nhận FTS5 được gọi. Vendor có errata cho Hardened Images, chưa xác nhận fixed RPM trong base Keycloak này. **OPEN, Category A** cho đến khi xác minh bản vá tương thích hoặc loại trừ FTS5 theo bề mặt release. [Red Hat advisory](https://access.redhat.com/security/cve/cve-2026-119373) |
| **CVE-2026-119586, SQLite CLI `.recover`** | `sqlite3` CLI vắng mặt. Trigger cần gọi `.recover` trên DB SQLite do attacker kiểm soát. **Trigger loại trừ trên exact candidate**, giữ raw record và kiểm lại operator workflow cùng digest release. Kết luận chỉ áp dụng trigger CLI này. [Red Hat issue](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2026-119586) |
| **CVE-2026-91403, OpenJDK truststore** | Cacerts thực resolve tới `/etc/pki/ca-trust/extracted/java/cacerts`, RPM CA `2026.2.92_v9.0.319-90.3.el9_8`. Vendor xác nhận OpenJDK RPM sử dụng CA bundle đã cập nhật. Candidate TLS còn dùng CA riêng. **MITIGATED trên exact candidate**. [Red Hat advisory](https://access.redhat.com/security/cve/cve-2026-91403) |

Constant-pool signatures hỗ trợ tìm điểm cần đọc và không phải full-program call graph. Giữ JAR server nguyên bản.

## 5. MySQL residual dispositions

**Giữ MySQL Docker Official 8.0.46 hiện tại làm fixture V5. Không đề xuất chọn digest đó làm release.** Baseline index `sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b` và child `sha256:62fb722c78b24245ddff1796a0fcee4a49cc5b87e0aaaf20c92d1da9e0a2497b` có rootfs layers giống nhau. So sánh Oracle Community Server 8.0.46 `sha256:f39194a3d3c85616ee132413edb03f658b03a2740a3b85a548dfce103d6391e8` có version smoke PASS nhưng vẫn 1 Critical/77 High và chưa chạy migration/grants/restore trên artifact đó.

- **Server/TLS.** `ldd` xác nhận mysqld nạp libssl/libcrypto 3.5.1-7.0.1.el9_7. MySQL dùng X.509, TLS 1.2/1.3, `require_secure_transport=ON`. ELF import có TLS client/server methods, không thấy API QUIC/DTLS/CMP/CMS/RPK. Active plugin inventory không có shared-file plugin. Mười advisory `openssl-libs` cần chính các feature/điều kiện đó, nên chưa thấy đường trigger trên runtime đã kiểm tra. Các match vẫn tồn tại, vendor có bản 3.5.8 cho OL9.8, và cả hai image khảo sát vẫn dùng OL9.7. [Oracle errata](https://linux.oracle.com/errata/ELSA-2026-67165-0.html)
- **MySQL Shell.** Critical GHSA-6q48-6c7w-9gw2 ở certifi 2026.2.25 cần đường public CA trust của Python trong mysqlsh. Cả hai image còn record. Fixture dùng mysqld, mysql và mysqldump qua CA riêng. 8 High Python khác được giữ từng dòng trong ma trận. Chọn distribution/operator tool đã vá nếu mysqlsh thuộc release boundary. [Certifi advisory](https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2)
- **Entry-point helper.** Fixture thực thi `gosu mysql` để hạ UID. Go 1.24.6 có 1 Critical/25 High raw, gồm CVE-2025-68121 cần TLS resumption. Không thấy marker `crypto/tls`, `net/http` hoặc `html/template` trong binary, có marker `os/exec`. Kết quả tách riêng startup path và điều kiện từng advisory, không miễn toàn bộ gosu. Oracle alternate không có target gosu trong scan. [Go advisory](https://pkg.go.dev/vuln/GO-2026-4337)
- **Các RPM còn lại.** Ma trận phân biệt CLI, thư viện TLS và thư viện phụ trợ ngoài direct ldd của mysqld. Đường operator, plugin hoặc dependency gián tiếp chưa xác minh theo cấu hình release. Không chọn image chỉ dựa vào số dòng thấp hơn.

V5 preflight vẫn yêu cầu MySQL 8.0.46. D-14 cần chốt hướng vendor-supported, có đường fresh V1–V5 và logical upgrade/restore nếu chuyển engine train. Oracle liệt kê MySQL 8.0 dưới Lifetime Sustaining Support. [MySQL support lifecycle](https://www.mysql.com/support/eol-notice.html)

## 6. Redis residual dispositions

**Thay fixture Redis cho candidate bằng Docker Official 7.4.12 Alpine** linux/amd64 `sha256:ec1c2d3603c3d7d65b153bedda0248b641aa3bd7684503406b27b9e870ac0796`. Cùng train 7.4. Vendor release và official-image metadata khớp version. Native `ldd` có libssl/libcrypto và musl. Alpine 3.21.10 chứa OpenSSL `3.3.7-r2`, musl `1.2.5-r12`, zlib `1.3.2-r1`. Entrypoint mới dùng `setpriv` 2.40.4-r1, image không chứa gosu. **Cả 80 raw Critical/High baseline không còn match**, còn một Medium CVE-2026-4738 ở zlib. Bookworm cùng Redis version còn 1 Critical/34 High, không chọn. [Redis release](https://github.com/redis/redis/releases/tag/7.4.12) · [Docker Official Images](https://github.com/docker-library/official-images/blob/master/library/redis)

CVE-2026-31789 có hai raw Critical records của OpenSSL trên baseline, vendor xác định trigger 32-bit. Fixture PD-R11 và candidate PD-R12 đều chạy linux/amd64. Baseline vẫn giữ raw records. Các Critical gosu v1.18.2 và High Alpine/Go giữ trace theo dòng gốc, cùng bằng chứng binary/package được thay ở bản mới. Redis mới dùng TLS, ACL scoped, AOF everysec và noeviction. Mẫu idle khoảng 3,9 MiB của container cap 128 MiB, fixture `maxmemory=32mb` và ca ép OOM kiểm guard. Đây là kiểm chứng chức năng có giới hạn. [OpenSSL advisory](https://openssl-library.org/news/secadv/20260407.txt)

## 7. Tools và Frontend release scope

Tools **TEST-ONLY**. Venv chạy setuptools 84.2.1, pip vendor manifest trong image khai 70.3.0 và scanner match CVE-2025-47273. Relay/fault helpers dùng Python stdlib, không chạy `PackageIndex.download`. Không sửa artifact chỉ để giảm số cảnh báo. Release preflight chặn tên fixture và các dạng tham chiếu Tools/Dockerfile đã biết. PD-03-03/04 vẫn cần digest allowlist để bắt artifact bị retag. [Setuptools advisory](https://github.com/pypa/setuptools/security/advisories/GHSA-5rjg-fvgr-3xxf) · [Preflight](../../../scripts/public_demo/validate_configuration.py)

Frontend giữ npm audit/build PD-R10. PD-03-04 build và scan image frontend đúng release config. Node base Bookworm và npm CLI scans cũ giữ lịch sử, không dùng cho digest frontend cuối. [PD-R10](PD-02-02_CONTROLLED_PLATFORM_MIGRATION.md)

## 8. Root cause Redis ACL/Health

Boot Redis health indicator mặc định dùng `INFO`. Runtime ACL chỉ cấp lệnh cần cho History. Vì vậy PD-R11 đã thấy Redis phục vụ ứng dụng nhưng health trả NOPERM. Option A thêm `INFO` tăng quyền metadata và không phát hiện lệnh History cần thiết bị cấm. Option B kiểm tra các quyền History bằng credential ứng dụng và giữ ACL nguyên bản. PD-R12 chọn **Option B**. [Redis ACL contract](../../../deploy/public-demo/redis-acl-contract.conf) · [Spring Boot health groups](https://docs.spring.io/spring-boot/reference/actuator/endpoints.html)

## 9. Redis ACL/Health remediation

Profile `public-demo` tắt Boot Redis indicator và dùng indicator mới trên cùng `StringRedisTemplate`. Lua chạy trong namespace History và dùng `redis.acl_check_cmd` với key theo ba loại event, subject và IP, bao gồm quyền EVAL fallback và các thao tác `EXISTS`, `SET NX EX`, `TYPE`, `GET`, `INCR`, `EXPIRE`. Probe gọi `TIME` thực, không tạo key hay cập nhật counter. Script thực thi qua EVALSHA/EVAL như store thật, và không đánh dấu `no-writes` để Redis đánh giá admission của script theo trạng thái write. Kết nối lỗi, lệnh bị từ chối hoặc kết quả khác 1 báo DOWN, response không trả chi tiết lỗi.

Readiness gồm `readinessState,db,redis,geoIp`. Liveness theo process state. Ba đường GET health chỉ mở theo policy của Risk service, probe group mới áp dụng trong profile Public Demo. Component detail, POST và endpoint Actuator khác giữ deny. Release ingress vẫn phải giữ Risk và Actuator ở mạng riêng. [Lua ACL API](https://redis.io/docs/latest/develop/programmability/lua-api/#redisacl_check_cmdcommand-arg) · [Ingress contract](../../../deploy/public-demo/INGRESS_CONTRACT.md)

## 10. Source và cấu hình thay đổi

- Thêm [PublicDemoRedisHealthIndicator](../../../risk-scoring-service/src/main/java/com/zerotrust/risk/config/PublicDemoRedisHealthIndicator.java) và [test](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/config/PublicDemoRedisHealthIndicatorTests.java).
- Mở các GET probe path chính xác trong profile Public Demo và khai readiness group tại [Risk security config](../../../risk-scoring-service/src/main/java/com/zerotrust/risk/config/RiskApiSecurityConfig.java) và [profile](../../../risk-scoring-service/src/main/resources/application-public-demo.properties).
- Thêm guard Tools và regression vào [release preflight](../../../scripts/public_demo/validate_configuration.py) và [preflight tests](../../../scripts/public_demo/test_configuration.py).

Fixture render một dòng ACL hợp lệ từ fragment, bỏ comment hướng dẫn và nạp hash credential synthetic riêng. ACL hiệu lực giữ nguyên command allowlist và `~zerotrust:risk:auth-history:*`, không cấp `INFO`. Risk health thay đổi theo profile, giữ policy B0/MFA/priority/fail-closed, history storage, TLS và academic read-only.


## 11. Runtime regression

Reused `zt-pd02-candidate-core`, MySQL, Keycloak và probe PD-R11. Hai container mới `zt-pd02-candidate-risk-r12` và `zt-pd02-candidate-redis-r12` chạy trên bridge đó. Không có cổng Docker publish. Relay TLS dùng `127.0.0.1:38441–38444`. Redis mới có volume dữ liệu riêng để giữ nguyên fixture cũ.

| Kiểm chứng native | Readiness | Liveness | Kết quả |
|---|---:|---:|---|
| Redis TLS khỏe với ACL gốc, MySQL khỏe | 200 | 200 | PASS |
| Redis dừng, sau đó start lại | 503 → 200 | 200 | PASS, state counter qua AOF |
| Password Redis sai | 503 | 200 | PASS |
| TLS hostname Redis sai | 503 | 200 | PASS |
| Redis từ chối EVALSHA | 503 | 200 | PASS |
| Redis trả PING nhưng từ chối INCR | 503 | 200 | PASS, Risk từ chối ghi failure event |
| Redis từ chối GET | 503 | 200 | PASS, evaluation INCOMPLETE và không ALLOW |
| Redis giới hạn sai key pattern | 503 | 200 | PASS |
| Redis noeviction bị ép OOM | 503 | 200 | PASS |
| MySQL dừng, sau đó phục hồi | 503 → 200 | 200 | PASS, Risk đánh giá được sau recovery |

Native ACL từ chối `INFO`, `ACL LIST`, `CONFIG GET`, `FLUSHDB` và GET ngoài namespace. Health root vẫn 200 lúc khỏe. GET component detail trả 401 anonymous, 403 service JWT, POST readiness và info bị chặn. Probe chỉ trả trạng thái và tên health groups ở root. Risk HTTPS chạy LOW/MFA, device registration/revocation và Redis counter/dedup bằng token thật. Keycloak exact image chạy lại realm readback, SPI execution, PKCE browser và RP-initiated logout sau đổi Risk/Redis. Các kịch bản OTP/trust chi tiết và same-version restore không đổi giữ receipt PD-R11.

**289 Java PASS / 0 FAIL / 0 SKIP**, gồm probe unit, startup, JWT/TLS, B0, trust service và V5. **22 Python PASS** cho configuration và secret contracts. **27 checkpoint native PASS** gồm health, ACL, data path, fault/recovery. Hai checkpoint Keycloak readback/browser logout PASS riêng. Lượt harness đầu chuyển cả comment của ACL fragment vào ACL file và kỳ vọng health root chỉ có trường status. Render bỏ comment và assertion chấp nhận group names đã được chỉnh, sau đó ma trận native chạy thành công. [Native receipt](../../../target/pd-02-02-residual/native-receipt.txt) · [Risk tests](../../../target/pd-02-02-residual/risk-tests.log) · [Keycloak recheck](../../../target/pd-02-02-residual/keycloak-r12.log)

## 12. Exact-image rescan và provenance

Risk build `zt-pd02-candidate/risk:pd-r12-c401e17`, Linux amd64, `Dockerfile.java`, `MODULE=risk-scoring-service`, tag local và OCI index `sha256:122237b9480449be28aa55f717747d3f2cc00cd3e3a45cbeae66d83ee60e202a`. Child manifest `sha256:06b7f626435d0f294a3e96fe3158109e71b32925c7df95331ce7d74dedff3583`. Label source snapshot `b710c5049dc30a4a17171ad8311218de38a41059235350f6abfebe65779110cd`. Scan **0 Critical/0 High, 53 Medium, 4 Low**. Build package tách khỏi targeted Maven test, đã kiểm chính image đó ở native runtime.

Có Trivy JSON/CycloneDX cho Risk và Redis Alpine đã chạy, Redis Bookworm và hai image MySQL đã so sánh. Portal, Gateway, Keycloak và Tools giữ exact image PD-R11. Phạm vi là filesystem cuối của các image local, đối chiếu theo OS và library inventory scanner nhận diện. [Build metadata](../../../target/pd-02-02-residual/build-risk.json) · [Scan và SBOM cục bộ](../../../target/pd-02-02-residual/)

## 13. Remaining applicable Critical/High

- Redis 7.4.12 Alpine và Risk mới có 0 Critical/High trong scan. Cần quét lại trên digest được chọn cho release.
- Keycloak **CVE-2026-102554** và **CVE-2026-119373** giữ OPEN, chưa đủ bằng chứng vá hoặc loại trừ trigger trên bề mặt cần hỗ trợ. CVE-2026-91403 có mitigation và CVE-2026-119586 loại trừ trigger CLI trên candidate.
- Cả hai MySQL 8.0.46 image có residual. Fixture current chỉ dùng kiểm chứng tương thích. Không có MySQL release digest đủ điều kiện. Các raw record mysqlsh, gosu và OpenSSL giữ riêng theo đường thực thi, chưa có waiver.
- Tools record được cô lập theo TEST-ONLY và guard preflight. Điều kiện này phụ thuộc release manifest giữ Tools ngoài boundary. [Ma trận](PD-02-02_RESIDUAL_ADVISORIES.csv)

## 14. Điều kiện chuyển Phase 03–07

| Category | Việc còn lại | Task |
|---|---|---|
| A | Xử lý Keycloak Guava/FTS5 bằng vendor patch hoặc mitigation có bằng chứng trong scope. | PD-02-02 và D-17 |
| B | Signed RC/N-1, CI trên SHA, exact digests/SBOM/secret scan, frontend image, manifest digest allowlist và pin Redis 7.4.12 Alpine hoặc digest đã requalify. | PD-03-01–05 |
| B | Chọn MySQL vendor-supported và đủ disposition. Lập plan V5 trên 8.0.46 hoặc logical migration/validated ledger sang engine mới theo quyết định. | D-14, PD-03-06 |
| C | TLS/ACL/health group và permissions trong manifest thực, restore/rollback đúng selected images, workload, monitoring và RPO/RTO. | PD-04-02–05, PD-05-02, PD-06-06, Phase 07 |
| C | Final realm, MFA/session/FGAP, operator/delivery, D-10/D-13. | PD-04-03/05, PD-06-04/05 |

Advisory áp dụng trên một artifact được đề xuất phát hành phải có disposition trước khi artifact đó đủ điều kiện. Yêu cầu downstream riêng không thay đổi kết quả kiểm chứng Redis tại PD-R12.

## 15. Blocker thực sự

Redis ACL/Health **CLOSED trong scope candidate PD-02-02**. Blocker đóng task là **Keycloak Guava và SQLite FTS5 còn unresolved** trên dependency platform đã chọn. D-17 xác định quyền dùng vendor artifact thay thế hoặc cách chứng minh mitigation. MySQL release selection cần D-14 vì cả hai artifact 8.0.46 khảo sát đều còn residual, nhưng fixture đó không được đưa vào release boundary. Full release SBOM, staging và DR có owner task riêng, không dùng các việc đó để giữ PD-02-02 PARTIAL.

## 16. Owner decision packet

| Đề xuất | Quyết định cần owner | Evidence phải có trước chấp nhận |
|---|---|---|
| **D-17 — PENDING** | Giữ Keycloak 26.8.2 Quay hiện tại chỉ cho test trong khi chờ vendor fix, hoặc cho phép đánh giá distribution/digest chính thức đã vá ngoài D-16 khi xác định được artifact. Giải quyết theo từng advisory nếu chọn mitigation. | Exact version/digest và support, Guava ≥33.7.2 hoặc vendor backport, SQLite FTS5 disposition, scan + SPI/provider/browser PKCE/MFA/trust/deny/caller matrix + compatible schema restore. Chưa có artifact mới đủ điều kiện để phê duyệt phát hành. |
| **D-14 — PENDING** | Chốt hướng MySQL release. So sánh cùng engine 8.0.46 đã vá, ví dụ supported rebuild có bản vá OS và operator boundary rõ, với MySQL 8.4 LTS có migration plan. Hai digest đã quét trong mục 5 là dữ liệu so sánh. | V5 chạy đúng 8.0.46 ở bước bootstrap, checksum/ledger nguyên, quyền migrator/runtime, TLS VERIFY_IDENTITY, schema/index/collation, logical snapshot/restore và rollback tương thích. Nếu đổi engine, chạy synthetic migration trước khi chọn release digest. |

D-15, D-16 và D-16-RUNTIME giữ phạm vi đã duyệt. D-10/D-13 vẫn PENDING. Redis 7.4.12 Alpine là đề xuất pin Phase 03 dựa trên candidate test, chưa là release approval.

## 17. Flyway V5

**661092940**, persisted row `success=1` trên candidate MySQL sau recovery. Bốn compiled classes V5 và `SubjectIdentityMigrationPreflight` cùng nested helpers giữ SHA-256 byte-for-byte giữa Risk PD-R11 và PD-R12. Class V5 chính `24449acbaab162df24350998c0e8c889140ddc404594738f2f8d8dc2713d77a1`. Targeted checksum test PASS. Engine guard và applied ledger giữ nguyên.

## 18. Lab và source preservation

24 container ngoài candidate khớp metadata baseline theo ID, image, status, started-at, restart count, cổng, network, mounts và restart policy. Mười Lab đều ở trạng thái Exited tại preflight PD-R12 và lúc bàn giao. PD-R11 từng quan sát trạng thái Running. Tái sử dụng cùng một internal bridge, không thêm Compose project. 13 candidate container đã dừng và giữ lại cùng 17 volume. Ba volume mới là `zt-pd02-candidate-risk-r12-cfg`, `zt-pd02-candidate-redis-r12-cfg`, `zt-pd02-candidate-redis-r12-data`. Loopback relay đã dừng. HEAD/branch giữ nguyên, 711/716 file baseline byte-identical, 5 file sửa trong scope và 4 file thêm. [Preservation receipt](../../../target/pd-02-02-residual/preservation-results.txt)

## 19. PD-02-02 acceptance

**PARTIAL** vì Keycloak Guava/FTS5 chưa đóng. Redis remediation, compatible Redis 7.4 patch, targeted security regressions và evidence normalization đạt scope. Giữ **PR-001/PR-016 OPEN, G1/G3 PARTIAL**. Chọn **Redis Official 7.4.12 Alpine** làm ứng viên cho Phase 03. Keycloak 26.8.2 hiện tại và cả hai MySQL 8.0.46 digest chỉ có bằng chứng candidate/fixture theo scope trên. Tiếp tục xử lý PD-02-02 khi chốt D-17. D-14 điều phối lựa chọn MySQL. PD-02-08 chờ PD-02-02 PASS.
