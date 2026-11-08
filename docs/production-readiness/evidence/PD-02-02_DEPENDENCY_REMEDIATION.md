# PD-02-02 — Dependency security remediation

Evidence **EV-PD-02-02-01**, ngày **06/11/2026, GMT+7**. Base HEAD
`c401e17029d64f9a96738d845b8c0ad0f03fc164`, branch `zerotrust-v4-risk-scoring`;
thay đổi vẫn ở working tree, không commit/push/deploy.

**Kết quả task: PARTIAL.** Đã thực hiện compatible patches, rebuild, regression và rescan.
Keycloak server 26.7.0 cùng các thư viện do server cung cấp còn findings; user cấm nâng server
trong task này. Release train Spring Cloud 2025.0 đã EOL; chiến lược platform được hỗ trợ chưa
chốt. Những cảnh báo OS chưa xác minh vẫn mở, không được ký waiver hàng loạt.
PR-001/PR-016 OPEN; G1/G3 PARTIAL; Public Demo tiếp tục NO-GO.

Tiến độ chỉ quản lý ở [PUBLIC_DEMO_ROADMAP](../PUBLIC_DEMO_ROADMAP.md).
[Dữ liệu kiểm chứng](PD-02-02_DEPENDENCY_DATA.json) chứa inventories, ranges/fixed versions,
triage từng advisory, source hashes, scan metadata, kết quả tests và image inventories.
Register [DEPENDENCY_FINDINGS](../DEPENDENCY_FINDINGS.md) là baseline lịch sử được giữ nguyên.

## 1. Baseline dependency inventory và phương pháp

Đã đọc roadmap/checkpoint PD-R2, PR-001/016, Security Audit, dependency register/raw scans,
evidence PD-02-01 và source mới chưa commit; đối chiếu bốn POM, Maven Wrapper, package.json,
lockfile, CI, toàn bộ Dockerfiles và các ràng buộc JDK/Node/V5.

| Phạm vi quét mới cùng phương pháp | Trước | Sau | Ý nghĩa |
|---|---:|---:|---|
| Unique Maven coordinates, 4 resolved graphs | 367 | 368 | Compile/runtime/test/provided, 581 instances mỗi bên |
| Maven coordinates có OSV match | 46 | 17 | Không đồng nghĩa 46/17 exploit |
| Unique Java advisory IDs | 132 | 49 | Có alias/cross-package records; không là số CVE độc lập |
| Coordinates hiện diện trong 3 executable Boot JARs | 157 | 158 | Đối chiếu filename/classifier với nested JAR, khác provided SPI |
| Runtime coordinates có match | 28 | 2 | Còn spring-webmvc/webflux 6.2.19 |
| Unique runtime advisory IDs | 116 | 3 | Ba điều kiện feature không áp dụng source hiện tại, chưa phải framework đã được vendor vá |
| npm audit package entries | 15: 1C/6H/8M | 8: 0C/0H/8M | Tám mục sau cùng là chuỗi dev lint của một advisory minimatch |
| npm lock inventory, gồm platform optional | 493 | 496 | Package/version/direct/dev/optional/os/cpu/libc ở JSON |

Số 164 coordinates của audit cũ sử dụng cả nested pom.properties/embedded metadata; không
so trực tiếp với 157 của phương pháp Maven graph + packaged filename hiện tại. So sánh
trước/sau ở bảng trên dùng cùng collector. OS/JDK/server image không được coi là đã quét
chỉ nhờ Maven. SPI `provided` là compile contract; không giả rằng đó là toàn bộ server SBOM.

Dependencies trực tiếp/transitive, scope, module, current version, advisory ranges và fixed
versions lưu ở `java.*.instances`, `java.*.advisories`, `java.triage`, `npm.*_inventory`.
Runtime/build/test được giữ riêng; không gửi source/secrets đến OSV, chỉ gửi coordinates.

Toàn bộ5 Dockerfiles và before/current FROM refs ở dockerfile_inventory trong JSON. Legacy Lab importer vẫn dùng JDK17.0.10, không được chọn trong canonical Public Demo build graph và giữ nguyên. Lab MySQL/Redis image refs được kiểm kê metadata; không nâng engine/image hoặc kết nối DB. Public Demo engine/V5 path còn D-14/PD-03-06, full release-image scan còn PD-03-04; không gọi các image này đã được remediation.

## 2. Advisory triage và điều kiện áp dụng

177 Java package/version/advisory records được xét: **127 FIXED**, **4 NOT APPLICABLE**
(ba advisory trên hai Spring artifacts), **45 NOT VERIFIED**, **1 BLOCKED**. Appendix nối
đủ **127 J-IDs lịch sử**; các record provided/test bổ sung dùng JD-ID riêng.
FIXED nghĩa affected coordinate đã được thay, rescan không còn match và build/regression mới đạt;
không khẳng định exploit từng xảy ra. Upstream severity không bị đổi theo project applicability.

| Advisory còn quan trọng | Prerequisites và đối chiếu source | Trạng thái đúng phạm vi |
|---|---|---|
| [GHSA-4gv3-mc9p-5wqc / CVE-2026-18963](https://github.com/keycloak/keycloak/issues/51833) | Reset-credentials flow có thể bỏ bước email verification; 26.7.0 thuộc affected range, fix gồm 26.7.2. Public Demo realm chưa tồn tại để chứng minh mitigation | **BLOCKED remediation**: user cấm nâng server. Không thay flow/realm/SPI provided version hoặc giả workaround đã hiệu lực |
| [GHSA-9qf2-26p9-2q2q](https://osv.dev/vulnerability/GHSA-9qf2-26p9-2q2q) | Cần functional header-predicate endpoint và deployment combination nêu trong advisory. Gateway dùng Reactor Netty + Spring Cloud RouteLocator, không app RouterFunctions/header predicate; Portal/Risk là JSON MVC | **NOT APPLICABLE — configured source**; không FIXED framework. Reopen khi thêm feature/deployment khác |
| [GHSA-j9f9-w8pj-32f8](https://osv.dev/vulnerability/GHSA-j9f9-w8pj-32f8) | Cần Spring SSE cùng view fragments; không có SseEmitter/ServerSentEvent/fragment rendering trong các handlers hiện tại | **NOT APPLICABLE — configured source**, không waive một deployment chưa kiểm tra |
| [GHSA-pc63-qcmh-9cmg](https://osv.dev/vulnerability/GHSA-pc63-qcmh-9cmg) | Cần XsltView và catch-all view resolution với tên view không chỉ định. Không có XsltView/resolver/XSL views; controllers trả JSON ResponseEntity | **NOT APPLICABLE — configured source**; thêm view resolver phải review lại |
| [CVE-2023-45853](https://security-tracker.debian.org/tracker/CVE-2023-45853) ở zlib1g trong frontend | Debian ghi rõ affected contrib/minizip không được build vào binary của bookworm; nguồn zlib bị match không đồng nghĩa binary zlib1g chứa mã lỗi | **NOT APPLICABLE cho binary này**; giữ raw Critical trong scan, không hạ severity |
| CVE-2025-47273 / setuptools@70.3.0 trong tools | Trivy lấy metadata từ `pip/_vendor/vendor.txt`. Phần vendored không có vulnerable PackageIndex/package_index.py; active venv setuptools 84.2.1, không dùng system site-packages | **NOT APPLICABLE cho component vendored này**; proof bằng kiểm tra filesystem/module trong container network-none, không miễn trừ các bản setuptools khác |

Source reachability dựa toàn bộ Portal controllers/services, GatewayRoutes và Risk controllers,
tìm các feature APIs/return types liên quan. Các `provided` Keycloak dependencies còn match
không được override riêng: classpath server có thể khác compile tree, server có feature riêng.
JSON giữ từng record và nguồn để tiếp tục triage; NOT VERIFIED không là NOT APPLICABLE.

## 3. Dependencies đã cập nhật

| Package / family | Baseline → current | Căn cứ / phạm vi |
|---|---|---|
| Spring Boot parent, Portal/Risk/Gateway | 3.5.7 → 3.5.16 | Latest public 3.5 train tại Maven Central lúc kiểm tra; không tự chuyển Boot major |
| Spring Security / Framework | 6.5.6 → 6.5.11 / 6.2.12 → 6.2.19 | Theo Boot BOM; ba Framework feature advisories vẫn còn, triage ở trên |
| Jackson BOM | 2.19.2 → 2.21.8 | Cùng Jackson 2; patch parser/type-cache/annotation/number handling, vượt BOM 2.21.4 bằng compatible patch |
| Tomcat / Netty BOM | 10.1.48 → 10.1.61 / 4.1.128.Final → 4.1.140.Final | Tomcat cho servlet modules; Netty family đồng bộ cho Gateway/Risk, không override codec rời rạc |
| Logback / Log4j BOM | 1.5.20 → 1.5.38 / 2.24.3 → 2.26.1 | Vá cùng dòng, giữ SLF4J/Logback behavior |
| Micrometer | 1.15.5 → 1.15.12 | Boot-managed Risk metrics dependency |
| Commons IO | 2.11.0 → 2.22.0 | RESTEasy transitive của Portal; XmlStreamReader advisory fix từ 2.14, không exclusion |
| Bouncy Castle family | 1.80.2 → 1.86 | Gateway dependencyManagement đồng bộ bcprov/bcpkix/bcutil; name constraints/ASN.1 advisories |
| Keycloak admin client / JS client | 26.0.11 → 26.0.12 / 26.2.4 → 26.2.5 | Client libraries; không nâng Keycloak server/SPI provided 26.7.0 |
| Next / eslint-config-next / sharp | 16.2.6 → 16.4.5 / 0.34.5 → 0.35.5 | Maintained Next 16 patch line; sharp theo transitive lock, Linux native load/render đạt |
| Node / npm CLI | 24.16.0 → 24.22.2 / bundled 11.13.0 → selected 11.21.2 | Giữ Node 24; npm 11.21.2 pin cho Docker build/runtime và CI, không nhảy npm 12 |
| JDK builder / JRE | 17.0.10+7 → 17.0.21+9 / 17.0.20.1+1 → 17.0.21+9 | Builder vẫn Ubuntu 22.04; runtime giữ Ubuntu 26.04, pin explicit `jre-resolute` |
| APT / JRE Brotli | Jammy apt 2.4.15ubuntu0.1; Resolute apt 3.2.1ubuntu0.1 + libbrotli1 1.2.0-3ubuntu0.1 | Patch layer cho CVE-2026-109518 và Brotli CVE; không sửa Lab image |
| cryptography / tools pip / setuptools | 44.0.3 → 50.0.2 / 26.3 / 84.2.1 | Crypto fix cần 50 cho PKCS#7; API dùng trong PKI được rà và test thực tế. Linux wheel OpenSSL 4.0.3 |

PyMySQL giữ **1.1.1**, OSV query không có match; không cần thay DB client ngoài mục tiêu.
React 19.2.6, SPI version 26.7.0, Cloud 2025.0.3, Flyway 11.7.2 và các B0 invariants giữ nguyên.
Cloud train EOL không được gọi là supported chỉ vì dùng bản cuối; xem phần còn mở.

## 4. Source/build compatibility changes

Chỉ sửa ba POM, package.json/lockfile, `.node-version`, bốn canonical Dockerfiles và bước
cài npm CLI trong CI. Thêm **V5ChecksumContractTest** và **FrameworkResponseHeadersTest**. Không đổi application API/controller,
PD-02-01 filter/config, B0 source/config, MFA/trust logic, realm hoặc database schema.
Java properties override whole BOM khi có BOM; BC family management dùng cùng version.
Không thêm dependency exclusion hay force audit/downgrade để làm scanner xanh.

`npm audit fix --package-lock-only --ignore-scripts` chỉ áp dụng compatible resolution.
Gợi ý `--force` sẽ đẩy eslint-config-next về 15.5.29; không thực hiện vì đổi major/downgrade
không có căn cứ. Thay đổi lockfile được rà theo package/version, không thay UI business source.

## 5. Migration V5 contract

| Kiểm chứng | Kết quả |
|---|---|
| Baseline Oracle JDK17.0.10 compile | checksum **661092940** |
| Temurin JDK17.0.21, release17/debug/parameters/UTF-8 | checksum **661092940** |
| Bốn compiled migration/helper class hashes trước/sau | **Giống byte-for-byte** |
| Metadata proxy MySQL8.4.13 | Refused UNREVIEWED_MYSQL_VERSION, **0 SQL calls**, đúng guard cũ |
| Regression mới V5ChecksumContractTest | PASS, expected checksum lấy từ baseline applied contract |

Thêm `project.build.sourceEncoding=UTF-8` rõ trong Risk POM. Một manual probe bỏ encoding
trên Windows tạo checksum khác do các chuỗi `café`/`é`; sau khi dùng đúng Maven encoding,
JDK mới cho đúng bốn class bytes và checksum. Không sửa source V5/preflight, số checksum,
Flyway history hoặc MySQL version guard. Đây không là real-engine migration/restore acceptance;
PD-03-06 vẫn chưa thực hiện. Không đổi expected test chỉ để repair applied history.

## 6. Regression results — đúng các lượt chạy mới

JDK **Temurin17.0.21+9**, Maven Wrapper **3.9.16**; bốn module đều `verify` BUILD SUCCESS.
Compiler plugin 3.14.1 ở Boot modules, SPI giữ 3.14.0. Surefire Boot-managed 3.5.6; SPI giữ 3.5.3.

| Suite | Total | Passed | Failed / errors | Skipped |
|---|---:|---:|---:|---:|
| Portal | 420 | 420 | 0 / 0 | 0 |
| Risk, gồm checksum test mới | 710 | 614 | 0 / 0 | 96 |
| Gateway | 20 | 20 | 0 / 0 | 0 |
| SPI | 203 | 176 | 0 / 0 | 27 |
| **Java tổng** | **1.353** | **1.230** | **0 / 0** | **123** |
| Frontend Node tests | 15 | 15 | 0 / 0 | 0 |
| Observatory viewer Node tests | 4 | 4 | 0 / 0 | 0 |
| Build contract Python tests | 5 | 5 | 0 / 0 | 0 |
| Linux tools PKI tests | 7 | 7 | 0 / 0 | 0 |

**90 tests PD-02-01 vẫn PASS**, nằm trong Portal420, không cộng lại. Ba tests mới còn kiểm Cache-Control no-store, X-Content-Type-Options nosniff và X-Frame-Options DENY trên 200/401/403 sau framework upgrade. Lint/typecheck và Next
production build PASS trên host Node24.22.2; có 1 warning postcss.config.mjs có sẵn.
Linux frontend Docker build cũng chạy lint/typecheck + 15 tests + Next build thành công.
Container network-none load sharp0.35.5/libvips8.18.7/librsvg2.63.2, tạo PNG1×1 thành công.
Tools Linux Python3.10.12 chạy cryptography50.0.2/OpenSSL4.0.3 và PKI bằng CA synthetic.
JRE Ubuntu26.04 startup/version17.0.21 đạt; chưa boot Portal/Risk/Gateway full stack trên JRE đó.

123 skips là opt-in integration/QA guards, không phải PASS: Risk qa.http.audit43,
qa.mysql.audit4, qa.redis.audit30, postfix03a.gateB3, postfix03b.native16; SPI qa.spi.audit27.
Không bật các bài có thể chạm môi trường ngoài scope. Một ControlledStudyExperiment XML cũ
không thuộc log current run đã được loại khỏi tổng. Kết quả JSON chỉ lấy classes trong log lượt mới.

Hai frontend test commands ban đầu bị lỗi tên log có dấu `:` trên Windows và chưa thực thi;
đã sửa tên log, chạy lại và chỉ tính 6+9 kết quả thật. OSV detail network errors đã retry thành
công; final baseline/candidate có 0 detail error. Trivy cache-lock ở lần chạy song song đầu
được xử lý bằng memory cache riêng; chỉ scan JSON hoàn tất được dùng, không coi lỗi tool là clean.

## 7. Commands thực sự chạy

Các lệnh Maven dùng process-local JAVA_HOME đến JDK17.0.21 đã tải và kiểm SHA-256;
không đổi JDK/Node global của máy. Ngoài baseline `-DskipTests package` để inventory, mọi
candidate `verify` dưới đây chạy tests; baseline package không được tính là test acceptance.

```powershell
.\mvnw.cmd --batch-mode --no-transfer-progress -f pom.xml verify dependency:tree -DoutputType=json -DoutputFile=target/pd-02-02-candidate-tree.json dependency:build-classpath -Dmdep.outputFile=target/pd-02-02-candidate-classpath.txt
.\mvnw.cmd --batch-mode --no-transfer-progress -f risk-scoring-service/pom.xml verify
.\mvnw.cmd --batch-mode --no-transfer-progress -f gateway/pom.xml verify dependency:tree -DoutputType=json -DoutputFile=target/pd-02-02-candidate-tree.json
.\mvnw.cmd --batch-mode --no-transfer-progress -f keycloak-risk-extension/pom.xml verify dependency:tree -DoutputType=json -DoutputFile=target/pd-02-02-candidate-tree.json
# Các npm commands chạy trong frontend/ với Node24.22.2.
npm install --package-lock-only --ignore-scripts --save-exact next@16.4.5 keycloak-js@26.2.5
npm install --package-lock-only --ignore-scripts --save-dev --save-exact eslint-config-next@16.4.5
npm audit fix --package-lock-only --ignore-scripts
npm ci --no-audit --no-fund
npm run lint
npm run typecheck
npm run test:student-scores
npm run test:portal-route
npm run build
npm audit --json
node --test ../scripts/observation/test_viewer.cjs
# Quay lại canonical root cho build-contract tests.
python -m unittest discover -s scripts/build -p 'test_*.py' -v
```

npm commands được gọi qua portable Node + npm CLI khi cần; initial host ci dùng bundled npm11.19.1, các checks/audit sau dùng portable11.21.2. CI/Docker pin11.21.2 và Linux build đã chạy ci bằng đúng bản này.
Maven tree/classpath goals cũng chạy cho Risk ở lượt candidate trước checksum-test-only change;
dependencies không đổi sau đó. OSV collector querybatch cả bốn graphs, tải từng advisory detail.
Scan image dùng Trivy0.76.2: `image --cache-backend memory --image-src remote|docker
--platform linux/amd64 --scanners vuln --format json`; ba local images thêm `--list-all-pkgs`.
Vulnerability DB UpdatedAt **2026-11-06T01:07:43Z**, không dùng clean result từ DB thiếu/expired.

Docker builds dùng context tar **trong bộ nhớ** từ canonical public source được chọn, không
worktree/source directory copy. Bốn Dockerfile checks PASS. Local test images gồm frontend,
tools và JRE-base fragment; không phải immutable release candidates, labels source defaults
không được coi release provenance. Containers kiểm thử `--rm --network none`, không mount
Lab; PKI chỉ mount read-only đúng hai source test/helper files và dùng temporary synthetic CA.

## 8. Security rescan và image scope

| Artifact scan | Raw Critical / High | Kết luận có giới hạn |
|---|---:|---|
| Old JDK17.0.10 Ubuntu22.04 base | 0 / 8 | Baseline public base, không phải Lab runtime scan |
| New JDK17.0.21 Ubuntu22.04 base | 0 / 2 | APT fixes được thêm vào build stages; tools artifact đã thực thi layer patch |
| Old JRE17.0.20.1 Ubuntu26.04 base | 0 / 7 | Đúng digest cũ; không suy version từ tag17-jre |
| New JRE17.0.21 Ubuntu26.04 base | 0 / 2 | Giữ OS family, patch APT/Brotli layer |
| Built patched JRE fragment | 0 / 0 | 53Medium/4Low còn nguyên raw; không là full application acceptance |
| Old Node24.16 Bookworm base | 5 / 58 | Baseline, có CLI/native/OS package matches |
| New Node24.22.2 Bookworm base | 1 / 39 | Sáu High có fix thuộc bundled npm; đã patch CLI trong Dockerfile |
| Built frontend, npm11.21.2 | 1 / 33 | Critical zlib/minizip không áp dụng binary theo Debian; 33 High không có fixed version trong scan vẫn NOT VERIFIED, không waive |
| Built tools, crypto50/pip26.3/setuptools84 | 0 / 1 | High là partial pip-vendored metadata case đã triage riêng; 55Medium/49Low chưa blanket close |
| Keycloak26.7.0 base, unchanged | 6 / 41 | Server upgrade bị cấm; giữ các findings mở, không suy từ SPI unit tests |

Ba final local inventories có **254 frontend / 205 tools / 151 JRE package records**.
Raw severities và per-record triage giữ ở JSON. Raw Trivy Status=fixed chỉ nói fix upstream tồn tại, không nói installed artifact đã được vá. Medium/Low không được gọi đã xử lý chỉ vì
task ưu tiên High/Critical. Debian13/Trixie alternative được inspect nhưng có 51High raw
và không cung cấp patch compatible cho tập còn mở; không dùng làm blanket fix, source vẫn Bookworm.

Full release-image scan/SBOM/provenance cho mọi service, including final Keycloak build và
Java application images, vẫn ở **PD-03-04**. Scans này không chứng minh CPU khác amd64,
toàn bộ bundled native CVEs hoặc vận hành an toàn chỉ từ immutable base digest.

## 9. Advisory còn mở và supported-platform decision

- **D-16:** chọn server patch/release và cho phép thực hiện upgrade riêng, có SPI/realm/MFA/trust
  compatibility trước dùng Public Demo. Ít nhất CVE-2026-18963 cần fixed range như26.7.2;
  đây không là cam kết version đó giải quyết mọi server advisory. Không sửa server/realm trong task này.
- **D-15:** chọn đường platform được hỗ trợ và phạm vi migration/extended support.
  [Spring Cloud matrix](https://spring.io/projects/spring-cloud/) đánh dấu2025.0 EOL.
  [Boot4 migration guide](https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-4.0-Migration-Guide)
  yêu cầu review Spring7/Servlet6.1, Jackson và ecosystem compatibility; không force đổi đồng loạt
  để xóa version matches. Source hiện tại dùng Jackson2/security contracts cần migration riêng được kiểm chứng.
- Provided Keycloak matches, các CVE OS chưa có fix và residual feature conditions phải được
  review từng record. Tám npm Moderate entries còn lại thuộc minimatch/TypeScript-ESLint dev chain;
  không nằm trong standalone app dependencies nhưng build input risk chưa được ký acceptance.
- ESLint9.39.4 báo hết support trong npm install; không có High/Critical match hiện tại cho nó,
  nhưng lifecycle build tooling cần được xử lý cùng maintained-platform decision, không được gọi supported.
- [Node vendor](https://nodejs.org/en/blog/vulnerability/november-2026-security-releases) đã thông báo security release11/11/2026; ngày kiểm chứng06/11 không thể coi
  patch tương lai đã có. Phải rescan lại trước freeze/go-live, không dùng báo cáo này vĩnh viễn.

## 10. Giới hạn kiểm chứng

Không live login/OTP, Keycloak realm readback, MySQL/Redis tests hoặc application rollout.
Mock/H2/JWKS loopback không là real issuer/browser/TLS/grants proof. Linux Node native,
Python PKI và JRE version chỉ chứng minh đúng các smoke/build scopes được liệt kê.
SPI compile/provided contract26.7.0 và 176 unit tests không là server26.7.2 runtime compatibility.
Không thử khai thác service Internet/Lab. Không thay B0 weights/thresholds/guards/failureMode.
Source-specific NOT APPLICABLE phải reopen khi handler/view/flow/config đổi.

## 11. Preservation verification

Checkpoint kiểm cuối ở roadmap/tool output đối chiếu hashes trước/sau: HEAD/branch không đổi;
mọi PD-02-01 source/config/tests và evidence cũ giữ nguyên byte, kể cả toàn bộ historical audit.
Lab10 containers vẫn exited, IDs/images/mounts/networks không đổi. Không đọc/ghi Lab DB,
Redis/realm/CA/secrets, không đổi volume, restart/recreate, worktree/clone/source copy, commit/push/deploy.
Chỉ thêm các local test images/caches và disposable network-none helpers được mô tả ở trên;
không gán chúng vào Lab manifests. Artifact source hashes ở appendix, không tự hash chính report.

## 12. Handover result

PD-02-02 **PARTIAL**, không tự giảm acceptance để PASS. Remediation có thể làm trong scope
đã thực hiện và kiểm chứng; server authorization/support strategy và unresolved records còn mở.
PR-001/PR-016 OPEN; G1/G3 PARTIAL; không Production GO. Task độc lập kế tiếp đủ dependency
là **PD-02-03**, vì PD-02-01 PASS; task đó chưa thực hiện. Trạng thái chi tiết duy nhất ở roadmap.

## Appendix — từng Java advisory/version match

FIXED chỉ kết luận affected coordinate đã được thay và rescan; không khẳng định exploit từng tồn tại. Full ranges/instances/prerequisites/references ở JSON. Historical J-IDs giữ trace về register audit cũ.

| Record / historical ID | Package: before → current; modules | Advisory; severity upstream | Triage / căn cứ |
|---|---|---|---|
| JD-001 / J-001 | ch.qos.logback:logback-core 1.5.20 → 1.5.38; gateway,portal,risk | [GHSA-jhq6-gfmj-v8fx](https://osv.dev/vulnerability/GHSA-jhq6-gfmj-v8fx); LOW | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-002 / J-002 | ch.qos.logback:logback-core 1.5.20 → 1.5.38; gateway,portal,risk | [GHSA-p47f-322f-whfh](https://osv.dev/vulnerability/GHSA-p47f-322f-whfh); LOW | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-003 / J-003 | ch.qos.logback:logback-core 1.5.20 → 1.5.38; gateway,portal,risk | [GHSA-qqpg-mvqg-649v](https://osv.dev/vulnerability/GHSA-qqpg-mvqg-649v); LOW | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-004 / J-004 | com.fasterxml.jackson.core:jackson-core 2.19.2 → 2.21.8; gateway,portal,risk | [GHSA-72hv-8253-57qq](https://osv.dev/vulnerability/GHSA-72hv-8253-57qq); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-005 / J-005 | com.fasterxml.jackson.core:jackson-core 2.19.2 → 2.21.8; gateway,portal,risk | [GHSA-7hhh-6rmp-j9qf](https://osv.dev/vulnerability/GHSA-7hhh-6rmp-j9qf); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-006 / J-006 | com.fasterxml.jackson.core:jackson-core 2.19.2 → 2.21.8; gateway,portal,risk | [GHSA-p6pp-m3f8-5c89](https://osv.dev/vulnerability/GHSA-p6pp-m3f8-5c89); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-007 / J-007 | com.fasterxml.jackson.core:jackson-core 2.19.2 → 2.21.8; gateway,portal,risk | [GHSA-r7wm-3cxj-wff9](https://osv.dev/vulnerability/GHSA-r7wm-3cxj-wff9); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-008 /  | com.fasterxml.jackson.core:jackson-core 2.21.2 → 2.21.2; spi | [GHSA-7hhh-6rmp-j9qf](https://osv.dev/vulnerability/GHSA-7hhh-6rmp-j9qf); HIGH | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-009 /  | com.fasterxml.jackson.core:jackson-core 2.21.2 → 2.21.2; spi | [GHSA-p6pp-m3f8-5c89](https://osv.dev/vulnerability/GHSA-p6pp-m3f8-5c89); HIGH | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-010 /  | com.fasterxml.jackson.core:jackson-core 2.21.2 → 2.21.2; spi | [GHSA-r7wm-3cxj-wff9](https://osv.dev/vulnerability/GHSA-r7wm-3cxj-wff9); HIGH | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-011 / J-008 | com.fasterxml.jackson.core:jackson-databind 2.19.2 → 2.21.8; gateway,portal,risk | [GHSA-3pjw-73gf-8qr5](https://osv.dev/vulnerability/GHSA-3pjw-73gf-8qr5); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-012 / J-009 | com.fasterxml.jackson.core:jackson-databind 2.19.2 → 2.21.8; gateway,portal,risk | [GHSA-5gvw-p9qm-jgwh](https://osv.dev/vulnerability/GHSA-5gvw-p9qm-jgwh); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-013 / J-010 | com.fasterxml.jackson.core:jackson-databind 2.19.2 → 2.21.8; gateway,portal,risk | [GHSA-5jmj-h7xm-6q6v](https://osv.dev/vulnerability/GHSA-5jmj-h7xm-6q6v); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-014 / J-011 | com.fasterxml.jackson.core:jackson-databind 2.19.2 → 2.21.8; gateway,portal,risk | [GHSA-cxp5-3px4-pw24](https://osv.dev/vulnerability/GHSA-cxp5-3px4-pw24); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-015 / J-012 | com.fasterxml.jackson.core:jackson-databind 2.19.2 → 2.21.8; gateway,portal,risk | [GHSA-gx83-3vf8-gh7j](https://osv.dev/vulnerability/GHSA-gx83-3vf8-gh7j); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-016 / J-013 | com.fasterxml.jackson.core:jackson-databind 2.19.2 → 2.21.8; gateway,portal,risk | [GHSA-hgj6-7826-r7m5](https://osv.dev/vulnerability/GHSA-hgj6-7826-r7m5); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-017 / J-014 | com.fasterxml.jackson.core:jackson-databind 2.19.2 → 2.21.8; gateway,portal,risk | [GHSA-j3rv-43j4-c7qm](https://osv.dev/vulnerability/GHSA-j3rv-43j4-c7qm); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-018 / J-015 | com.fasterxml.jackson.core:jackson-databind 2.19.2 → 2.21.8; gateway,portal,risk | [GHSA-q4xh-88c3-wmh7](https://osv.dev/vulnerability/GHSA-q4xh-88c3-wmh7); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-019 / J-016 | com.fasterxml.jackson.core:jackson-databind 2.19.2 → 2.21.8; gateway,portal,risk | [GHSA-rmj7-2vxq-3g9f](https://osv.dev/vulnerability/GHSA-rmj7-2vxq-3g9f); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-020 / J-017 | com.fasterxml.jackson.core:jackson-databind 2.19.2 → 2.21.8; gateway,portal,risk | [GHSA-vvgp-rfg2-7rr6](https://osv.dev/vulnerability/GHSA-vvgp-rfg2-7rr6); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-021 / J-018 | com.fasterxml.jackson.core:jackson-databind 2.19.2 → 2.21.8; gateway,portal,risk | [GHSA-wjgm-6hv5-3cvf](https://osv.dev/vulnerability/GHSA-wjgm-6hv5-3cvf); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-022 / J-019 | com.fasterxml.jackson.core:jackson-databind 2.19.2 → 2.21.8; gateway,portal,risk | [GHSA-wv8q-qhhj-9h54](https://osv.dev/vulnerability/GHSA-wv8q-qhhj-9h54); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-023 /  | com.fasterxml.jackson.core:jackson-databind 2.21.2 → 2.21.2; spi | [GHSA-3pjw-73gf-8qr5](https://osv.dev/vulnerability/GHSA-3pjw-73gf-8qr5); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-024 /  | com.fasterxml.jackson.core:jackson-databind 2.21.2 → 2.21.2; spi | [GHSA-5gvw-p9qm-jgwh](https://osv.dev/vulnerability/GHSA-5gvw-p9qm-jgwh); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-025 /  | com.fasterxml.jackson.core:jackson-databind 2.21.2 → 2.21.2; spi | [GHSA-5hh8-q8hv-fr38](https://osv.dev/vulnerability/GHSA-5hh8-q8hv-fr38); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-026 /  | com.fasterxml.jackson.core:jackson-databind 2.21.2 → 2.21.2; spi | [GHSA-5jmj-h7xm-6q6v](https://osv.dev/vulnerability/GHSA-5jmj-h7xm-6q6v); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-027 /  | com.fasterxml.jackson.core:jackson-databind 2.21.2 → 2.21.2; spi | [GHSA-9fxm-vc8v-hj55](https://osv.dev/vulnerability/GHSA-9fxm-vc8v-hj55); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-028 /  | com.fasterxml.jackson.core:jackson-databind 2.21.2 → 2.21.2; spi | [GHSA-cxp5-3px4-pw24](https://osv.dev/vulnerability/GHSA-cxp5-3px4-pw24); HIGH | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-029 /  | com.fasterxml.jackson.core:jackson-databind 2.21.2 → 2.21.2; spi | [GHSA-gx83-3vf8-gh7j](https://osv.dev/vulnerability/GHSA-gx83-3vf8-gh7j); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-030 /  | com.fasterxml.jackson.core:jackson-databind 2.21.2 → 2.21.2; spi | [GHSA-hgj6-7826-r7m5](https://osv.dev/vulnerability/GHSA-hgj6-7826-r7m5); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-031 /  | com.fasterxml.jackson.core:jackson-databind 2.21.2 → 2.21.2; spi | [GHSA-j3rv-43j4-c7qm](https://osv.dev/vulnerability/GHSA-j3rv-43j4-c7qm); HIGH | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-032 /  | com.fasterxml.jackson.core:jackson-databind 2.21.2 → 2.21.2; spi | [GHSA-mhm7-754m-9p8w](https://osv.dev/vulnerability/GHSA-mhm7-754m-9p8w); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-033 /  | com.fasterxml.jackson.core:jackson-databind 2.21.2 → 2.21.2; spi | [GHSA-q4xh-88c3-wmh7](https://osv.dev/vulnerability/GHSA-q4xh-88c3-wmh7); HIGH | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-034 /  | com.fasterxml.jackson.core:jackson-databind 2.21.2 → 2.21.2; spi | [GHSA-rcqc-6cw3-h962](https://osv.dev/vulnerability/GHSA-rcqc-6cw3-h962); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-035 /  | com.fasterxml.jackson.core:jackson-databind 2.21.2 → 2.21.2; spi | [GHSA-rmj7-2vxq-3g9f](https://osv.dev/vulnerability/GHSA-rmj7-2vxq-3g9f); HIGH | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-036 /  | com.fasterxml.jackson.core:jackson-databind 2.21.2 → 2.21.2; spi | [GHSA-vvgp-rfg2-7rr6](https://osv.dev/vulnerability/GHSA-vvgp-rfg2-7rr6); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-037 /  | com.fasterxml.jackson.core:jackson-databind 2.21.2 → 2.21.2; spi | [GHSA-wjgm-6hv5-3cvf](https://osv.dev/vulnerability/GHSA-wjgm-6hv5-3cvf); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-038 /  | com.fasterxml.jackson.core:jackson-databind 2.21.2 → 2.21.2; spi | [GHSA-wv8q-qhhj-9h54](https://osv.dev/vulnerability/GHSA-wv8q-qhhj-9h54); HIGH | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-039 /  | com.google.guava:guava 32.1.2-jre → 32.1.2-jre; spi | [GHSA-xxph-c9ww-hj94](https://osv.dev/vulnerability/GHSA-xxph-c9ww-hj94); HIGH | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-040 /  | com.google.protobuf:protobuf-java 3.25.1 → 3.25.1; spi | [GHSA-735f-pc8j-v9w8](https://osv.dev/vulnerability/GHSA-735f-pc8j-v9w8); HIGH | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-041 / J-020 | commons-io:commons-io 2.11.0 → 2.22.0; portal | [GHSA-78wr-2p64-hpwj](https://osv.dev/vulnerability/GHSA-78wr-2p64-hpwj); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-042 / J-021 | io.micrometer:micrometer-core 1.15.5 → 1.15.12; risk | [GHSA-g3pr-3p32-fp23](https://osv.dev/vulnerability/GHSA-g3pr-3p32-fp23); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-043 / J-022 | io.micrometer:micrometer-core 1.15.5 → 1.15.12; risk | [GHSA-w737-wx49-qj23](https://osv.dev/vulnerability/GHSA-w737-wx49-qj23); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-044 / J-023 | io.netty:netty-codec 4.1.128.Final → 4.1.140.Final; gateway,risk | [GHSA-558v-64gr-wgg4](https://osv.dev/vulnerability/GHSA-558v-64gr-wgg4); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-045 / J-024 | io.netty:netty-codec 4.1.128.Final → 4.1.140.Final; gateway,risk | [GHSA-mj4r-2hfc-f8p6](https://osv.dev/vulnerability/GHSA-mj4r-2hfc-f8p6); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-046 /  | io.netty:netty-codec 4.1.135.Final → 4.1.135.Final; spi | [GHSA-558v-64gr-wgg4](https://osv.dev/vulnerability/GHSA-558v-64gr-wgg4); HIGH | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-047 / J-025 | io.netty:netty-codec-dns 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-cm33-6792-r9fm](https://osv.dev/vulnerability/GHSA-cm33-6792-r9fm); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-048 / J-026 | io.netty:netty-codec-dns 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-mfg7-5gfp-c4w3](https://osv.dev/vulnerability/GHSA-mfg7-5gfp-c4w3); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-049 /  | io.netty:netty-codec-dns 4.1.130.Final → 4.1.130.Final; spi | [GHSA-cm33-6792-r9fm](https://osv.dev/vulnerability/GHSA-cm33-6792-r9fm); HIGH | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-050 /  | io.netty:netty-codec-dns 4.1.130.Final → 4.1.130.Final; spi | [GHSA-mfg7-5gfp-c4w3](https://osv.dev/vulnerability/GHSA-mfg7-5gfp-c4w3); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-051 /  | io.netty:netty-codec-haproxy 4.1.135.Final → 4.1.135.Final; spi | [GHSA-q6cq-mhr2-jmr5](https://osv.dev/vulnerability/GHSA-q6cq-mhr2-jmr5); HIGH | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-052 /  | io.netty:netty-codec-haproxy 4.1.135.Final → 4.1.135.Final; spi | [GHSA-wh89-7897-x99h](https://osv.dev/vulnerability/GHSA-wh89-7897-x99h); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-053 / J-027 | io.netty:netty-codec-http 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-38f8-5428-x5cv](https://osv.dev/vulnerability/GHSA-38f8-5428-x5cv); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-054 / J-028 | io.netty:netty-codec-http 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-4mp9-239f-g9hg](https://osv.dev/vulnerability/GHSA-4mp9-239f-g9hg); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-055 / J-029 | io.netty:netty-codec-http 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-57rv-r2g8-2cj3](https://osv.dev/vulnerability/GHSA-57rv-r2g8-2cj3); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-056 / J-030 | io.netty:netty-codec-http 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-6cqp-g7gg-8hr5](https://osv.dev/vulnerability/GHSA-6cqp-g7gg-8hr5); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-057 / J-031 | io.netty:netty-codec-http 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-6jqx-86gh-f27w](https://osv.dev/vulnerability/GHSA-6jqx-86gh-f27w); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-058 / J-032 | io.netty:netty-codec-http 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-84h7-rjj3-6jx4](https://osv.dev/vulnerability/GHSA-84h7-rjj3-6jx4); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-059 / J-033 | io.netty:netty-codec-http 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-8c42-7qj2-3j46](https://osv.dev/vulnerability/GHSA-8c42-7qj2-3j46); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-060 / J-034 | io.netty:netty-codec-http 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-f6hv-jmp6-3vwv](https://osv.dev/vulnerability/GHSA-f6hv-jmp6-3vwv); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-061 / J-035 | io.netty:netty-codec-http 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-gcjf-9mgh-3p7g](https://osv.dev/vulnerability/GHSA-gcjf-9mgh-3p7g); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-062 / J-036 | io.netty:netty-codec-http 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-hvcg-qmg6-jm4c](https://osv.dev/vulnerability/GHSA-hvcg-qmg6-jm4c); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-063 / J-037 | io.netty:netty-codec-http 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-jppx-w49h-x2qq](https://osv.dev/vulnerability/GHSA-jppx-w49h-x2qq); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-064 / J-038 | io.netty:netty-codec-http 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-m4cv-j2px-7723](https://osv.dev/vulnerability/GHSA-m4cv-j2px-7723); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-065 / J-039 | io.netty:netty-codec-http 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-mvh2-crg5-v77c](https://osv.dev/vulnerability/GHSA-mvh2-crg5-v77c); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-066 / J-040 | io.netty:netty-codec-http 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-pwqr-wmgm-9rr8](https://osv.dev/vulnerability/GHSA-pwqr-wmgm-9rr8); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-067 / J-041 | io.netty:netty-codec-http 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-q4f6-jm68-57ww](https://osv.dev/vulnerability/GHSA-q4f6-jm68-57ww); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-068 / J-042 | io.netty:netty-codec-http 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-v8h7-rr48-vmmv](https://osv.dev/vulnerability/GHSA-v8h7-rr48-vmmv); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-069 / J-043 | io.netty:netty-codec-http 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-xxqh-mfjm-7mv9](https://osv.dev/vulnerability/GHSA-xxqh-mfjm-7mv9); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-070 /  | io.netty:netty-codec-http 4.1.135.Final → 4.1.135.Final; spi | [GHSA-4mp9-239f-g9hg](https://osv.dev/vulnerability/GHSA-4mp9-239f-g9hg); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-071 /  | io.netty:netty-codec-http 4.1.135.Final → 4.1.135.Final; spi | [GHSA-6cqp-g7gg-8hr5](https://osv.dev/vulnerability/GHSA-6cqp-g7gg-8hr5); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-072 /  | io.netty:netty-codec-http 4.1.135.Final → 4.1.135.Final; spi | [GHSA-6jqx-86gh-f27w](https://osv.dev/vulnerability/GHSA-6jqx-86gh-f27w); HIGH | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-073 /  | io.netty:netty-codec-http 4.1.135.Final → 4.1.135.Final; spi | [GHSA-8c42-7qj2-3j46](https://osv.dev/vulnerability/GHSA-8c42-7qj2-3j46); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-074 /  | io.netty:netty-codec-http 4.1.135.Final → 4.1.135.Final; spi | [GHSA-gcjf-9mgh-3p7g](https://osv.dev/vulnerability/GHSA-gcjf-9mgh-3p7g); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-075 /  | io.netty:netty-codec-http 4.1.135.Final → 4.1.135.Final; spi | [GHSA-jppx-w49h-x2qq](https://osv.dev/vulnerability/GHSA-jppx-w49h-x2qq); HIGH | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-076 /  | io.netty:netty-codec-http 4.1.135.Final → 4.1.135.Final; spi | [GHSA-mvh2-crg5-v77c](https://osv.dev/vulnerability/GHSA-mvh2-crg5-v77c); HIGH | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-077 /  | io.netty:netty-codec-http 4.1.135.Final → 4.1.135.Final; spi | [GHSA-q4f6-jm68-57ww](https://osv.dev/vulnerability/GHSA-q4f6-jm68-57ww); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-078 / J-044 | io.netty:netty-codec-http2 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-563q-j3cm-6jxm](https://osv.dev/vulnerability/GHSA-563q-j3cm-6jxm); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-079 / J-045 | io.netty:netty-codec-http2 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-5x3r-wrvg-rp6q](https://osv.dev/vulnerability/GHSA-5x3r-wrvg-rp6q); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-080 / J-046 | io.netty:netty-codec-http2 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-93wv-jw9v-4972](https://osv.dev/vulnerability/GHSA-93wv-jw9v-4972); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-081 / J-047 | io.netty:netty-codec-http2 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-c2gf-v879-257j](https://osv.dev/vulnerability/GHSA-c2gf-v879-257j); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-082 / J-048 | io.netty:netty-codec-http2 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-c69g-56f8-xwqj](https://osv.dev/vulnerability/GHSA-c69g-56f8-xwqj); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-083 / J-049 | io.netty:netty-codec-http2 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-f6hv-jmp6-3vwv](https://osv.dev/vulnerability/GHSA-f6hv-jmp6-3vwv); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-084 / J-050 | io.netty:netty-codec-http2 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-w9fj-cfpg-grvv](https://osv.dev/vulnerability/GHSA-w9fj-cfpg-grvv); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-085 /  | io.netty:netty-codec-http2 4.1.135.Final → 4.1.135.Final; spi | [GHSA-93wv-jw9v-4972](https://osv.dev/vulnerability/GHSA-93wv-jw9v-4972); HIGH | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-086 /  | io.netty:netty-codec-http2 4.1.135.Final → 4.1.135.Final; spi | [GHSA-c69g-56f8-xwqj](https://osv.dev/vulnerability/GHSA-c69g-56f8-xwqj); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-087 / J-051 | io.netty:netty-handler 4.1.128.Final → 4.1.140.Final; gateway,risk | [GHSA-3qp7-7mw8-wx86](https://osv.dev/vulnerability/GHSA-3qp7-7mw8-wx86); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-088 / J-052 | io.netty:netty-handler 4.1.128.Final → 4.1.140.Final; gateway,risk | [GHSA-c4c3-7fpv-j4q5](https://osv.dev/vulnerability/GHSA-c4c3-7fpv-j4q5); CRITICAL | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-089 / J-053 | io.netty:netty-handler 4.1.128.Final → 4.1.140.Final; gateway,risk | [GHSA-c653-97m9-rcg9](https://osv.dev/vulnerability/GHSA-c653-97m9-rcg9); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-090 / J-054 | io.netty:netty-handler 4.1.128.Final → 4.1.140.Final; gateway,risk | [GHSA-fccg-mwvh-qqg4](https://osv.dev/vulnerability/GHSA-fccg-mwvh-qqg4); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-091 / J-055 | io.netty:netty-handler 4.1.128.Final → 4.1.140.Final; gateway,risk | [GHSA-x4gw-5cx5-pgmh](https://osv.dev/vulnerability/GHSA-x4gw-5cx5-pgmh); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-092 /  | io.netty:netty-handler 4.1.135.Final → 4.1.135.Final; spi | [GHSA-c4c3-7fpv-j4q5](https://osv.dev/vulnerability/GHSA-c4c3-7fpv-j4q5); CRITICAL | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-093 /  | io.netty:netty-handler 4.1.135.Final → 4.1.135.Final; spi | [GHSA-fccg-mwvh-qqg4](https://osv.dev/vulnerability/GHSA-fccg-mwvh-qqg4); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-094 / J-056 | io.netty:netty-handler-proxy 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-45q3-82m4-75jr](https://osv.dev/vulnerability/GHSA-45q3-82m4-75jr); LOW | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-095 /  | io.netty:netty-handler-proxy 4.1.130.Final → 4.1.130.Final; spi | [GHSA-45q3-82m4-75jr](https://osv.dev/vulnerability/GHSA-45q3-82m4-75jr); LOW | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-096 / J-057 | io.netty:netty-resolver-dns 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-5pvg-856g-cp85](https://osv.dev/vulnerability/GHSA-5pvg-856g-cp85); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-097 / J-058 | io.netty:netty-resolver-dns 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-676x-f7gg-47vc](https://osv.dev/vulnerability/GHSA-676x-f7gg-47vc); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-098 / J-059 | io.netty:netty-resolver-dns 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-xmv7-r254-6q78](https://osv.dev/vulnerability/GHSA-xmv7-r254-6q78); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-099 /  | io.netty:netty-resolver-dns 4.1.130.Final → 4.1.130.Final; spi | [GHSA-5pvg-856g-cp85](https://osv.dev/vulnerability/GHSA-5pvg-856g-cp85); HIGH | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-100 /  | io.netty:netty-resolver-dns 4.1.130.Final → 4.1.130.Final; spi | [GHSA-676x-f7gg-47vc](https://osv.dev/vulnerability/GHSA-676x-f7gg-47vc); HIGH | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-101 /  | io.netty:netty-resolver-dns 4.1.130.Final → 4.1.130.Final; spi | [GHSA-xmv7-r254-6q78](https://osv.dev/vulnerability/GHSA-xmv7-r254-6q78); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-102 / J-060 | io.netty:netty-transport-native-epoll 4.1.128.Final → 4.1.140.Final; gateway | [GHSA-w573-9ffj-6ff9](https://osv.dev/vulnerability/GHSA-w573-9ffj-6ff9); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-103 /  | io.opentelemetry:opentelemetry-api 1.57.0 → 1.57.0; spi | [GHSA-ccrj-gw8r-854m](https://osv.dev/vulnerability/GHSA-ccrj-gw8r-854m); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-104 /  | io.opentelemetry:opentelemetry-api 1.57.0 → 1.57.0; spi | [GHSA-rcgg-9c38-7xpx](https://osv.dev/vulnerability/GHSA-rcgg-9c38-7xpx); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-105 /  | io.vertx:vertx-core 4.5.24 → 4.5.24; spi | [GHSA-3g76-f9xq-8vp6](https://osv.dev/vulnerability/GHSA-3g76-f9xq-8vp6); MODERATE | **NOT VERIFIED**; Remaining provided/server or test-scope match: do not override libraries supplied by Keycloak independently. Actual server paths and complete server patch compatibility require separate validation. |
| JD-106 / J-061 | org.apache.logging.log4j:log4j-api 2.24.3 → 2.26.1; gateway,portal,risk | [GHSA-qv9r-c865-cp47](https://osv.dev/vulnerability/GHSA-qv9r-c865-cp47); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-107 / J-062 | org.apache.tomcat.embed:tomcat-embed-core 10.1.48 → 10.1.61; portal,risk | [GHSA-563x-q5rq-57qp](https://osv.dev/vulnerability/GHSA-563x-q5rq-57qp); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-108 / J-063 | org.apache.tomcat.embed:tomcat-embed-core 10.1.48 → 10.1.61; portal,risk | [GHSA-5m62-pw8w-7w9f](https://osv.dev/vulnerability/GHSA-5m62-pw8w-7w9f); CRITICAL | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-109 / J-064 | org.apache.tomcat.embed:tomcat-embed-core 10.1.48 → 10.1.61; portal,risk | [GHSA-5mp6-jrq3-r938](https://osv.dev/vulnerability/GHSA-5mp6-jrq3-r938); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-110 / J-065 | org.apache.tomcat.embed:tomcat-embed-core 10.1.48 → 10.1.61; portal,risk | [GHSA-5v3h-fjv2-54fg](https://osv.dev/vulnerability/GHSA-5v3h-fjv2-54fg); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-111 / J-066 | org.apache.tomcat.embed:tomcat-embed-core 10.1.48 → 10.1.61; portal,risk | [GHSA-9m3c-qcxr-9x87](https://osv.dev/vulnerability/GHSA-9m3c-qcxr-9x87); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-112 / J-067 | org.apache.tomcat.embed:tomcat-embed-core 10.1.48 → 10.1.61; portal,risk | [GHSA-9m89-8frq-c98c](https://osv.dev/vulnerability/GHSA-9m89-8frq-c98c); LOW | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-113 / J-068 | org.apache.tomcat.embed:tomcat-embed-core 10.1.48 → 10.1.61; portal,risk | [GHSA-9xv2-5v5q-p794](https://osv.dev/vulnerability/GHSA-9xv2-5v5q-p794); CRITICAL | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-114 / J-069 | org.apache.tomcat.embed:tomcat-embed-core 10.1.48 → 10.1.61; portal,risk | [GHSA-fpj8-gq4v-p354](https://osv.dev/vulnerability/GHSA-fpj8-gq4v-p354); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-115 / J-070 | org.apache.tomcat.embed:tomcat-embed-core 10.1.48 → 10.1.61; portal,risk | [GHSA-fv25-8xcx-gqjc](https://osv.dev/vulnerability/GHSA-fv25-8xcx-gqjc); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-116 / J-071 | org.apache.tomcat.embed:tomcat-embed-core 10.1.48 → 10.1.61; portal,risk | [GHSA-gcx9-497g-6cp6](https://osv.dev/vulnerability/GHSA-gcx9-497g-6cp6); CRITICAL | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-117 / J-072 | org.apache.tomcat.embed:tomcat-embed-core 10.1.48 → 10.1.61; portal,risk | [GHSA-gx5v-xp9w-j4cg](https://osv.dev/vulnerability/GHSA-gx5v-xp9w-j4cg); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-118 / J-073 | org.apache.tomcat.embed:tomcat-embed-core 10.1.48 → 10.1.61; portal,risk | [GHSA-h3x4-894j-xpx5](https://osv.dev/vulnerability/GHSA-h3x4-894j-xpx5); CRITICAL | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-119 / J-074 | org.apache.tomcat.embed:tomcat-embed-core 10.1.48 → 10.1.61; portal,risk | [GHSA-h6fc-48rj-7qqh](https://osv.dev/vulnerability/GHSA-h6fc-48rj-7qqh); CRITICAL | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-120 / J-075 | org.apache.tomcat.embed:tomcat-embed-core 10.1.48 → 10.1.61; portal,risk | [GHSA-h792-v28v-ppgr](https://osv.dev/vulnerability/GHSA-h792-v28v-ppgr); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-121 / J-076 | org.apache.tomcat.embed:tomcat-embed-core 10.1.48 → 10.1.61; portal,risk | [GHSA-mgp5-rv84-w37q](https://osv.dev/vulnerability/GHSA-mgp5-rv84-w37q); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-122 / J-077 | org.apache.tomcat.embed:tomcat-embed-core 10.1.48 → 10.1.61; portal,risk | [GHSA-mqg3-r7h5-24x4](https://osv.dev/vulnerability/GHSA-mqg3-r7h5-24x4); CRITICAL | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-123 / J-078 | org.apache.tomcat.embed:tomcat-embed-core 10.1.48 → 10.1.61; portal,risk | [GHSA-r29c-68gh-xp6x](https://osv.dev/vulnerability/GHSA-r29c-68gh-xp6x); CRITICAL | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-124 / J-079 | org.apache.tomcat.embed:tomcat-embed-core 10.1.48 → 10.1.61; portal,risk | [GHSA-rv64-5gf8-9qq8](https://osv.dev/vulnerability/GHSA-rv64-5gf8-9qq8); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-125 / J-080 | org.apache.tomcat.embed:tomcat-embed-core 10.1.48 → 10.1.61; portal,risk | [GHSA-x4m4-345f-5h5g](https://osv.dev/vulnerability/GHSA-x4m4-345f-5h5g); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-126 /  | org.assertj:assertj-core 3.27.6 → 3.27.7; gateway,portal,risk | [GHSA-rqfh-9r24-8c9r](https://osv.dev/vulnerability/GHSA-rqfh-9r24-8c9r); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-127 / J-081 | org.bouncycastle:bcprov-jdk18on 1.80.2 → 1.86; gateway | [GHSA-9pwp-9qqc-pr26](https://osv.dev/vulnerability/GHSA-9pwp-9qqc-pr26); CRITICAL | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-128 / J-082 | org.bouncycastle:bcprov-jdk18on 1.80.2 → 1.86; gateway | [GHSA-qp49-qgx5-5m26](https://osv.dev/vulnerability/GHSA-qp49-qgx5-5m26); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-129 /  | org.keycloak:keycloak-services 26.7.0 → 26.7.0; spi | [GHSA-4gv3-mc9p-5wqc](https://osv.dev/vulnerability/GHSA-4gv3-mc9p-5wqc); CRITICAL | **BLOCKED**; Vendor fixes include 26.7.2. User explicitly forbids server upgrade in PD-02-02. SPI provided version and server image stay 26.7.0; no flow workaround or waiver is assumed. |
| JD-130 / J-083 | org.springframework.boot:spring-boot 3.5.7 → 3.5.16; gateway,portal,risk | [GHSA-wwpq-f5c3-7hvx](https://osv.dev/vulnerability/GHSA-wwpq-f5c3-7hvx); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-131 / J-084 | org.springframework.boot:spring-boot-autoconfigure 3.5.7 → 3.5.16; gateway,portal,risk | [GHSA-ggg2-9786-hwc8](https://osv.dev/vulnerability/GHSA-ggg2-9786-hwc8); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-132 /  | org.springframework.boot:spring-boot-devtools 3.5.7 → 3.5.16; portal | [GHSA-56v8-86gj-66jp](https://osv.dev/vulnerability/GHSA-56v8-86gj-66jp); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-133 /  | org.springframework.boot:spring-boot-starter-actuator 3.5.7 → 3.5.16; risk | [GHSA-8hfc-fq58-r658](https://osv.dev/vulnerability/GHSA-8hfc-fq58-r658); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-134 /  | org.springframework.boot:spring-boot-starter-actuator 3.5.7 → 3.5.16; risk | [GHSA-mgvc-8q2h-5pgc](https://osv.dev/vulnerability/GHSA-mgvc-8q2h-5pgc); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-135 / J-085 | org.springframework.data:spring-data-commons 3.5.5 → 3.5.13; portal,risk | [GHSA-5m4m-73w9-8433](https://osv.dev/vulnerability/GHSA-5m4m-73w9-8433); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-136 / J-086 | org.springframework.data:spring-data-commons 3.5.5 → 3.5.13; portal,risk | [GHSA-5vpf-xvv7-c8vh](https://osv.dev/vulnerability/GHSA-5vpf-xvv7-c8vh); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-137 / J-087 | org.springframework.data:spring-data-commons 3.5.5 → 3.5.13; portal,risk | [GHSA-88fw-v6x4-3f58](https://osv.dev/vulnerability/GHSA-88fw-v6x4-3f58); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-138 / J-088 | org.springframework.data:spring-data-commons 3.5.5 → 3.5.13; portal,risk | [GHSA-9fw2-h3hf-293r](https://osv.dev/vulnerability/GHSA-9fw2-h3hf-293r); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-139 / J-089 | org.springframework.data:spring-data-keyvalue 3.5.5 → 3.5.13; risk | [GHSA-xg2j-3hj6-pc24](https://osv.dev/vulnerability/GHSA-xg2j-3hj6-pc24); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-140 / J-090 | org.springframework.security:spring-security-core 6.5.6 → 6.5.11; gateway,portal,risk | [GHSA-vxf7-qj7q-83fh](https://osv.dev/vulnerability/GHSA-vxf7-qj7q-83fh); LOW | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-141 / J-091 | org.springframework.security:spring-security-core 6.5.6 → 6.5.11; gateway,portal,risk | [GHSA-x2wq-9x2f-fhj7](https://osv.dev/vulnerability/GHSA-x2wq-9x2f-fhj7); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-142 / J-092 | org.springframework.security:spring-security-oauth2-jose 6.5.6 → 6.5.11; gateway,portal,risk | [GHSA-cvc6-q2cp-2xhw](https://osv.dev/vulnerability/GHSA-cvc6-q2cp-2xhw); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-143 / J-093 | org.springframework.security:spring-security-web 6.5.6 → 6.5.11; gateway,portal,risk | [GHSA-293q-567p-wmwq](https://osv.dev/vulnerability/GHSA-293q-567p-wmwq); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-144 / J-094 | org.springframework.security:spring-security-web 6.5.6 → 6.5.11; gateway,portal,risk | [GHSA-mf92-479x-3373](https://osv.dev/vulnerability/GHSA-mf92-479x-3373); CRITICAL | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-145 / J-095 | org.springframework.security:spring-security-web 6.5.6 → 6.5.11; gateway,portal,risk | [GHSA-x2r2-rvhq-2mqv](https://osv.dev/vulnerability/GHSA-x2r2-rvhq-2mqv); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-146 / J-096 | org.springframework:spring-core 6.2.12 → 6.2.19; gateway,portal,risk | [GHSA-659m-px2c-25wj](https://osv.dev/vulnerability/GHSA-659m-px2c-25wj); LOW | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-147 / J-097 | org.springframework:spring-expression 6.2.12 → 6.2.19; gateway,portal,risk | [GHSA-9f52-rjqv-25qv](https://osv.dev/vulnerability/GHSA-9f52-rjqv-25qv); LOW | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-148 / J-098 | org.springframework:spring-expression 6.2.12 → 6.2.19; gateway,portal,risk | [GHSA-r5w3-xv2f-j59q](https://osv.dev/vulnerability/GHSA-r5w3-xv2f-j59q); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-149 / J-099 | org.springframework:spring-expression 6.2.12 → 6.2.19; gateway,portal,risk | [GHSA-wxpp-56q6-5pcg](https://osv.dev/vulnerability/GHSA-wxpp-56q6-5pcg); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-150 / J-100 | org.springframework:spring-web 6.2.12 → 6.2.19; gateway,portal,risk | [GHSA-7m2p-62gw-p8qq](https://osv.dev/vulnerability/GHSA-7m2p-62gw-p8qq); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-151 / J-101 | org.springframework:spring-webflux 6.2.12 → 6.2.19; gateway | [GHSA-4773-3jfm-qmx3](https://osv.dev/vulnerability/GHSA-4773-3jfm-qmx3); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-152 / J-102 | org.springframework:spring-webflux 6.2.12 → 6.2.19; gateway | [GHSA-4hfh-6x8g-gwpp](https://osv.dev/vulnerability/GHSA-4hfh-6x8g-gwpp); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-153 / J-103 | org.springframework:spring-webflux 6.2.12 → 6.2.19; gateway | [GHSA-5843-p793-ghmm](https://osv.dev/vulnerability/GHSA-5843-p793-ghmm); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-154 / J-104 | org.springframework:spring-webflux 6.2.12 → 6.2.19; gateway | [GHSA-6hcq-hmm3-jj3c](https://osv.dev/vulnerability/GHSA-6hcq-hmm3-jj3c); LOW | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-155 / J-105 | org.springframework:spring-webflux 6.2.12 → 6.2.19; gateway | [GHSA-6p4f-wcwh-5vvm](https://osv.dev/vulnerability/GHSA-6p4f-wcwh-5vvm); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-156 / J-106 | org.springframework:spring-webflux 6.2.12 → 6.2.19; gateway | [GHSA-72pg-x5f8-j25j](https://osv.dev/vulnerability/GHSA-72pg-x5f8-j25j); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-157 / J-107 | org.springframework:spring-webflux 6.2.12 → 6.2.19; gateway | [GHSA-83f7-v6px-pp3h](https://osv.dev/vulnerability/GHSA-83f7-v6px-pp3h); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-158 / J-108 | org.springframework:spring-webflux 6.2.12 → 6.2.19; gateway | [GHSA-9qf2-26p9-2q2q](https://osv.dev/vulnerability/GHSA-9qf2-26p9-2q2q); CRITICAL | **NOT APPLICABLE**; NOT APPLICABLE to configured source: no WebFlux functional header-predicate endpoint. Gateway is Reactor Netty/Spring Cloud RouteLocator; Portal/Risk use JSON MVC controllers, not that deployment combination. |
| JD-159 / J-109 | org.springframework:spring-webflux 6.2.12 → 6.2.19; gateway | [GHSA-cjpg-rgq5-fr37](https://osv.dev/vulnerability/GHSA-cjpg-rgq5-fr37); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-160 / J-110 | org.springframework:spring-webflux 6.2.12 → 6.2.19; gateway | [GHSA-h3qp-gqrc-q736](https://osv.dev/vulnerability/GHSA-h3qp-gqrc-q736); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-161 / J-111 | org.springframework:spring-webflux 6.2.12 → 6.2.19; gateway | [GHSA-j9f9-w8pj-32f8](https://osv.dev/vulnerability/GHSA-j9f9-w8pj-32f8); CRITICAL | **NOT APPLICABLE**; NOT APPLICABLE to configured source: no Spring SSE endpoint with fragment/view rendering. REST JSON handlers and Gateway proxy routes do not use SSE view fragments. |
| JD-162 / J-112 | org.springframework:spring-webflux 6.2.12 → 6.2.19; gateway | [GHSA-mq64-j8f9-9gcj](https://osv.dev/vulnerability/GHSA-mq64-j8f9-9gcj); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-163 / J-113 | org.springframework:spring-webflux 6.2.12 → 6.2.19; gateway | [GHSA-wg35-8jpf-2xv3](https://osv.dev/vulnerability/GHSA-wg35-8jpf-2xv3); LOW | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-164 / J-114 | org.springframework:spring-webflux 6.2.12 → 6.2.19; gateway | [GHSA-x23c-287f-qqv5](https://osv.dev/vulnerability/GHSA-x23c-287f-qqv5); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-165 / J-115 | org.springframework:spring-webmvc 6.2.12 → 6.2.19; portal,risk | [GHSA-3chg-m5w7-qfv5](https://osv.dev/vulnerability/GHSA-3chg-m5w7-qfv5); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-166 / J-116 | org.springframework:spring-webmvc 6.2.12 → 6.2.19; portal,risk | [GHSA-4773-3jfm-qmx3](https://osv.dev/vulnerability/GHSA-4773-3jfm-qmx3); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-167 / J-117 | org.springframework:spring-webmvc 6.2.12 → 6.2.19; portal,risk | [GHSA-6hcq-hmm3-jj3c](https://osv.dev/vulnerability/GHSA-6hcq-hmm3-jj3c); LOW | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-168 / J-118 | org.springframework:spring-webmvc 6.2.12 → 6.2.19; portal,risk | [GHSA-6p4f-wcwh-5vvm](https://osv.dev/vulnerability/GHSA-6p4f-wcwh-5vvm); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-169 / J-119 | org.springframework:spring-webmvc 6.2.12 → 6.2.19; portal,risk | [GHSA-72pg-x5f8-j25j](https://osv.dev/vulnerability/GHSA-72pg-x5f8-j25j); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-170 / J-120 | org.springframework:spring-webmvc 6.2.12 → 6.2.19; portal,risk | [GHSA-957g-f97v-vppc](https://osv.dev/vulnerability/GHSA-957g-f97v-vppc); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-171 / J-121 | org.springframework:spring-webmvc 6.2.12 → 6.2.19; portal,risk | [GHSA-cjpg-rgq5-fr37](https://osv.dev/vulnerability/GHSA-cjpg-rgq5-fr37); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-172 / J-122 | org.springframework:spring-webmvc 6.2.12 → 6.2.19; portal,risk | [GHSA-h3qp-gqrc-q736](https://osv.dev/vulnerability/GHSA-h3qp-gqrc-q736); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-173 / J-123 | org.springframework:spring-webmvc 6.2.12 → 6.2.19; portal,risk | [GHSA-j9f9-w8pj-32f8](https://osv.dev/vulnerability/GHSA-j9f9-w8pj-32f8); CRITICAL | **NOT APPLICABLE**; NOT APPLICABLE to configured source: no Spring SSE endpoint with fragment/view rendering. REST JSON handlers and Gateway proxy routes do not use SSE view fragments. |
| JD-174 / J-124 | org.springframework:spring-webmvc 6.2.12 → 6.2.19; portal,risk | [GHSA-mq64-j8f9-9gcj](https://osv.dev/vulnerability/GHSA-mq64-j8f9-9gcj); MODERATE | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-175 / J-125 | org.springframework:spring-webmvc 6.2.12 → 6.2.19; portal,risk | [GHSA-pc63-qcmh-9cmg](https://osv.dev/vulnerability/GHSA-pc63-qcmh-9cmg); CRITICAL | **NOT APPLICABLE**; NOT APPLICABLE to configured source: no XsltView/resolver or catch-all route resolving attacker-selected view names; Portal/Risk controllers return JSON ResponseEntity. |
| JD-176 / J-126 | org.springframework:spring-webmvc 6.2.12 → 6.2.19; portal,risk | [GHSA-wg35-8jpf-2xv3](https://osv.dev/vulnerability/GHSA-wg35-8jpf-2xv3); LOW | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |
| JD-177 / J-127 | org.springframework:spring-webmvc 6.2.12 → 6.2.19; portal,risk | [GHSA-x23c-287f-qqv5](https://osv.dev/vulnerability/GHSA-x23c-287f-qqv5); HIGH | **FIXED**; Affected coordinate removed/replaced by the patched resolved dependency graph; current OSV query no longer matches it. New regression results verify this source build, not exploit reproduction or deployment. |

## Appendix — source/build/test manifest

| File | SHA-256 sau remediation |
|---|---|
| [ci.yml](../../../.github/workflows/ci.yml) | `6515d221361d4cb4960e92016e36d1298345e8a5759b9e40de2cd8e0ce1c6893` |
| [.node-version](../../../.node-version) | `9185b9f67843cabfa8054f65ce47ce0b52036b0bfe07ae5a6b834d97cc127140` |
| [pom.xml](../../../pom.xml) | `f8cbc823f9e34b1ca8fd6376439bae4c0866ea409bc5c64464ec9253cf68744d` |
| [pom.xml](../../../gateway/pom.xml) | `96b3f829a0ca8d0ec2e819e73330114548f6a09011de670ab054221f0c58852e` |
| [pom.xml](../../../risk-scoring-service/pom.xml) | `f10a90e9b31b1e84ac5aaecb08261eb3cef5df644b5d78a03f1b38f4adbfa29d` |
| [package.json](../../../frontend/package.json) | `3a4586fe173dc681e95f79e4d65d39d7522dcbbe7fa2830b76ebb24028b312a3` |
| [package-lock.json](../../../frontend/package-lock.json) | `d8f02bfdf4aad2e58c6d7ffd7650a35e99ccf5da34c29e29be6f8dc1ff0e8d66` |
| [Dockerfile.java](../../../deploy/docker/Dockerfile.java) | `f34ccd1e50fe581f9b68b7c632feabed96479795f8b392a958aa5a6e456d9a6d` |
| [Dockerfile.keycloak](../../../deploy/docker/Dockerfile.keycloak) | `04ff7f22284bc56332546b3b7ec1b0441989eb42825d794bf624f0b1f474b457` |
| [Dockerfile.frontend](../../../deploy/docker/Dockerfile.frontend) | `2e4899728925bf38c3d4e340c920822f8e41d8257d1d77bd6f35580e04c4fe87` |
| [Dockerfile.tools](../../../deploy/docker/Dockerfile.tools) | `e5a64333681e50a67c2ac5f65832ea4e0a024517a6f4d2b66b6f1f38cfcf93ab` |
| [V5ChecksumContractTest.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/migration/V5ChecksumContractTest.java) | `93219575488e8f383a88d127c4a2219986686ee772a0e85487c94cbe40b20adb` |

## Appendix — npm historical crosswalk

| Historical ID | Package / baseline → current | Advisory | Kết quả |
|---|---|---|---|
| N-001 | brace-expansion: 1.1.18, 5.0.9 → 1.1.21,5.0.12 | GHSA-q2hr-2g5m-vwhr | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-002 | brace-expansion: 1.1.18, 5.0.9 → 1.1.21,5.0.12 | GHSA-q2hr-2g5m-vwhr | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-003 | brace-expansion: 1.1.18, 5.0.9 → 1.1.21,5.0.12 | GHSA-qhr7-859c-m2p7 | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-004 | brace-expansion: 1.1.18, 5.0.9 → 1.1.21,5.0.12 | GHSA-qhr7-859c-m2p7 | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-005 | brace-expansion: 1.1.18, 5.0.9 → 1.1.21,5.0.12 | GHSA-6j4f-fj2g-mc7p | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-006 | brace-expansion: 1.1.18, 5.0.9 → 1.1.21,5.0.12 | GHSA-6j4f-fj2g-mc7p | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-007 | js-yaml: 4.3.1 → 4.3.2 | GHSA-2883-xcg3-v3hh | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-008 | minimatch: 10.2.6, 3.1.5 → 10.2.6,3.1.5 | GHSA-g3hv-75wg-m249 | NOT VERIFIED; dev/build only |
| N-009 | next: 16.2.6 → 16.4.5 | GHSA-6gpp-xcg3-4w24 | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-010 | next: 16.2.6 → 16.4.5 | GHSA-m99w-x7hq-7vfj | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-011 | next: 16.2.6 → 16.4.5 | GHSA-89xv-2m56-2m9x | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-012 | next: 16.2.6 → 16.4.5 | GHSA-68g3-v927-f742 | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-013 | next: 16.2.6 → 16.4.5 | GHSA-4633-3j49-mh5q | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-014 | next: 16.2.6 → 16.4.5 | GHSA-4c39-4ccg-62r3 | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-015 | next: 16.2.6 → 16.4.5 | GHSA-p9j2-gv94-2wf4 | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-016 | next: 16.2.6 → 16.4.5 | GHSA-q8wf-6r8g-63ch | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-017 | next: 16.2.6 → 16.4.5 | GHSA-955p-x3mx-jcvp | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-018 | next: 16.2.6 → 16.4.5 | GHSA-p293-qw3h-jr36 | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-019 | next: 16.2.6 → 16.4.5 | GHSA-2xp9-vwfh-vxw4 | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-020 | next: 16.2.6 → 16.4.5 | GHSA-vcvr-r3jv-pc5j | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-021 | next: 16.2.6 → 16.4.5 | GHSA-4jqv-mc3x-m676 | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-022 | next: 16.2.6 → 16.4.5 | GHSA-39w2-rjm5-chcv | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-023 | next: 16.2.6 → 16.4.5 | GHSA-f87g-xv8r-7p7x | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-024 | next: 16.2.6 → 16.4.5 | GHSA-mcj8-r9mp-w47p | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-025 | next: 16.2.6 → 16.4.5 | GHSA-cjq9-62q9-8jv4 | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-026 | next: 16.2.6 → 16.4.5 | GHSA-2464-fhr4-w9xw | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-027 | next: 16.2.6 → 16.4.5 | GHSA-p3m5-59mp-jv5r | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-028 | next: 16.2.6 → 16.4.5 | GHSA-673q-mjm6-r5xr | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-029 | postcss: 8.4.31, 8.5.26 → 8.5.23,8.5.26 | GHSA-qx2v-qp2m-jg93 | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-030 | postcss: 8.4.31, 8.5.26 → 8.5.23,8.5.26 | GHSA-6g55-p6wh-862q | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-031 | postcss: 8.4.31, 8.5.26 → 8.5.23,8.5.26 | GHSA-fxqj-rqcc-2cmp | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-032 | postcss: 8.4.31, 8.5.26 → 8.5.23,8.5.26 | GHSA-r28c-9q8g-f849 | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-033 | sharp: 0.34.5 → 0.35.5 | GHSA-f88m-g3jw-g9cj | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-034 | sharp: 0.34.5 → 0.35.5 | GHSA-rgj7-g3m4-5g8c | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-035 | sharp: 0.34.5 → 0.35.5 | GHSA-wq5f-xc86-pv6w | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-036 | source-map-js: 1.2.1 → 1.2.2 | GHSA-68fv-2mgg-jv7q | FIXED; coordinate/remediation verified by final npm audit and new build/tests |
| N-037 | zod: 4.4.3 → 4.6.7 | GHSA-mrhx-c7xc-m3w5 | FIXED; coordinate/remediation verified by final npm audit and new build/tests |

Header regression source: [FrameworkResponseHeadersTest.java](../../../src/test/java/com/zerotrust/zerotrust/config/FrameworkResponseHeadersTest.java), SHA-256 `710909c82e642b0427dacfb9729b6f5054c1306bf88c7ff38eff102ce1208491`.
