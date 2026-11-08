# PD-02-03 — Public Demo fail-fast data & configuration

Evidence ID **EV-PD-02-03-01**; ngày **06/11/2026, GMT+7**.
Canonical working tree trên branch `zerotrust-v4-risk-scoring`, base HEAD
`c401e17029d64f9a96738d845b8c0ad0f03fc164`; chưa commit/push/deploy.

**Task PASS trong phạm vi source/config và kiểm thử cô lập được giao.** Không phải
MySQL/TLS/grants LIVE VERIFIED. PR-002/PR-011 vẫn OPEN; G2/G4 PARTIAL; NO-GO public.
Tiến độ duy nhất ở [Master Roadmap](../PUBLIC_DEMO_ROADMAP.md).

## 1. Baseline đã đối chiếu

Đã đọc toàn bộ roadmap PD-R3, task/acceptance PD-02-03, PR-002/011, G2/G4, evidence
PD-02-01/02, quyết định approved/pending, source properties/profiles/environment binding,
main entry points, POMs, canonical Docker entrypoint và các generator DB School/Risk/Keycloak.
Baseline Git HEAD như trên, working tree chứa đầy đủ thay đổi chưa commit của các task trước.
Hash inventory đầu task gồm **653 files** tracked/untracked không ignored; 10 Lab containers
đều exited theo selected metadata. Không đọc/ghi DB/Redis/realm hoặc dùng secrets Lab.

| Baseline | Rủi ro với Public Demo | Xử lý trong task |
|---|---|---|
| Portal base URL localhost/vip_pro, root, createDatabaseIfNotExist/useSSL=false, ddl update | Profile prod trước đây chỉ bắt issuer/JWKS/CORS; DB có thể kế thừa Lab defaults | Giữ default Lab; launcher production từ chối effective defaults, thêm profile Public Demo riêng |
| Risk base URL localhost/risk_db, root, secret blank, Flyway startup bật | App runtime có thể tạo/migrate DB bằng quyền không phù hợp | Public Demo validate-only, runtime Flyway off, credentials riêng, pool writable |
| PD-02-01 mode/filter | Đã deny academic writes, chưa có DB fail-fast | Giữ nguyên Java/filter/controllers/tests; mở rộng hai resource properties cần cho contract |
| Lab/demo generators | Có TLS và account/schema riêng theo mục đích Lab, không là Public Demo release inputs | Không sửa/chạy generator hoặc manifest Lab; không tái sử dụng private generated config |
| Keycloak26.7.0 / Spring train | D-15/D-16 pending, PD-02-02 PARTIAL | Không đổi server/platform, không waiver các dependency blockers |
| Risk V5 | Exact MySQL8.0.46 guard, checksum661092940 | Không sửa SQL/Java migrations/helper/history/version guard; D-14 vẫn pending |

## 2. Production configuration contract

[Contract cho operator/release](../../../deploy/public-demo/README.md) và
[configuration fragment](../../../deploy/public-demo/configuration-contract.json) là nguồn cấu hình;
không phải manifest hoàn chỉnh hay tracker khác.

Canonical `main` của Portal/Risk đăng ký `PublicDemoStartupInitializer`. Check chạy trên
**effective Spring Environment sau ConfigData, trước bean creation và DB I/O**. Mode được
kiểm độc lập tên profile; `prod`, `production`, `public-demo` buộc strict path ngay cả khi
thiếu mọi mode/read-only marker. Không có cờ tắt guard, H2 exception hoặc test-profile bypass
trong launcher. Các test context component cũ không gọi `main` tiếp tục kiểm scope hẹp của nó.

Contract giữ `PUBLIC_DEMO_MODE=public-demo`, `PUBLIC_DEMO_ACADEMIC_READ_ONLY=true` và thêm
`PUBLIC_DEMO_ENVIRONMENT=staging|production`. Schema/user bắt buộc là
`pd_<environment>_school` / `pd_<environment>_school_runtime`, tương ứng `_risk` cho Risk.
Đây là namespace isolation contract, không chọn/nâng/hạ engine. Reject schema/user Lab,
root, migrator/provisioner identity. Secret phải resolve, không blank và ít nhất16 ký tự.

| Effective setting | Public Demo bắt buộc |
|---|---|
| Datasource | Explicit single-host MySQL URL, đúng namespace, runtime user/secret riêng |
| TLS URL | `sslMode=VERIFY_IDENTITY`; chỉ thêm UTC/UTF-8 và bounded positive connection/socket timeout options |
| Hibernate | ddl-auto validate; generate-ddl false; SQL display false; không property override DDL |
| Initialization | SQL init never; Flyway/Liquibase false; không migration credentials trong runtime |
| Pool | Portal read-only true + actual-grant startup guard; Risk read-only false |
| Alternate settings | Không JNDI/custom driver/custom datasource/Hikari URL/user/password/init SQL hoặc driver property override |
| Portal security config | HTTPS issuer/JWKS/IdP/Risk/token endpoints, HTTPS CORS origin, service secrets |
| Risk security config | HTTPS issuer/JWKS; require-https; server TLS keystore/secret/alias; Redis TLS/password; existing peppers |

`VERIFY_IDENTITY` kiểm CA và hostname theo [MySQL Connector/J](https://dev.mysql.com/doc/connector-j/en/connector-j-connp-props-security.html).
Không coi URL parser là TLS handshake hoặc proof CA/SAN của server thật. Trust material phải
fresh, cấu hình qua JVM truststore; không mở JDBC trust bypass để làm test xanh.

## 3. Cấu hình không an toàn bị từ chối

- Missing/unresolved URL, username, DB secret, selector/read-only flag, isolation environment
  hoặc mandatory service secret/security endpoint.
- root/Lab/schema hoặc migrator/provisioner account, localhost/127.x/known Lab host/schema,
  H2, alternate/load-balanced JDBC form trong production launcher.
- TLS disabled/PREFERRED/REQUIRED/VERIFY_CA, legacy useSSL, public-key retrieval, database
  auto-create; credential/session SQL/custom socket/deserialize parameters; encoded/duplicate options.
- ddl update/create-drop, generate-ddl true, SQL seed always, startup Flyway/Liquibase,
  migration credentials, Hibernate/JPA DDL overrides và Hikari URL/property/camel-case alias bypass.
- Read-only pool ở Risk; writable pool ở Portal. HTTP identity config, Redis plaintext/blank
  credentials hoặc thiếu Risk TLS keystore secret.

Default Lab values giữ nguyên; production path chủ động reject chúng. Profile `prod` nay
không còn là cách chạy Public Demo mà bỏ mode/DB contract. Các private Lab config từng sinh
với label prod không phải release input, không được launch lại bằng đường Production mới.
Không restart/rebuild/reconfigure Lab trong task này.

## 4. Application/database account separation và startup grants

Portal runtime chỉ SELECT đúng5 bảng School. Migrator chạy schema/ledger và synthetic
provisioner chạy seed/crosswalk qua quy trình private riêng; hai credentials này không mount
vào runtime. Không thêm installer SQL hoặc job seed chạy tự động trong task.

`PublicDemoSchoolDatabaseVerifier` được launcher đăng ký như `SmartInitializingSingleton`:
trước readiness, kiểm actual catalog, MySQL product, effective CURRENT_USER runtime identity, session SSL cipher và SHOW GRANTS của
CURRENT_USER. Chỉ cho USAGE + SELECT từng bảng `users/students/student_classes/subjects/scores`.
Reject DML/DDL/global/schema-wide privilege, role, GRANT OPTION, extra table, thiếu SELECT,
unknown grant format hoặc metadata query failure. Chỉ gọi read-only metadata SQL, không thử ghi.
Unknown format fail-closed phải được review trong real-engine acceptance, không tự nới parser.

Risk runtime tiếp tục writable, schema do installer riêng chuẩn bị; không chặn evaluation,
history/trusted-device/revocation/event/counter APIs. Exact Risk DML grants và Keycloak
session/credential/MFA grants cần nghiệm thu theo schema thật ở downstream tasks.
Không lấy pool hint hoặc annotation transaction làm proof database authorization.

Keycloak source fragment yêu cầu URL TLS, runtime identity riêng, private complete
`keycloak.conf` secret và `migration-strategy=validate`, `initialize-empty=false` cho quarkus
JPA provider. Installer/provisioner độc lập chuẩn bị schema/realm synthetic. Theo
[vendor database contract](https://www.keycloak.org/server/db), [provider options](https://www.keycloak.org/server/all-provider-config)
và [CLI config-file syntax](https://www.keycloak.org/server/configuration).
Chưa chạy server26.7.0 hay chứng minh custom-extension/schema behavior; không upgrade server.

## 5. Deployment-layer omission protection

Fragment pin profile/mode/read-only cả environment và Java launch arguments, dùng đường
`/run/public-demo` riêng. [Preflight](../../../scripts/public_demo/validate_configuration.py)
đọc final rendered Compose JSON qua stdin, không đọc secret files hoặc xuất values.
Reject thiếu từng marker và **thiếu toàn bộ markers**, service thiếu, root/unsafe URL,
environment mismatch, thiếu secret target, inline secret hoặc command/entrypoint override.
Keycloak schema strategy/empty initialization cũng được kiểm.

Fragment chưa có images/resources/secret mounts/endpoints đầy đủ; test chứng minh fragment
chưa render **không được chấp nhận** làm deployment. Final manifest phải merge/pin và chạy
preflight ở PD-03-03/04. Xóa toàn bộ contract/preflight và launch app như Lab không thể được
suy ra bằng ý định; bảo vệ tầng manifest là prerequisite release cần kiểm trực tiếp ở03/04.
Không khai báo actual manifest acceptance hoặc deployment contract đã LIVE VERIFIED.

## 6. Negative configuration tests và lệnh đã chạy

JDK **Temurin17.0.21+9**, Maven Wrapper3.9.16; process-local JAVA_HOME/Path, không đổi toolchain
global. Đã chạy targeted rồi full verify trên dependency candidate PD-02-02 hiện hành:

```powershell
$env:JAVA_HOME=(Resolve-Path 'target\pd-02-02\toolchain\jdk\jdk-17.0.21+9').Path
$env:Path="$env:JAVA_HOME\bin;$env:Path"
.\mvnw.cmd --batch-mode --no-transfer-progress '-Dtest=PublicDemoStartupConfigurationTest,PublicDemoSchoolDatabaseVerifierTest' test
.\mvnw.cmd --batch-mode --no-transfer-progress -f risk-scoring-service\pom.xml '-Dtest=PublicDemoStartupConfigurationTest,V5ChecksumContractTest' test
.\mvnw.cmd --batch-mode --no-transfer-progress -f pom.xml verify
.\mvnw.cmd --batch-mode --no-transfer-progress -f risk-scoring-service\pom.xml verify
.\mvnw.cmd --batch-mode --no-transfer-progress -f gateway\pom.xml verify
.\mvnw.cmd --batch-mode --no-transfer-progress -f keycloak-risk-extension\pom.xml verify
python -X utf8 -m unittest discover -s scripts/public_demo -p 'test_*.py' -v
```

Portal/Risk verify chạy lại sau module-specific cleanup/probe tests và positive configtree binding tests; bảng dưới lấy **final run**,
không cộng các lần chạy trùng. Python final run10 PASS; subtests không tính thành test độc lập.

| Yêu cầu | Bằng chứng mới, controlled offline |
|---|---|
| Valid context | Actual ConfigData + initializer + DataSourceProperties binding + mounted configtree secret + JDBC mocks; Portal metadata mock pass, Risk pool writable |
| Missing URL/user/password | Từng environment variable vắng hẳn và effective property blank bị reject |
| Root/unsafe TLS/DDL/create DB | Negative parameterized effective overrides và JDBC parser cases |
| Missing read-only, missing profile/markers | Negative launcher tests; canonical main prod với mọi marker absent bị reject |
| Default Lab | Runner load base properties vẫn root/update Portal, root/validate/Flyway true Risk; initializer không thay Lab |
| Risk writes | Public Demo valid config nhận pool read-only false; true bị reject; full existing Risk write/lifecycle regression pass |
| No secret in errors/logs | CapturedOutput canonical-main tests, credential-bearing malicious URL, pool/migrator override; SQL exception sanitized/no chained cause; CLI malformed JSON/URL secret redaction |
| Pre-bean failure | Negative effective overrides có initialization probe=0; không tạo bean/DB connection |
| Not H2=production | H2 URL bị reject bởi launcher; valid context dùng mocked MySQL metadata, không actual MySQL |
| SELECT-only guard |19 parser/JDBC-mock cases; extra DML/DDL/role/global/schema/unknown grants, missing table, wrong engine/catalog/current account/TLS and query failure |

Main-path negative tests còn exclude DB/Redis auto-config như lớp cô lập bổ sung nếu launcher
regression. Không gọi Lab ngay cả để chứng minh rejection. Một compile error ban đầu do tên
AssertJ assertion chưa có đã được sửa; final tests chạy thật đạt, không disable/skip assertions.

## 7. Final regression results

| Suite | Total | PASS | FAIL / errors | SKIPPED | Final finish GMT+7 |
|---|---:|---:|---:|---:|---|
| Portal,48 classes |512|512|0 / 0|0|14:52:26|
| Risk,65 classes |787|691|0 / 0|96|14:47:05|
| Gateway,3 classes |20|20|0 / 0|0|14:37:44|
| SPI,26 classes |203|176|0 / 0|27|14:37:55|
| **Java tổng** |**1.522**|**1.399**|**0 / 0**|**123**|06/11/2026|
| Deployment config Python |10|10|0 / 0|0|06/11/2026|

New Java tests **169**: Portal startup73 + School metadata/grants19; Risk startup77.
Portal512 bao gồm **90 PD-02-01 tests vẫn PASS** và3 response-header tests PD-02-02;
Risk787 bao gồm V5 checksum test1 PD-02-02 PASS. Không cộng lại vào totals.
Full suites giữ authorization ADMIN/STUDENT/ownership, signed-JWT validation, School
persistence, B0 policy/mandatory/priority/fail-closed và MFA/trusted-device caller/lifecycle contracts.

123 skips vẫn là opt-in external QA/integration: Risk HTTP43/MySQL4/Redis30/postfix gateB3/native16,
SPI QA27. Không bật để chạm Lab, không tính PASS. Collector chỉ tổng hợp classes có `Running`
trong log final run, không lấy historical ControlledStudyExperiment XML còn ở target.
Remote CI/frontend/image build không chạy trong task; Python preflight integration vào final release pipeline còn PD-03-03/04.
JUnit XML/log local nằm `target/pd-02-03` + module surefire reports; không là release artifacts.

## 8. Migration safety và giới hạn chưa kiểm chứng

V5ChecksumContractTest tiếp tục PASS **661092940**; bốn compiled V5/helper class SHA-256 giống
PD-02-02 byte-for-byte. SQLV1–V4, JavaV5/helper, version guard và Flyway history không sửa.
Không chọn MySQL engine/version hoặc chạy installer/migration/repair trên DB thật.

H2 regression chứng minh mapping/logic trong test environment; mock JDBC chứng minh guard
behavior theo metadata giả. Chưa có MySQL SELECT-only grants, TLS handshake/CA/SAN, server-side
REQUIRE SSL, real schema validation, DB fresh install/upgrade/partial-DDL recovery hoặc Risk
runtime writes trên MySQL Public Demo. Không LIVE VERIFIED bất kỳ mục nào trong số đó.
Không browser OIDC/OTP/session/trust/Redis acceptance, không start/staging/production runtime,
không build/deploy Docker images trong task. Frontend/native/image scans PD-02-02 là historical,
không chạy lại hoặc lấy làm acceptance mới. D-15/D-16 và dependency blockers giữ nguyên.

## 9. Bàn giao downstream

- **PD-03-06 / D-14:** chốt supported engine/version/fresh schema/installer/ledger/V5 path;
  riêng migrator/provisioner identities; schema vs JPA validate; review Risk/Keycloak runtime
  DML grants và private host restrictions; unchanged V5/quiescence/checksum/partial-DDL restore.
- **PD-03-03/04:** hoàn chỉnh variant manifest/endpoints/secret mounts/JVM trust, integrate
  preflight trên final rendered config; test cả omission/override; exact source/image/config provenance.
- **PD-04-02:** stores mới tách Lab, synthetic only; real MySQL TLS positive/negative handshake,
  catalog/current user/effective grants/roles, SELECT reads và denied DML/DDL/seed; clean/upgrade
  schema acceptance. Verify Portal startup guard với output server thật và Risk writes hợp lệ;
  Keycloak validate/initialize-empty behavior và installer độc lập.
- **PD-05-05:** fresh final prod stores/accounts/keys/secrets, không reuse Lab/staging; mount
  runtime-only credentials, no migration/seed credentials; effective config/grants/TLS trước
  readiness. Recheck exact final candidate tại PD-06-03/05.

PR-002 và PR-011 **OPEN**. G2 **PARTIAL — source/config slice**, G4 **PARTIAL — source/test slice**;
không đóng database gates. PD-02-02 vẫn PARTIAL. Task tiếp theo đủ dependency: **PD-02-04**,
chỉ bàn giao; không thực hiện task đó hoặc các task PD-02-05–08.

## 10. Preservation verification

Đối chiếu trước/sau và manifest ở cuối report: Git HEAD/branch giữ nguyên, không reset/stash,
stage/commit/push/deploy; 10 Lab containers vẫn exited, IDs/images/mounts/networks không đổi.
Không tạo worktree/source copy, runtime/image/volume mới, không xóa file/backup/artifact có trước.
Toàn bộ dependency/build/test files13 của PD-02-02 và hai evidence files giữ nguyên SHA-256.
PD-02-01 Java/controller/filter/config classes/tests và evidence giữ nguyên; riêng base/profile
resource properties được mở rộng có chủ đích cho PD-02-03, filter contract không đổi và90 tests
đều PASS. Historical audit/README/Observatory/presentation/unrelated files giữ nguyên.
Only5 existing source/resources +11 new source/config/test/contract files, roadmap và report
này thay đổi. Không dùng việc bảo toàn metadata để tuyên bố Lab đang healthy/live verified.

## 11. Source/config/test manifest

SHA-256 xác định đúng working-tree inputs đã kiểm thử; không là release SHA/digest.

| File | SHA-256 |
|---|---|
| [deploy/public-demo/README.md](../../../deploy/public-demo/README.md) | `282a340aedd8d90261c5a002331b47ac065c925cc7a5385e7c89769c7befec5d` |
| [deploy/public-demo/configuration-contract.json](../../../deploy/public-demo/configuration-contract.json) | `90644a110f5cef19b7730b6c5d65d775db19fd41bd05d1efbbcfef837e5e8be7` |
| [risk-scoring-service/src/main/java/com/zerotrust/risk/RiskScoringApplication.java](../../../risk-scoring-service/src/main/java/com/zerotrust/risk/RiskScoringApplication.java) | `25bbe2f5a8058cadee95183c6bfb779b8c1fe3399e23f0e58750331826f8818d` |
| [risk-scoring-service/src/main/java/com/zerotrust/risk/config/PublicDemoStartupInitializer.java](../../../risk-scoring-service/src/main/java/com/zerotrust/risk/config/PublicDemoStartupInitializer.java) | `7aeb78aa40cbd92a9e1798d70a0a130b1fc523146c777ef7aab3ae5657fb9037` |
| [risk-scoring-service/src/main/resources/application-public-demo.properties](../../../risk-scoring-service/src/main/resources/application-public-demo.properties) | `150bce21f3c752f6b954e3cf1f5cd4b48ed45c0b56c59236ec6537c73a2d47a3` |
| [risk-scoring-service/src/main/resources/application.properties](../../../risk-scoring-service/src/main/resources/application.properties) | `1a40d392aec412879f2caa66c609488baeb3d36d71e8ef758c4236273b7efd57` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/config/PublicDemoStartupConfigurationTest.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/config/PublicDemoStartupConfigurationTest.java) | `f1d5064f911bbfe551a52a51a935a9587abe2ee10e9b6e0a2c1f98a44fa94eb1` |
| [scripts/public_demo/test_configuration.py](../../../scripts/public_demo/test_configuration.py) | `f7e15a44a75852dbbd11959a6af5e2908fc482c0d4e7c03e39a17e461e5f37f8` |
| [scripts/public_demo/validate_configuration.py](../../../scripts/public_demo/validate_configuration.py) | `6ea5e905d25fa927a5bb4b72df9d8c9de380b2747716ddcdfda2abd64bb25c51` |
| [src/main/java/com/zerotrust/zerotrust/ZerotrustApplication.java](../../../src/main/java/com/zerotrust/zerotrust/ZerotrustApplication.java) | `352d488352382d9973363ee36b42a5e56b6b2d95cac384724e7b9c8f7cfd736b` |
| [src/main/java/com/zerotrust/zerotrust/config/PublicDemoSchoolDatabaseVerifier.java](../../../src/main/java/com/zerotrust/zerotrust/config/PublicDemoSchoolDatabaseVerifier.java) | `795cca2b47906c95abbca81bdde737f4f3d57241fbf1fb277160ce8ae744c3ef` |
| [src/main/java/com/zerotrust/zerotrust/config/PublicDemoStartupInitializer.java](../../../src/main/java/com/zerotrust/zerotrust/config/PublicDemoStartupInitializer.java) | `ae931dbb611654cd9c438b5fb1e455f722ab94a92482fd273a6c5ad695c3d383` |
| [src/main/resources/application-public-demo.properties](../../../src/main/resources/application-public-demo.properties) | `c3c55acab46f541f77286269ae1496b4dea0efc8c2470206769516a02af84f4b` |
| [src/main/resources/application.properties](../../../src/main/resources/application.properties) | `89775984908facf91a55c600f3c916aa3ba6f541244b099d1bdaf27a1923e25a` |
| [src/test/java/com/zerotrust/zerotrust/config/PublicDemoSchoolDatabaseVerifierTest.java](../../../src/test/java/com/zerotrust/zerotrust/config/PublicDemoSchoolDatabaseVerifierTest.java) | `671791465b35d1b874ec8f1e16a89d476c211b2722f21f1dcd67973bf0930cca` |
| [src/test/java/com/zerotrust/zerotrust/config/PublicDemoStartupConfigurationTest.java](../../../src/test/java/com/zerotrust/zerotrust/config/PublicDemoStartupConfigurationTest.java) | `ffd2d9b320aeb7b942428e739395d647b283e8c432c8c65d13e7f2ee85ecbc3b` |

V5/helper compiled hashes đối chiếu EV-PD-02-02-01, giữ nguyên:

| Class | SHA-256 |
|---|---|
| `risk-scoring-service/target/classes/db/migration/V5__isolate_subject_identity.class` | `24449acbaab162df24350998c0e8c889140ddc404594738f2f8d8dc2713d77a1` |
| `risk-scoring-service/target/classes/com/zerotrust/risk/migration/SubjectIdentityMigrationPreflight$Plan.class` | `dfa6f251de3d6579fafc7378e5a311b0f68fd271c43ee2d07903551be62f3e0f` |
| `risk-scoring-service/target/classes/com/zerotrust/risk/migration/SubjectIdentityMigrationPreflight$Snapshot.class` | `307f931418b9254194f219eaf3f62dbc81164029e3f18b92fe8973d5840bc711` |
| `risk-scoring-service/target/classes/com/zerotrust/risk/migration/SubjectIdentityMigrationPreflight.class` | `6005aeeeba2cdefc09e4a2c2daf950b5448497fa8be8111efbe40d0d3cf8b74e` |

Final preservation QA: **647/653 files có trước giữ nguyên**; đúng6 existing files thay đổi (5 source/resources + roadmap),12 files mới (11 source/config/test/contract + report),0 bị xóa;42 historical audit/evidence files,13 PD-02-02 inputs,10 PD-02-01 inputs ngoài2 resource mở rộng giữ nguyên SHA-256. HEAD/branch và10 Lab containers metadata/exited không đổi. Documentation QA:50 unique task IDs/16fields,7PASS/37TODO/1PARTIAL/5BLOCKED,18OPEN findings,16pending decisions,14approved entries,dependency DAG acyclic và68 local links hợp lệ.
