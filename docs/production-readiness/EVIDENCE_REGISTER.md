# Evidence Register

**06/11/2026, Asia/Saigon — baseline c401e17.** Không có bằng chứng được dựng để làm checklist PASS. Trạng thái Production NO-GO; [report](PRODUCTION_READINESS_REPORT.md), [findings](SECURITY_AUDIT.md), [inventory](BASELINE_INVENTORY.md).

## E01 — Git/Docker/runtime baseline

**VERIFIED metadata.** `git status --short --branch`, `git rev-parse HEAD`, `git log`, `docker version/context/ps -a`, selected container/image/network inspect; [collect_baseline.py](tools/collect_baseline.py). [baseline.json](evidence/baseline.json) ghi IDs/images/state/mounts/network/limits/user/log rotation/env names, không Config.Env values. Mười container stopped; restart=no; core internal; DB/Redis không publish. `python scripts/ops/zt.py doctor` trả0 lỗi/10 stopped warnings; `config-check` thành công. Không start/recreate canonical containers.

Git đầu audit: HEADc401e17 ahead3/upstream1c9fa97; untracked đã có hai file Observatory và presentation/. Không thay/stage chúng. Audit chỉ thêm docs/tools/evidence và link mục lục docs. [Post-check](evidence/preservation-check.json) đối chiếu cùng IDs/images/mounts/networks/stopped; không phải checksum dữ liệu DB.

## E02 — Remote/CI

**VERIFIED qua connected GitHub read-only API.** [Branch](https://github.com/NguyenTruong-An/zerotrust/tree/zerotrust-v4-risk-scoring), [remote CI run](https://github.com/NguyenTruong-An/zerotrust/actions/runs/41021344954); [sanitized result](evidence/ci-status.json). Branch remote1c9fa97/protected=false, rulesets[], head lookupc401e17 trả422/no commit; CI remote success ngày30/10 eventpush. Không dùng wrapper chỉ lọc pull_request runs để kết luận không có push CI. Không push/rerun workflow trong audit; CI logs/secret logs đầy đủ chưa được scan.

## E03 — Source/build/runtime provenance

**HISTORICAL VERIFIED build04/11 + VERIFIED hash/metadata ngày audit.** Manifest `.build-artifacts/c401e17029d6-74d896368c3a-lab/build-manifest.json`, committed_head,473 input hashes; so Git cat-file blobs khớp473/473, không so raw Windows CRLF để kết luận drift giả. Sáu image ID tồn tại và revision/snapshot labels khớp. [Sanitized build-provenance.json](evidence/build-provenance.json). Canonical candidate image IDs khác sáu build image; đều stopped nên không gọi image mới là deployed.

## E04 — Java executable suites

**TEST VERIFIED.** Git HEAD archive riêng trong ignored audit workspace; trên Windows archive có CRLF conversion, source semantics không sửa. Helper image cũ e30e722a3d86/JDK17.0.10, networknone, không canonical mounts,2CPU/3GiB/PID512. Host i5-11400H/12logicalCPU/16,89GBRAM; Docker12CPU/8,18GB. Host Java mặc định8 không phù hợp nên dùng helper có sẵn, không đổi PATH/JDK hệ thống.

`bash mvnw --batch-mode --no-transfer-progress -o -f <pom> verify` cho pom.xml, risk-scoring-service/pom.xml, keycloak-risk-extension/pom.xml, gateway/pom.xml. [test-results.json](evidence/test-results.json) giữ suite names/counts/scope. Baseline tổng1259,1136pass,123skip,0failure/error. Skip thuộc conditional diagnostics có sẵn, không bật các gate cần dữ liệu ngoài. Local verify không tương đương GitHub CI hoặc full Browser/Keycloak/MySQL acceptance.

## E05 — Frontend/tooling

**TEST VERIFIED.** Node24.16.0/npm; existing frontend dependencies. `npm.cmd run check`, test:student-scores6, test:portal-route9, `node --test scripts/observation/test_viewer.cjs`4: đạt; warning import/no-anonymous-default-export ở postcss.config.mjs,0errors. Python3.13: ops25/build5/portability3/fixtures3/observation13 =49pass. [tool-results.json](evidence/tool-results.json). Fixture tests không boot demo/seed vào Lab.

## E06 — Docker build definitions

**TEST VERIFIED build checks only.** `python scripts/build/images.py --check` cho6Dockerfiles, tất cảpassed. Check manifest/log ở ignored .build-artifacts, không publish trong report. BuildKit check không phải image scan hoặc application rebuild/deployment. Dockerfiles/pins/multi-stage/non-root review trong deploy/docker; compose.lab/dev/build/legacy được phân biệt.

## E07 — New isolated stale-score characterization

**TEST VERIFIED FAIL behavior.** [StaleScoreEditAuditTest.java](tools/StaleScoreEditAuditTest.java) chỉ copy vào isolated snapshot test folder; Maven `-Dtest=StaleScoreEditAuditTest test`,1casepass theo assertion xác nhận overwrite. H2 fixture synthetic/example.invalid, transactions độc lập mô phỏng hai HTTP saves. Midterm7→A8→staleB7/final10, version2 được chấp nhận. Không có Lab DB access. [Result](evidence/test-results.json). Fix regression tương lai phải đổi assertion thành conflict/rejection, không giữ characterization PASS làm proof fixed.

## E08 — Real Redis Lua isolated

**TEST VERIFIED.** Redis7.4.7 image có sẵn, networknone, tmpfs/tmp, readonly root/cap-drop, không publish/mount Lab. Extract nguyên text block từ RedisAuthenticationFailureStore, thực thi bằng [redis-isolated-check.sh](tools/redis-isolated-check.sh). [redis-isolated.json](evidence/redis-isolated.json):7ca firstincrement/dedup/TTL/malformed/overflow/no partial predictable writes/fixedwindow đềuPASS. Không chứng minh concurrency mọi trường hợp/Redis Cluster/AOF/TLS/restore/HA; counterAOF/memory failure cần staging.

## E09 — Source/config/architecture review

**SOURCE REVIEWED.** [Portal security](../../src/main/java/com/zerotrust/zerotrust/config/SecurityConfig.java), [Gateway](../../gateway/src/main/java/com/zerotrust/gateway/), [Risk security](../../risk-scoring-service/src/main/java/com/zerotrust/risk/config/RiskApiSecurityConfig.java), controllers/services/DTO/entities/repositories, migration SQL, SPI/authenticator/listener/client/config/trace/context, frontend lib/components, Dockerfiles/Compose/workflow/ops/backup/restore.

Trace request→security→service→client→persistence cho self profile/grades/admin score/reset và Risk evaluate/register/events/revoke/complete. Kiểm API input/bounds/caller/ownership/generation/transaction/timeouts/cookie/replay boundaries. Không phải formal proof mọi dòng code/ASVS requirement đã an toàn; business test coverage/source review không thay deployed configuration acceptance.

## E10 — Historical acceptance/docs

**HISTORICAL VERIFIED đúng ngày/phạm vi báo cáo.** [Adaptive report](../../ADAPTIVE_AUTH_ACCEPTANCE_REPORT.md), [final consolidation](../../ZEROTRUST_FINAL_CONSOLIDATION_REPORT.md), [research plan](../../TRUST_SCORE_RESEARCH_AND_EXPERIMENT_PLAN.md), [Observatory live03/11](../testing/RISK_OBSERVATORY_ACCEPTANCE_2026-11-03.md), [ops runtime04/11](../operations/CURRENT_RUNTIME.md). A1–A6/priority DENY/OTP/trust/read-only RBAC/ownership không được coi weightedHIGH/prod-domain/outage/performancePASS. Không lặp login/reset fixtures thật trong audit.

## E11 — Risk observability/lifecycle

**SOURCE/TEST REVIEWED + HISTORICAL VERIFIED một phần.** [Observatory](../testing/RISK_OBSERVATORY.md), RiskScoreTrace/RiskEvaluationTrace, DatabaseBackedRiskFeatureExtractor/calculators/lifecycle, listener/client. D/N/T/H snapshot/correlation/reason/outcome và allowlist có tests. SSO/refresh/fallback/null/conflict được phân biệt. Chưa có production retention/alerts/full durable event delivery. B0 unchanged, không dùng B1 để đạt test.

## E12 — Runtime public TLS/config

**VERIFIED offline metadata/config, không live handshake.** [inspect_runtime.py](tools/inspect_runtime.py) chạy helper cryptography có sẵn, mount runtimeRO/networknone; chỉ parse public .crt/.crl và allowlisted nonsecret settings. [runtime-public.json](evidence/runtime-public.json):17certfile/copies valid time/signature against LabCA; SANservice/localhost; leaf expiry24/01/2027; CRL signaturevalid/nextUpdate11/11/2026. JDBC VERIFY_IDENTITY/nonroot, Redis TLS/AOF everysec, Keycloak prodoptimized config. Không dump passwords/keys/truststore contents. Runtime còn stopped nên no current TLS reachability/JWT/DB permission proof.

Đọc application.jar từ **stopped canonical Risk container** bằng docker cp, không khởi động app/DB: [packaged policy](evidence/lab-risk-packaged-policy.json) xác nhận defaults B0/weights0.25/threshold40–75. Selected container env không có model/weight/threshold override; private application.properties cũng không có các override đó. Đây là configuration evidence cho lần start theo cấu hình đã inspect, không phải live scoring response. Network/GeoIP flags true, Flyway false trong container env.

## E13 — Secret patterns/ACL/backup confidentiality

**TEST VERIFIED giới hạn + SOURCE REVIEWED.** [scan_git_metadata.py](tools/scan_git_metadata.py) local reachable Git text blobs≤2MB,1186blobs,60candidates; output locations/categories only [git-secret-patterns.json](evidence/git-secret-patterns.json). Không thấy confirmed active secret từ marker/token pattern và triage candidate đang xem; fixture/label/expression không gọi leak. Không cover binary keystore/unreachable refs/full entropy scans/CI logs/image layer secrets.

Root ACL runtime/backup đã đọc, quyền operator/SYSTEM/Administrators; không đưa account identity/secret values vào evidence. Không đại diện recursive file ACL audit hoàn chỉnh. backup.py tar.gz runtime gồm authority/private material không encryption; offsite/at-rest encryption chưa có bằng chứng. Không đọc private key/password để báo cáo.

## E14 — Backup/restore hiện có

**HISTORICAL VERIFIED.** [Restore report04/11](../operations/RESTORE_VERIFICATION_REPORT.md): archiveintegrity/DBreadability, School9bảng50rows, Risk5bảng143rows, Keycloak100bảng2048rows; chỉ số aggregate lịch sử, không row cá nhân. Keycloak JGROUPS_PING/SERVER_CONFIG checksumdelta; không có snapshot lúcbackup, nguyên nhân SERVER_CONFIG chưa xác định. Rediskeyspaceempty chỉ chứng minh snapshot hiện có mở được. FullapprecoveryNOTVERIFIED. Không restore/restart DB cũ trong audit; không chạy restore_check.py vốn đọc canonical đangrunning khi Labdừng.

## E15 — Microbenchmark

**TEST VERIFIED giới hạn.** [ScoringMicrobenchmark.java](tools/ScoringMicrobenchmark.java), đúng compiled B0 RiskScoringService/currentsource;100kwarmup/1moperations mỗi concurrency1/4, networknone2CPU512MiB, heap128–256MiB, noLabmounts. [JSONL](evidence/scoring-microbenchmark.jsonl) ghi duration/p50/p95/p99/errors/processCPU/heap/GC. Pure scoring, không I/O/HTTP/full feature/auth capacity; sub-second samples có JIT/sharedsink, không JMH/statistical claim. Không load vào Lab, không real login storm.

## E16 — Dependency/security scanning

**TEST VERIFIED version/advisory matching; source applicability review.** npm audit JSON không fix; JAR inventory + Maven offline dependencytree3.8.1 cho ba executable modules, OSV querybatch/details chỉ gửi public packagecoordinates/versions. [Java evidence](evidence/java-osv.json), [npm](evidence/npm-audit.json), [per-advisory register](DEPENDENCY_FINDINGS.md). DockerScout available1.20.4 nhưng loginrequired; targetfrontend/risk không sinhSARIF. Không tự cài/đăng nhập scanner hoặc gọi CVEclean.

Primary sources tra ngày06/11: [OWASP ASVS](https://asvs.owasp.org/), [Keycloak production](https://www.keycloak.org/server/configuration-production), [reverseproxy](https://www.keycloak.org/server/reverseproxy), [MySQL release model](https://dev.mysql.com/doc/refman/9.1/en/mysql-releases.html), [Next SVG](https://github.com/vercel/next.js/security/advisories/GHSA-2464-fhr4-w9xw), [Next cache](https://github.com/vercel/next.js/security/advisories/GHSA-673q-mjm6-r5xr), [Next Windows](https://github.com/vercel/next.js/security/advisories/GHSA-p293-qw3h-jr36), [Spring headers](https://spring.io/security/cve-2026-22732/), [Spring issuer](https://spring.io/security/cve-2026-22748/), [Tomcat security](https://tomcat.apache.org/security-10.html). Vendor conditions khác scanner aggregate severity; source-based reachability là suy luận, không exploit proof.

## Các giới hạn không che giấu

**E17 — TEST VERIFIED migration characterization:** [MigrationCompatibilityAudit.java](tools/MigrationCompatibilityAudit.java) chạy compiled SubjectIdentityMigrationPreflight và V5 bằng metadata proxy MySQL8.4.13; từ chối UNREVIEWED_MYSQL_VERSION trước SQL, checksum661092940 đúng current pinned toolchain. [JSON](evidence/migration-compatibility.json). Source là [V5 Java](../../risk-scoring-service/src/main/java/db/migration/V5__isolate_subject_identity.java) + [preflight helper](../../risk-scoring-service/src/main/java/com/zerotrust/risk/migration/SubjectIdentityMigrationPreflight.java); bốn SQL V1–V4 nằm resources. Không kết luận đã upgrade engine hoặc thực thi DDL trên MySQL thật.

Không có live Lab Browser/DB/Keycloak/handshake, no full image/OS/JDK/provided-Keycloak scan hoặc full secret scan, no Production host/firewall/domain/realm, no end-to-end load/failure/recovery/rollback execution. Không render Mermaid bằng engine ảnh. Những mục đó giữ NOT VERIFIED và có acceptance plan, không biến thành PASS để kết thúc audit. Việc audit hoàn tất là bàn giao sự thật/khoảng trống, không phải mọi gate Production đều đạt.
