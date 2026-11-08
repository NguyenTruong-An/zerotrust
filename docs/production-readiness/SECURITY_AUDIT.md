# Security Audit và sổ phát hiện

**06/11/2026 — baseline c401e17 — NO-GO.** Phạm vi ADMIN/STUDENT, audit source/config/metadata và harness cô lập. Không thay sản phẩm hoặc Lab. Các nhãn bằng chứng và test totals trong [báo cáo chính](PRODUCTION_READINESS_REPORT.md). Dùng [OWASP ASVS 5.0](https://asvs.owasp.org/) làm khung tham chiếu cho authentication, session, token, authorization, validation, configuration, data protection và logging; đây không phải chứng nhận/đánh giá đầy đủ từng requirement ASVS.

**P0: không có finding mới được chứng minh đủ điều kiện gán P0 trong lượt này.** Có upstream advisory Critical; không tự đổi nó thành exploit/P0 của ứng dụng. P1 bên dưới vẫn chặn go-live theo phạm vi đề xuất. Mục NOT VERIFIED là gate thiếu chứng cứ, không phải khẳng định đã có lỗ hổng. Danh sách dependency theo từng advisory/package/version/fix/điều kiện nằm tại [DEPENDENCY_FINDINGS](DEPENDENCY_FINDINGS.md); đây là phần mở rộng PR-001.

## Những kiểm soát có bằng chứng

| Ranh giới | Kết quả | Nguồn |
|---|---|---|
| Portal/Gateway JWT | Signature/JWKS, issuer, exp bắt buộc, aud; bearer stateless | SecurityConfig, GatewaySecurityConfig; PortalJwtDecoderTest/GatewaySecurityTests; E04 |
| Risk caller | Issuer/aud/exp + azp và client role, default deny | RiskApiSecurityConfig/RiskJwtAuthenticationConverter; signed-JWT RiskApiSecurityTests |
| STUDENT ownership | Subject từ JWT, không nhận arbitrary studentId cho self endpoints | StudentController/StudentQueryService/ScoreAdministrationServiceImpl; security tests và historical 16 checks |
| ADMIN | Path + method guards; không đưa Teacher vào scope | AdminController, các service @PreAuthorize |
| Risk guards | Priority deny, incomplete→MFA, mandatory guards, B0 | RiskEvaluationService/DatabaseBackedRiskFeatureExtractor; E04 |
| Trust reset | Pending/generation dưới subject lock, operation owner, completion; timeout không giả rollback | DeviceTrustLifecycle/DeviceTrustStateRepository/UserServiceImpl; E04 |
| Cookie | 256 bit random, HttpOnly/Lax/realm path/host-only, Secure theo context; chỉ issue sau 204 | KeycloakDeviceCookieWriter/SecureRandomDeviceIdGenerator/registration; SPI tests |
| Input/data | JPA bound queries, sort allowlist, validation, batch ≤100, HMAC identifier | DTO/repositories/calculators; E04/E08 |
| Gateway header boundary | X-Forwarded/role/user headers bị loại; correlation mới; loại Cookie vào API | CanonicalRequestFilter/GatewayRoutesConfig; GatewayHeaderTests |
| Data transport | TLS file config, DB VERIFY_IDENTITY, Redis TLS/password; không publish DB/Redis | E01/E12; handshake hiện tại NOT VERIFIED |

Các decoder dùng withJwkSetUri và setJwtValidator có issuer; vì vậy không thấy điều kiện issuer-misconfiguration của [CVE-2026-22748](https://spring.io/security/cve-2026-22748/) ở ba decoder. RS256 mặc định của Nimbus cần giữ/ghi rõ trong release và kiểm thử thuật toán không cho phép; không coi việc thư viện hỗ trợ nhiều algorithm là một lỗi đã xác nhận.

Replay có phạm vi: evaluate/registration không dùng one-time request nonce độc lập; trust API tin caller Keycloak đã thực hiện MFA, generation chỉ fence reset/race. TLS + caller token giới hạn quyền/expiry không phải MFA attestation riêng. Failure-event dedup chỉ trong TTL1giờ, sau TTL event ID cũ có thể được nhận lại; success-event uniqueness nằm DB. Bị đánh cắp risk-caller credential có quyền gửi context/event/register trong scope của nó, nên secret isolation/rotation/monitoring là ranh giới quan trọng. Không có bằng chứng credential đó đã bị lộ hay caller bên ngoài bypass được JWT; không gọi đây là exploit đã xác nhận.

## PR-001 — Dependency/advisory và khoảng trống image scanning

- **Component / mô tả:** Next 16.2.6, sharp 0.34.5, Spring Boot 3.5.7 và các thư viện runtime có version match advisory; chưa có image OS/JDK scan hoàn tất. **Status:** TEST VERIFIED version matching + SOURCE REVIEWED applicability; exploit NOT VERIFIED. **Severity/priority:** P1 HIGH; **blocking:** có, cần patch/triage và xác nhận image trước Internet.
- **Evidence:** [npm scan](evidence/npm-audit.json), [Java scan](evidence/java-osv.json), [runtime JARs](evidence/java-runtime-jars.json), [tool results](evidence/tool-results.json). npm báo 15 package entries: 1 Critical, 6 High, 8 Moderate; không phải 15 exploit. Java scan chỉ Spring executable JAR runtime, không phủ đủ Keycloak server/OS/JDK. Docker Scout 1.20.4 yêu cầu login, không sinh SARIF; không coi là scan sạch.
- **Impact / likelihood:** Next SVG/lib image trên glibc Linux có điều kiện ảnh hưởng; server Linux standalone dùng sharp cũ, Gateway route `/**` có thể chuyển image endpoint. Không tìm thấy use cache/Server Action/custom rewrites/middleware/next/og trong source nghiệp vụ; Windows-hosted RCE không phù hợp Linux image. Chưa thử payload exploit. Spring servlet security 6.5.6 nằm trong range [CVE-2026-22732](https://spring.io/security/cve-2026-22732/): có nguy cơ thiếu security/cache headers ở một số response; Gateway API no-store giảm một phần, không thay patch trên mọi path. Tomcat/Netty HTTP parsing có thể liên quan proxy chain; AJP/DIGEST/WebDAV/JNDI-specific advisories không tự áp dụng cho JWT REST hiện tại.
- **Verification:** chạy npm audit không dùng fix; Java tool trích tọa độ JAR + Maven tree, query OSV, đối chiếu vendor. **Fix:** chọn Boot/Security/Tomcat/Netty/Next patch train tương thích Java17 hiện có; Next tối thiểu bản bao phủ advisory (scan gợi ý 16.4.5 tại ngày audit), sharp ≥0.35.5 cho SVG advisory. Không tự hạ eslint-config-next theo đề xuất npm hay cập nhật major mù. Chặn endpoint optimizer không dùng ở ingress là mitigation tạm phải thử, không sửa baseline trong audit.
- **Regression / deployment:** JWT/caller/RBAC/CORS/header/error/caching/HTTP parsing + frontend check/build/browser; rescan dependency và cả 10 image digest, SBOM và reachability/waiver từng advisory còn lại. Rebuild release mới; không áp image cũ đã khóa nếu chưa đánh giá.

## PR-002 — Profile prod vẫn kế thừa DB defaults nguy hiểm

- **Component/status/priority:** Portal/Risk source config; SOURCE REVIEWED, P1 HIGH, **blocking** trước tạo Production mới. [Portal properties](../../src/main/resources/application.properties), [prod](../../src/main/resources/application-prod.properties), [Risk properties](../../risk-scoring-service/src/main/resources/application.properties).
- **Description/evidence:** Portal default ddl-auto=update, username=root; JDBC default useSSL=false/allowPublicKeyRetrieval=true/createDatabaseIfNotExist. Prod override chỉ bắt buộc issuer/JWKS/CORS, chưa buộc DB URL/user/schema policy an toàn. Risk có defaults DB tương tự dù validate. Lab runtime đã override validate/VERIFY_IDENTITY/non-root, nên không kết luận Lab đang kết nối DB plaintext.
- **Impact/conditions:** deployment thiếu env có thể tự thay schema/dùng root/plaintext hoặc lỗi khởi động khó đoán. **Verify:** resolve prod config với input cố ý thiếu trong test, không nối DB thật.
- **Fix:** prod bắt buộc URL/user/secret, validate, VERIFY_IDENTITY và migration account riêng; fail-fast khi thiếu/localhost/insecure URL. **Regression:** profile validation + missing vars + rejected insecure settings. **Deployment impact:** manifest/env/secrets mới và schema job; không sửa cấu hình Lab để che finding.

## PR-003 — Domain/PKI/canonical IP chưa có cấu hình Production

- **Component/status/priority:** Keycloak/SPA/Gateway/PKI; VERIFIED Lab config, prod NOT VERIFIED; P1 HIGH, **blocking** mở domain thật. E01/E12; [context extractor](../../keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/context/KeycloakLoginContextExtractor.java), compose.build frontend args localhost:28444.
- **Description/evidence:** issuer/hostname/redirect/CORS/SPA build args là localhost; leaf SAN chỉ service/localhost. Keycloak không khai proxy headers/trusted addresses. App không tự đọc forwarding header, đúng cho direct Lab nhưng chưa đủ cho proxy đích.
- **Impact/conditions:** domain mismatch/code exchange/CORS/cookie lỗi; Risk dùng IP proxy/shared counter hoặc header spoof khi trust sai; admin console chung listener nếu public hóa thiếu filter. **Verify:** staging exact-domain OIDC discovery/redirect/logout, chain/SAN/CRL, forged forwarding headers/direct bypass/IPv4+IPv6/NAT; so sánh IP synthetic đã biết xuyên SPI→Risk.
- **Fix:** public portal/auth hostnames, certificate public CA, internal PKI, explicit proxy allowlist+overwrite+firewall; `/admin` và management qua VPN/allowlist, không chỉ đổi hostname-admin. Rebuild SPA với URL đích. **Regression:** proxy and OIDC suite + Secure/HttpOnly/SameSite/Path cookie. **Deployment:** cấu hình riêng, không sao chép CA/private keys Lab.

## PR-004 — Thiếu rate limit và hard request-body limit ở đường Internet

- **Component/status/priority:** Gateway/ingress; SOURCE REVIEWED FAIL, P1 HIGH, **blocking** public access. [Routes](../../gateway/src/main/java/com/zerotrust/gateway/GatewayRoutesConfig.java), [properties](../../gateway/src/main/resources/application.properties), toàn bộ bốn class Gateway.
- **Description/evidence:** không có RequestRateLimiter/token bucket/body-size enforcement; `spring.codec.max-in-memory-size=1MB` không chứng minh chặn mọi body stream được proxy. Validation batch100 không ngăn body khổng lồ parse trước validation. Chưa xác minh brute-force realm live.
- **Impact/likelihood:** resource exhaustion, credential abuse, synchronous Risk/Keycloak/pool saturation khi public. **Verify:** synthetic staging trả 429/413 theo giới hạn, body chunked, nhiều principal sau NAT; không stress Lab.
- **Fix:** ingress connection/header/body/read-timeout limits + login/IP/account controls + API per-principal policy, 429/Retry-After, quota metrics; tránh khóa toàn NAT do một user. **Regression:** burst/slow request/body bounds/RBAC unchanged. **Deployment:** ingress/rate state/capacity policy mới, không chỉ thêm dependency.

## PR-005 — Stale browser form ghi đè điểm đã lưu

- **Component/status/priority:** Portal API + UI; **TEST VERIFIED FAIL**, P1 HIGH, **blocking** ghi điểm thật. [Harness](tools/StaleScoreEditAuditTest.java), [test evidence](evidence/test-results.json), ScoreResponseDTO/UpdateScoreRequestDTO/SubjectScoreItemRequestDTO, ScoreAdministrationServiceImpl.updateScore và frontend admin-scores.
- **Description:** @Version có trong entity nhưng version không đi qua HTTP. Transaction sau đọc version mới rồi ghi toàn payload cũ; không phát hiện form đã stale.
- **Impact/conditions:** hai ADMIN mở cùng bản ghi/batch, một người lưu sau làm mất thay đổi người trước; dữ liệu học vụ sai, không cần attacker. **Reproduce:** H2 synthetic: ban đầu midterm7/final9, A lưu midterm8, B stale payload midterm7/final10; cả hai request thành công, version2/midterm7. Không viết Lab.
- **Fix:** expectedVersion hoặc If-Match từ GET tới PATCH/batch/delete; reject 409/412 và UI reload/merge rõ; batch atomic hoặc conflict result có contract; giữ @Version. **Regression:** hai transaction overlap (đã có) + serial stale form + stale batch + delete race trên MySQL đích. **Deployment:** additive API/UI change cần phối hợp release; schema đã có version nhưng phải validate migration.

## PR-006 — Backup chứa bí mật nhưng chưa được mã hóa; offsite chưa chứng minh

- **Component/status/priority:** scripts/ops/backup.py; SOURCE REVIEWED FAIL confidentiality + VERIFIED archive placement/ACL; P1 HIGH, **blocking** dữ liệu thật. E13/E14.
- **Description/evidence:** archive runtime bằng tar.gz, gồm authority/private material; gzip không mã hóa. Chỉ thấy backup cùng máy; không có bằng chứng encrypted offsite/copy/restore key escrow. ACL folder root hạn chế giúp giảm rủi ro local, không thay encryption.
- **Impact/conditions:** mất host/backup media hoặc người có quyền đọc archive có thể lộ DB/credentials/MFA/signing/CA material. Không có bằng chứng đã bị exfiltrate.
- **Verify/fix:** kiểm manifest/packer, inventory archive names không đọc key; backup mã hóa bằng key tách host, offsite có version/immutability, restrict restore operator, audit download, recovery escrow thử thật. **Regression:** không giải mã khi thiếu key, hash sau decrypt, restore khi mất host/key path, secret không vào log. **Deployment:** backup job/secret store/retention riêng, không rotate Lab trong audit.

## PR-007 — Chưa có full application/DR/rollback rehearsal

- **Component/status/priority:** Recovery; HISTORICAL VERIFIED DB, full app NOT VERIFIED; P1 HIGH, **blocking** recovery gate. [Restore report](../operations/RESTORE_VERIFICATION_REPORT.md), backup/restore_check.py.
- **Description/evidence:** mới mở DB; JGROUPS_PING/SERVER_CONFIG lệch so với DB đang chạy, thiếu point-in-time witness. Restore checker so với canonical đang chạy nên không thể chạy nguyên lệnh khi canonical dừng. CRL backup hết hạn sau 06/11 09:30:48 GMT+7. Image chỉ lưu ID không bảo đảm kéo lại được khi mất local image store.
- **Impact/conditions:** backup hash đúng nhưng không login/MFA/token/grade được sau disaster; rollback schema không tương thích; mất key/image làm không khôi phục. **Verification:** restore trên volumes mới, isolated stack, đọc realm/credential metadata, synthetic login/MFA/SSO/roles/risk, TLS và matching restore checkpoints; không khớp checksum bằng UPDATE.
- **Fix/regression:** giữ image theo registry digest hoặc signed archive offsite, runtime/key recovery, full rehearsal/timing/RPO data witness; điều tra SERVER_CONFIG có snapshot mới đủ bằng chứng. **Deployment:** chưa mở traffic đến khi rehearsal đạt; rollback chi tiết tại [plan](PRODUCTION_ROLLBACK_PLAN.md).

## PR-008 — Không tự restart; healthcheck chưa đủ readiness

- **Component/status/priority:** compose.lab.yaml/ops; VERIFIED FAIL readiness, P1 HIGH, **blocking** khi tái dùng Lab manifest cho Production. E01.
- **Evidence/description:** 10 restart=no; Backend probe chỉ đòi 401 trước controller/DB, Gateway /200 chỉ frontend. Exit143/0 lịch sử là stopped, không chứng minh crash; CRL exit137 không đủ kết luận OOM (metadata không OOMKilled).
- **Impact/conditions:** host reboot/process crash không tự phục vụ, DB lỗi vẫn probe đạt. **Verify:** staging dependency unavailable/process restart/host reboot/drain; không thử trên Lab.
- **Fix:** manifest Production riêng, restart/supervision có owner, liveness tách readiness, DB-backed read-only synthetic probe, dependency budget, graceful shutdown/drain. **Regression:** failure/recovery không traffic trước ready, không restart cascade vô hạn. **Deployment:** sửa manifests/probes/ops, đo downtime và saturation; không gọi single server là HA.

## PR-009 — Observatory chưa có alerting/monitoring Production

- **Component/status/priority:** observability; SOURCE REVIEWED FAIL readiness, P1 HIGH, **blocking** vận hành public. E09/E11; RiskScoreTrace/RiskEvaluationTrace/collector.
- **Description/evidence:** có D/N/T/H + evaluation/correlation + TIMEOUT trace nhưng thiếu centralized metrics, alert routing/on-call, JVM/DB/Redis/pool/error/latency dashboard. Rotation5m×2 không đảm bảo retention theo ngày.
- **Impact/conditions:** DENY/error spike/pending reset/CRL hết hạn/DB đầy/backup lỗi không được phát hiện kịp. **Verify:** inject synthetic alerts vào kênh vận hành thử, trace một login qua services, không log token/PII.
- **Fix:** uptime/TLS/backup checks bắt buộc, metrics tối thiểu + centralized logs có RBAC/retention; Prometheus/Grafana hoặc dịch vụ tương đương tùy đội vận hành. **Regression:** alert delivery/ack/runbook và cardinality/redaction. **Deployment:** đặt owner/channel/storage quota; không public Observatory HTML.

## PR-010 — Release chưa được CI và supply-chain gates bảo vệ

- **Component/status/priority:** GitHub/build; VERIFIED FAIL release gate, P1 HIGH, **blocking** phát hành HEAD. E02/E03; .github/workflows/ci.yml.
- **Description/evidence:** 3 commit local chưa push; CI xanh chỉ remote 1c9fa97; branch không protected/rulesets rỗng. Workflow có bốn Java, frontend/build contracts nhưng chưa có dependency/secret/image scan gate, release deploy approval, SBOM/signing workflow; actions dùng tag v4/v5, không SHA pin.
- **Impact/conditions:** unreviewed release/vulnerable artifacts không bị gate ngăn; provenance local chưa bảo đảm remote rebuild/recovery. **Verify:** exact release SHA CI, required checks/rules/approval và artifact digest lineage; không push trong audit.
- **Fix/regression:** sau khi chủ sở hữu cho phép, push release, PR required reviews/checks, scans/waivers, SBOM + immutable digest registry, protected deployment environment; SHA-pin actions theo maintenance process. Thử release/rollback staging từ registry. **Deployment:** không deploy commit khác SHA đã nghiệm thu; signing có thể phase sau nếu provenance/digest/registry ACL đủ và risk acceptance rõ.

## PR-011 — DB lifecycle/migration chưa chốt cho Production

- **Component/status/priority:** School MySQL9.1/Risk migrations; VERIFIED versions + SOURCE REVIEWED gap, P1 HIGH, **blocking** dữ liệu thật. E01/E09/E14; database/*.sql.
- **Description:** School9.1.0 Innovation khác hai DB8.x; chưa có tracked migration ledger tự động School. Risk có V1–V4 SQL + V5 Java; SubjectIdentityMigrationPreflight.inspect chỉ chấp nhận MySQL8.0.46 (UNREVIEWED_MYSQL_VERSION), writers-quiesced, exact old layout/collation; V5 ALTER COPY/EXCLUSIVE không atomic. getChecksum theo compiled bytecode/helper, legacy helper đòi661092940. Lab tắt Flyway Risk có chủ đích; không bật mù trên database nhập legacy. Không có bằng chứng support/patch policy cho9.1.0 đích.
- **Impact/conditions:** đổi Risk image DB sang8.4 và chạy clean Flyway có thể dừng ở V5; partial nontransactional DDL cần restore, không rollback giả. JDK/compiler update có thể làm bytecode checksum drift, phải đo chứ không sửa checksum để validate xanh. School version downgrade/incompatible datadir/schema drift có thể mất dữ liệu. **Verify:** test fresh bootstrap/upgrade path từng engine, immutable V5 checksum, logical export/import synthetic, schema/index/FK/CHECK và MySQL concurrency; đo disk/time/heap của migration snapshot toàn bảng.
- **TEST VERIFIED giới hạn:** [MigrationCompatibilityAudit](tools/MigrationCompatibilityAudit.java) gọi compiled preflight bằng metadata proxy8.4.13, trả UNREVIEWED_MYSQL_VERSION trước0SQLcalls, compiled checksum661092940. [Kết quả](evidence/migration-compatibility.json). Không gọi đây là MySQL8.4 full migration test hoặc upgrade đã được chứng minh.
- **Fix:** chọn MySQL supported LTS phù hợp từng service; không chỉnh applied V5 để nới version/checksum. Đánh giá đường bootstrap V1–V5 trên reviewed8.0.46 riêng rồi upgrade/logical import cả schema+ledger sang LTS được hỗ trợ, hoặc installer/baseline mới được review riêng cho DB mới; thử hết đường đi, không tự coi đề xuất này PASS. Giữ compiled migration/checksum/toolchain provenance khi patch JDK. School ledger/validated ADMIN/STUDENT schema, Risk migrator account riêng. **Regression:** fresh+upgrade+partial-DDL recovery+checksum across build+backup/restore; không Teacher/scheduling. **Deployment:** stop writers có xác minh tất cả replica, maintenance/disk/headroom, không raw downgrade datadir.

## PR-012 — Realm/session/B0 policy chưa nghiệm thu Production

- **Component/status/priority:** Keycloak/adaptive policy; SOURCE REVIEWED + HISTORICAL VERIFIED một phần, prod NOT VERIFIED; P1 HIGH, **blocking** mở users thật. E09/E10/E11.
- **Description/evidence:** numeric policy development; flow/password/MFA/trust có source/history nhưng chưa có production realm readback cho lockout/password policy/redirect allowlist/service account grants/token TTL/key rotation/admin exposure. SSO/refresh bypass form/Risk theo thiết kế, backend không kiểm auth_time/acr cho reset MFA.
- **Impact/conditions:** policy hiểu sai, refresh/old token dùng ngoài revocation window, admin sensitive action chỉ dựa bearer role; chưa chứng minh MFA bypass bằng exploit. **Verify:** staging flow read-only inspection + required negative cases, redirect/logout/PKCE, recovery/enrollment/reset-pending/stale generation, old session/token/refresh.
- **Fix:** approve B0 unchanged với scope/giới hạn; realm contract/config-as-code không secrets, exact redirects, disable unused grants, brute force/session TTL, fresh admin MFA hoặc chấp thuận cửa sổ token có căn cứ, signing key rotation drill. **Regression/deployment:** exact realm/client/SPI/domain acceptance; không sửa Browser Flow Lab hoặc bật B1 trong audit.

## PR-013 — Thiếu capacity và resilience evidence ở tải đích

- **Component/status/priority:** Performance/SRE; **NOT VERIFIED**, P1 gate, **blocking** chốt capacity/SLO; không phải lỗi hiệu năng đã xác nhận. E15.
- **Description/evidence:** micro B0 không có I/O; chưa đo HTTP evaluation/login/API/query, p95/p99, errors/timeouts, JVM GC/pools, DB/Redis recovery ở production-size environment. TIMEOUT lịch sử không có root cause đủ mạnh.
- **Impact/conditions:** mở cohort lớn/burst khiến synchronous chain/pools quá tải, DENY do timeout. **Verify/fix:** thực hiện [performance gate](PRODUCTION_ACCEPTANCE_CHECKLIST.md#performance-gate), chốt workload/SLO/budget rồi đo sizing; không tăng timeout/retry để che lỗi. **Regression:** measured baseline + overload/recovery/error budget. **Deployment:** giới hạn cohort/rate theo số đã nghiệm thu, không tuyên bố hàng nghìn users từ unit tests.

## PR-014 — Redis memory/durability/topology chưa có contract vận hành

- **Component/status/priority:** Redis/auth history; VERIFIED config + TEST VERIFIED Lua, P2 MEDIUM; **blocking có điều kiện:** phải chốt memory/loss behavior trước public; Redis Cluster không hỗ trợ nguyên trạng. E08/E12.
- **Description:** container128MiB, AOF everysec, không khai maxmemory/eviction; Lua nhiều key không hash-tag. Restore lịch sử keyspace rỗng không chứng minh nonempty counters/TTL/AOF replay.
- **Impact/conditions:** OOM/counter loss làm thay đổi H, restored expiry sai; Cluster CROSSSLOT. **Verify:** synthetic memory/TTL/AOF restart/expired dedup/nonempty restore, no partial write lỗi tài nguyên; không xóa keys Lab.
- **Fix:** standalone hoặc primary/replica+Sentinel được thử; explicit maxmemory thấp hơn container có headroom AOF/fragmentation, policy noeviction đánh giá lỗi thành incomplete; alert event-delivery failures và policy sau loss. **Regression/deployment:** durability/failover/load tests; không coi Redis là disposable cache hoặc dùng Cluster chỉ để scale.

## PR-015 — Thiếu retention/purge và audit chỉnh điểm theo actor

- **Component/status/priority:** data privacy/audit; SOURCE REVIEWED FAIL controls, P1 HIGH cho grade audit/retention gate, **blocking** dữ liệu thật. AuditableEntity chỉ created_at/updated_at; Score service chưa có append-only actor/before/after/reason. UserServiceImpl log reset chứa ID/requester; Risk history/metadata vẫn cần bảo vệ.
- **Impact/conditions:** không truy nguyên ai sửa điểm, không phục hồi logic thay đổi sai; pseudonymous/security history tích lũy vô hạn. Temporal90day query không xóa row. Không chứng minh đã lộ PII.
- **Verify/fix:** thiết kế audit actor/subject/op/correlation/before-after hạn chế, immutable retention/access logging và purge thực thi cho history/exports; privacy notice/owner/GeoLite license. **Regression:** audit cùng transaction nghiệp vụ, unauthorized audit read denied, purge boundary/idempotency và không log token/raw IP/cookie. **Deployment:** schema/storage/jobs/role vận hành mới; thống nhất retention với backup.

## PR-016 — Container hardening chưa đồng đều

- **Component/status/priority:** Dockerfiles/Compose; VERIFIED metadata, P2 MEDIUM, **blocking:** không riêng lẻ nếu compensating controls được chấp thuận. E01/E06.
- **Description:** app non-root và image pinning tốt; chỉ CRL read-only/cap-drop rõ; app khác thiếu read-only root/no-new-privileges/cap-drop/CPU/PID quota. Tools image dùng JDK17.0.10 và apt/pip sources không khóa toàn bộ transitive, cũ và lớn cho CRL; base digest cố định không đồng nghĩa còn được vá.
- **Impact/conditions:** blast radius/resource starvation/reproducibility khi compromise; chưa xác nhận container escape. **Verify/fix:** patch/rescan bases, service-specific CPU/PID/heap limits, cap-drop/no-new-privileges/tmpfs/read-only sau thử, tối giản runtime CRL nếu có lợi; không bật blind làm mất ghi hợp lệ. **Regression/deployment:** boot/health/TLS/truststore/log/temp behavior + resource peaks; thay image theo rollout bình thường.

## PR-017 — Event delivery best-effort và đồng bộ có thể làm chậm login

- **Component/status/priority:** RiskEventListener/HTTP client; SOURCE REVIEWED, P2 MEDIUM, **blocking có điều kiện** nếu yêu cầu audit/security counter đầy đủ. onEvent gửi đồng bộ, catch lỗi chỉ warn, fallback event ID random nếu thiếu.
- **Impact/conditions:** Risk chậm giữ thread login; thất bại gửi làm counter/history thiếu và có thể giảm H dù score sau đó COMPLETE; process crash mất event; không có retry bền vững/exactly-once. **Verify:** mock delay/error đã có; cần staging bounded delivery latency/loss metric/recovery, không shutdown Lab.
- **Fix:** trước hết timeout budget/loss alerts; nếu yêu cầu cần, transactional/outbox/durable delivery tương thích Keycloak event lifecycle; stable idempotency ID. Không thêm broker mặc định. **Regression/deployment:** auth result không bị telemetry đảo, duplicate/race/timeout-after-commit, nonblocking budget; contract và sizing nếu thay delivery.

## PR-018 — Một số tài liệu lịch sử không còn mô tả cấu hình hiện tại

- **Component/status/priority:** Documentation; SOURCE REVIEWED, P3 LOW, **blocking:** không riêng lẻ. ARCHITECTURE có đoạn compose.yaml bảy service; thực tế compose.yaml rỗng, runtime/config/state phải đọc theo ngày và entrypoint hiện hành. V1–V5 Risk là mô tả đúng khi tính V5 Java, không chỉ liệt kê SQL resources.
- **Impact/conditions:** operator dùng nhầm startup/migration hoặc coi historical healthy là live. **Verify:** đối chiếu README/CURRENT_RUNTIME với files/metadata. **Fix:** cập nhật current pointers trong đợt release, giữ lịch sử có ngày. **Regression:** link/path/entrypoint check. **Deployment:** docs-only, không thay runtime; báo cáo audit này ghi đúng baseline.

## Ưu tiên và phần chưa kiểm chứng

1. PR-001 và PR-005: patch dependency + bảo vệ điểm trước tạo release mới.
2. PR-002/003/004/010/011/012: prod config, domain/proxy/realm, limits, release và schema.
3. PR-006/007/008/009/015: bảo vệ/khôi phục dữ liệu, vận hành, audit.
4. PR-013/014: workload sizing + Redis contract, đóng acceptance gates.
5. PR-016/017/018: hardening/telemetry/docs theo đánh giá rủi ro, không che các gate còn thiếu.

Actual DB grants/encryption-at-rest/query plans; production firewall/admin reachability; live realm/session/key rotation; image CVEs/OS/JDK/provided Keycloak dependencies; complete secret scan/CI logs; browser recovery and failure/load/DR chưa đủ bằng chứng. [Checklist](PRODUCTION_ACCEPTANCE_CHECKLIST.md) nêu cách đóng từng gate. Không có sự cố nguồn ngoài phạm vi hoặc kiểm thử tấn công lên hạ tầng khác.
