# PD-02-06 — Public Demo secrets, service identity & account security

**EV-PD-02-06-01; PD-R7; thực thi06–07/11/2026, Asia/Saigon.**
**PASS — source/configuration/isolated security testing**, không là native realm/deployment/backup acceptance.
Canonical `<repo-root>`, branch `zerotrust-v4-risk-scoring`,
HEAD `c401e17029d64f9a96738d845b8c0ad0f03fc164`, ahead3 so local upstream; toàn bộ thay đổi chưa commit.
[Master Roadmap](../PUBLIC_DEMO_ROADMAP.md) là SSOT duy nhất. Không thực hiện PD-02-07/08.

## 1. Security baseline

Đã đối chiếu PD-R6/PD-02-06 dependency PD-01-05 PASS; PR-006/010/012, G2/G3/G7,
evidence PD-02-01–05, ingress contract, service clients/security/JWT, reset orchestration, configuration,
Docker/CI/build context và backup/restore **source**. Không chạy Lab tooling hoặc đọc runtime secret files.
Baseline690 nonignored files được hash trước thay đổi; Docker daemon không khả dụng.

Source đã có ConfigTree support, effective fail-fast/main initializer, School SELECT-only metadata guard,
issuer/aud/azp/role separation và secret-safe token/Risk responses. Baseline gaps được xác nhận:
rollback Keycloak client log nguyên exception; SPI config parser giữ cause có thể chứa giá trị;
SPI realm config nhận inline client secret; local secret reuse/pepper pre-binding validation còn thiếu;
chưa có reference/account/ACL/backup crypto contracts và tests tương ứng. Existing Lab backup tạo
`tar.gz`, không chứng minh encryption. PR-006/010/012 không đóng bằng source evidence này.

## 2. Secrets inventory — chỉ tên/nguồn tham chiếu

Không đưa giá trị thực, digest của credential thực, private logs, password/token/OTP/key vào inventory.
Các đường dẫn bên dưới là **new-environment references**, không phải file đã tạo/đã đọc.

| Loại / owner → consumer | Purpose & source/delivery | Scope / rotation | Leak risk & missing-secret check |
|---|---|---|---|
| `risk-caller-client`; Keycloak → SPI | Client credentials cho Risk; `/run/secrets/risk-caller-client-secret`, realm chỉ lưu file reference |3 endpoint-specific roles, không revoke/admin. Rotate phối hợp Keycloak+SPI/cache/old-token window | Inline realm/export/env/process risk được tránh trong Public Demo; provider init +resolver/readFile fail-closed, redacted |
| `portal-risk-client`; Keycloak → Portal | ConfigTree `app.risk-admin.client-secret` | Chỉ revoke/completion bằng dedicated azp+role; restart/cache/reconcile khi rotate | No browser/build args; missing/short/reuse fail trước beans; upstream errors không echo body |
| `portal-identity-client`; Keycloak → Portal identity client | ConfigTree `keycloak.admin.client-secret` | Current user operations/reset; native manage-users coarse, FGAP acceptance pending | Không realm-admin; current permissions vẫn rộng hơn operation-specific. Missing/reuse fail; toString redacted |
| `school-db-runtime`, `risk-db-runtime`, Keycloak DB password; MySQL → own runtime | School/Risk ConfigTree password; Keycloak private config. Username pattern `pd_<env>_<domain>_runtime`, schema tách | School SELECT-only; Risk security-state DML; Keycloak validate-only. Independent secrets, coordinated DB/pool rotation | No root/URL credentials/Lab fallback; Java/data preflight reject. Real grants/passwords NOT_VERIFIED |
| MySQL root/migrator/bootstrap credentials; private operator | Private installation only, không app runtime/image/env | Explicit bootstrap/grants, remove from normal runtime; recovery owner pending | Không có runtime mount trong spec; không tạo/đọc root password; native installer/grants Phase03/04 |
| `risk-redis-auth`, private Redis config; Redis → Risk | ConfigTree `spring.data.redis.password`, sealed server ACL/TLS config | Dedicated instance/credential; restricted key/command ACL fragment; rotate server/client together, no counter/Lua reset | Inline env/default admin ACL risk; missing/reuse Java guard. ACL source tests, native Redis/Lettuce pending |
| `device-pepper`, `history-pepper`; Risk only | ConfigTree fingerprint/history pepper properties | Distinct32+ chars; rotation affects persistent fingerprints/HMAC/counters, requires separate plan | No log/toString values; pre-binding size/reuse guard avoids rejected-value exposure; no rotation |
| JWT signing private keys; Keycloak only | New realm's own key provider/DB/keystore; public JWKS to API verifiers | Operator-only native rollover/JWKS overlap; no Lab key import | Not Git/image/browser config. No real keys read/generated/changed; native key state/readback pending |
| TLS private keys/keystores; each Gateway/Portal/Risk/Keycloak/ingress/Redis/DB owner | Independent RO secret mounts; Java PKCS12 +ConfigTree password; ingress file refs | Separate leaf keys/identity, renewal/re-encryption; final aliases/SAN/chain need acceptance | PEM/key/p12/pfx/jks excluded build context; missing/file/mount checks only, actual graph/keys NOT_VERIFIED |
| Truststores/trust anchors/passwords; service TLS client | Private approved truststore file/JVM nonsecret file refs; CA certificates public, integrity protected | Trust anchor change distinct from leaf rotation; no trust-all | No password in CLI/build args; actual truststore validation/mount owner Phase03–06 |
| CA private keys; PKI operator offline | Never mounted to application or bundled in image/backup plaintext | Separate authority/escrow/recovery; no reuse Lab CA | Forbidden runtime material; no contents read; ownership/storage NOT_VERIFIED |
| OTP seeds/recovery credentials; Keycloak/user | Independent enrollment; own realm DB encrypted-backup protection | Per-user native credential lifecycle; never shared/imported from Lab | No raw OTP/recovery in source/logs/fixtures; native enrollment/recovery policy/readback pending D-10 |
| Session/cookie secrets; Keycloak | Keycloak realm/session/signing state. No separate Portal/Gateway session-signing secret in source; stateless user bearer | Native session/key policy; Trusted Device cookie is opaque random ID with Risk state/generation, not an app signing key | No cookie/header logging; native storage/cookie/old-session acceptance pending |
| Demo passwords; private bootstrap → individual users | Generated independently outside Git; aliases only in account spec | Per-account enrollment, disable/session termination/trust revoke after approved window | No default password/OTP; no actual accounts created; D-05/07/10 delivery/expiry pending |
| Backup decryption identities; recovery operator offline | Separate `age` identity files, public recipients only on writer; primary/escrow test keys only | Independent key recovery/approved re-encryption; keys never inside backup tree | Capture child stderr/no key logging; missing/wrong key/tamper/no-overwrite tests. Actual custody/offsite/restore pending |
| Other operator/CI/registry/VPS/DNS/offsite/SMTP credentials | Owner-controlled references for future authorized deployment | Least privilege/expiry/revocation separately reviewed | No values requested/read/provisioned; remote CI/image/offsite permissions NOT_VERIFIED |

ConfigTree/native config still hold secrets in process memory; host root/Docker daemon/debuggers can
read mounted material. File delivery reduces environment/inspection exposure, not a host-compromise
boundary. Legacy Lab Keycloak entrypoint exports a bootstrap password from its mount; that source is
reviewed as a reference/process-env risk, unchanged and not reused for Public Demo.

## 3. Service identity matrix

| Source → target | Credential/claim boundary | Authorized operation | Negative proof |
|---|---|---|---|
| Browser/ADMIN/STUDENT → Gateway/Portal | User JWT issuer/aud/signature/roles/ownership | Read-only academic views; current ADMIN reset remains | Signed JWT/RBAC/header spoofing +90 PD-02-01 cases; reset401/403/204 contract preserved |
| Gateway → backend | Original user bearer; forwarding/identity aliases stripped | Same user authority, no new service impersonation | PD-02-05 Gateway111 cases retained |
| SPI → Risk | RS256 issuer, Risk audience, azp=`zerotrust-risk-caller`, endpoint client role | Evaluation, registration, authentication events separately checked | Signed150-cell matrix, wrong issuer/audience/missing expiry on all six endpoints |
| Portal → Risk | Dedicated azp=`zerotrust-portal-risk-admin`, `risk:device:revoke` | Revoke/completion only | Cannot evaluate/register/write events even with another role; SPI cannot revoke with revoke role |
| Portal identity client → Keycloak private Admin API | Separate client secret, no Risk/user realm role | Current profile/user/reset/logout needs | Account policy rejects realm-admin/omni roles; effective native management permissions pending |
| Portal → School MySQL | Distinct runtime user/password and TLS schema contract | SELECT-only five tables | Existing metadata/grant mocks retained; native grants not proven |
| Risk → own MySQL/Redis | Separate DB identity/Redis credential/peppers | Security-state writes/counters | Reuse and missing files rejected; source ACL covers Lua commands, excludes broad grants; native DB/Redis pending |
| Keycloak → own MySQL | Own runtime user/private config/new schema | Runtime security state, no migrate/init-empty | Existing data preflight +new private config tests; no actual database access |

Matrix uses five caller identities ×five roles ×six paths: eval/register/failure/success/revoke/completion.
Correct caller+role succeeds200/204; all other cells403, no protected service interaction. A realm ADMIN
claim or forged X-Role cannot supply Risk authority. Eighteen wrong issuer/aud/missing-expiry HTTP calls
are grouped in six additional cases, all401. Existing wrong-signature/algorithm/role/caller/JWT tests retained.

## 4. Least-privilege assessment

Application ADMIN is not Keycloak/infra operator. Public client has no client secret/service account,
direct access grant/full scope/management roles. Service identities have distinct secrets/references
and do not receive ADMIN/STUDENT realm roles. Dedicated revoke identity remains distinct from Risk
evaluation/registration/event roles; no new omnipotent role. Runtime Public Demo initializers pin the
existing Risk caller/revoke IDs/audience and reject Portal identity-client collisions.

The Keycloak management requirement `manage-users` is coarse: operation/target-limited permissions,
transitive role effects, token grants, DB DML-only rights and Redis effective ACL require native readback.
No narrow native permission is falsely declared achieved. Redis ACL fragment limits the unchanged
History prefix and existing Lua/GET/connection commands; private source validator rejects broad keys,
`+@all`, extra users/commands and unresolved password hash. No Lua, prefix, counter or HMAC algorithm changed.
Native Redis/Lettuce command/TLS compatibility and operator access are downstream requirements.

## 5. Public Demo secrets contract

Artifacts: [secret specification](../../../deploy/public-demo/secret-contract.json),
[reference/file/deployment preflight](../../../scripts/public_demo/secret_contract.py),
[complete contract notes](../../../deploy/public-demo/SECRETS_IDENTITY_CONTRACT.md).
17 distinct runtime input refs are explicitly consumer-scoped; root CA/backup identity/bootstrap admin/
Lab export forbidden. No real `.env`, password/key, image-layer content or account is generated.
Host paths are outside repo/build context; RO/0400 ownership is required, no secret env/build args or
JVM/JSON override channels, shared/wrong-stage/missing/shadowed mounts. ConfigTree is mandatory for Java;
Keycloak receives private config +fixed SPI file. Missing public markers or required SPI file reject
provider initialization; actual Keycloak global startup still needs native verification.

The SPI reader checks literal absolute file, no final symlink/directory, UTF-8/single-line,16–4096 bounds
and restrictive POSIX permissions when available, with redacted errors. Three factories call startup
validation; resolver Public Demo mode rejects inline/ambiguous secrets, wrong client and non-HTTPS/Lab
endpoints. Optional legacy file transport is also tested end-to-end through real loopback token HTTP,
including cache reuse and missing-file/no-network behavior. No Vault/cloud manager or auto-rotation added.

Portal/Risk effective secrets reject blank/control/oversize/reuse. Pepper minimum32 is checked before
binding, not left to a potentially value-bearing validation exception. All3 Portal/all5 Risk credential
ConfigTree values load without secret env vars; each missing file fails redacted before DB beans.
Fixtures were made distinct to satisfy new requirements; no assertion was removed or test bypass added.

Compose file-backed uid/gid/mode semantics must be verified as actual Linux runtime UID; Windows tests
are not that proof. Whole-file duplicate fingerprints detect equal inputs, not equal embedded fields
inside different aggregate configs/keystores, nor entropy. Private bootstrap must generate distinct
credentials and validate per-field derivation. Parent directory protections and final files/images/
environment remain downstream acceptance. Documentation and code do not assert actual runtime secret isolation.

Primary references: [Docker Compose secret delivery](https://docs.docker.com/compose/how-tos/use-secrets/)
and [Spring external configuration](https://docs.spring.io/spring-boot/reference/features/external-config.html).
Actual ConfigTree behavior was also tested against this repository's Boot3.5.16 candidate, rather than
assuming current online manual version describes every detail of the pinned build.

## 6. Keycloak account security

[Account specification](../../../deploy/public-demo/account-contract.json) and
[validator](../../../scripts/public_demo/account_contract.py) are **not importable realm JSON**.
They require registration off, ADMIN/STUDENT only, no TEACHER, public SPA code+PKCE S256,
no direct grants/service accounts/full scope, exact HTTPS `/` and `/silent-check-sso.html` redirects
and web origin. These match current frontend redirect shapes. Final D-04 hostname/issuer/logout/Account
Console compatibility requires real browser acceptance. Service clients are confidential client-credentials
only, distinct role sets/secrets, no browser flow/realm business role. Demo aliases have no credentials.

Native client secrets are stored in the new Keycloak state, not in source/realm export; private bootstrap
must reconcile client-side secret files and server-side credentials without logging values. No Lab DB,
realm/user/OTP/signing key is read/reused. Public ingress keeps Admin/master/management/operator hostname
unrouted. No Keycloak admin credential is distributed to lecturers. Existing realm/Browser Flow unchanged.
Credential strength, session/enrollment/recovery and effective permissions are D-10/native acceptance,
not an approved policy inferred from a template.

## 7. D-10 policy recommendation

**PENDING OWNER DECISION — current source policy unchanged.** Valid ADMIN currently may reset an ACTIVE
Portal user's MFA through `/api/admin/users/{id}/mfa/reset`. STUDENT/anonymous denied; ADMIN204 retained.
Portal resolves Keycloak subject, creates operation/requester context, revokes Risk trust/pends generation,
updates Keycloak required actions/removes OTP+recovery/logs out, then completes reconciliation. Error/pending
semantics, old generation fences and mandatory native MFA proof remain intact. Current policy has no
fresh-MFA/acr/auth_time condition; stateless already-issued Portal JWTs are not instantly revoked.

Risk: a demo ADMIN can disrupt other accounts/recovery. **PROPOSED — NOT APPROVED:** public demo ADMIN
academic read-only, cross-account reset only via separate private recovery operator; independent identity,
verified requester/target, fresh MFA (e.g.5min, owner to decide), least privilege, bounded operations and
audited operation/outcome without OTP/token/password/cookie. Preserve revoke→reset→complete and pending
reconciliation; require native OTP/recovery verification before new trust. Never skip MFA for recovery.
Decide delivery/identity checks, old-token/session window, native Account Console/self-service credential
removal, retries/escalation and retention. No operator endpoint/role/policy toggle or real reset added.

## 8. Synthetic account lifecycle

Minimum fixture aliases: demo-admin ADMIN, demo-student-a/b STUDENT; not actual created users or approved
cohort. Private user provisioning creates new Keycloak subjects and maps separate Portal/student UUIDs;
academic provisioning uses a separate installer, not public writes/School runtime credential. Credentials
generated individually outside Git, delivered privately, independent OTP/recovery enrollment and proof
before trust. No shared password/OTP or realm-admin demo user. Expiration/distribution/count/session
choices remain D-05/07/10. Authorized end-of-demo disables accounts, ends sessions, revokes trust with
reconciliation and reviews remaining JWT lifetime; no automatic lifecycle job is scheduled here.

## 9. Backup encryption contract

[age orchestration helper](../../../scripts/public_demo/backup_encryption.py) accepts an explicit local
artifact; it does not tar/collect/read Lab, schedule, upload or delete. It uses public X25519 recipient
files, captured child stderr, owner-only private partial outputs, successful-only no-overwrite publishing.
Decryption identity must be outside the archive tree. Primary/escrow synthetic keys both decrypt the same
ciphertext; wrong key and altered ciphertext fail without publishing a restore result or logging markers.
No custom cryptographic format/algorithm was implemented. Native tool semantics documented by
[age upstream](https://github.com/FiloSottile/age/blob/main/doc/age.1.html).

Portable age1.3.2 downloaded from
[official release](https://github.com/FiloSottile/age/releases/tag/v1.3.2), asset SHA-256
`f48d8f8f9ebe903ab5027ed067652f2cc1db94bc206976430133b905dcd8e8c7` matched official GitHub release digest.
No independent release-proof verification or Production tool selection claimed; binary stays ignored target.
Synthetic identities are generated only under `target/pd-02-06/backup-fixtures`; no Lab CA/key is touched.

Private partial/quarantine artifacts retained under the task's no-delete rule. Failed decrypt may write
an authenticated plaintext prefix privately; it is never accepted/published. Phase07 must approve cleanup/
retention/storage safeguards, exclude plaintext staging and keys from collection, establish authorized
backup readers/key escrow/recovery, pin/verify tool, encrypt scheduled/offsite archives and test full
restore/RPO/RTO/security-state reconciliation. No actual backup/offsite/restore acceptance; **PR-006 OPEN**.

## 10. Logging/secret leakage review

Verified source fixes: Keycloak rollback logs stage/reason class only, no throwable/message/user profile;
SPI URI/integer/failure-mode parsing drops cause/value. Existing token/Risk response errors suppress raw
bodies, parse excerpts, auth headers/cookies; property/credential record toString guards remain. No request
or HTTP wire logging is enabled by this work; contract forbids raw credential logging/debug dumps and
requires final logging-config review. Existing Risk/SPI traces use explicit computed allowlists, not raw
LoginContext; retention/export/privacy/native logging remain D-12/PD-02-07/Phase07 responsibilities.

Negative tests use synthetic markers for provider/nested exceptions, malformed config, missing files,
secret mounts, CLI failures and crypto errors. Six final Java/Python/Node logs contain **0 occurrences**
of the five new marker strings and existing startup secret marker; test responses/errors checked without
echo. This is scoped synthetic proof, not a claim that every possible external logger/config is safe.
Startup/HTTP/Risk/SPI/JSON/backup error paths were reviewed. Lab backup/restore tools were only read as
source; CI has no new secret environment/build args or remote run. No effective CI logs/images inspected.

Bounded [source/history scanner](../../../scripts/public_demo/leakage_audit.py) emits type/path/line only,
no matched value/excerpt/token/key/digest. It scans nonignored source text ≤2MiB and reachable local source
blobs; ignored runtime/.env/private key/keystore/DB/backups and other sensitive paths excluded NOT_VERIFIED.
Initial scan509 current files/972 historical blobs:0 private-key blocks/API token patterns;
34 current/16 historical low-confidence literal candidates. Final rescan512 source files/38 current
literal candidates,0 private-key/API-token patterns; additional candidates are credential-reference
labels in the extended metadata. Reviewed candidates are synthetic tests,
field-name/secret-reference identifiers and a Lab shell file-reference substitution, not detected actual
Public Demo credentials. Reference JSON changes/additional tests post-scan are covered by final current
rescan/manifest. Heuristics cannot prove absence in all Git history or establish revocation; no rotation.

## 11. Source/configuration changes

Production source: Portal/Risk fail-fast secret separation/length and service-ID pins; SPI file reader,
resolver and three provider init hooks/config metadata; safe Keycloak rollback logging. No business reset
authorization/orchestration, JWT crypto validator, B0 calculator, HTTP nonce/strict Risk response, trust
generation/MFA proof, Event ID, Lua/counter/migration/dependency changed. `.gitignore`/`.dockerignore`
exclude new private staging/key material. New reference/account/Redis ACL templates, validators, age
helper/scanner, tests and contract notes. Input SHA manifest below binds29 files, independent of unchanged HEAD.

## 12. Regression tests

JDK17.0.21+9/current Boot3.5.16/Cloud2025.0.3 dependency candidate; four independent `verify` runs.
Counts use only classes named `Running` in the latest module log, not stale experimental XML.

| Suite | Total | PASS | FAIL / ERROR | SKIP |
|---|---:|---:|---:|---:|
| Portal50 classes |534|534|0 /0|0|
| Risk68 classes |999|903|0 /0|96|
| Gateway8 classes |111|111|0 /0|0|
| SPI30 classes |278|251|0 /0|27|
| **Java** |**1922**|**1799**|**0 /0**|**123**|
| Python (PD01–05 configuration/ingress24 +new17) |41|41|0|0|
| Node auth/PortalRoute/student dashboard |22|22|0|0|

**201 additional Java cases**: Portal11 (6 fail-fast negatives,4 ConfigTree,1 logging), Risk171 (9 config,
6 ConfigTree,150 caller matrix,6 grouped invalid-JWT), SPI19 (18 secret/config,1 native token HTTP).
All new mandatory cases executed, no new skip. Python17 =11 secret/account/deployment/ACL +3 scanner
redaction/scope +3 native age cases. Native NGINX8 from PD-02-05 rerun with synthetic HTTPS peers and
loopback only, including413/429/header spoofing/NAT/concurrency/TE+CL. No Keycloak brute-force/stress/live probe.
Native token HTTP proves mounted-file credential is sent only as Basic authorization to the configured
test endpoint, cached and never requested if file missing; Public Demo HTTPS validation separately tested.

123 skips retained: Risk43 opt-in HTTP audit,30 Redis,23 MySQL/investigation/timestamp; SPI27 opt-in audit.
No real stores/realm were started to force green; old optional permissive characterizations still need
PD-02-08 review as recorded in PD-R5/6.90 read-only cases/B0/JWT/RBAC/MFA/trust/strict JSON/attempt nonce/
event lifecycle/proxy abuse tests retained. V5 checksum **661092940**, four compiled class hashes preserved.
Windows cannot attest POSIX ownership/native Linux permission branches or actual database/realm grants.

Commands actually used (logs in ignored `target/pd-02-06`):

```powershell
$env:JAVA_HOME=(Resolve-Path 'target/pd-02-02/toolchain/jdk/jdk-17.0.21+9').Path
$env:Path="$env:JAVA_HOME\bin;$env:Path"
.\mvnw.cmd --batch-mode --no-transfer-progress -f pom.xml verify
.\mvnw.cmd --batch-mode --no-transfer-progress -f risk-scoring-service/pom.xml verify
.\mvnw.cmd --batch-mode --no-transfer-progress -f gateway/pom.xml '-Dserver.address=127.0.0.1' verify
.\mvnw.cmd --batch-mode --no-transfer-progress -f keycloak-risk-extension/pom.xml verify
$env:PD05_JAVA_HOME=$env:JAVA_HOME
$env:PD05_NGINX_EXE=(Resolve-Path 'target/pd-02-05/toolchain/nginx-1.31.8/nginx.exe').Path
$env:PD06_AGE_EXE=(Resolve-Path 'target/pd-02-06/toolchain/age/age.exe').Path
python -m unittest discover -s scripts/public_demo -p 'test*.py' -v
python scripts/public_demo/leakage_audit.py
# From frontend:
& ../target/pd-02-02/toolchain/node/node-v24.22.2-win-x64/node.exe --test tests/authentication-contract.test.mjs tests/portal-route.test.mjs tests/student-score-dashboard.test.mjs
```

Targeted SPI/config/logging/matrix/Python checks preceded full runs. Development failures corrected:
Windows text stdin added CR to `git check-ignore` fixture (changed to NUL protocol), and ACL fragment
validator initially ignored an extra non-user directive (now rejects every noncomment extra line).
No assertion/security control disabled; final suites green. Existing backup/restore tests not run against
Lab; actual encrypted backup/restore belongs Phase07. No remote CI/image/security rescan claimed.

## 13. Security findings

| ID / qualitative severity | Evidence / source result | Residual / parent |
|---|---|---|
| PD06-S1 / P2 secret-context log exposure | Source cũ truyền provider throwable trực tiếp vào logger; source mới stage/class-only, captured nested-exception marker test passes. Không chạy source cũ để tạo live disclosure | Source fixed; live logger/access/retention not verified; PR-006/012 OPEN |
| PD06-S2 / P2 config error value/cause exposure | URI/numeric/failure-mode parser kept underlying value-bearing exception; five marker cases now redacted/no cause | Source fixed; native Keycloak error handling/logging acceptance pending; PR-006/012 OPEN |
| PD06-S3 / P2 configuration/credential boundary gap | Inline SPI secret, local reuse and short pepper before binder; file/mode/size/duplicate/identity guards implemented and tested | Source fixed in Public Demo path; real files/credentials/realm/images not verified; PR-006/010/012 OPEN |
| PD06-R1 / release security policy risk | Current application ADMIN may reset another account without fresh MFA; confirmed existing authorized behavior, not newly declared bypass | D-10 PENDING; no policy/endpoint change; PR-012 OPEN |
| PD06-R2 / least-privilege residual | manage-users coarse; DB/Redis/realm native effective privileges and transitive grants unknown | Private native acceptance/fine-grained design before GO; no false FIXED status |

No new independent global PR ID; source subfindings mapped to existing parent findings. No detected real
credential disclosed/revoked. **PR-006/PR-010/PR-012 OPEN**, no deployment mitigation closure. **G2/G3 PARTIAL;
G7 PARTIAL** only scoped encryption/reference/recovery-preparation proof, not scheduled/offsite/full restore.
PD-02-02 PARTIAL, D-15/D-16 pending. D-10 PENDING. Public access NO-GO.

## 14. Unverified runtime requirements

Phase03 final images/source/digests/config/secret mounts/logging/build contexts and permission checks;
native Linux UID/GID/read-only/symlink-parent protections; new independently generated credentials;
Keycloak startup/realm/user/OTP/key/provider/effective roles/grants and no admin exposure; MySQL/Redis
TLS/ACL/native queries/Lua/denied admin commands; final hostnames/issuer/PKCE/cookies/logout/self-service
recovery; D-10 operator/fresh-MFA/session/old-token decisions; encrypted scheduled/offsite backups/key
custody/escrow/full auth/app/Redis/revocation/keys restore and RPO/RTO remain outstanding.
No staging/Production realm/runtime, Lab login, real provisioning/reset, credential rotation or backup job.
Next eligible task **PD-02-07**, dependency PD-02-01 PASS; not executed.

## 15. Lab/repository preservation

Baseline690 files. Final **677/690 unchanged;13 intentionally changed (12 inputs +SSOT),18 new
(17 inputs +report),0 removed**.45 historical readiness/audit/evidence files immutable.12 PD-02-01 and
13 PD-02-02 inputs unchanged. Since PD-R6:12/16 PD-02-03 inputs unchanged (two initializers/two tests
extended);24/26 PD-02-04 unchanged (Risk initializer/security tests extended);19/24 PD-02-05 unchanged
(same startup/config tests +Risk security tests). Entire Gateway/ingress abuse/proxy implementation and
PD-02-04 transport/nonce/strict JSON/MFA/trust/event production classes remain unchanged.
Four V5/migration class bytes and checksum retained; calculators/Lua/dependency inputs unchanged.

HEAD/branch unchanged; no commit/push/stage/reset/rebase/worktree/clone/source copy or artifact deletion.
No Lab secrets/DB/realm/CA/signing keys read or changed, no Docker/Lab start/restart/recreate. Baseline/final
Docker daemon unavailable: **current container metadata NOT_VERIFIED**, no inference from historical10
exited at PD-R5. Only own synthetic loopback HTTP/TLS servers/processes started and closed; no public port.
Real runtime state and ignored sensitive files are not attested by source hashes. Final source/link/task/
dependency/hash/document QA is recorded below.

### Input SHA-256 manifest

29source/config/test/contract inputs;report/SSOT excluded.

| Input | SHA-256 |
|---|---|
| [.dockerignore](../../../.dockerignore) | `0af74e703d13ab50adfb1dffecd635910a4bca8a7919c70ede4b1e8a81bfaeee` |
| [.gitignore](../../../.gitignore) | `a279c83a07102e69bb7465448ebc038335c5f1f5161129241f3210838dd29a31` |
| [deploy/public-demo/SECRETS_IDENTITY_CONTRACT.md](../../../deploy/public-demo/SECRETS_IDENTITY_CONTRACT.md) | `cdee9530feb7a6fae80041acb33a019563077b2b2c187ac4a8cc99549ecb3c12` |
| [deploy/public-demo/account-contract.json](../../../deploy/public-demo/account-contract.json) | `01a29ba0803b41fad04bc1e1d6430819b1b47be0ae38c9373af8ed729fb93d06` |
| [deploy/public-demo/redis-acl-contract.conf](../../../deploy/public-demo/redis-acl-contract.conf) | `75f9b7bbfa77cf1b8264bb7b243d5822180e9e3c362a78269e3306b4d6669276` |
| [deploy/public-demo/secret-contract.json](../../../deploy/public-demo/secret-contract.json) | `954f80ddc98fbf614693d8712379d2bbca47dc8e7e143ea3e7c281dd516a15ad` |
| [keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/authenticator/RiskAuthenticatorFactory.java](../../../keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/authenticator/RiskAuthenticatorFactory.java) | `c19466f33713979dc08b85867aa2c7919d789649a7810277add6540ecc815eb4` |
| [keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/authenticator/TrustedDeviceRegistrationAuthenticatorFactory.java](../../../keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/authenticator/TrustedDeviceRegistrationAuthenticatorFactory.java) | `f58486ffe8254a2805e0833cc1a5b046541d4fa5b0b0a652ff7e4e615abb352e` |
| [keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/config/PublicDemoServiceSecrets.java](../../../keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/config/PublicDemoServiceSecrets.java) | `c176fb86d7c33ff7e07efa1e87e04bb14d464df140705baedaf1608afc4e6a01` |
| [keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/config/RiskAuthenticatorConfigResolver.java](../../../keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/config/RiskAuthenticatorConfigResolver.java) | `7b7bcb15ec7c92b27590282a1bab76de69f5ce5526cd106eeea9155a7395414a` |
| [keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/listener/RiskEventListenerFactory.java](../../../keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/listener/RiskEventListenerFactory.java) | `6a67acfd45336e4a7e328fc5daed135e5b8a55677c089a64fe47b537458ac184` |
| [keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/client/SecretFileTokenHttpTest.java](../../../keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/client/SecretFileTokenHttpTest.java) | `bdf455fba82e794c1d5cf1839531c2880e779cb6e2da467451cf099ec375af2c` |
| [keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/config/PublicDemoServiceSecretsTest.java](../../../keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/config/PublicDemoServiceSecretsTest.java) | `1575c90f12470b0f2b94a96feaee121a6a8bcc3622a686f69205cdb7c94a628d` |
| [risk-scoring-service/src/main/java/com/zerotrust/risk/config/PublicDemoStartupInitializer.java](../../../risk-scoring-service/src/main/java/com/zerotrust/risk/config/PublicDemoStartupInitializer.java) | `064715c8af3d68c4a5b20522f2fbfb034e504e49bec7dcc5b984efc657d6c441` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/config/PublicDemoSecretFilesTest.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/config/PublicDemoSecretFilesTest.java) | `025b1df5d81187d772d91e71b8d4b49e8dfc53ade9b3be05e57bd71008dc351d` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/config/PublicDemoStartupConfigurationTest.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/config/PublicDemoStartupConfigurationTest.java) | `9ce72887d318c73311a65b84982836aed4b824af6ae166ab7ebd5bcf1bda4c81` |
| [risk-scoring-service/src/test/java/com/zerotrust/risk/security/RiskApiSecurityTests.java](../../../risk-scoring-service/src/test/java/com/zerotrust/risk/security/RiskApiSecurityTests.java) | `92f3924f9a2a80f234634440f48b91310004e510873a29f5e5cfba27667683c5` |
| [scripts/public_demo/account_contract.py](../../../scripts/public_demo/account_contract.py) | `53edfe72536efd3ee733ad4cc43616ea861103a5838796ee1f970ccb52a8c9d0` |
| [scripts/public_demo/backup_encryption.py](../../../scripts/public_demo/backup_encryption.py) | `05fa64836b99f91dffcab0c4690d2141c4cde5392581e8fad48ab45a124a3355` |
| [scripts/public_demo/leakage_audit.py](../../../scripts/public_demo/leakage_audit.py) | `0bd5909eb6b24e7af54ce1f682a994f5ba6962eee64ebae031b8aaa361bd5787` |
| [scripts/public_demo/secret_contract.py](../../../scripts/public_demo/secret_contract.py) | `d4e70807104f5b252b599597c04509543853d3b57b7d811cf9ad288429b35440` |
| [scripts/public_demo/test_backup_encryption.py](../../../scripts/public_demo/test_backup_encryption.py) | `e61b3373fe1f9a322937c22ec78f71e67dbdb4b4e13557f6e539b135043b185b` |
| [scripts/public_demo/test_leakage_audit.py](../../../scripts/public_demo/test_leakage_audit.py) | `9810d07df78206f6abe5f72a885fc17b10f51b9cff526d786de42ee046d90023` |
| [scripts/public_demo/test_secret_contract.py](../../../scripts/public_demo/test_secret_contract.py) | `9e3ebdc390f5235440b1e34b1c12a5b12f6cd62a1222b9acff4b18a09324a5f0` |
| [src/main/java/com/zerotrust/zerotrust/config/PublicDemoStartupInitializer.java](../../../src/main/java/com/zerotrust/zerotrust/config/PublicDemoStartupInitializer.java) | `fde1c6691b3149fbd1f6801eafd2c568dcdc56989db834f2755d2b1061cf0c47` |
| [src/main/java/com/zerotrust/zerotrust/identity/keycloak/KeycloakUserClient.java](../../../src/main/java/com/zerotrust/zerotrust/identity/keycloak/KeycloakUserClient.java) | `00a6c10a5582d6c9157ef3e0c30063137ecaa9356ef56a53e59f72f9b6f7b8eb` |
| [src/test/java/com/zerotrust/zerotrust/config/PublicDemoSecretFilesTest.java](../../../src/test/java/com/zerotrust/zerotrust/config/PublicDemoSecretFilesTest.java) | `6aeac5a850052a6d357bd3b53e83fde4138f120da3ec919f146ded776e9583bb` |
| [src/test/java/com/zerotrust/zerotrust/config/PublicDemoStartupConfigurationTest.java](../../../src/test/java/com/zerotrust/zerotrust/config/PublicDemoStartupConfigurationTest.java) | `b14461179060cca1266399819abd7d830a84b902978af6b97bc404e53e03981d` |
| [src/test/java/com/zerotrust/zerotrust/identity/keycloak/KeycloakRollbackLoggingTest.java](../../../src/test/java/com/zerotrust/zerotrust/identity/keycloak/KeycloakRollbackLoggingTest.java) | `cc03c36c1052d3ac52a1ff12766be46ff841cfadf888a546689c364c4191c951` |

**Final QA PASS:**50unique tasks/16fields;10PASS/34TODO/1PARTIAL/5BLOCKED;18OPEN findings/18risks/16pending decisions/17approved entries;acyclic task DAG;97 local link occurrences resolve across SSOT/report/contract;29source hashes verified;0synthetic secret marker log hits;V5/four class bytes/dependency/old evidence preservation verified. PD-02-07 remains TODO with dependencies PASS.
