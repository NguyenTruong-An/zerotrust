# Public Demo secrets, service identity & account contract — PD-02-06

Source/configuration/isolated tests only. No runtime, realm, account, credential rotation or backup job
is created. [Master Roadmap](../../docs/production-readiness/PUBLIC_DEMO_ROADMAP.md) is the only tracker.
Integrate with [data contract](README.md) and [ingress contract](INGRESS_CONTRACT.md) in Phase03; this
document and the two JSON specifications are **not a final Compose manifest or realm export**.

## Secret delivery

[secret-contract.json](secret-contract.json) enumerates17 distinct runtime input references and their
allowed consumers/targets. Files live outside source/build context under
`/srv/zerotrust-secrets/<staging|production>/`, independently generated for the new environment.
The file names, identities and reference paths are public metadata; no password/key/token is included.
Never derive a secret from a user name, reuse a Lab secret or use one password for multiple identities.

| Consumer | Delivery | Required material |
|---|---|---|
| Portal backend | Spring `configtree:/run/secrets/` + private keystore mount | School DB runtime password, Portal identity client secret, Portal Risk revoke client secret, Portal TLS keystore/password |
| Risk | ConfigTree + keystore mount | Risk DB password, Redis password, distinct fingerprint/history peppers, Risk TLS keystore/password |
| Keycloak | Read-only private `/run/public-demo/keycloak.conf`; fixed SPI secret-file + keystore | Own DB/TLS settings in private config; `/run/secrets/risk-caller-client-secret`; independent Keycloak TLS keystore |
| Gateway | ConfigTree + keystore mount | Own TLS keystore/password; user JWT passes through, no machine client secret |
| Redis | Private read-only config | Dedicated Risk Redis authentication/ACL configuration; no admin credential to Risk |

Spring's profile placeholders do not require secrets in environment variables: imported ConfigTree
properties override packaged properties. Tests load every Portal/Risk credential without the associated
secret environment variables, and omit each file separately to prove fail-fast. Effective configuration
must keep import mandatory (no `optional:`), pin Public Demo markers independently of the profile and
use the PD-02-03 canonical Java launcher. Do not put secrets in command-line options, `JAVA_TOOL_OPTIONS`,
`JDK_JAVA_OPTIONS`, `SPRING_APPLICATION_JSON`, build arguments, labels, application YAML or public assets.
Keep nonsecret JVM/config files read-only; there is no need to put a credential into JVM arguments.
Final Gateway/Portal TLS enablement, certificate aliases/paths, truststores and native TLS graph still
need Phase03/04/05 integration and verification; secret references alone do not prove TLS is active.

Keycloak native config has secret values **only inside the private mounted config file**, not in source,
CLI or process environment. A private bootstrap operation must render it with distinct DB/keystore
passwords and validate-only/initialize-empty=false settings. `validate_keycloak_config()` checks a
rendered synthetic/private config before native startup; it does not contact a realm or DB. Never mount
the bootstrap administrator password into normal runtime. Initial realm/client/DB-user creation is a
separate authorized private setup operation; MySQL root/provisioner credentials are not application
runtime credentials. Existing Lab generators/entrypoints remain unchanged and are not Public Demo tools.

The custom SPI accepts `serviceClientSecretFile`; Public Demo uses exactly
`/run/secrets/risk-caller-client-secret`, an empty inline secret and explicit `zerotrust-risk-caller`.
Set `PUBLIC_DEMO_MODE=public-demo`, `PUBLIC_DEMO_ACADEMIC_READ_ONLY=true`,
`PUBLIC_DEMO_RISK_CALLER_SECRET_FILE=/run/secrets/risk-caller-client-secret` in Keycloak runtime.
Three provider factories validate the required file during initialization. The resolver also checks
references/HTTPS/non-Lab service endpoints; missing/unreadable/oversized/nonregular/final-symlink or
multiline/invalid UTF-8 secret files fail closed with no path/value/cause disclosure. Bound is4096 bytes,
minimum16 characters, optionally one terminal LF. POSIX group/other permissions are refused by the reader.
Legacy inline transport remains available only outside Public Demo; Lab realm/configuration is unchanged.

Mounts are read-only, per-consumer and owner-readable (`0400`), with host ownership matching the verified
runtime UID. File-backed Compose mounts do not provide an attestation that requested uid/gid/mode became
effective; prepare host permissions and test as the actual container UID on Linux. These Windows tests
verify metadata and file reads, **not native Linux ownership/ACL/Compose behavior**. Protect parent
directories from writes/symlink replacement; root/Docker daemon/host administrators remain trusted.
No live secret content was read in this task.

[Redis ACL fragment](redis-acl-contract.conf) restricts the dedicated Risk instance's default identity
to the unchanged History key prefix and commands needed by current Lua/GET plus connection negotiation.
Its password hash is a placeholder, never a credential value in Git. The validator rejects broad keys,
`+@all`, extra users and missing hashes; tests compare required Lua commands without modifying Lua.
This is an ACL fragment, not runnable Redis/TLS config or native least-privilege proof. Merge privately
with TLS/storage and separately approved operator access; verify actual Redis/Lettuce permissions and
failure behavior, including denied administrative commands, before acceptance. Do not use it unchanged
if the approved key prefix changes; do not reset counters to accommodate an ACL mistake.

Review-only commands (no Docker/runtime/network calls):

```powershell
python scripts/public_demo/secret_contract.py deploy/public-demo/secret-contract.json
# For an authorized final rendered Compose JSON, combine data and secret reference checks:
python scripts/public_demo/secret_contract.py deploy/public-demo/secret-contract.json --deployment-json <reviewed-compose.json>
```

`--check-files` additionally reads the explicitly referenced **new-environment** files; do not point it
at Lab. It rejects missing/empty/oversized/nonregular files, duplicate whole-file fingerprints and
insecure POSIX modes without returning values/digests. It is not a parser or entropy/uniqueness proof for
every field inside aggregated Keycloak/Redis configs or keystores. Bootstrap must validate individual
credential values across derived configs and generate independent random secrets. Portal/Risk also
reject blank/control/oversized/reused local secret values; peppers require32 characters before bean
binding to prevent rejected-value leakage. No secret manager or automatic rotation is installed.

The combined deployment preflight rejects inline secret env/build args, common JVM/JSON override
channels, missing/duplicate/shared/wrong-stage mounts, unsafe modes and volume shadowing of secret/config
directories. It accepts only reviewed runtime consumers. Future bootstrap/DB/operator consumers need an
explicitly reviewed extension before use, not an exception to put secrets in environment variables.
`.public-demo-private/` is excluded from Git and Docker context; private key/keystore extensions are also
excluded from context. Real secrets should still remain outside the repository entirely. No build/image
or remote CI was performed, so final image layers and effective environment remain unverified.

## Service and account boundaries

[account-contract.json](account-contract.json) is a strict specification, validated by
`scripts/public_demo/account_contract.py`. It has no password, OTP seed, signing key or importable users.
It separates public SPA, Risk caller, Portal Risk administrator and Portal Keycloak identity client.

| Caller | Accepted target/permission | Explicitly excluded |
|---|---|---|
| SPA / ADMIN / STUDENT user | Portal user JWT + role/ownership; ADMIN/STUDENT business scope | No client secret, Risk/internal service authority or Keycloak/infrastructure admin grant |
| `zerotrust-risk-caller` | Risk evaluation `risk:evaluate`, registration `risk:device:write`, events `risk:events:write`; each endpoint checks its own role | Revoke/completion, Keycloak administration, Portal business roles |
| `zerotrust-portal-risk-admin` | Revoke/completion only, `risk:device:revoke` | Evaluation, registration, events, provisioning |
| `zerotrust-provisioner` (Portal identity client) | Current user queries/update/credential reset/logout through private Keycloak API | Risk roles; no realm-admin/client-management privilege |
| Gateway → Portal | Original signed user bearer, no new machine identity/headers granting rights | No role/subject impersonation from headers |
| Portal → School DB | Dedicated `pd_<environment>_school_runtime`, SELECT-only five tables | DML/DDL/global/schema privilege; PD-02-03 metadata guard remains |
| Risk → Risk DB/Redis | Dedicated DB runtime identity and isolated Redis credentials/ACL for required counters/Lua | Root/admin/provisioner; no limiter keys/Lua changes |
| Keycloak → own DB | Dedicated Keycloak runtime user, validate-only existing schema | Shared School/Risk DB user, Lab schema/import, runtime schema migration |

Native `manage-users` is coarse and is **not** proof of operation/target-specific least privilege.
Current MFA reset needs user updates/credential deletion/logout; do not remove required permissions to
make a test green. Fine-grained admin permissions, transitive roles, effective service-account grants,
DB DML-only grants and Redis ACL command/key boundaries require native readback/negative tests before
public access. Keep signing-key/CA administration, client configuration and privilege mapping outside
demo accounts and outside Portal's required runtime responsibilities.

Proposed SPA: public client, auth code+PKCE S256, no direct access grants, no service account/full scope;
exact HTTPS redirect `/` and `/silent-check-sso.html`, exact web origin, no wildcard. Source frontend
uses these redirect shapes. Final approved origins/issuer/audiences and post-logout/Account Console
compatibility require D-04 and browser acceptance. Service clients have client credentials only, no
browser/direct grants or full scope, no realm ADMIN/STUDENT role and distinct client secrets. Public
registration is off. Realm roles are ADMIN/STUDENT only; no TEACHER or realm-admin demo user. The public
ingress continues to deny Keycloak Admin/master/management and does not route the operator hostname.

## D-10 — proposal only, current policy unchanged

Current source permits an authenticated application ADMIN to call
`POST /api/admin/users/{id}/mfa/reset`; STUDENT/unauthenticated callers cannot. It maps an ACTIVE Portal
UUID to the Keycloak subject, records requester/operation UUID, revokes Risk trust first (pending +new
generation), removes old OTP/recovery credentials, adds enrollment actions, logs out Keycloak sessions,
then completes Risk reconciliation. Existing failures keep fail-closed/pending behavior. It does not
require fresh MFA/acr/auth_time and does not instantly revoke already-issued stateless Portal JWTs.
Public academic read-only does not disable this security-state operation. Tests retain ADMIN204.

**PROPOSED — NOT APPROVED:** remove cross-account MFA reset from public demo ADMIN, use a separate
private recovery operator identity/workflow; verify requester out of band, require fresh MFA (e.g.5min,
subject to owner decision), target/operation authorization, bounded operation rate and security audit
with requester/subject/operation/outcome but no credentials/OTP/cookie. Preserve revoke→reset→complete,
pending reconciliation, generation fences and native OTP/recovery proof before new trust. Recovery must
not grant a temporary bypass/skip MFA. Review existing access-token expiry window and native Account
Console/self-service credential removal/recovery against trust invalidation before go-live.

D-10 must decide authority, delivery/recovery checks, freshness/session/OTP/recovery policy, old-token
window, failure/retry/incident owner and audit retention. No operator endpoint/role, auth policy change,
real MFA reset or realm/Browser Flow change is implemented here. D-10 remains PENDING.

## Synthetic account lifecycle

Minimum fixtures: `demo-admin` (ADMIN), `demo-student-a` and `demo-student-b` (STUDENT). These are aliases,
not created accounts/cohort approval. A private bootstrap operator creates new Keycloak subjects and
maps separate Portal user/student UUIDs; academic seed provisioning uses a separate installer, never
public CRUD or runtime School credential. Generate per-account temporary credentials outside Git,
deliver individually through an approved channel, enroll independent OTP/recovery credentials and
confirm successful MFA before device registration. Never share password/OTP, import Lab user/state or
hand a lecturer Keycloak admin credentials. Require studentA/B ownership negatives and admin read-only
proof on the final candidate. Account count, distribution, enrollment/recovery/session/lifetime and
expiration date remain D-05/D-07/D-10 decisions.

After the demonstration, authorized operator disables accounts, terminates sessions and revokes trust
with reconciliation; preserve required evidence/retention and explicitly review old JWT lifetime.
Scheduling, actual user creation/expiry, identity recovery and admin operations are separate actions.

## Backup key protection and rotation

`scripts/public_demo/backup_encryption.py` orchestrates explicit local `age` artifact encryption. It does
not collect files, run tar/DB dumps, schedule, upload, invoke Lab tooling or delete artifacts. Two public
X25519 recipients can provide independent primary/escrow recovery. Encryption writer needs **only public
recipients**, not the decryption key. Store identities offline/separately from the archive, with approved
readers/escrow access, owner-only permissions and a tested recovery process. Never Git/image/log a key,
use Lab keys, store identities inside backup archives or assume gzip provides encryption.

The helper captures child stderr, uses private partial files, publishes only after successful native
encryption/decryption and refuses overwrite. Wrong identity/tampering never publishes a restore result.
Private partial/quarantine files are retained because this task forbids artifact deletion; they are not
accepted restores. Failed decrypt may contain an authenticated plaintext prefix in that private
quarantine: Phase07 needs an approved cleanup/retention/storage policy, not public/readable staging.
Actual backup collection must exclude plaintext staging and decryption keys, validate encrypted output,
use a pinned verified tool, protect all copies and measure full restore/RPO/RTO on authorized isolated
resources. Synthetic round-trip is not offsite/full-stack recovery acceptance.

Rotate client/DB/Redis credentials in a coordinated approved procedure with controlled app restart and
native grant/readback tests; never assume ConfigTree, cached tokens or pools hot-reload. Secret rotation
does not itself invalidate issued JWTs. Peppers affect persisted fingerprints/History HMAC/counters and
need a separate reviewed migration/recovery plan. Native Keycloak signing-key/JWKS overlap, TLS renewal,
CA recovery and encrypted-backup re-encryption/escrow are distinct workflows. No rotation is performed.

See [PD-02-06 evidence](../../docs/production-readiness/evidence/PD-02-06_SECRETS_SERVICE_IDENTITY.md)
for source findings, tests, scan limits and preservation. PR-006/010/012 remain OPEN; D-10 PENDING;
runtime ownership/realm/native grants/full restore are not established by these specifications.
