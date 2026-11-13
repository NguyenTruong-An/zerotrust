# Full-function ZeroTrust — isolated local candidate

**Phase2 strict Adaptive Authentication acceptance: PARTIAL.** The full legacy
browser/recovery tree is restored and verified; existing functional PASS receipts
remain valid. GeoIP/network input parity, D-10 decisions and promotion of the tested
Risk locking fix remain open. See the single [Phase2 acceptance packet](PHASE2_ACCEPTANCE.md).
The active profile keeps its old immutable image receipt; the new locking image
was tested only on separate restored synthetic stores and is retained stopped.

Owner corrected the target on 11/11/2026: legacy-equivalent ADMIN/STUDENT business
behavior is required; Academic Demo PD-R19 is a preserved read-only reference only.
This profile uses the same canonical source, a **new synthetic DoAn realm**, new
credentials/keys and new Docker stores. It never clones or modifies the original
DoAn accounts, School database, Keycloak database, volumes or PD-R19.

Current project: `zt-full-function-20261111b`. Portal/Auth use
`https://portal.full-function.test:39443` and
`https://auth.full-function.test:39443`. Only loopback39443 and public-CRL
loopback39445 are published. MySQL/Redis/Risk/Keycloak admin/management have no host
ports. Nine steady services include a separate CRL publisher.

**LOCAL SYNTHETIC FUNCTIONAL ACCEPTANCE PASS**, including real browser ADMIN MFA
reset/re-enrollment/old-device-cookie replay. This is not release approval, live GCP
acceptance, a clone of old realm state, or a CVE waiver. D-17 remains PENDING;
G8 remains INTERNET NO-GO. See the [SSOT](../../docs/production-readiness/PUBLIC_DEMO_ROADMAP.md).

## Actual feature parity

The legacy column is based on the current canonical controller/service/frontend
contract and the existing integration runbook. Its original containers remain
stopped; historical acceptance is not presented as a fresh legacy runtime test.
Reset MFA was also verified read-only in the actual stopped legacy backend JAR
and compiled frontend chunks: UI/API, ADMIN annotation, revoke/completion,
OTP/recovery required actions, credential removal/logout and completion audit
code are present. [Compiled-reference receipt](../../target/full-function-20261111b/legacy-reset-reference.json).

| Feature | Implemented legacy/current-source operation | PD-R19 restriction | New isolated acceptance |
|---|---|---|---|
| ADMIN users | List mapped School users; Reset MFA for an active mapped user | Query-only provisioner prevents native identity writes; reset UI/API itself was not removed | Real list and UI/API reset PASS |
| Student administration | Create STUDENT identity + School record; list/detail; update profile and linked Keycloak profile | Frontend create/edit hidden; backend academic writes denied; School SELECT-only | Real create/update/read PASS |
| Classes | Create/list/delete empty class; reject deletion in use | Create/delete hidden/denied | Real create/read/delete PASS |
| Subjects | Create/list/delete unused subject; read score sheet | Create/delete hidden/denied | Real create/read/delete PASS |
| Scores | Create/read/PATCH/delete; subject score-sheet batch upsert and calculation | Read-only UI/backend/SQL | Real create/update/delete/batch PASS |
| STUDENT self-service | Read own profile, grades and summary using JWT subject | Intentionally retained | Both initial students' first-login grades/profile/summary PASS; other-user query cannot change ownership |
| ADMIN MFA Reset — mandatory | ADMIN -> mapped active School user -> Risk revoke -> Keycloak OTP/recovery deletion + required actions + logout -> completion/audit | Source endpoint retained, but query-only service grants are insufficient | Real rendered ADMIN UI to backend/Keycloak/Risk PASS; STUDENT403; unknown target404 |
| Re-enrollment/trust | CONFIGURE_TOTP + CONFIGURE_RECOVERY_AUTHN_CODES; generation fencing, revoke old devices | Security operations retained independently of School read-only | Old cookie replay cannot skip native OTP/recovery enrollment; new STUDENT token only after completion; other accounts unchanged |
| Keycloak/OIDC | DoAn, zerotrust-spa, Code + PKCE S256, custom theme and Risk SPI | Different realm/hostnames/build args | Real browser and strict issuer/JWT checks PASS |
| MFA/Trusted Device | Enrollment mandatory; fresh-device step-up; trusted LOW may skip OTP | Retained | Real OTP challenge/registration, LOW relogin without OTP, reset/re-enroll and restart PASS |
| Risk B0 | 25% each D/N/T/H, thresholds40/75; mandatory MFA/priority/fail-closed | Retained | Real API LOW0, MEDIUM40, HIGH77.5; real HIGH browser DENY/no token; actual Risk outage fails closed |
| RBAC/JWT/TLS | ADMIN/STUDENT, managed-user mapping, signed JWT, audience/issuer, TLS | Retained | STUDENT ADMIN/write/reset403; altered JWT401; TLS/CRL positive and negative checks PASS |

There is **no general ADMIN-account create/delete/role editor**, student-delete
endpoint, class-update endpoint or subject-update endpoint in this source contract.
STUDENT profile editing/enrollment management is not implemented. These are not
claimed as restored features. No TEACHER, scheduling or teaching assignment is added.

## What actually changed

- Frontend rebuilt from the existing Dockerfile/source with `PORTAL_MODE=standard`,
  `KEYCLOAK_REALM=DoAn` and the new private hostnames. Lint/typecheck,34frontend tests
  and production build passed. No application UI/business code was rewritten.
- Backend uses the existing standard/LAB business mode under an explicit
  `full-function` Spring profile, Hikari writable, JPA validate and School-only
  SELECT/INSERT/UPDATE/DELETE. No DDL, Keycloak-schema or Risk-schema privilege is
  granted to School runtime. LAB here selects business behavior, **not the original
  Lab destination**. Public-demo write-deny remains intact for PD-R19.
- Gateway and Risk retain their reviewed guarded profiles, trusted proxy handling,
  JWT, rate/body limits, B0 and fail-closed behavior. These Gateway settings do not
  deny normal ADMIN business verbs. NGINX retains HTTPS verification, limits,
  overwritten forwarded headers and private management routes.
- Only the fresh provisioner receives its existing delegated user-management roles
  plus the built-in `kc-admin-api` default client scope. Keycloak26.8.2 requires
  both this scope and its intended audience. The SPA receives neither management
  permissions nor this scope. No super-admin user is used for business acceptance.
  [Official upgrade requirement](https://www.keycloak.org/docs/latest/upgrading/index.html#_admin_rest_api_now_enforces_an_audience_check).
- Reset behavior is unchanged in shared Java: current principal name is
  preferred_username, falling back to sub. Tests check that exact audit contract.
  Keycloak admin events are enabled without request-body details on the new realm.
- New CA/leaf/CRL/CDP, private truststores and separate public-only CRL volume.
  Java PKIX revocation and NGINX upstream CRL checks are enabled. The browser helper
  trusts the new CA in an ephemeral NSS store; no SPKI/TLS-ignore flag or Windows
  Root-store edit is used. Expired CRL, revoked leaf and wrong hostname are rejected.

## Synthetic fixtures and old data

The new realm has fresh ADMIN/STUDENT fixture accounts and disposable users created
through the real ADMIN API during tests. Credentials are in the new private
`target/full-function-20261111b/private/accounts.json`; do not print/share them.
The browser tests enroll OTP/recovery, so the file does not contain OTP seeds.
This is not the old DoAn password/OTP/signing state.

Real HIGH uses the actual source address of one disposable helper,
`10.253.245.27/32`, explicitly classified high-risk in this **local test profile**,
plus synthetic history signals. Headers are not forged and B0 thresholds are not
changed. These test CIDRs are not a Google Cloud production policy.

Reusing old accounts/data is feasible only after a separately approved verified
copy: keep Keycloak UUID/password/OTP/signing-state and School BINARY16 mappings
consistent, plan supported export/import and preserve Risk V5/generation state.
Legacy School MySQL9.1 must not be physically downgraded into8.4. Sessions and
some event/workflow state do not survive CLI realm export. No such copy/export or
secret migration occurred here. Synthetic data is the safe current rehearsal input.

Legacy public CA/leaf certificates were still valid, but the existing CRL was
expired when inspected. Its dates are in the read-only receipt; no renewal or old
PKI change was made. Do not reuse historical TLS acceptance as current proof.

## Reproduce and operate

Requires Docker Linux amd64/Compose with `!override`, Python3.11+ with
`cryptography==50.0.2`, and JDK17 keytool. Use the canonical checkout. Existing exact
backend/Risk/Gateway and remediation images are selected in `operate.py`; their IDs
are recorded in the non-release `profile-images.json`. The frontend build uses:

```text
docker buildx build --platform linux/amd64 --load -f deploy/docker/Dockerfile.frontend --build-arg NODE_IMAGE=node:24.22.2-alpine@sha256:ec318aabf188af4e5488847eea4b24452650b9917140563e140762526a37f1df --build-arg KEYCLOAK_URL=https://auth.full-function.test:39443 --build-arg KEYCLOAK_REALM=DoAn --build-arg PORTAL_MODE=standard --build-arg SITE_URL=https://portal.full-function.test:39443 --build-arg RUN_CHECKS=true --build-arg SOURCE_REVISION=81d6322a7624d3632f69215daf45537f922dd950 -t zt-full-function/frontend:20261111-1 .
docker buildx build --platform linux/amd64 --load -f deploy/full-function/Dockerfile.browser -t zt-full-function/browser:20261111-1 .
```

Do not overwrite an existing immutable image tag/receipt. Commands below assume
the profile's Python prerequisites are installed in the selected interpreter:

```text
python -B deploy/full-function/operate.py validate
python -B deploy/full-function/operate.py install
python -B deploy/full-function/operate.py status
```

`install` requires empty owned destinations. `resume` is limited to an incomplete
owned pre-application bootstrap and validates rather than overwrites schema.
Installed profiles use `restart`/`stop`, never import or re-seed on restart.
`test` performs fresh-account browser/CRUD acceptance. `test-mfa` is the targeted
continuation used after the audited reset assertion was corrected, `test-risk`
uses the dedicated real high-risk source IP, `test-persistence` checks after an
explicit `restart`, and `test-failclosed` stops/restores **only this project's Risk**.
Never run these tests against another project or non-disposable data.

The main executed receipts are:

- [Browser/API/reset/Risk results](../../target/full-function-20261111b/results/acceptance.json)
- [Restart proof](../../target/full-function-20261111b/results/persistence-after.json)
- [TLS negative cases](../../target/full-function-20261111b/tls-results.json)
- [Legacy public TLS/CRL inspection](../../target/full-function-20261111b/legacy-tls-readonly.json)

## Open the new local system

[Open-Full-Function.cmd](../../target/full-function-20261111b/Open-Full-Function.cmd)
starts a separate pinned Firefox executable/profile, not the PD-R19 Chrome profile.
The new CA is trusted only in its private NSS database, with `.test` resolution
only in that profile. Normal Firefox Portal/Auth TLS was verified without an
exception, hostname bypass, hosts-file or Windows Root-store change.
[Owner-browser receipt](../../target/full-function-20261111b/owner-browser.json).

[Open-Admin-Credentials.cmd](../../target/full-function-20261111b/Open-Admin-Credentials.cmd)
opens the new synthetic ADMIN username/password/current OTP locally. Password and
OTP remain hidden until the owner requests them in that window; no seed is shown,
exported or logged. It reads only this project's DB. This local operator helper
is not a public endpoint or a replacement for MFA. It closes after10minutes.
Use `show_account.py --account student_a`/`student_b` for the other synthetic users.
Old DoAn passwords/OTP do not belong to this new realm state.

Failed first-attempt state `zt-full-function-20261111` is stopped and retained;
subsequent state uses a distinct project/subnet. No cleanup/prune or release-lock
replacement occurred. Current functional results come from `...20261111b` only.

## Limits before Cloud/public release

[Phase2.3A-ACTIVE-CONTEXT](PHASE23A_ACTIVE_CONTEXT.md) now implements the dedicated
active execution binding. [Executable descriptor](risk-active-execution.v1.json)
and [pending packet v2](active-risk-cutover.PENDING.v2.json) bind exact active
contracts and code; independent owner signatures anchored outside Git are needed
for every future mutation. Default `risk_active_context.py preflight` is read-only.
126 targeted tests and disposable namespace/crash/recovery regression passed;
native active access was preflight only,9healthy OLD/GeoIP=false. Active private
state/checkpoint and owner trust anchor are NOT_CREATED. See the
[authorization protocol](ACTIVE_OWNER_AUTHORIZATION.md); no APPLY/public approval.

[Phase2.3A-FIX](PHASE23A_FIX.md) closes the disposable rollback-interruption
runtime gap and holds ingress closed during internal verification, preserving
running intent. Two real rollback-crash recovery branches and the changed
promoted cold restart passed;40 targeted unit tests passed. Active mutation
context was not yet implemented at that checkpoint; the paragraph above records
its subsequent closure. Active checkpoint is still NOT_CREATED and daemon/Windows
restart remains NOT_VERIFIED. The [historical pending packet](active-risk-cutover.PENDING.json)
is retained; use v2 for the current review, without treating it as authorization.

[Phase2.3A executor rehearsal](PHASE23A_EXECUTOR_REHEARSAL.md) adds scoped
backup/restore-verify/apply/rollback/status/restart/stop/recover operations to the
[Phase2.2 read-only controller](PHASE22_PROMOTION_TOOLING.md). Mutation is compiled
to the retained disposable lane only. Encrypted independent restore, exact-image
cutover/rollback, promoted restart and three real process-crash recoveries passed
there. The active proposal remains PENDING with execution disabled. Active
integration/maintenance review and a new explicit owner authorization are still
required; no flag, manifest edit or rehearsal signature enables active cutover.
Legacy operations continue to reject promoted or ambiguous state.

The [Phase2.1 decision packet](PHASE21_DECISION_PACKET.md) reviews country policy,
the exact locking/GeoIP candidate, D-10 choices, targeted test reuse and rollback.
It is a proposal: no policy change or promotion is authorized by the document.
Existing image/config receipts need explicit promotion-aware tooling before a
reviewed Risk-only cutover; changing an image tag alone is insufficient.

Real GeoLite2 City/ASN acquisition, authenticated Risk scoring, browser peer/header
integrity and controlled reader restart/replacement/rollback have now been tested
only in the retained synthetic restore lane. See the [Phase2.1A packet](PHASE21A_GEOIP_ACCEPTANCE.md).
The active `zt-full-function-20261111b` Risk image/config remain unchanged: GeoIP is
still disabled there pending reviewed promotion. No public-peer browser GeoIP PASS
is claimed from Docker's private/NAT peer. The private updater reads owner credentials
from `target/full-function-20261111b/geoip-private/GeoIP.conf`; never copy that directory
into an image, export it, or mount its credential file into Risk. Data activation
only selects a verified pair; in-memory readers need a controlled replacement and
health/lookup check. Original release pins and public gates remain unchanged.

The previous Academic read-only GCP staging script is paused, not uploaded.
No GCP application/resource/firewall change occurred. The new full-write public
configuration/hostname/TLS/startup/grant acceptance still needs its own review;
do not treat the local LAB business selector as public production approval.
Existing release/security gates remain open; prior read-only mitigations do not
automatically cover writable grade administration. Original realm configuration
IDs/state were not cloned or compared byte-for-byte. The owner-browser connection
and normal TLS were automated-verified; the owner's hands-on business acceptance
and actual GCP acceptance are not claimed by the automated local browser results.

Reset invalidates refresh/SSO and device trust, but an already issued self-contained
access JWT can remain valid until exp. No instantaneous access-token revocation is
claimed. D-10 lifecycle/public acceptance, D-17 and G8 are not silently closed.
