# Owner runbook — corrected Network v2 SHADOW binding v3

**Current runtime: SHADOW / V7 / 9 ready / unfinished=[]; runtime acceptance PASS.**
Executed only separately owner-signed backup984a6589, independent restore9971fa28 and APPLY10919aed.
Exact selected image pins are Risk85a7...463fe7 and Keycloakec2b...c94df. B0 remains live; retention disabled.
13 encrypted files authenticated, all restore schema/config/Redis witnesses verified, 16 protected table hashes
unchanged after cutover, strict Portal/OIDC/JWKS TLS/CRL200 and anonymous API401. Fresh browser/MFA after
THIS cutover was not rerun; existing candidate integration and prior local browser evidence are reused.
See target/full-function-20261111b/network-v2-shadow/v3-rollout-complete.json and v3-post-cutover-acceptance.json.
No agent signing, automatic rollback, new reset/account operation, image rebuild, cleanup or cloud deployment.
Frozen descriptor/packet remain PENDING review artifacts; actual authorization is the three owner signatures.

| Artifact | SHA-256 |
|---|---|
| execution.v3.json | 815be605db90cefa467725fd807ab6f497ddb1d2cafd0c8a5b0f4048e1f0a7da |
| operation.PENDING.v3.json | 591d7582ef09d4bd7a9c9bda72ebb749b472bdcde9561730b45543fa51e501c7 |
| network_v2_rollout.py | 477481e1b7ac81b57f6f867ce0aabea431188f02c87652c4088440afe33d7c27 |

Pins remain Risk85a7e95a...463fe7 / Keycloakec2b4710...c94df, core26.8.2.
B0 remains the only live policy; Network v2 SHADOW only, retention disabled.
V3 requires exact validated V7 and does not run Flyway or any DDL.

## Changed safety behavior

One strict JSON/Env canonicalizer is used by materialization, projection, create and verification.
Only JSON key order/whitespace and environment list ordering are normalized. Unexpected/missing/
changed variables, duplicate keys, malformed/non-object/non-finite JSON, pins, command, entrypoint,
mounts, networks, labels, users, health and hardening drift fail validation.

APPLY performs read-only projection before admission and again under the shared lock. Both actual
candidate containers are created dormant and completely inspected **before any ingress/writer stop**.
No candidate process starts until all contracts pass and maintenance begins. Dormant staging is
part of a separately signed APPLY, not permission to run it now.

A staging rejection closes only its own journal if the baseline selection/running states are intact
and any staged operation-owned candidates are still exact, dormant containers. It records the failure
code and retains candidates; it does not stop ingress or alter data. Unknown state or any failure after
maintenance starts remains fail-closed/recovery-required. Quiescence validates every running target
before stopping any, rejects duplicate/foreign writers and never touches inactive rejected candidates.
Recovery marks intent on its own journal before target/service mutation, retains CURRENT storage and
V7, and requires a fresh exact signed request. No journal deletion, DB restore or automatic retry.

V1/v2 descriptors/packets/anchors/private state/journals and emergency recovery evidence remain intact.
Original source copies are under history/<prior descriptor SHA>/. V3 uses separate controller metadata
and owner anchor under network-v2-shadow-v3; no new Docker project or application data copy.

## Owner signing workflow — completed for this rollout; fresh approval for any future operation

When owner separately permits this next maintenance preparation, open:

`<repo-root>\target\full-function-20261111b\network-v2-shadow\owner-v3\Owner-Review-and-Sign-Backup-v3.cmd`

This uses a native console, so no PowerShell Execution Policy change is needed. It never executes
backup/APPLY. Owner reviews the three hashes above; the helper verifies all pinned inputs.
If no v3 anchor exists, type `ENROL NETWORK V2 BACKUP RESTORE ONLY` at the approval prompt.
Then type `SIGN NETWORK V2 BACKUP-ONLY` at its separate prompt. Enter the existing key passphrase
only at the subsequent hidden prompt. Never enter it in the scope confirmation field or chat.
No private key/passphrase is supplied to Codex. Historical grants/requests cannot authorize v3.

## Agent-operated continuation — only after each exact owner authorization

All routine commands run in the canonical workspace with:

```powershell
$py = '.\target\full-function-20261111\tools\Scripts\python.exe'
$ctl = '.\deploy\full-function\network_v2_rollout.py'
$auth = '.\deploy\full-function\owner_shadow_authorize.py'
$owner = '<owner-home>\.zerotrust-owner\network-v2-shadow-v3'
```

1. Read/verify `latest-backup-only.path`; execute that new signed request once. Run
   `checkpoint-status --checkpoint <actual request ID>` and require COMPLETE plus plan PASS.
   An ID/folder alone is not backup success. Stop/analyze actual failure before any recovery proposal.
2. Prepare a private owner console for `sign restore-verify --checkpoint <exact COMPLETE ID>`.
   After that signature, execute restore-verify on independent disposable storage. Never restore active.
3. If restore verification succeeds and checkpoint age remains <20min, prepare owner review of
   `scope-cutover --checkpoint <ID>` and a separate `sign apply --checkpoint <ID>`.
   Then execute only that newly signed APPLY, not an old request or generic chat approval.
4. APPLY itself validates both actual dormant contracts, exact V7 no-op, one writer, internal TLS/CRL,
   Risk health, strict issuer/OIDC/JWKS, durable selection and saved service resume before ingress opens.
   After success, agent runs plan, strict public-facing local HTTPS/OIDC/JWKS and SHADOW/B0/config/log
   checks automatically. Reuse existing auth receipts; fresh browser MFA/subject API behavior needs
   existing authenticated evidence or owner browser interaction. Never fabricate fresh-MFA PASS.

Requests remain one-use/TTL10min. Anchor scope does not execute or sign an operation. Checkpoint
freshness is30min from creation; signing APPLY reserves10min. Freshness is rechecked after staging,
before quiescence, and before the switch. A stale staging failure leaves baseline available when
all safety conditions hold; never edit timestamps or reuse failed/consumed requests.

Rollback/restart/recovery always require their own scoped owner request. BASELINE recovery needs
recover+rollback scope; `scope-recovery --recover-of <ID> --recover-target BASELINE` is available without
a checkpoint. No automatic recovery is implied by a failed APPLY. Retain/analyze HMAC journals first.

**D-10 UNRESOLVED; D-17 PENDING; G8 INTERNET_NO_GO.** No GCP/public deployment.
