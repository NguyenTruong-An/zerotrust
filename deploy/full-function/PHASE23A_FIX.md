# Phase 2.3A-FIX — Risk promotion blockers

12/11/2026, Asia/Saigon. **Targeted rehearsal hoàn tất; active readiness PARTIAL / NO-GO.**
Mutation chỉ trên `zt-full-function-phase2-restore`. D-17 PENDING,
G8 INTERNET_NO_GO; không cấp owner approval.

**A. Findings từ Phase2.3A**

[Report gốc](PHASE23A_EXECUTOR_REHEARSAL.md) giữ nguyên. Hai gap chính là ingress
được start trước verification/commit và rollback-interruption recovery mới có
unit evidence. Apply/rollback/restart cũng start toàn bộ service thay vì giữ
pre-maintenance intent. Cold restart đã PASS nhưng daemon/Windows chưa thực hiện.
Active proposal vẫn PENDING và execution disabled.

**B. Sửa chính xác**

- Thêm [promotion_maintenance.py](promotion_maintenance.py): exact IDs/scope,
  stop ingress trước, quiesce writers/Redis, kiểm nội bộ khi ingress còn đóng,
  resume đúng `running_before`, ingress cuối sau verification. Resume health lỗi
  đóng ingress và giữ journal. Từ chối ingress-running/dependency-stopped trước
  mutation. Active binding chỉ được inspect read-only.
- [promotion_executor.py](promotion_executor.py): tích hợp maintenance cho backup,
  apply/rollback/restart/recover; lưu `running_intent`, thêm stage
  `ROLLBACK_OLD_STARTED`, explicit signed recovery STOPPED cho backup/restart/stop
  dở. Không dùng STOPPED để âm thầm undo committed apply/rollback.
- Reuse candidate chỉ khi exact image/config/hardening và HMAC creation journal
  đúng manifest/ID/DONE; không sửa provenance labels. Kiểm restart policy
  `unless-stopped`. Chặn backup/restore dưới15GiB, cảnh báo dưới20GiB.
- [promotion_verify.py](promotion_verify.py): thêm internal TLS/CRL/JWT/V5,
  pending/trust/credential continuity và GeoIP check không cần ingress. Browser
  OTP/Recovery/PKCE/RBAC giữ evidence Phase2.3A, không chạy lại.
- [test_promotion_executor.py](test_promotion_executor.py) điều chỉnh tests cho
  controller mới; [test_promotion_maintenance.py](test_promotion_maintenance.py)
  bổ sung fence, intent, identity/scope, health failure, storage và reuse/restart.
  [promotion_fix_rehearsal.py](promotion_fix_rehearsal.py) là harness bounded mới.

**C. Maintenance evidence**

[40 targeted unit tests][unit] PASS, không Docker mutation từ unit tests;48
controller tests cũ reuse. Runtime đã xác minh internal baseline restart, giữ
frontend+ingress đang dừng và restore checkpoint. Ingress không cần mở cho service
JWT/TLS checks; normal apply chỉ resume sau durable commit.

Fixture đầu tiên dừng frontend nhưng giữ ingress có health phụ thuộc frontend.
Resume không thể healthy: attempt được giữ, preflight/failure-close được sửa và
explicit STOPPED recovery đã dừng đúng lane. Không sửa intent cũ để làm test xanh.
Checkpoint complete của attempt đó được reuse rồi independent restore-verify;
không tạo checkpoint thứ hai. [Attempt][attempt] · [STOPPED recovery][held].

Scope ceiling vẫn chặn active ở executor. [Active maintenance review][binding]
xác nhận exact active IDs/contracts, ingress127.0.0.1:39443, CRL127.0.0.1:39445,
các service khác không publish port. Đây là read-only binding, không là approval
hoặc active execution context. Không thể dùng một flag/đổi manifest để mở quyền.

**D. Interrupted rollback runtime**

**Hai nhánh runtime PASS** tại [runtime receipt][runtime]: abort về exact NEW
trước commit và finish về exact OLD, lần lượt~240s/~228s gồm crash + recovery.
Child process bị `os._exit(86)` sau OLD start, journal đã fsync. Kiểm controller
restart bị từ chối khi partial; recovery signed request mới chọn PROMOTED hoặc
BASELINE; recovery lặp là no-op. Witness gồm School data, toàn bộ Keycloak
CREDENTIAL, exact synthetic generation/pending/trust/audit rows; không import DB.
Những probes được phép có thể thêm Risk fixture rows riêng, không restore snapshot.

**E. Restart/crash coverage**

Reuse ba apply-crash receipts Phase2.3A; promoted cold stop/start bằng controller
mới **PASS**, restart~126s và giữ đúng NEW. **Không restart Docker Desktop/WSL/Windows**.
[Quy trình daemon/Windows riêng](PROMOTED_DAEMON_RESTART_PROCEDURE.md) là DRAFT,
NOT_EXECUTED, cần approval host-wide riêng. Theo [Docker restart policy](https://docs.docker.com/engine/containers/start-containers-automatically/),
container đã dừng với `unless-stopped` không tự chạy lại sau daemon restart;
điều đó hỗ trợ fence nhưng không chứng minh host acceptance.

**F. Storage và reuse**

C: đầu lượt38,47GiB, trên20GiB. Không build/pull image, worktree hoặc prune.
Reuse database/realm/accounts hiện hữu của lane synthetic, cùng reviewed Risk
container/image và MMDB. Chỉ một checkpoint mới để đáp ứng freshness gate<30phút;
restore-verify cần10 fresh volumes và2 clone containers private/network-none.
Không restore vào volume đang có. Resources mới được giữ và dừng sau test.
Cuối lượt còn khoảng38,30GiB; snapshot ngay trước runtime38,65GiB, net giảm
khoảng0,35GiB. Số liệu/IDs ở [storage][storage] và [preservation][preservation]; Δfree
là số đo net của Windows, không phải dung lượng riêng tuyệt đối của Docker.

**G. Bảo toàn hệ thống**

Đối chiếu cuối tại [preservation][preservation]: **179 container contracts/running
states và51 protected hashes giữ nguyên**. Active9/9healthy, OLD Risk/GeoIP=false;
legacy/PD-R19/flows/V5/pins/locks không đổi. Không active checkpoint, account reset,
GCP/public changes, commit/push. HEAD vẫn b0eaca9; thay đổi Java có từ trước giữ nguyên.
Lane đã về BASELINE,9 services dừng;2 restore clones mới dừng;0 operation dở.

**H. Packet owner review**

[Packet JSON PENDING](active-risk-cutover.PENDING.json), SHA256
`5b3c017e36bc3df9dcd1213dde9e312ee02b0887402df578ef7b43b08a381314`.
Packet khóa code/config/dataset và exact active contracts; không executable,
không tạo owner signature/approval và không thay proposal cũ.

Active proposal SHA256:
`0e73318230304040434ce0da03fa812ec61e486ccd9e76dd636e32ad05027b88`.
Rehearsal descriptor SHA256:
`56e4bfcf4c6d07f47a280aab4c5c8089514de468a333d4700ee82b3493523fee`.

NEW `sha256:1ec3c4db626d6c232ca9a30c61188d69e883d40eb0005c29bd0d15921258686a`;
OLD/rollback `sha256:3f540f3de29a4ac69ec916a81d153b8d4befd9238c9c06b26b9b9f0f2b843571`.
Đây là local Linux/amd64 image identities, không suy thành signed provenance.

Dataset `20261111T154359Z-a25e6a9fc2b8`, readonly City/ASN; không mount GeoIP.conf.
B0 giữ bốn weights0.25, HALF_UP2, thresholds40/75, N50/50/100; country lists rỗng.
Trusted CIDR198.51.100.0/25; high203.0.113.0/24 và10.253.245.27/32 là fixture/local
policy được giữ nguyên, không là policy GCP. Chỉ GeoIP bật theo proposed override.
Delta: UID10001:10001, rootfs readonly, cap-dropALL, no-new-privileges, tmpfs/tmp,
640MiB, readonly config/MMDB, không Risk port; TLS/CRL/JWT giữ nguyên.

Trước APPLY cần owner-authorized active context, lock/maintenance + checkpoint
active **mới**, encrypted3 schemas/Redis/8configs/runtime/manifest/dataset refs,
independent restore-verify và tuổi<30phút. Không dùng checkpoint disposable.
Rollback chỉ OLD/config với CURRENT data; giữ generations/pending/revocations/
audit/credentials, data restore phải được duyệt riêng. Dự trù maintenance15–20phút,
rollback3–5phút theo máy local, không là cam kết Cloud.

Residuals: D-10 SSO/refresh pending và access JWT window/fresh ADMIN MFA/session
choices không đổi; public-browser-peer GeoIP, host restart, signed provenance và
D-17/G8 còn mở. Packet local Risk không chấp nhận CVE hoặc cấp public GO.
Active checkpoint **NOT_CREATED**. Phải có authorization mới ràng buộc exact
descriptor/hash, project, images, code/config/dataset, maintenance, checkpoint,
rollback và expiry; planning/disposable approval không thay thế.

**Remaining blocker chính xác:** maintenance logic đã có runtime evidence trên
disposable, nhưng executor ghi vẫn hard-code lane đó. **Mutable active execution
context chưa được triển khai/review**, không chỉ thiếu một field APPROVED. Cần
binding active được review trước, rồi authorization riêng cho active maintenance/
backup và checkpoint thật. Chưa được gọi đây là active APPLY-ready. Daemon test
vẫn NOT_VERIFIED theo giới hạn owner; không suy thành PASS hoặc bỏ G8.

**I. Gates**

| Gate | Kết quả | Phạm vi |
|---|---|---|
| MAINTENANCE_ADAPTER | PARTIAL | Logic/fence/intent disposable PASS; active binding chỉ read-only, mutable context còn thiếu |
| ROLLBACK_INTERRUPTION_RUNTIME | PASS | Hai crash thật/recovery/idempotence/TLS/current security state |
| PROMOTED_RESTART | PARTIAL | Controller cold restart PASS; daemon/Windows NOT_VERIFIED |
| ACTIVE_CHECKPOINT_READINESS | PARTIAL | Workflow/independent restore PASS; active checkpoint NOT_CREATED, cần approval/context riêng |
| MANIFEST_VALIDATION | PASS | Active proposal immutable PASS; packet PENDING/non-executable |
| ACTIVE_RUNTIME_UNCHANGED | PASS | 179 contracts/running states,51 hashes; active9healthy |

[Gates JSON][gates] và [final receipt][final] tách technical evidence với owner
approval. **Dừng sau targeted remediation; active cutover vẫn NO-GO.**

[unit]: ../../target/full-function-20261111b/phase23a-fix/unit-tests.json
[runtime]: ../../target/full-function-20261111b/phase23a-fix/runtime.json
[attempt]: ../../target/full-function-20261111b/phase23a-fix/attempt-01-failure.json
[held]: ../../target/full-function-20261111b/phase23a-fix/recovered-checkpoint.json
[binding]: ../../target/full-function-20261111b/phase23a-fix/active-maintenance-review.json
[preservation]: ../../target/full-function-20261111b/phase23a-fix/preservation.json
[storage]: ../../target/full-function-20261111b/phase23a-fix/storage.json
[final]: ../../target/full-function-20261111b/phase23a-fix/final-receipt.json
[gates]: ../../target/full-function-20261111b/phase23a-fix/acceptance-gates.json
