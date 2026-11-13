# Phase 2.3A — executor và disposable rehearsal

12/11/2026, Asia/Saigon. **Rehearsal hoàn tất; chưa cutover active.**
Phạm vi ghi duy nhất: `zt-full-function-phase2-restore`, synthetic state được giữ
lại từ Phase2. Không cấp owner approval. D-17 **PENDING**, G8 **INTERNET_NO_GO**.

**A. Kiến trúc và file thay đổi**

- [promotion_executor.py](promotion_executor.py): scope ceiling, signed request,
  operation lock, encrypted checkpoint, independent restore, apply/rollback,
  state/journal, status/restart/stop/recover.
- [promotion_rehearsal.py](promotion_rehearsal.py): harness **TEST ONLY**, request
  signer riêng, resume theo receipt, crash injection và preservation checks.
- [promotion_verify.py](promotion_verify.py): HTTPS/browser và continuity checks
  chỉ trong synthetic lane; credentials/OTP/recovery codes không xuất vào receipt.
- [test_promotion_executor.py](test_promotion_executor.py):26 tests mới.
- [risk_promotion.py](risk_promotion.py): thêm CLI routing tới executor scoped;
  default active plan/validate và cơ chế chặn mutation vẫn giữ nguyên.
- README, docs index và master roadmap cập nhật kết quả. Không sửa Java/SPI/flow,
  V5, proposal v1/schema, release pins/locks hoặc guard của `operate.py` trong lượt này.

**B. Authorization và operation lock**

Ed25519 request ràng buộc project, manifest SHA, operation, old/new image,
config/dataset SHA, maintenance writers, checkpoint, rollback và recovery target.
TTL tối đa600s, one-use ledger, chặn stale/replay/mismatch/tamper. Signer chỉ là
`TEST_HARNESS_CURRENT_USER_REHEARSAL_ONLY`, không phải chữ ký owner.
Compiled scope từ chối active ngay cả khi test signature hợp lệ; không có flag,
environment variable hoặc field manifest để mở quyền đó.

OS-exclusive lock; state/journal HMAC, atomic replace + file flush/fsync. Gián đoạn
chặn normal mutations tới khi có request recovery mới đúng scope. Không coi đây
là kiểm chứng mất điện vật lý hay hệ thống phê duyệt active đã hoàn thiện.

48 tests controller cũ PASS được giữ;26 tests executor PASS trên code cuối:
**74 tests phân biệt**, không cộng lặp receipt68 và receipt26.
[Unit evidence][unit] · [legacy48 + executor20][tests]. Wrong-project dùng unit
checks thật của verifier với Docker mock; replay/stale và writer conflict có
kiểm runtime thực trong lane disposable. [Writer conflict receipt][conflict];
fixture chỉ chạy sleep, không mount database và bị chặn trước quiescence/journal.

**C. Backup-only**

Quiesce6 owned writers và stop Redis, dump3 schema School/Keycloak/Risk, archive
Redis AOF và8 config volumes. AES-256-GCM, authenticated scope/manifest/label;
key riêng, NTFS ACL chỉ current owner + SYSTEM. SQL/archive plaintext chỉ ở RAM.
Runtime contracts có thể chứa secret được giữ **bên trong ciphertext**.
Finally resume đúng service trước đó đang chạy; crash cần explicit recovery.

Checkpoint cuối `4bb39d40b520420d88aeba7584c64dde`:12 encrypted objects gồm SQL,
Redis,8 configs, runtime contract và execution manifest; dataset được tham chiếu
bằng exact hashes. Key ở vùng private riêng với ciphertext, không đưa vào Git.
Đây là checkpoint **disposable**, không dùng nó làm backup active.
[Final checkpoint evidence][checkpoint].

**D. Restore verification**

Restore thật vào10 volumes mới và2 container MySQL/Redis mới, network `none`,
không publish port. So khớp15 bảng trọng yếu, canonical data dump của **toàn bộ
bảng trong cả3 schema**, V5 checksum661092940, Redis archive member hashes + TLS
health sau boot,8 config archives và runtime/manifest đã giải mã. Giữ nguyên
entrypoint và TLS hostname verification; không tắt TLS/CRL để test qua.

Không boot lại một full9-service stack trên storage vừa restore trong lượt này;
full-stack restore evidence Phase2 được reuse. Không tuyên bố đã kiểm lại mọi
application grant/host-disaster scenario. Storage thử và failed attempts được
giữ lại, container mới đều đã dừng; không cleanup/prune.

**E. Apply rehearsal**

Exact OLD → NEW Risk, không recreate8 container còn lại; chỉ controlled stop/start.
Fresh independently verified checkpoint <30min bắt buộc. Candidate chạy UID
`10001:10001`, rootfs read-only, drop ALL capabilities, no-new-privileges,
tmpfs `/tmp`,640MiB, readonly config/City+ASN mounts, chỉ core network, không port.
Không bootstrap/import/migration trong apply. [Runtime hardening/GeoIP][runtime].

Ingress trong lane không có host port và chỉ được dùng bởi internal test helper.
Service được start để chạy browser smoke trước commit. **Chưa có adapter giữ
maintenance cho active ingress có loopback port**; không dùng executor này để
cutover active hoặc suy rằng public traffic được bảo vệ bởi cùng cơ chế.

**F. Rollback và security-state continuity**

Rollback thật về exact OLD, dùng **CURRENT databases/Redis**, không restore
checkpoint. Sau checkpoint đã tăng generation của subject synthetic lên1,
đặt pending và revoke trust; sau promoted restart/rollback vẫn giữ generation,
pending, audit, revoked trust và credential hashes của3 fixture users.
Stale-generation registration bị từ chối409,
pending Risk DENY. Không reset account DoAn/active. OLD vẫn có hạn chế
deadlock/GeoIP=false; rollback không sửa những hạn chế đó.
[Rehearsal cases][rehearsal] · [Runtime checks][checks].

**G. Crash/interruption**

Ba child processes bị kết thúc thật bằng `os._exit(86)` tại QUIESCED,
NEW_CREATED và COMMITTED. Recovery trước commit về BASELINE; sau durable commit
giữ PROMOTED và cần rollback riêng. Request recovery mới cho operation đã xử lý
trả idempotent no-op; replay chính request cũ vẫn bị từ chối. Không import DB.

Ba lỗi restore tooling ban đầu (stdin tar, entrypoint, hostname TLS của clone)
được sửa và recovered bằng journal; independent restore cuối PASS. Evidence
attempt cũ giữ nguyên, `final-receipt.json` xác nhận không còn operation dở.
Không lặp full CI/rehearsal hoặc scan/build image.

Review code cuối phát hiện recovery của rollback bị gián đoạn chưa phân biệt với
apply. Đã thêm nhánh riêng: finish rollback tới OLD hoặc abort trước commit về
recorded NEW, luôn giữ CURRENT storage; committed rollback muốn promote lại cần
APPLY mới.4 unit tests PASS; **rollback-crash runtime riêng chưa chạy**, không
suy từ3 crash tests của apply. Preflight chỉ chấp nhận exact known writers trong
journal và vẫn cấm hai writer đang chạy đồng thời.

**H. Post-promotion restart**

Cold stop/start9 services thật chọn durable promoted NEW; không quay về OLD.
Status/validate hỗ trợ BASELINE/PROMOTED, unknown/partial có recovery path.
Legacy `operate.py` guard vẫn fail-closed. **Chưa shutdown Windows hoặc restart
Docker daemon thật**, vì sẽ ảnh hưởng active; không coi cold service restart là
host-reboot acceptance đầy đủ. [Stopped final status][status].

**I. GeoIP/Adaptive Authentication regression**

3 promoted runtime traces: real public-IP service context lookup countryUS,
ASN15169, N50 ×0.25 =12.50; ASN/city chỉ metadata. B0 trọng số0.25, thresholds40/75,
country lists rỗng và CIDR precedence giữ nguyên. Mandatory15→STEP_UP_MFA,
LOW0→ALLOW, MEDIUM40→STEP_UP_MFA, HIGH77.5→DENY.
Real browser HTTPS/CRL, OTP, PKCE S256, native Recovery Code trên actor synthetic
mới; STUDENT own grades200/admin403, ADMIN users200. Continuity pending/reset
không bị mất. Reuse concurrency/deadlock, JWT, ADMIN Reset MFA và flow evidence
đã PASS; không tuyên bố đã chạy lại các suites đó.

**Public-browser GeoIP vẫn NOT_VERIFIED**: Docker peer private/NAT. Service test
IP công khai không thay thế browser-peer E2E. GeoIP acceptance tổng thể5/7 PASS
trước đây không tự nâng thành7/7.

**J. Bảo toàn active**

[Final receipt][final] và [preservation][preservation]:167 container có sẵn giữ
identity/image/config/mount/network contracts; running state cuối khớp trước test.
14 receipts/markers và6 protected file hashes giữ nguyên. Active9/9healthy,
OLD Risk/GeoIP=false, không pause/backup/reset active. Lane disposable9 services
đã dừng lại; không còn operation RUNNING. Legacy DoAn/PD-R19 được bảo toàn.
HEAD `b0eaca90589a21dbe34e5b06d5c72883bf1e791d`; không commit/push/worktree,
GCP/public-port changes hoặc owner approval được tạo.

**K. Packet review trước active cutover — CHƯA AUTHORIZED**

| Nội dung | Exact scope/giá trị |
|---|---|
| Active project | `zt-full-function-20261111b` |
| Active proposal v1 SHA256 | `0e73318230304040434ce0da03fa812ec61e486ccd9e76dd636e32ad05027b88` — vẫn PENDING, execution disabled |
| Rehearsal execution manifest SHA256 | `56e4bfcf4c6d07f47a280aab4c5c8089514de468a333d4700ee82b3493523fee` — **chỉ disposable**, không là active authorization |
| Proposed NEW | `sha256:1ec3c4db626d6c232ca9a30c61188d69e883d40eb0005c29bd0d15921258686a` |
| OLD/rollback | `sha256:3f540f3de29a4ac69ec916a81d153b8d4befd9238c9c06b26b9b9f0f2b843571` |
| Dataset | `20261111T154359Z-a25e6a9fc2b8`, exact City/ASN hashes trong proposal; mount pair readonly, không mount license key |
| Backup bắt buộc | Checkpoint **active mới**:3 schema, Redis,8 configs, encrypted runtime+manifest, dataset refs; independent restore-verify; không lấy checkpoint disposable thay thế |
| Rollback | Exact OLD/config, CURRENT DB/Redis; giữ generations/pending/revocations/audit/credentials; data restore là quyết định disaster recovery riêng |
| Downtime quan sát | Backup~140s, independent restore~79s, apply~136s, rollback~121s; promoted stop/start~155s ở máy local. Dự trù maintenance10–15phút gồm preflight/verification; không là cam kết host khác |
| Residuals | D-10 SSO/refresh pending boundary, access-JWT window, fresh ADMIN MFA/session8h choices chưa đổi; signed artifact provenance chưa VERIFIED; public-browser GeoIP, real host restart và D-17/G8 còn mở |

**Boundary chính xác:** executor hiện từ chối active theo code. Cần active adapter
và maintenance/restart integration được review, descriptor active có digest được
chốt, cơ chế owner authorization riêng và checkpoint active mới trước APPLY.
Chỉ duyệt report hoặc đổi proposal PENDING không đáp ứng boundary đó.
Nhánh rollback-interruption recovery cuối mới có unit evidence, cần targeted
runtime acceptance trước khi xem xét active readiness.
**Bước owner duy nhất:** review packet này và cấp phạm vi authorization mới cho
giai đoạn active; actual cutover chỉ sau khi owner duyệt exact active descriptor
và các điều kiện trên. Không yêu cầu chọn lại policy D-10 trong lượt này.

**L. Gates cuối**

| Gate | Kết quả | Giới hạn |
|---|---|---|
| EXECUTOR_IMPLEMENTATION | PARTIAL | Disposable operations PASS; rollback-interruption nhánh cuối unit-only; active adapter chưa triển khai/authorized |
| APPROVAL_ENFORCEMENT | PASS — rehearsal boundary | Test signer; không có owner signature được tạo |
| BACKUP_RESTORE_REHEARSAL | PASS | Independent DB/Redis/config storage; giới hạn ở D |
| APPLY_REHEARSAL | PASS | Exact image/hardening, no published port |
| ROLLBACK_REHEARSAL | PASS | CURRENT state continuity |
| POST_PROMOTION_RESTART | PARTIAL | Promoted cold stop/start PASS; Windows/daemon restart NOT_VERIFIED |
| GEOIP_B0_REGRESSION | PASS — targeted local scope | Public-browser GeoIP NOT_VERIFIED |
| ACTIVE_RUNTIME_UNCHANGED | PASS | Active9/9healthy, OLD/GeoIP=false |

**Dừng sau rehearsal. Active cutover chưa GO; D-17 PENDING, G8 INTERNET_NO_GO.**

[unit]: ../../target/full-function-20261111b/phase23a/executor-unit-tests.json
[tests]: ../../target/full-function-20261111b/phase23a/tooling-tests.json
[checkpoint]: ../../target/full-function-20261111b/phase23a/final-checkpoint-verification.json
[runtime]: ../../target/full-function-20261111b/phase23a/geoip-b0-runtime.json
[rehearsal]: ../../target/full-function-20261111b/phase23a/rehearsal.json
[checks]: ../../target/full-function-20261111b/phase23a/checks
[status]: ../../target/full-function-20261111b/phase23a/stopped-status.json
[final]: ../../target/full-function-20261111b/phase23a/final-receipt.json
[preservation]: ../../target/full-function-20261111b/phase23a/preservation.json
[conflict]: ../../target/full-function-20261111b/phase23a/conflicting-writer.json
