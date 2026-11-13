# Phase 2.3A-ACTIVE-CONTEXT — implementation và review packet

12/11/2026, Asia/Saigon. **Gap implementation active context đã đóng.**
Technical capability được kiểm bằng unit/disposable; **active mutations0**,
checkpoint/private active chưa tạo, owner authorization chưa cấp. D-17 PENDING,
G8 INTERNET_NO_GO. Không restart daemon/Windows.

**A. Root cause**

Engine cũ cố định project, descriptor, signer, core network, private keys/lock và
fixture paths của disposable. Chỉ bỏ scope ceiling sẽ trộn state/authorization
giữa hai môi trường và không xử lý đúng ingress có loopback ports. Các report/
receipts cũ và packet5b3c… được giữ nguyên, chỉ là checkpoint lịch sử.

**B. Code/descriptor changes**

- [promotion_context.py](promotion_context.py): hai fixed contexts, isolated module
  namespaces, guarded mutable methods/Docker backend, strict active descriptor,
  owner signature verifier, virtual read-only baseline, future authorized private
  initialization. Không keygen/sign/approve owner request.
- [risk_active_context.py](risk_active_context.py): CLI mặc định read-only preflight;
  context chỉ `active`/`disposable`, không nhận arbitrary project/descriptor/anchor.
- [active_risk_verify.py](active_risk_verify.py): future internal TLS/CRL/service
  JWT/B0 verification không mở ingress; chỉ ephemeral Risk-only history/evaluation,
  không tạo/reset Keycloak account, credential hoặc Trusted Device registration.
- [prepare_active_context.py](prepare_active_context.py): offline/read-only binding
  preparation, từ chối regenerate khi active private root/owner anchor đã tồn tại.
- Engine thêm EXPECTED_KIND/scope callback; maintenance dùng scope của engine
  đang chạy. `risk_promotion.py` fence legacy operations khi dedicated active
  private root đã được owner-authorized khởi tạo; không revert cấu hình cũ.
- [test_promotion_context.py](test_promotion_context.py), [context_rehearsal.py](context_rehearsal.py),
  [authorization protocol](ACTIVE_OWNER_AUTHORIZATION.md), report/index/roadmap.
  Không sửa Java/SPI/flow/B0/V5/release locks hoặc image.

**C. Isolation architecture**

Hai context load cùng reviewed engine vào **module dictionaries riêng**, không
patch globals của legacy executor hoặc context còn lại. Active bind exact project/
9baseline IDs/contracts/networks; lock/key/journal/ledger ở `promotion-private`.
Disposable giữ nguyên descriptor56e4… và root Phase2.3A cũ. Code/packet/descriptor
và metadata source hash được kiểm; boolean/đổi project/path không cấp quyền ghi.
Known loopback ports chỉ được phép trên đúng ingress/CRL IDs; Risk/DB/Redis và
restore clones không được publish. Maintenance logic/checkpoint/rollback engine
được reuse, không fork business/auth behavior.

**D. Authorization enforcement**

Future active operation yêu cầu Ed25519 owner signature, anchor ngoài Git đúng
fixed path + owner/SYSTEM-only ACL, reviewed descriptor và packet SHA. Payload
bind operation/project/images/config/dataset/policy/writers/checkpoint rules/
rollback/expiry/one-use ID. Verification có trước mọi mutation; kiểm lại dưới
project lock. Direct Docker mutation không có operation grant bị chặn. Grant
tách thread/context và bị thu hồi khi exit; stale/replay/mismatch/TEST issuer
bị từ chối. **Không có production owner anchor/key/request được tạo hoặc ký trong lượt này.**

Missing-approval/wrong-active-scope tests dùng mocked Docker và signer TEST trong
RAM; không gọi native active mutator để chứng minh rejection.

**E. Active preflight — READ ONLY PASS**

[CLI preflight][preflight]:9/9healthy, exact OLD/GeoIP=false; NEW Linux/amd64 sẵn
có; exact proposal/receipts/config/source/City+ASN release/B0/TLS/CRL/networks,
V5 checksum661092940, rollback destination đúng; không operation pending hoặc
Risk writer cạnh tranh. Chỉ đọc metadata/config/hash và SELECT V5; không gọi
account APIs, DML hoặc active verification helper. Active state/lock/checkpoint
chưa khởi tạo; preflight không cấp cutover permission.

[Backup headroom][headroom]:10 owned volumes khoảng225,7MiB theo Docker; C: khoảng
74,7GiB lúc preflight, mẫu đo cuối66,45GiB. Ước lượng thận trọng4×logical volume size +5GiB scratch (~5,88GiB), vẫn
giữ hard minimum15GiB/warn20GiB. Đây là estimate, không phải checkpoint đã tạo.

**F. Disposable targeted tests**

[126 tests][tests] PASS:38 context/authorization tests mới +40 common executor/
maintenance +48 controller/legacy-guard. Chỉ chạy các lớp bị đổi; không full CI,
rebuild, scan hoặc lặp GeoIP acquisition/browser/MFA suites. Signers giả chỉ RAM.

[3 runtime cases][runtime] PASS trên retained disposable:

- Restart qua namespace mới; internal verifier tương lai chạy với **mount/core
  disposable** khi ingress dừng: strict TLS/CRL, service JWT, score27.5/STEP_UP_MFA.
- Child process bị `os._exit(86)` sau STOPPED_FOR_RESTART: durable journal, OS lock
  recovery, normal restart bị từ chối khi partial, recovery mới idempotent và
  cùng envelope replay bị từ chối; current security-state witness giữ nguyên.
- Exact identity/config/B0/V5/health và một Risk writer; sau test toàn lane dừng.

Final ContextVar/thread isolation/error branches có unit evidence; native child
và [final-source admission][admission] kiểm namespace/guard cuối. Không suy ra
đã chạy active mutable operation hay daemon/Windows restart.

**G. Rollback/recovery compatibility**

Reuse hai rollback-interruption runtime receipts PROMOTED/BASELINE của
[Phase2.3A-FIX](PHASE23A_FIX.md) và backup/independent-restore receipts. Engine
operation bodies được dùng chung, giữ CURRENT DB/Redis, không auto data restore.
New-context restart/crash/recovery witness gồm School data, Keycloak credentials
và exact synthetic generation/pending/revoked trust/audit; không giảm generation
hoặc phục hồi trust cũ. Freshness<1800s/independent restore vẫn enforced; unit
case stale checkpoint bị từ chối. Không tạo checkpoint để test lại guard này.

**H. Storage**

Không pull/build, checkpoint mới, volume mới, retained container mới, worktree,
cleanup/prune. Chỉ reuse images/datasets/lane cũ và helpers transient. Số đo C:
và net delta ở [preservation][preservation]; background Windows có thể thay đổi
free space, không quy delta toàn bộ thành dung lượng của test. Owner cleanup
được hoãn; lượt này không thực hiện cleanup.

[Mẫu storage cuối][storage]: C:74,78→66,45GiB, net giảm8,33GiB trong lượt. Evidence
public mới khoảng246KiB;2 retained unit fixtures khoảng114,14MiB logical (không
phải measured physical allocation), cộng source/descriptor/docs nhỏ. Chưa xác
định phần biến động toàn máy còn lại; không khẳng định test dùng8,33GiB hay
truy tìm/cleanup ngoài scope. Vẫn trên20GiB, không có large build/restore mới.

**I. Active preservation**

[Preservation][preservation]:181 existing containers giữ identity/config/mount/
network/running states;71 protected hashes giữ nguyên. Active9healthy, OLD/
GeoIP=false. Không active private root/checkpoint/owner anchor, không reset user/
MFA, không Lab/PD-R19/GCP/public change, commit/push. Historical receipts và
old pending packet không sửa; Java change từ phase trước giữ nguyên.

**J. Technical readiness và approval tách riêng**

| Gate | Kết quả | Phạm vi |
|---|---|---|
| ACTIVE_CONTEXT_IMPLEMENTATION | PASS | Dedicated binding, guarded backend, same verified engine; không cần bỏ disposable ceiling |
| AUTHORIZATION_ENFORCEMENT | PASS | Unit signatures/scope/drift/replay, no production owner grant created |
| ACTIVE_PREFLIGHT_READ_ONLY | PASS |9healthy OLD/GeoIP=false, B0/V5/TLS/source/data/network/headroom |
| DISPOSABLE_CONTEXT_REGRESSION | PASS |126 targeted tests +3 actual runtime cases |
| ROLLBACK_RECOVERY_COMPATIBILITY | PASS scoped | Shared engine + new-context recovery; prior real rollback/restore receipts reused |
| ACTIVE_RUNTIME_UNCHANGED | PASS |181 contracts/states +71 hashes |
| ACTIVE_OWNER_AUTHORIZATION | NOT_VERIFIED | Không có owner grant; chờ phase mới |
| ACTIVE_CHECKPOINT_CREATED | NOT_VERIFIED | NOT_CREATED theo giới hạn lượt này |
| REAL_DAEMON_WINDOWS_RESTART | NOT_VERIFIED | Không thực hiện; quy trình riêng vẫn DRAFT |

Technical capability ready cho **owner-reviewed maintenance/backup phase**;
actual active execution vẫn NOT_AUTHORIZED. Không nói public/production READY.

**K. Exact next owner authorization**

Theo [protocol](ACTIVE_OWNER_AUTHORIZATION.md), owner review exact digests ở L,
enrol owner-controlled public-key anchor ngoài Git, ký ticket `backup-only` riêng
cho active maintenance/checkpoint/verified resume. Sau khi có checkpoint ID,
ticket `restore-verify` riêng chỉ cho independent disposable storage. Nếu bị gián
đoạn, ticket recover mới bind original operation/target; không tự cấp APPLY.
Owner cần duyệt riêng timeframe, checkpoint/encryption/restore scope và residuals.
Private key/secrets không gửi chat hoặc Git. Lượt này không sinh/sign thay owner.

**L. Updated review artifacts — PENDING**

- [Executable descriptor v1](risk-active-execution.v1.json), SHA256
  `50f92863d913eb30199d2f1aebde8204a3520c3c43bb3d85d65b8fed7f497b2d`.
- [Packet v2](active-risk-cutover.PENDING.v2.json), SHA256
  `f94c9d96c7b2b650d5e375ad99b4eaa08f4ed026d333e9152ffe5b781ce304d3`.
- Old active proposal SHA0e733… và packet5b3c… giữ nguyên, không đổi PENDING thành
  APPROVED. Descriptor/packet mới cũng PENDING, signature riêng là gate thực thi.
- NEW `sha256:1ec3c4db626d6c232ca9a30c61188d69e883d40eb0005c29bd0d15921258686a`;
  OLD/rollback `sha256:3f540f3de29a4ac69ec916a81d153b8d4befd9238c9c06b26b9b9f0f2b843571`.
- Dataset20261111T154359Z-a25e6a9fc2b8; readonly MMDB, no license config mount.
  B0 weights0.25/thresholds40,75, country lists rỗng/CIDR fixtures giữ nguyên.
- D-10 unchanged; D-17 PENDING, G8 INTERNET_NO_GO, signed image provenance và
  public-browser GeoIP/daemon acceptance chưa đóng. Không CVE waiver.

**Dừng tại review packet; không active backup/apply/rollback/restart/stop/recovery.**

[preflight]: ../../target/full-function-20261111b/phase23a-active-context/active-preflight.json
[headroom]: ../../target/full-function-20261111b/phase23a-active-context/backup-headroom.json
[tests]: ../../target/full-function-20261111b/phase23a-active-context/targeted-tests.json
[runtime]: ../../target/full-function-20261111b/phase23a-active-context/runtime.json
[admission]: ../../target/full-function-20261111b/phase23a-active-context/final-source-admission.json
[preservation]: ../../target/full-function-20261111b/phase23a-active-context/preservation.json
[storage]: ../../target/full-function-20261111b/phase23a-active-context/storage-final.json
