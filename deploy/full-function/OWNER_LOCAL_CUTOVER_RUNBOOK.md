# Owner runbook — local Risk cutover

**Chỉ owner chạy trong PowerShell riêng. Chưa có lệnh nào dưới đây được Codex ký
hoặc thực thi. GCP/public vẫn NO-GO; D-17/G8 không đổi.** Dùng images/dataset và
receipts126tests/3context cases/rollback/restore/MFA/GeoIP đã có; không rebuild,
full-suite, worktree, cleanup, sửa D-10/Network v2 hoặc Lab/PD-R19.

**1. Review trước khi tạo checkpoint**

- [Descriptor](risk-active-execution.v1.json):
  `50f92863d913eb30199d2f1aebde8204a3520c3c43bb3d85d65b8fed7f497b2d`.
- [Packet PENDING](active-risk-cutover.PENDING.v2.json):
  `f94c9d96c7b2b650d5e375ad99b4eaa08f4ed026d333e9152ffe5b781ce304d3`.
- NEW: `sha256:1ec3c4db626d6c232ca9a30c61188d69e883d40eb0005c29bd0d15921258686a`.
  OLD/rollback: `sha256:3f540f3de29a4ac69ec916a81d153b8d4befd9238c9c06b26b9b9f0f2b843571`.
- Review luôn kế hoạch APPLY/restart/rollback/recovery ở4–6 **trước T0** để không
  tốn cửa sổ30phút. Review kế hoạch không phải ký authorization cho execution.
- Mỗi operation cần owner duyệt và ký riêng; allowlist không tự execute hoặc
  thay chữ ký. Key/passphrase giữ ngoài Git/chat/transcript; không reset key cũ.

Khởi tạo các biến và hàm tiện ích trong cùng cửa sổ. Hàm chỉ chạy khi owner gọi:

```powershell
$ErrorActionPreference = 'Stop'
$ztRepo = '<repo-root>'
$ztPy = "$ztRepo\target\full-function-20261111\tools\Scripts\python.exe"
$ztAuth = "$ztRepo\deploy\full-function\owner_authorize.py"
$ztExec = "$ztRepo\deploy\full-function\risk_active_context.py"
$ztOwner = '<owner-home>\.zerotrust-owner\active-risk'
function Confirm-ZtExit { if ($LASTEXITCODE -ne 0) { throw 'Dừng: kiểm tra status/journal; không retry request mù.' } }
function Invoke-ZtApproved([string]$op) {
    $request = (Get-Content "$ztOwner\latest-$op.path" -Raw).Trim()
    $result = & $ztPy -B $ztExec $op --context active --request $request
    Confirm-ZtExit
    $result | Set-Content "$ztOwner\result-$op.json" -Encoding UTF8
    $result | ConvertFrom-Json
}
& $ztPy -B $ztAuth review; Confirm-ZtExit
# Chỉ lần đầu, nếu owner chưa có key/anchor:
& $ztPy -B $ztAuth setup; Confirm-ZtExit
```

Setup tạo key mã hóa/owner-SYSTEM ACL và signing scope backup/restore; không ký
hoặc chạy active operation. Nếu key/anchor đã có, **bỏ dòng setup**, không overwrite.

**2. Owner approve BACKUP-ONLY — bắt đầu maintenance window**

```powershell
& $ztPy -B $ztAuth scope backup; Confirm-ZtExit
& $ztPy -B $ztAuth sign backup-only; Confirm-ZtExit
$ztBackup = Invoke-ZtApproved 'backup-only'
$ztCheckpoint = $ztBackup.id
$ztDeadline = [DateTimeOffset]::FromUnixTimeSeconds([long][Math]::Floor($ztBackup.created)).AddMinutes(30)
```

Owner gõ các confirmation helper hiển thị và nhập passphrase ẩn. Executor đóng
ingress/quiesce owned writers, checkpoint nhất quán mã hóa và verified resume.
**T0 là `checkpoint.created`**, không phải lúc ký hay backup return. Ghi deadline.

**3. Owner approve RESTORE-VERIFY riêng — chạy ngay**

```powershell
& $ztPy -B $ztAuth sign restore-verify --checkpoint $ztCheckpoint; Confirm-ZtExit
$ztRestore = Invoke-ZtApproved 'restore-verify'
if ($ztRestore.status -ne 'PASS' -or $ztRestore.checkpoint -ne $ztCheckpoint) { throw 'Restore chưa PASS; không APPLY.' }
```

Restore chỉ dùng fresh independent disposable storage, không import vào active.
Nhắm hoàn tất2–3 trong~5–8phút; chưa cấp quyền APPLY.

**4. Owner review/ký APPLY riêng, rồi mới execute**

Chỉ khi restore PASS, active9healthy OLD/GeoIP=false, không journal pending/drift,
TLS/CRL/dataset/code đúng và còn **ít nhất10phút** trước deadline:

```powershell
& $ztPy -B $ztAuth scope cutover --checkpoint $ztCheckpoint; Confirm-ZtExit
& $ztPy -B $ztAuth sign-cutover apply --checkpoint $ztCheckpoint; Confirm-ZtExit
# Chỉ owner execute sau confirmation SIGN APPLY:
if ([DateTimeOffset]::UtcNow -ge $ztDeadline.AddMinutes(-10)) { throw 'Không đủ10phút dự phòng; không APPLY.' }
$ztApply = Invoke-ZtApproved 'apply'
```

`scope cutover` chỉ owner mở allowlist apply/restart/rollback/recover, không ký
chung hay thực thi. Mỗi lệnh vẫn cần request riêng. Helper kiểm checkpoint còn
>10phút dự phòng cả trước/sau owner review; engine vẫn giữ gate gốc: verified,
tuổi<1800s tại APPLY admission. Nhắm APPLY trước T0+15phút, không đợi sát30phút.

Request có TTL10phút, một lần dùng, ký sát lúc chạy; kiểm trước admission và dưới
lock. Sau khi được nhận/consume, TTL không phải timer tự kill operation giữa
maintenance. Mỗi service có timeout; lỗi/gián đoạn phải theo journal/recovery.
Backup có verified resume, restore không tự giữ maintenance suốt30phút; APPLY
đóng ingress lại và chỉ mở sau internal verification + durable commit.

**Checkpoint không đủ tươi:** không ký/chạy APPLY, không sửa timestamp hoặc gate.
Nếu không có operation pending, owner `scope backup` và duyệt cycle2–3 mới; giữ
checkpoint cũ, không cleanup. Nếu APPLY đã ghi journal rồi bị từ chối, resolve
pending qua6 trước; không chạy backup/restart chồng lên. Ticket expired/consumed
không tái dùng; ký ID mới chỉ khi owner duyệt lại và checkpoint vẫn đủ tươi.

**5. Targeted checks sau APPLY — không full suite**

- Health/TLS/CRL; exact NEW, readonly GeoIP mounts, một Risk writer/private ports.
- Real service lookup: trace đã lọc có source GEOIP/country, N và0.25×N; fixture
  public lookup defaultN50 đóng góp12.5. Docker/NAT không chứng minh public-browser E2E.
- Fresh browser MFA; ADMIN smoke, STUDENT own grades200/ADMIN API403. Không reset
  OTP hoặc đổi flow/trust để test xanh; dùng account đã có, không log secrets.
- Check V5/data/security-state continuity, volumes giữ nguyên.
- Owner ký restart riêng, rồi recheck NEW/health/persistence:

```powershell
& $ztPy -B $ztAuth sign-cutover restart; Confirm-ZtExit
$ztRestart = Invoke-ZtApproved 'restart'
```

Không restart Docker Desktop/WSL/Windows. B0, SPI/MFA, ADMIN/STUDENT và CURRENT
data/security state giữ nguyên; không coi local PASS là GCP/public GO.

**6. Lỗi: dừng chuỗi, recovery/rollback theo trạng thái**

Read-only status: `& $ztPy -B $ztExec status --context active`.

| State | Owner approval cần có |
|---|---|
| APPLY partial, chưa commit | Recover original operation ID về BASELINE/OLD |
| APPLY đã durable commit, journal chưa DONE | Recover PROMOTED để hoàn tất; không fake precommit rollback |
| Known committed PROMOTED, journal sạch, reviewed running intent | Rollback riêng về OLD/config, giữ CURRENT DB/Redis |
| Drift/unknown/hard failure, recovery không verified | Giữ maintenance; dừng, owner review; không compose up/reset/import snapshot để ép PASS |

Pending operation: owner chọn đúng UUID từ status/journal và target từ bảng.
Nếu cần từ backup-only scope, chỉ mở recovery scope; không cần checkpoint verified:

```powershell
& $ztPy -B $ztAuth scope recovery; Confirm-ZtExit
# Owner tự điền UUID/target đã review, không dùng placeholder:
& $ztPy -B $ztAuth sign-cutover recover --recover-of $ztInterruptedId --recover-target $ztTarget; Confirm-ZtExit
$ztRecovery = Invoke-ZtApproved 'recover'
```

Rollback khi đã PROMOTED/journal sạch: nếu anchor đang recovery-only, owner
`scope cutover` **không checkpoint** để duyệt lại allowlist, rồi:

```powershell
& $ztPy -B $ztAuth scope cutover; Confirm-ZtExit
& $ztPy -B $ztAuth sign-cutover rollback; Confirm-ZtExit
$ztRollback = Invoke-ZtApproved 'rollback'
```

Không tự restore data cũ: generations/pending/revoked devices/audit/credentials
hiện tại phải được giữ. Nếu rollback/recovery preconditions không xác minh được,
dừng; runbook không bảo đảm tự rollback từ arbitrary unknown/hard-stopped state.

**Remaining gates:** owner chưa ký/cấp quyền ở lượt chuẩn bị này; checkpoint phải
được tạo và verified thực tế. Không có controller change cần thiết cho known-state
workflow trên. D-17 PENDING, G8/GCP/public NO-GO; không ký thay owner, commit/push.
