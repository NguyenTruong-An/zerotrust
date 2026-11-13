# Active operation authorization — protocol, chưa có approval

Tài liệu giao thức, **không phải authorization**. Không tạo signer/private key,
anchor hoặc signed active request trong Phase2.3A-ACTIVE-CONTEXT. Test signers chỉ
ở RAM và không được enrol vào anchor thật.

Owner có thể dùng [owner_authorize.py](owner_authorize.py) trong PowerShell riêng:
`setup`, rồi `sign backup-only`, và `sign restore-verify --checkpoint <exact-id>`.
Helper chỉ chuẩn bị/ký theo xác nhận tương tác của owner, không gọi executor;
key PKCS8 mã hóa/ACL ngoài Git. Setup/sign ban đầu chỉ backup/restore. Với
[single owner cutover runbook](OWNER_LOCAL_CUTOVER_RUNBOOK.md), `scope cutover`
và `sign-cutover` yêu cầu review/xác nhận riêng cho APPLY/restart/rollback/recover;
`scope recovery` chỉ cho recovery khi có operation dở. Controller/descriptor/
packet giữ nguyên; Codex không chạy setup/scope/sign thay owner.

**Binding cố định**

- Project: `zt-full-function-20261111b`.
- Descriptor: [risk-active-execution.v1.json](risk-active-execution.v1.json).
- Packet: [active-risk-cutover.PENDING.v2.json](active-risk-cutover.PENDING.v2.json).
- Anchor public-key do owner kiểm soát, ngoài Git:
  `<owner-home>/.zerotrust-owner/active-risk/anchor.json`.
- State/key/lock/journal active: `target/full-function-20261111b/promotion-private`.
  Chỉ khởi tạo sau khi một request đã xác minh thành công. Không tạo trong lượt này.
- Disposable tiếp tục dùng root/signature/descriptor cũ; không thể authorize active.

**Owner trust anchor: các field cần có**

Owner enrol public key Ed25519 raw32bytes/base64 của signer riêng, giữ private key
ngoài Git/Codex logs. Anchor có `kind=OWNER_CONTROLLED_ACTIVE_ONLY`, `project`,
`owner_sid` đúng descriptor, `issuer=OWNER_EXPLICIT_ACTIVE_AUTHORIZATION`,
`descriptor_sha256`, `packet_sha256`, `expires` (Unix seconds), `operations`
(allowlist), `public_key`, `public_key_sha256`. Runtime chỉ đọc đường dẫn cố định;
không có CLI/env override để chọn test anchor. File **và parent** phải có protected
Windows ACL chỉ owner SID + SYSTEM. Không dùng test key hoặc key của Keycloak.

Anchor là trust setup do owner thực hiện; nó không thay chữ ký riêng cho từng
operation. Đổi descriptor/packet/code cần owner review và enrol đúng digests mới.

**Signed envelope**

Đúng hai field: `payload`, `signature` (Ed25519/base64 của canonical payload).
Canonical JSON là UTF-8 từ `json.dumps(payload, sort_keys=True, separators=(',', ':'))`.
Không log/export private key hoặc signed capability ra chat.

| Payload field | Ràng buộc |
|---|---|
| id | Unique32lowercase hex; ledger từ chối replay |
| project / operation | Exact active project và đúng method được gọi/anchor allowlist |
| descriptor_sha256 / packet_sha256 | Hash exact bytes của hai artifact đã review |
| old_image / new_image / rollback | Exact pins; rollback=OLD |
| config_sha256 | SHA256 canonical descriptor.proposed |
| dataset_sha256 / policy_sha256 | SHA256 canonical descriptor.geoip / policy |
| maintenance | Đúng thứ tự ingress,gateway,frontend,backend,risk,keycloak |
| checkpoint_rules_sha256 | SHA256 canonical descriptor.checkpoint_rules |
| checkpoint | UUIDhex32 cho apply/restore-verify; null cho operations khác |
| issued / expires | Unix seconds, integer, TTL≤600s, expired/future sai bị từ chối |
| issuer / owner_sid | Exact owner issuer/SID, không nhận TEST_HARNESS issuer |
| recover_of / recover_target | Chỉ recover có original operation UUID; BASELINE/PROMOTED/STOPPED theo engine contract |

Authorization admission có trước private initialization, project-lock writes và
Docker mutations; verifier kiểm lại dưới lock trước one-use journal. Capability
chỉ sống trong operation, tách execution context/thread và bị thu hồi trong finally.
Crash phải có request recovery mới, không dùng lại envelope đã consume.

**Scope tiếp theo cần owner duyệt riêng**

1. `backup-only`: exact active descriptor/packet, maintenance window, consistent
   School/Keycloak/Risk/Redis checkpoint, config/runtime/GeoIP references, AES-GCM
   key tách riêng, resume đúng running intent. Không đổi Risk image/GeoIP.
2. `restore-verify`: request mới bind checkpoint ID vừa tạo, chỉ fresh independent
   private storage; không import vào active databases. Gate verified/fresh<30phút
   vẫn bắt buộc trước APPLY tương lai.
3. Nếu operation gián đoạn: approval/ticket `recover` riêng, bind original ID và
   recovery target; không mặc nhiên cấp quyền APPLY/rollback/restart/stop.

Không cấp APPLY trong scope trên. Không approve D-17/G8 hoặc daemon/Windows test.
Actual active rollout và host restart phải có authorization riêng sau đó.
