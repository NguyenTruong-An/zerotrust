# Phase 2.2 — chuẩn bị controller Risk promotion

12/11/2026 (GMT+7). **Hoàn tất phần chuẩn bị read-only; chưa có cutover.**
Active `zt-full-function-20261111b` vẫn9/9healthy, Risk cũ/GeoIP=false.
D-10 không đổi; **D-17 PENDING, G8 INTERNET_NO_GO**.

**A. File tạo/sửa**

- [risk_promotion.py](risk_promotion.py): controller `plan`/`validate`, adapter chỉ
  cho phép inspect/copy-to-stdout và một SELECT V5 cố định; không có executor ghi.
- [risk-promotion.v1.json](risk-promotion.v1.json) và
  [schema](risk-promotion.schema.json): proposal version1, exact project/pins,
  runtime/config/network witnesses, receipts, policy, dataset, health và rollback.
- [test_risk_promotion.py](test_risk_promotion.py):48test tooling offline.
- [operate.py](operate.py): guard trước mọi Compose/receipt write; từ chối legacy
  operation nếu có promoted marker, image/config/mount khác baseline hoặc Risk
  candidate/writer khác trên core, kể cả candidate đang dừng sau partial cutover.
- README/mục lục/roadmap chỉ thêm hướng dẫn và link. Không sửa Java/SPI/flow,
  release lock, `profile-images.json`, installed marker hoặc private config.

**B. Manifest cụ thể**

Project duy nhất `zt-full-function-20261111b`; version1 vẫn **PENDING/PROPOSED**,
`execution_enabled=false`. Candidate:
`sha256:1ec3c4db626d6c232ca9a30c61188d69e883d40eb0005c29bd0d15921258686a`.
Old/rollback:
`sha256:3f540f3de29a4ac69ec916a81d153b8d4befd9238c9c06b26b9b9f0f2b843571`.
Hai image local/linux-amd64 khớp; source file sửa deadlock khớp hash receipt.
Build HEAD81d6322 và current/review HEADb0eaca9 được ghi riêng, selected committed
Risk build inputs không đổi. Signed source provenance vẫn NOT_VERIFIED; không
suy thành signed release/CVE acceptance.

Dataset release `20261111T154359Z-a25e6a9fc2b8`, exact City/ASN SHA256+metadata từ
receipt Phase2.1A; chỉ đề xuất mount directory này read-only tại `/geoip`, không
mount GeoIP.conf/license key. Override GeoIP=true được ghi trong proposal, chưa áp
dụng. Read-only rootfs, cap-drop ALL, no-new-privileges, tmpfs và640MiB là **delta
đề xuất có khai báo**, không nói Risk đang chạy đã có những giới hạn đó.

`BASELINE_B0`, bốn trọng số0.25, ngưỡng40/75, N default/elevated/high50/50/100,
country lists rỗng và CIDR precedence giữ nguyên. Local CIDRs có fixture đã khai
báo; manifest khóa đúng project local, không là cấu hình GCP. Health yêu cầu HTTPS/
CRL, readiness200, GeoIP health+lookup và targeted smoke sau cutover tương lai.

**C. Operations đã triển khai**

Từ canonical root, dùng interpreter hiện có:

```text
target/full-function-20261111/tools/Scripts/python.exe -B deploy/full-function/risk_promotion.py plan
target/full-function-20261111/tools/Scripts/python.exe -B deploy/full-function/risk_promotion.py validate
```

Cả hai chỉ xuất JSON ra stdout, không tự ghi file/state. Kiểm schema strict,
ownership, source/HEAD, exact images,14base receipts/markers, active config, B0,
V5 ledger, certificate/CRL signatures/validity và runtime public TLS material,
dataset missing/hash/age, mounts, network definitions/internal flags, loopback ports,
writer conflicts và rollback identity. Git revisions bắt buộc full commit hashes;
không cho manifest chèn option ghi file hoặc gọi external diff helper.

`plan` còn xuất **thiết kế khai báo** backup/apply/rollback, không shell/Compose
commands để tự thực thi. Các tên `backup-only`, `apply`, `rollback` được reserve
nhưng **luôn bị từ chối trước Docker**. Không có flag/đổi status manifest nào tự
mở executor. Không gọi các lệnh này trong lượt thực hiện.

Normal legacy restart không được tự quay về image cũ sau promotion. Nếu gặp
promoted/partial/unknown state, guard dừng trước Compose; phải dùng quy trình
promotion/recovery được review. Chưa có normal restart support cho promoted state.

**D. Kết quả read-only**

[48/48 offline tests][tests] PASS,0fail/error/skip: schema/unknown/duplicate fields,
wrong project/image/platform/source, config/B0/V5 drift, missing/corrupt/stale data,
TLS/CRL expiry/verification, unsafe mount/path, network/ports, conflicting writers,
Git option injection, base receipt drift và rollback constraints. Sparse MMDB
placeholders/hash mocks chỉ nằm trong fixtures tooling; không gọi đó là GeoIP thật.

[Live plan][plan] và [live validate][validate] PASS. Reuse MMDB acquisition/reader/
lookup evidence; chỉ đọc checksum để phát hiện drift, không tải/scan/probe lại DB.
SQL duy nhất là SELECT checksum/success của V5, không chạy migration hoặc SQL ghi.

[Preservation][preservation]:167container giữ identity/config/mount/network/running
state;14receipts/installed-owner markers và6protected hashes giữ nguyên;9healthy.
Snapshot command lines chỉ lưu hash; không lưu token/password/license key.
Active Risk vẫn old digest, GeoIP=false. Không restart, backup hoặc reset account.

**E. Backup-only readiness**

**PARTIAL — có thiết kế, chưa có executor/checkpoint mới.** Plan yêu cầu exclusive
project lock +owner authorization; maintenance chỉ owned writers; quiesce School/
Keycloak/Risk và dừng Redis để lấy consistent SQL+AOF/config cùng mốc; mã hóa
AES-256-GCM, key riêng/private ACL, kiểm MAC/archive/manifest và finally resume đúng
các service trước đó đang chạy. Không dump plaintext vào log hoặc tái tạo stores.
Root dự kiến `target/full-function-20261111b/promotion-private/checkpoints`;
`status=NOT_CREATED`. Reuse bằng chứng backup/restore cũ, không chạy lại script
restore vốn từ chối namespace hiện hữu. Executor backup-only phải được implementation
và kiểm trên state disposable trước khi thực sự pause profile này.

**F. Rollback safety/giới hạn**

**PARTIAL — exact destination đã kiểm, plan offline đã test; chưa rollback thật.**
Chỉ đổi Risk image/config/container về snapshot đã ghi, dùng **CURRENT database**.
Manifest/validator cấm `restore_database=true`; giữ generation, revoked devices,
pending operations, audit và credentials hiện tại. Không tự restore DB/Redis backup,
xóa pending, hạ generation hoặc import lại realm. Việc này tránh rollback ứng dụng
làm sống lại trust/credential đã revoke. Executor chưa tồn tại nên chưa có operational
guarantee cho cutover mới; nếu state không rõ phải giữ maintenance/fail-closed.
Old fallback vẫn mang hạn chế deadlock/GeoIP tắt của baseline local.

**G. Evidence reuse và gap**

Reuse26lifecycle/B0/V5 tests +4MySQL/browser cases của candidate,201JWT tests,
47MFA orchestration tests, SPI/flow/Recovery evidence và GeoIP5/7PASS/lifecycle.
Không build/scan/full CI hoặc lặp acceptance cũ. Signed provenance, D-10,
public-peer browser GeoIP và D-17/G8 không được đóng bằng tooling này. Hai GeoIP
gates PARTIAL giữ nguyên; Docker/NAT private peer không là public GeoIP E2E.

**H. Approval/điều kiện trước APPLY**

Owner cần duyệt riêng exact project/from-to image, SHA256 manifest version này,
dataset/policy P0 local, các security/mount deltas, phạm vi maintenance và backup,
rollback target cùng residuals/gates đang mở. Approval phải được ghi riêng và bind
với descriptor, không sửa receipt/installed marker cũ thành approved. Sau đó vẫn
phải implementation+test executor/operation lock/crash recovery và backup-only,
tạo checkpoint mới đã xác minh, trước một authorization cutover riêng. Approval
policy/decision packet không tự mở `apply`; chuẩn bị này không cấp public/GCP GO.

**I. Trạng thái cuối**

| Gate | Trạng thái | Evidence/phạm vi |
|---|---|---|
| PROMOTION_TOOLING |PASS chuẩn bị|[Controller](risk_promotion.py), [48tests][tests]; plan/validate và restart guard; executor ghi chưa triển khai |
| MANIFEST_VALIDATION |PASS|[Schema](risk-promotion.schema.json), [live validate][validate] |
| BACKUP_READINESS |PARTIAL|[Plan][plan]; design-only, checkpoint NOT_CREATED |
| ROLLBACK_READINESS |PARTIAL|[Plan][plan], [negative tests][tests]; exact old target, không restore DB; chưa có executor/rehearsal mới |
| ACTIVE_RUNTIME_UNCHANGED |PASS|[Preservation][preservation],9/9healthy, old Risk/GeoIP=false |

**Dừng tại đây. Chưa đủ điều kiện thực thi APPLY.** Không GCP, public ports,
worktree, cleanup, commit/push; không thay Lab/PD-R19 hoặc D-10/authentication policy.

[tests]: ../../target/full-function-20261111b/phase22/tooling-tests.json
[plan]: ../../target/full-function-20261111b/phase22/plan.json
[validate]: ../../target/full-function-20261111b/phase22/validate.json
[preservation]: ../../target/full-function-20261111b/phase22/preservation.json
