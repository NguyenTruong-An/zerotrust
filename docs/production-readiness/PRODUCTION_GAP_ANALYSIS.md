# Production Gap Analysis

**06/11/2026, c401e17; NO-GO.** Bảng dưới dùng trạng thái từ [report](PRODUCTION_READINESS_REPORT.md) và finding đầy đủ ở [security](SECURITY_AUDIT.md). “Bắt buộc” là gate cho Internet Production có điểm/dữ liệu thật theo kiến trúc đề xuất, không giả định tất cả đã là SLA được duyệt.

| Hạng mục | Hiện trạng/bằng chứng | Khoảng trống/đích | Ưu tiên / điều kiện đóng |
|---|---|---|---|
| Source/release | VERIFIED HEAD ahead3, CI chỉ remote | Exact release pushed/tested, approved artifact lock | P1 PR-010; CI đúng SHA, registry digest |
| Dependency | TEST VERIFIED version matches, exploit chưa chứng minh | Patch/triage từng advisory, all-image scan + SBOM | P1 PR-001; không còn applicable Critical/High chưa xử lý |
| Domains/OIDC | VERIFIED localhost/private CA; frontend build-time | Domain/cert/issuer/redirect/CORS đúng target | P1 PR-003; browser+negative tests |
| Client IP | SOURCE REVIEWED getRemoteAddr | Trusted proxy overwrite/allowlist/direct-path deny | P1 PR-003; synthetic IP chain evidence |
| Realm/MFA/session | TEST/HISTORICAL VERIFIED một phần | Prod readback, lockout, exact grants, old-token/SSO boundaries | P1 PR-012; policy + runtime acceptance |
| Numeric B0 | SOURCE REVIEWED research baseline | Approved B0 scope/threshold limitations, no B1 switch | P1 PR-012; signed policy acceptance |
| RBAC/ownership | TEST VERIFIED + historical | Same tests on release/domain/prod-like realm, two distinct students | Runtime gate; 401/403/own-data evidence |
| Grade updates | TEST VERIFIED stale form overwrite | HTTP expectedVersion/If-Match, UI conflict handling | P1 PR-005; serial+overlap+batch MySQL tests |
| Grade audit | SOURCE REVIEWED timestamps only | Actor/change/audit integrity+authorized read | P1 PR-015; audit transaction tests |
| DB defaults | SOURCE REVIEWED prod inherits unsafe defaults | Explicit fail-fast TLS/user/validate config | P1 PR-002; missing/insecure vars refused |
| DB schema/version | VERIFIED9.1/8.0/8.4; manual School SQL; Risk V5 Java hard-pin8.0.46 và bytecode checksum | Chosen DB/validated bootstrap-upgrade path, immutable checksum ledger | P1 PR-011; clean/upgrade/partial-DDL/restore rehearsal |
| DB privileges/performance | Runtime username non-root; grants/EXPLAIN NOT VERIFIED | DML/migrator/backup least privilege, plans/latency/pools | Gate; readback + staging load |
| Redis | TEST VERIFIED Lua; AOF/TLS config | maxmemory/headroom/noeviction/loss/failover contract | P2 PR-014, acceptance gate trước public |
| TLS lifecycle | VERIFIED valid files/CRL until11/11; no live | Public/internal CA split, automation/expiry/revocation | P1 PR-003/007; renewal and disaster drill |
| Secrets | VERIFIED external runtime/ACL, limited Git patterns | Production secrets isolated, full scan/layer review/escrow | P1 PR-006/010; no copied Lab keys |
| Backups | Historical cold tar.gz+DB restore | Encryption/offsite/PITR if required/image/key recovery | P1 PR-006/007; decrypt+off-host restore |
| Disaster recovery | HISTORICAL DB readability only | Full app auth/MFA/keys/data/TLS restore timing | P1 PR-007; measured RPO/RTO |
| Availability | VERIFIED restart=no, single instances | Production supervision/probes/drain/recovery | P1 PR-008; failure/reboot acceptance |
| Abuse protection | SOURCE REVIEWED no rate/body hard limit | Public login/API limits/timeouts/429/413 | P1 PR-004; safe staging tests |
| Monitoring | Observatory trace exists; no alert chain | Uptime/latency/error/pool/TLS/backup alerts+owner | P1 PR-009; triggered alert acknowledged |
| Retention/privacy | SOURCE REVIEWED no purge; logs size-only | Approved retention/purge/audit access and notice | P1 PR-015; boundary/purge proof |
| Performance | TEST VERIFIED short in-process score only | Target-size HTTP/auth/API/DB/Redis latency+failure tests | P1 PR-013; raw metrics and approved targets |
| Containers | Pinning/multi-stage/non-root/log quota | Resource/PID/capability/read-only/base patching | P2 PR-016; compatibility/resources tested |
| Event delivery | SOURCE REVIEWED synchronous best effort | Budget/loss monitoring; durable if policy demands | P2 PR-017; loss/recovery acceptance |
| Documents | Good ops/history; some old pointers | Current entrypoints/version/status consistent | P3 PR-018; links/config check |

## Thứ tự xử lý và phụ thuộc

1. Chốt workload/data/identity migration/SLO/RPO/RTO/owners, vẫn kiểm chứng các phần độc lập nền tảng trước.
2. PR-001/005: patch dependency + bảo vệ stale writes; tests/review tạo release candidate.
3. PR-002/003/004/010/011/012: cấu hình prod riêng, network/domain/realm/TLS, migrations và release gates. Không đưa Teacher/scheduling vào schema mới.
4. PR-006/007/008/009/015: backup/key recovery, supervision/readiness, alerts và audit/retention.
5. Staging synthetic, exact release digest, MySQL/Redis/Keycloak thật; đóng chức năng, security, performance, recovery, rollback gates. Có thể song song công việc độc lập nhưng audit này không tự phân công/triển khai.
6. Go/no-go review: blocker nào chưa đóng vẫn NO-GO; một gap phụ thuộc hạ tầng chưa đo không tự thành PASS vì unit xanh.

## Có thể làm sau theo risk acceptance

P2 container read-only toàn bộ, image CRL nhỏ hơn, event outbox nếu chưa yêu cầu delivery bền vững, signing nâng cao khi digest/provenance/registry ACL đã đủ; P3 sửa warning lint và tài liệu lịch sử. Không trì hoãn encryption backup, stale-write protection, relevant security patches, auth/proxy validation, alert delivery hoặc restore gate chỉ vì chúng tốn công.

Chưa có hạ tầng thật nên infrastructure production readiness là NOT VERIFIED. Application có thiếu hụt xác nhận nên application readiness NO-GO. Deployment overall NO-GO. [Acceptance](PRODUCTION_ACCEPTANCE_CHECKLIST.md) quy định đầu ra đóng gate.
