# PD-02-08 — Chuẩn bị nghiệm thu hồi quy Phase 02

**PD-R18 · 08/11/2026 (Asia/Saigon) · Readiness review · PD-02-08 TODO**

Đây là checklist để chạy khi PD-02-02 PASS và task được giao. Bằng chứng source và candidate Quay được phân loại theo scope. Runtime DHI cần receipt riêng. [Master Roadmap](../PUBLIC_DEMO_ROADMAP.md) · [Kế hoạch runtime DHI](PD-02-02_DHI_RUNTIME_TRIAL_PLAN.md)

## 1. Evidence reuse

| Hạng mục | Phạm vi evidence tái sử dụng | Phần phải chạy lại khi đổi DHI |
|---|---|---|
| PD-02-01 | **VERIFIED CURRENT ở cấp source.** Academic write deny, SELECT-only School contract và read authorization có receipt MockMvc/H2/guard theo scope từng test. | Kiểm direct backend và DB grants/unchanged state trên candidate exact. [PD-02-01](PD-02-01_BACKEND_READ_ONLY.md) |
| PD-02-03 | **VERIFIED CURRENT ở cấp source/config tests.** Startup fail-fast và TLS/grant contracts. | Kiểm startup bằng secret file và TLS/MySQL trên config candidate mới. [PD-02-03](PD-02-03_FAIL_FAST_CONFIGURATION.md) |
| PD-02-04 | **VERIFIED CURRENT ở cấp source.** JWT, Risk caller, B0 và Keycloak enforcement có các test mục tiêu. | Tất cả OIDC/PKCE, flow, OTP, trust, JWT/service identity, fail-closed và logout có đường Keycloak. [PD-02-04](PD-02-04_AUTH_SECURITY_HARDENING.md) |
| PD-02-05 | **VERIFIED CURRENT ở cấp source/isolated HTTP.** Trusted proxy, canonical IP, 413/429. | Kiểm reverse proxy thật, không bypass qua direct edge, canonical peer/IP và giới hạn trên lane release. [PD-02-05](PD-02-05_ABUSE_LIMITS_TRUSTED_PROXY.md) |
| PD-02-06 | **VERIFIED CURRENT ở cấp source/synthetic.** Secret-file, caller identities và crypto backup tests. | Xác minh quyền mount thực của UID 65532 và các thao tác secret/TLS, backup/restore scope riêng. [PD-02-06](PD-02-06_SECRETS_SERVICE_IDENTITY.md) |
| PD-02-07 | **VERIFIED CURRENT ở cấp source/build.** UI read-only, operator-only paths và evidence projection. | Kiểm đường access qua edge candidate, browser UI với issuer mới, không public raw data. [PD-02-07](PD-02-07_PUBLIC_DEMO_UI_OBSERVATORY.md) |
| PD-R11/R12 | **VERIFIED HISTORICAL** trên exact Quay/native topology, gồm realm/PKCE/OTP, policy cases, Redis ACL/AOF và same-version restore. | **REQUIRES RERUN AFTER DHI** cho lanes integration/compatibility/rollback. [R11](PD-02-02_CANDIDATE_RUNTIME_CLOSEOUT.md) · [R12](PD-02-02_RESIDUAL_SECURITY_CLOSEOUT.md) |
| PD-R13/R14 | **VERIFIED HISTORICAL** theo receipt Quay và filtered trial. Thử nghiệm filter/NSS có scope riêng; shutdown receipt không phải rollback. | Dùng expected behavior cho regression DHI. Không chạy lại probe nghiên cứu. [R13](PD-02-02_KEYCLOAK_D17_SECURITY_REVIEW.md) · [R14 receipt](../../../target/pd-02-02-mitigation/regression-receipt.txt) |
| PD-R15–R17 | **VERIFIED CURRENT ở cấp metadata/signature** trên exact DHI index/SBOM/SLSA. | **NOT_VERIFIED** cho runtime. Kết quả scanner/rootfs PD-R18 có bảng riêng. [R15](PD-02-02_VENDOR_PATCH_VERIFICATION.md) · [R16–R17](PD-02-02_DHI_EXACT_ARTIFACT_VERIFICATION.md) · [R18 rootfs](PD-02-02_DHI_ROOTFS_SECURITY_VERIFICATION.md) |

Bốn log Maven ngày 08/11 ghi Portal **534**, Risk **905**, Gateway **112**, SPI **251** PASS, tổng **1.802 PASS / 123 SKIP / 0 failure/error**. So SHA-256 với snapshot PD-R14, 719/719 tệp ngoài roadmap và docs index vẫn khớp. Tái sử dụng các suite theo scope đã kiểm, giữ rõ các ca SKIP, nhất là MySQL opt-in. Runtime DHI cần receipt mới. Không chạy lại Maven/Node trong PD-R18 vì source, build và cấu hình liên quan giữ nguyên. [Log Maven](../../../target/pd-02-02-defensive)

## 2. Rà source có trọng tâm

| Biên | Quan sát code và bằng chứng cần giữ |
|---|---|
| Academic read-only | Filter chạy sau JWT/URL authorization, dùng handler MVC đã phân loại, default deny với handler chưa review. READ chỉ GET/HEAD. Security-state ADMIN MFA reset theo contract riêng, chờ quyết định D-10. Kiểm direct backend và School SELECT-only trên deployment. [Filter](../../../src/main/java/com/zerotrust/zerotrust/security/PublicDemoAcademicReadOnlyFilter.java) · [PD-02-01](PD-02-01_BACKEND_READ_ONLY.md) |
| JWT, role và ownership | Portal kiểm issuer/audience, deny default và gate ADMIN/STUDENT. Student controller lấy UUID từ JWT subject cho các đường `/me`; user input `subjectId` là filter môn học. Giữ test hai STUDENT khác nhau, JWT sai audience/issuer và role crossover. [Portal security](../../../src/main/java/com/zerotrust/zerotrust/config/SecurityConfig.java) · [Student controller](../../../src/main/java/com/zerotrust/zerotrust/controller/StudentController.java) |
| Risk isolation | Risk kiểm expiry, issuer, audience, caller azp và role theo từng nhóm endpoint; default deny. Runtime phải kiểm network reachability ngoài service identity. [Risk API security](../../../risk-scoring-service/src/main/java/com/zerotrust/risk/config/RiskApiSecurityConfig.java) |
| B0, fail-closed và trust | Priority trước scoring, incomplete yêu cầu step-up; policy unavailable của candidate chạy DENY, code chung có lựa chọn STEP_UP_MFA. Trust registration cần trạng thái MFA thành công, generation và binding subject/session. Giữ negative cases OTP sai, enrollment, outage, malformed response và revoke. [Risk evaluation](../../../risk-scoring-service/src/main/java/com/zerotrust/risk/service/RiskEvaluationService.java) · [Enforcement](../../../keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/policy/RiskDecisionHandler.java) · [Trust registration](../../../keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/authenticator/TrustedDeviceRegistrationAuthenticator.java) |
| Trusted proxy và quotas | Gateway nhận forwarding từ peer CIDR được duyệt, yêu cầu đúng một header hợp lệ, strip headers người dùng, và khóa operator paths. Bounded admission/body kiểm 429/413. Kiểm ingress config thật, duplicate XFF, bypass trực tiếp, body stream và deadlines. [Canonical filter](../../../gateway/src/main/java/com/zerotrust/gateway/CanonicalRequestFilter.java) · [Abuse filter](../../../gateway/src/main/java/com/zerotrust/gateway/GatewayAbuseFilter.java) |
| Secrets và Observatory | Private config và secret file theo từng service, quyền mount tách biệt. Projection xây lại dữ liệu từ allowlist; raw trace chỉ operator. Giữ negative tests cho file thiếu, raw identifiers, secret và đường public. [Secret contract](../../../deploy/public-demo/SECRETS_IDENTITY_CONTRACT.md) · [Projection](../../../scripts/observation/filtered_evidence.py) |

Không phát hiện lỗi source mới có đủ bằng chứng trong lát cắt review. Các finding và guard chưa nghiệm thu vẫn giữ disposition của roadmap. PR-005 phụ thuộc chứng minh read-only trên target. PR-015 còn yêu cầu chính sách context/security logs. PR-003/004 cần ingress/runtime, PR-002 cần DB runtime, PR-012 cần realm/session/native B0. PR-001 và PR-016 cần artifact triage và release hardening. [Findings Matrix](../PUBLIC_DEMO_ROADMAP.md#6-production-findings-matrix--pr-001-đến-pr-018)

## 3. Checklist nghiệm thu khi đủ điều kiện

- [ ] **Prerequisite:** PD-02-02 PASS theo exact approved image, D-17 disposition và runtime acceptance. PD-02-08 hiện **TODO**.
- [ ] Chốt source SHA + dirty snapshot hashes, base/derived digests, Java/Node/toolchain và cấu hình synthetic. Đối chiếu Git diff và link các receipt source tái sử dụng; ghi SKIP có lý do.
- [ ] Chạy các lane DHI phụ thuộc artifact trong [kế hoạch runtime](PD-02-02_DHI_RUNTIME_TRIAL_PLAN.md). Kiểm direct academic deny, real grants, JWT service identity, proxy/quotas và privacy trên candidate đích. Khi source/config không đổi, dùng lại các suite source đã có phạm vi tương ứng.
- [ ] Tái quét exact derived artifact và đối chiếu applicable findings với evidence per-CVE. Kiểm V5 checksum `661092940` và logical rollback. Chụp metadata trước/sau cho Lab, image, volume và Git.
- [ ] Lưu acceptance record gồm digest, config/issuer, test receipts và raw scans, trạng thái PR-001/002/003/004/005/012/015 và phần còn thiếu G1/G3/G4. Chỉ chốt sau khi các tiêu chí Phase 02 được đáp ứng.

**Blocker hiện tại:** PD-02-02 còn PARTIAL. D-17 và DHI runtime chưa được duyệt/thực thi. Các điều kiện release downstream và Public Demo NO-GO giữ nguyên.
