[Mục lục](../README.md) · [Kế hoạch D-10](D10_REMEDIATION_PLAN.md) · [Acceptance](../../target/full-function-20261111b/post-cutover-functional-acceptance-20261113/ACCEPTANCE.md)

# D-10 Phase 1 — quyết định đề xuất và sửa offline

**13/11/2026 — OFFLINE ONLY. D-10 UNRESOLVED; D-17 PENDING; G8 INTERNET_NO_GO.** Chưa deploy, đổi image/restart, realm/flow/schema hoặc B0/SHADOW. Không dùng owner credentials, reset/revoke tài khoản thật hoặc chạy lại acceptance đang PASS.

**Checkpoint lịch sử:** đề xuất A bên dưới đã được owner thay bằng quyết định **B — strict revocation cho offline engineering**. Xem [Phase2 implementation và native evidence](D10_STRICT_PHASE2.md).201 tests là bằng chứng Phase1, chỉ tái sử dụng phần không đổi; không phải authorization deploy và không đóng D-10.

## 1. Quyết định đề xuất

**Đề xuất A cho hardening giai đoạn đầu của đồ án local, nếu owner chấp nhận residual; B khi tiêu chí bắt buộc block issuance/API ngay sau revoke/pending.** Chưa có owner approval. Không gọi A là strict ZeroTrust revocation.

| Tiêu chí | A — TTL300/skew60 và confirmed logout | B — strict server-side revocation/issuance gate |
|---|---|---|
| Bảo mật | JWT còn dùng tới exp+60. **TTL giới hạn từng token, không giới hạn toàn bộ cửa sổ sau revoke nếu SSO/refresh còn mint token khi logout lỗi.** | Gate cả SSO/refresh tại issuer và security-state check ở cả Gateway/Backend; không chỉ thêm Redis denylist. |
| Khả thi | Giữ API stateless; phạm vi nhỏ hơn: reset ordering, proof consumer và native proof producer. | Cần authority/epoch, session/device mapping, delivery/reconciliation, cache fencing và outage contract. |
| Hiệu năng | API thường không thêm network hop; reset thêm logout sớm ngoài logout cuối. | State lookup/synchronization trên request và issuance; cần đo p95/p99, throughput, convergence, chưa có số đo. |
| Cache/outage | Không thêm Redis vào JWT validation; unknown reset giữ pending/lỗi. Issuance residual chưa được giải quyết khi logout lỗi. | Authority/ledger bền vững; Redis chỉ cache nếu phù hợp. Positive cache TTL tạo stale-allow window, không được gọi zero-window. Outage không fallback bearer-only. |
| Subject/session/device | Native logout theo subject và Risk generation; không tự đồng nghĩa revoke JWT theo device. | Epoch/valid-after theo subject/`sid`; revoke device cần mapping server-side device→sessions, không tin cookie tự khai. |
| Rollback | Giữ pending/revocations/generation; không restore trạng thái bảo mật cũ. | Epoch/tombstones phải monotonic qua cache loss/rollback; cache rỗng không được hồi sinh token. |

Nếu chọn B: định nghĩa điểm hiệu lực và propagation SLA. Pending không tự hết hạn để mở khóa; session tombstones giữ đủ lifetime của mọi credential được chấp nhận, kể cả offline nếu có. Native mutation ngoài orchestration cũng phải được bao phủ. Lease hết hạn không hủy được một Keycloak HTTP mutation đang in-flight: outcome UNKNOWN phải reconcile trước takeover/supersession hoặc có native fencing. Protected API có thể503 khi không xác minh được state; invalid JWT401 và sai role403 vẫn giữ.

Tham chiếu nền: [RFC7009 implementation note](https://www.rfc-editor.org/rfc/rfc7009.html#section-3). Local JWT verification không tự biến logout thành access-token revocation.

## 2. Gap xác nhận và giới hạn còn lại

- Runtime còn residual pending Risk nhưng SSO/refresh cũ mint token, theo integration trước; issuer gate chưa sửa.
- API decoder không đọc enabled/session/epoch mỗi request. TTL300/skew60 không phải bảo đảm toàn hệ thống revoke trong360s.
- Runtime reset chưa có fresh-MFA guard; source offline mới đã có consumer nhưng chưa deploy.
- Logout cũ nằm sau credential mutation; source offline nay có early/final logout và lỗi riêng.
- Chưa có durable reset resume/native fencing. Risk revoke204 của operation cũ không cấp quyền replay credential: operation có thể completed hoặc superseded.

Baseline source/runtime/historical và native cases chưa kiểm chứng: [kế hoạch ban đầu](D10_REMEDIATION_PLAN.md).

## 3. Fresh ADMIN MFA

### Consumer offline đã triển khai

[FreshAdminMfaGuard](../../src/main/java/com/zerotrust/zerotrust/security/FreshAdminMfaGuard.java) chạy đầu [UserServiceImpl.resetMfa](../../src/main/java/com/zerotrust/zerotrust/service/impl/UserServiceImpl.java), trước target lookup/mutation. JWT vẫn qua decoder/role converter hiện có; ADMIN role bắt buộc.

Contract candidate: issuer ký `zt_mfa_at` epoch-second nguyên, `zt_mfa_method`=`otp`/`recovery-authn-codes`, `zt_mfa_subject` khớp JWT.sub; `zt_mfa_client` và JWT.azp cùng `zerotrust-spa`. Không lấy proof từ header/body/cookie hoặc dùng `iat`/`auth_time` bù proof thiếu/cũ. Timestamp lỗi/future/quá age bị từ chối. `app.security.fresh-admin-mfa.maximum-age-seconds` mặc định300, chỉ cho1–300: đây là giá trị candidate cần owner duyệt.

Thiếu/sai proof trả403 `FRESH_ADMIN_MFA_REQUIRED` trước side effect; không force-refresh để giả factor mới. STUDENT403, invalid JWT401 giữ. Consumer không tự phát token/xác minh OTP trong Portal. Proof hiện dùng lại được trong freshness window, chưa có nonce single-use/per-target; cần chọn nếu muốn mỗi reset có proof riêng.

### Capability exact pin

Read-only copy `keycloak-services` từ image `sha256:ec2b47104a9b85a2272689edd2cc009536f566595e1f7efa82fc1ae29f6c94df`. JAR và mapper classes khác bytes với Maven cùng nhãn26.8.2; test dùng child-first loader nạp mapper/helper từ **runtime JAR**.

Hai tests xác nhận actual UserSessionNoteMapper đọc server note thành claim long; note vắng không sinh proof; gọi mapper lặp cùng note giữ timestamp, không gọi setNote. [Capability hashes](../../target/full-function-20261111b/d10-phase1/factor-proof-capability.json) · [Exact-pin test](../../keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/PinnedUserSessionNoteMapperTest.java) · [Log](../../target/full-function-20261111b/d10-phase1/keycloak-capability.log).

**Chưa xác nhận nguồn timestamp factor; chưa nối publisher vào SPI/flow.** OTP SUCCESS đọc ở registration hoặc LOGIN delivery time không đủ chứng minh thời điểm factor. Không stamp `now` ở bước sau để tạo freshness giả. Publisher candidate phải ghi tại callback native factor validate thành công, bind subject/client/attempt, không restamp trên SSO/refresh/re-entry. Nếu chọn native LoA phải kiểm primitive timestamp trên exact pin; nếu bọc native OTP/recovery success phải kiểm failure/challenge/required-action/repeated-attempt semantics trước khi bind flow.

Mapper unit tests không phải native OTP→session note→signed JWT→refresh end-to-end. Current realm không có publisher/mapping này. **Deploy consumer riêng sẽ chặn mọi reset thiếu proof; không thêm guard-off fallback.** [Keycloak step-up](https://www.keycloak.org/docs/latest/server_admin/index.html#_step-up-flow) và [RFC9470](https://www.rfc-editor.org/rfc/rfc9470.html#section-6.1) là hướng thiết kế, chưa phải flow mới đã nghiệm thu.

## 4. Reset ordering offline

Source mới chạy: **role/proof → target ACTIVE → Risk revoke/generation++/pending → early logout confirmed → credential/enrollment mutation → final logout confirmed → completion confirmed → 204**.

[Gateway interface](../../src/main/java/com/zerotrust/zerotrust/identity/IdentityProviderGateway.java), [adapter](../../src/main/java/com/zerotrust/zerotrust/identity/keycloak/KeycloakIdentityProviderGateway.java), [Keycloak client](../../src/main/java/com/zerotrust/zerotrust/identity/keycloak/KeycloakUserClient.java) sửa đồng bộ: resetMfa chỉ là credential phase, logoutSessions tách riêng. Audit requester lấy authenticated principal, không fallback system.

| Lỗi | Hành vi offline mới |
|---|---|
| Không xác nhận Risk revoke | Không gọi Keycloak; remote Risk commit có thể unknown, không giả rollback. |
| Early logout lỗi/timeout | Giữ pending, trả MFA_RESET_PARTIAL; chưa sửa credential. |
| Credential mutation lỗi | Dừng, giữ pending/visible partial error; không tự replay credential. |
| Final logout lỗi/unknown |503 MFA_RESET_SESSION_LOGOUT_PENDING; không completion hoặc lặp mutation. |
| Completion lỗi | MFA_RESET_COMPLETION_PENDING; không báo204 giả. |

**Resume chưa triển khai:** cần durable stages, server operation ID và owner/generation/pending checks; completed trả terminal không gọi Keycloak, superseded bị từ chối, UNKNOWN reconcile. Không dùng in-memory lock làm bảo đảm qua crash/multi-instance. Risk fencing/idempotency tests không chứng minh toàn reset có distributed serialization. Không giảm generation, tự clear pending hoặc phục hồi credential cũ.

## 5. Tests thực chạy

[verification.json](../../target/full-function-20261111b/d10-phase1/verification.json): **201 distinct targeted tests PASS, 0 failure/error/skip**, gồm regression liên quan, không phải201 test mới. JDK17, H2 in-memory, mocks, JWKS loopback tạm và actual runtime mapper local; không gọi auth/DB của owner.

| Class | Tests | Phạm vi |
|---|---:|---|
| FreshAdminMfaGuardTest |16| Thiếu/sai/cũ/future proof, bindings, method, role, age |
| UserServiceImplTest |11| Reject trước mutation; ordering và unknown outcome |
| KeycloakUserClientTest |20| Credential phase không xóa password, logout/failure tách riêng |
| PortalJwtDecoderTest |19| Signed proof+role converter; giả factor time hỏng signature; new iat không renew proof; exp+59/+60 nhận, exp+61 từ chối bằng clock kiểm soát |
| AdminControllerSecurityTest |53| Contract/RBAC/401/403 liên quan |
| PublicDemoAcademicReadOnlyTest |73| Real service/MVC/H2: ADMIN thiếu proof403 trước mutation, proof fixture204; STUDENT403/anonymous401 và School boundaries |
| DeviceTrustLifecycleTests |7| Idempotency, supersession, concurrency, stale generation và không hồi sinh device; không thay MySQL native proof |
| PinnedUserSessionNoteMapperTest |2| Runtime mapper bytes, absent/stable note mapping |

Logs: [Portal](../../target/full-function-20261111b/d10-phase1/portal-targeted.log), [signed-proof extension](../../target/full-function-20261111b/d10-phase1/portal-signed-proof.log), [Risk](../../target/full-function-20261111b/d10-phase1/risk-lifecycle.log). Tổng từ latest XML từng class, không cộng trùng rerun. Lỗi fixture/import lúc phát triển đã sửa; final0 failures.

T04/T05/T09/T12–T14/T18 có coverage offline từng phần. Native T02/T03/T06–T08/T10/T11/T15–T17 và phần native của các ca còn lại chưa PASS mới. Không fake SSO/refresh success làm native evidence.

## 6. Phê duyệt và lộ trình

Cần owner chọn A/B và issuance/revocation SLA; residual JWT window sau confirmed logout; age≤300 và proof reusable/single-use; nguồn timestamp/publisher/mapping; SSO8h hay thay policy; scope subject/session/device và outage handling nếu chọn B. Không tự chuyển APPROVED.

Tiếp theo: review contract → exact-pin publisher/native timestamp bằng fixture được cho phép → durable resume/fencing nếu cần → targeted native lifecycle → review pin/config/flow và authorization triển khai riêng. T01 browser/API PASS được giữ, không chạy full acceptance thay bằng chứng thiếu.

Rollback sau này giữ monotonic generation/epoch/pending/revocations; không restore DB/OTP/recovery/session cũ, drop tombstone hoặc tắt guard để bearer-only. Nếu pin cũ không hiểu proof, reset phải tiếp tục fail-closed qua cơ chế tương thích được duyệt. Phase này không thêm migration và không rollback runtime.

Read-only continuity cuối lượt: 9 running pins khớp receipt; 5 service có baseline ID/start time giữ nguyên; Risk override khớp binding, SHADOW/retention=false. **Source offline không phải behavior đã deploy và chưa đóng D-10.**
