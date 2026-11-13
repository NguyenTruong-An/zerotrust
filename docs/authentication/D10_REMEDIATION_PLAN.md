[Mục lục](../README.md) · [Acceptance hiện tại](../../target/full-function-20261111b/post-cutover-functional-acceptance-20261113/ACCEPTANCE.md)

# D-10 — kế hoạch xử lý session, revocation và fresh ADMIN MFA

**13/11/2026 — lịch sử review và ma trận acceptance. D-10 UNRESOLVED.** Owner đã chọn **B — strict revocation** cho engineering offline; [implementation Phase2](D10_STRICT_PHASE2.md) là checkpoint mới. Các phần hiện trạng/đề xuất dưới đây mô tả baseline trước sửa, không phủ định source candidate mới. Chưa được phép deploy hoặc thay runtime/realm thật. D-17 PENDING; G8 INTERNET_NO_GO.

**Baseline trước Phase1:** các mô tả source dưới đây ghi checkpoint review ban đầu. [D10 Phase1 offline](D10_PHASE1_OFFLINE_REMEDIATION.md) có201 targeted tests PASS lịch sử. Quyết định B, native producer, authority và lifecycle tests mới được ghi riêng trong Phase2; không cộng trùng tests hoặc coi evidence isolated là acceptance runtime đích. Các gap runtime vẫn mở cho đến controlled deployment và native acceptance.

## 1. Bằng chứng và hiện trạng

Readback chỉ lấy các cột/attribute được cho phép, không lấy secret/token/session cookie: [d10-readonly-evidence.json](../../target/full-function-20261111b/post-cutover-functional-acceptance-20261113/d10-readonly-evidence.json). File có hash nguồn, dòng đối chiếu, pin/ID/start time của các service được theo dõi và mapping ownership dưới dạng SHA-256. Đây là inspection, không phải bằng chứng HTTP authorization hoặc lifecycle test mới.

| Biên | Hiện trạng đã quan sát |
|---|---|
| SPA | Code + PKCE S256; public client; standard flow bật; implicit/direct grant/service account tắt. `keycloak-js` 26.2.5 theo package manifest. |
| Token/refresh | Realm access TTL300s; không có SPA TTL override trong allowlist. Rotation bật, maxReuse0. Code gọi `updateToken(30)`, coalesce refresh trong một tab; API401 force refresh và retry một lần. Chưa replay refresh token mới để kiểm rotation/reuse. |
| SSO | Idle1800s/max28800s (30 phút/8 giờ); remember-me tắt. Client session idle/max realm attributes=0, không thấy client override trong allowlist. Root Browser Flow có `auth-cookie` ALTERNATIVE; Risk nằm trong nhánh forms. SPA dùng `check-sso`, tắt `checkLoginIframe`. |
| Logout | SPA gọi Keycloak end-session; client frontchannel logout=false, không có backchannel URL trong allowlist. API stateless không có session applicative để xóa. Remote logout có thể chỉ được tab nhận biết khi refresh/API thất bại. |
| Offline | Không có `offline_access` trong các client scope gắn với SPA đã readback. Realm vẫn có offline idle30 ngày/max-limit=false. Không suy ra đã hoặc chưa tồn tại mọi offline token; chưa thử offline lifecycle. |
| API JWT | Portal/Gateway xác minh chữ ký/JWKS, issuer, required exp, thời gian, audience và role; không introspect hoặc đọc Risk generation/Keycloak enabled/not-before mỗi request. |
| MFA reset | ADMIN role → Risk revoke/generation++/pending → Keycloak enrollment actions và xóa OTP/recovery → logout → Risk completion. Chưa có guard fresh-MFA tại endpoint/service reset. |

Nguồn chính: [SPA adapter](../../frontend/lib/keycloak.ts), [API transport](../../frontend/lib/api.ts), [route/login/logout](../../frontend/components/portal-route.tsx), [Gateway JWT/RBAC](../../gateway/src/main/java/com/zerotrust/gateway/GatewaySecurityConfig.java), [Portal JWT/RBAC](../../src/main/java/com/zerotrust/zerotrust/config/SecurityConfig.java), [reset orchestration](../../src/main/java/com/zerotrust/zerotrust/service/impl/UserServiceImpl.java), [native credential/logout order](../../src/main/java/com/zerotrust/zerotrust/identity/keycloak/KeycloakUserClient.java).

Tài liệu Keycloak giải thích adapter memory/refresh và phát hiện logout; hành vi cụ thể trên pin hiện tại vẫn phải được kiểm thử. [JavaScript adapter](https://www.keycloak.org/securing-apps/javascript-adapter). Rotation và offline tokens là các lifecycle riêng. [Session/token timeouts và offline access](https://www.keycloak.org/docs/latest/server_admin/index.html#_timeouts).

## 2. Đã xác nhận và chưa kiểm chứng

| ID | Phân loại | Kết luận / giới hạn |
|---|---|---|
| D10-C1 | Residual đã chứng minh bằng integration cũ; cấu trúc flow hiện tại phù hợp | Risk pending tự nó không chặn SSO/refresh: [session-boundaries.json](../../target/full-function-20261111b/phase2/session-boundaries.json) ghi refresh200 và SSO phát token; forced/fresh login bị Risk DENY. Không chạy lại thao tác pending trên tài khoản thật sau cutover. |
| D10-C2 | Gap xác nhận từ decoder và bytecode receipt cũ | Access JWT còn hợp lệ có thể tiếp tục qua API dù session/trust đã bị thu hồi. [jwt-expiry-bound.json](../../target/full-function-20261111b/phase2/jwt-expiry-bound.json) ghi TTL300/skew60, bound danh nghĩa ≤360s từ issuance khi không có override, không phải kết quả wait-until-exp mới. Không gọi logout là thu hồi JWT tức thì. |
| D10-C3 | Gap source xác nhận | Reset MFA chỉ đòi ADMIN JWT, không kiểm ACR/LoA, factor proof hoặc độ mới của MFA trước side effect. Hai fresh OTP PASS không chứng minh endpoint tự bắt fresh MFA. |
| D10-C4 | Gap orchestration/source xác nhận | Logout nằm sau cập nhật required actions/xóa credential; lỗi trước logout có thể để session cũ tồn tại khi Risk pending. Partial failure không được xử lý như rollback remote commit. |
| D10-C5 | Thiếu integration được xác nhận trong listener được review | [RiskEventListener](../../keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/listener/RiskEventListener.java) chỉ ingest LOGIN/LOGIN_ERROR; admin-event callback không thực hiện security-state invalidation. Chưa chứng minh các đường password reset/disable native tự đồng bộ Risk trust. Không khẳng định toàn Keycloak không có cơ chế logout riêng. |
| D10-U1 | Chưa kiểm chứng mới | JWT/refresh/SSO sau password change tự phục vụ, admin password reset, account disable/re-enable, MFA reset và device SECURITY revoke trên exact pin. Native password/disable effects phải kiểm riêng, không suy từ MFA reset. |
| D10-U2 | Chưa kiểm chứng | Refresh rotation/reuse, multi-tab race, hết SSO idle/max, logout lan truyền giữa tab, offline access và failure/timeout giữa các dịch vụ. |
| D10-U3 | Chưa quyết định | SLA thu hồi, chấp nhận JWT residual window hay cần online invalidation; phạm vi per-device/per-session/per-subject; age và proof cho fresh ADMIN MFA; SSO8h hay parity10h. |

Đây là gap/điểm mở của D-10; không gán mọi mục thành exploit đã chạy thành công. Không suy Portal `User.status` từ Keycloak `enabled`: student `/me` kiểm School ACTIVE, còn ADMIN list dựa JWT role; hai nguồn trạng thái khác nhau.

## 3. Phương án sửa để review, chưa áp dụng

Kế thừa [D-10 decision packet](../../deploy/full-function/PHASE21_DECISION_PACKET.md), không tự đổi chính sách đã giữ:

| Quyết định | Đề xuất cụ thể | Tác động / giới hạn |
|---|---|---|
| Thu hồi theo bounded window | Giữ TTL300s/skew60 hiện tại nếu owner chấp nhận residual tối đa danh nghĩa exp+60; logout sớm ngay sau Risk revoke, trước sửa credential; logout xác nhận lần cuối trước completion. | Giảm cửa sổ SSO/refresh nhưng không bảo đảm zero-window giữa hai dịch vụ hoặc khi logout lỗi. User mục tiêu có thể bị logout dù reset chưa hoàn tất. |
| Nếu cần strict issuance block | Thêm gate server-side cho cả SSO và refresh, cùng pending/security state có thẩm quyền; outage/unknown outcome fail-closed theo contract được chốt. | Logout ordering đơn lẻ không đủ. Phải bao phủ mọi đường native mutation; event delivery trễ ngoài orchestration không cho guarantee tức thì. Không truy cập Risk DB trực tiếp từ SPI. |
| Nếu cần chặn JWT trước exp | Thiết kế authorization security epoch/valid-after hoặc introspection + session state tại cả Gateway và Portal. Ký claim/bind `sub`/`sid`; xác định đúng mapping device→session nếu revoke riêng device. | Trust generation hiện bảo vệ registration, không tự là access-token revocation. Positive cache TTL tạo residual mới; phải có SLA, race/convergence và outage tests. Không dùng JWKS rotation/not-before UI thay kiểm tra online. |
| Fresh ADMIN MFA | Bảo vệ riêng `POST /api/admin/users/{id}/mfa/reset` trước mọi Risk/Keycloak mutation; đề xuất age≤300s. Keycloak phải cung cấp mức xác thực và thời điểm factor được backend xác minh trong access-token context đúng issuer/audience/client/sub. | `iat` mới, `auth_time` đơn lẻ, `prompt=login`, SSO cookie hay trusted-device cookie không đủ. Refresh không được làm mới thời điểm MFA. Không ép mọi trusted LOW login/refresh chạy OTP. |
| Password reset/disable/revoke | Chốt bảng sự kiện→logout scope→Risk trust invalidation→API epoch. Adapter sự kiện cần idempotency, after-commit/durable delivery và reconciliation, phân biệt native self-change/admin-change/disable. | Chưa thêm listener hook. Nếu không map được một device sang session, phải chọn rõ revoke cả subject hay giữ bounded window, không tự suy đoán. |
| Partial reset | Tách early logout, credential mutation, final logout và completion thành stage được audit; confirmed/unknown failure hiển thị rõ; pending được giữ; retry/resume cùng operation phải fence subject/requester/supersession. | Bấm reset hiện tạo operation mới; cần API/support nội bộ phù hợp nếu chọn resume, không mở public completion bypass, không giảm generation. |

Fresh-MFA cần mapping ACR/LoA và factor freshness được kiểm trên exact Keycloak/SPI pin. Nếu `auth_time` của phiên không chứng minh factor mới, phải bổ sung proof/claim server-side được chốt, không nhận timestamp tự khai từ browser. Challenge có thể theo [RFC9470](https://www.rfc-editor.org/rfc/rfc9470.html#section-6.1); mapping tham khảo [Keycloak step-up](https://www.keycloak.org/docs/latest/server_admin/index.html#_step-up-flow). Đây là thiết kế cần kiểm compatibility, không phải khả năng đã chứng minh trên flow hiện tại.

## 4. Test cases và acceptance criteria dự kiến

**T01 đã PASS bằng owner DevTools + SQL trong follow-up; T02–T18 chưa chạy mới.** Receipt: [http-owner-verification.json](../../target/full-function-20261111b/post-cutover-functional-acceptance-20261113/http-owner-verification.json). Owner báo trực tiếp HTTP200/403, Codex xác minh role metadata và ownership đúng native STUDENT subject; anonymous401 giữ receipt trước. Không phải HAR/network capture tự động. Có3 native LOGOUT trong cửa sổ nhưng chưa chứng minh propagation/revocation; không có native REFRESH_TOKEN mới được quan sát. Sau khi policy/implementation được duyệt, dùng unit/signed-JWT MVC/WebFlux trước; chỉ dùng fixture synthetic cô lập đã được phép cho mutation/session tests. Không đụng tài khoản owner.

| Case | Thao tác / kiểm tra | Điều kiện đạt |
|---|---|---|
| T01 — PASS follow-up | ADMIN200, STUDENT own200, STUDENT→ADMIN403, anonymous401 | Owner DevTools trực tiếp + role/mapping SQL; profile/user ID và score studentId đúng ownership trên trang đã quan sát. Anonymous401 tái sử dụng receipt runtime trước; không xuất credential. |
| T02 | SSO còn hạn và fresh/forced login trước reset | Phân biệt nhánh không có evaluation với fresh evaluation; mandatory MFA/B0 giữ nguyên. |
| T03 | Dừng reset ngay sau Risk revoke; thử SSO/refresh | Bounded policy: ghi chính xác residual; strict policy: không token mới sau điểm hiệu lực được định nghĩa. Không chấp nhận claim zero-window không được đo. |
| T04 | Early logout lỗi/timeout trước hoặc sau remote commit | Không sửa tiếp credential nếu chưa đạt contract; pending và visible error giữ; retry hữu hạn, không completion giả. |
| T05 | Lỗi ở required-action update, OTP/recovery deletion, final logout, completion | Audit đúng stage; stale generation không re-trust; không giảm generation/xóa pending để PASS. |
| T06 | Refresh hợp lệ, token cũ dùng lại, multi-tab/concurrent refresh | Rotation/maxReuse đúng effective policy; per-tab single-flight không được coi là cross-tab lock. |
| T07 | SSO idle/max/remember-me và client override | Đúng timeout đã duyệt; không lấy lifespan access token làm lifespan refresh. |
| T08 | Logout bình thường / logout từ tab khác | Refresh/SSO bị chặn theo native session contract; UI clear token khi phát hiện; JWT cũ được xử lý theo bounded/online policy. |
| T09 | JWT tại exp−1, exp+59 và exp+61 với clock kiểm soát | Với skew60 đang chọn: kiểm rõ biên và clock drift; không coi <=360s receipt cũ là wait-test đã chạy. |
| T10 | Self password change, admin reset password, disable/re-enable | Ma trận riêng cho new login/SSO/refresh/JWT/device trust; native identity và School status không bị nhầm. Re-enable không tự hồi sinh token/trust đã revoke. |
| T11 | MFA reset / SECURITY revoke một device | Old cookie, paused MFA attempt, session, refresh và JWT đúng scope; user/device không liên quan được giữ. |
| T12 | Fresh ADMIN factor proof hợp lệ rồi gọi reset | Chỉ side effect sau proof hợp lệ; role ADMIN vẫn bắt buộc; audit không có token/OTP. |
| T13 | Thiếu/sai ACR, timestamp cũ/future, wrong client/aud/sub, token giả | Reject trước mọi mutation; role STUDENT403; invalid JWT401; thiếu freshness dùng challenge contract đã chốt. |
| T14 | Refresh JWT / password-only prompt / device cookie | Không gia hạn MFA age hoặc giả thành factor success. |
| T15 | OTP và Recovery thực, code dùng lại, required actions/enrollment | Giữ hai nhánh factor và 15-execution baseline; CONFIGURE_TOTP không bị coi là MFA thành công trước khi hoàn tất. |
| T16 | Authorization-state outage/cache/race/negative delivery | Không fail-open; TTL/convergence đúng SLA; API direct-to-backend không vượt guard Gateway. |
| T17 | Offline scope/token nếu được cấp sau này | Có acceptance riêng, không suy regular logout đã thu hồi offline token. |
| T18 | Rollback candidate | Không hồi sinh credential/token/trust cũ; state/schema và dữ liệu nghiệp vụ được giữ. |

Điểm bắt đầu có sẵn: [UserServiceImplTest](../../src/test/java/com/zerotrust/zerotrust/service/impl/UserServiceImplTest.java), [KeycloakUserClientTest](../../src/test/java/com/zerotrust/zerotrust/identity/keycloak/KeycloakUserClientTest.java), [PortalJwtDecoderTest](../../src/test/java/com/zerotrust/zerotrust/config/PortalJwtDecoderTest.java), [AdminControllerSecurityTest](../../src/test/java/com/zerotrust/zerotrust/controller/AdminControllerSecurityTest.java), [StudentControllerSecurityTest](../../src/test/java/com/zerotrust/zerotrust/controller/StudentControllerSecurityTest.java), [GatewaySecurityTests](../../gateway/src/test/java/com/zerotrust/gateway/GatewaySecurityTests.java), [DeviceTrustLifecycleTests](../../risk-scoring-service/src/test/java/com/zerotrust/risk/service/DeviceTrustLifecycleTests.java). H2/mock không thay chứng cứ native session, MySQL locking hoặc browser OTP.

## 5. Trình tự và rollback dự kiến

1. Chốt D10-U3 bằng một decision riêng; chọn bounded hoặc strict và fresh-factor proof trước khi viết enforcement. Chưa có approval trong tài liệu này.
2. Viết sửa/test theo biên nhỏ: reset stages và fresh-MFA guard; sau đó security-state/session integration nếu được chọn. Giữ B0, Network v2 SHADOW và các invariants generation/required-action.
3. Kiểm trên exact candidate pins, snapshot/config contracts và fixture được phê duyệt; review kết quả T01–T18. Không yêu cầu rebuild hay tạo worktree trong lượt chuẩn bị này.
4. Chỉ sau authorization triển khai riêng mới backup/checkpoint/bind/cutover. Không dùng receipt hoặc binding cũ để tự cho phép D-10 deployment.
5. Rollback code/config/flow bằng pin và snapshot cấu hình tương thích đã review; **không restore DB cũ để rollback bảo mật**, không phục hồi OTP/recovery, giảm generation/security epoch hoặc bật lại revoked session. Schema mới nếu có phải additive/backward-compatible và giữ nguyên khi rollback. Nếu pin cũ thiếu fresh-MFA/online guard, đóng thao tác nhạy cảm hoặc giữ bản guard tương thích trong cửa sổ sửa; không fallback sang bearer-only/fail-open. Không bật/tắt security control khi chưa được cho phép.

**Điều kiện đóng D-10:** policy có quyết định rõ; code và native lifecycle/mutation cases phù hợp quyết định trên exact pin; HTTP authorization/ownership có bằng chứng trực tiếp; bounded window hoặc revocation SLA được đo và ghi nhận; rollback không hồi sinh trạng thái bảo mật. Cho đến đó D-10 vẫn UNRESOLVED.
