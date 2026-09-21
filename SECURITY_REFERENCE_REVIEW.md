# Đối chiếu kiến trúc với các khung tham chiếu bảo mật

**Ngày rà soát:** 2026-09-18
**Phạm vi:** Keycloak authentication flow, Keycloak extension, Risk Scoring
Service, Portal SPA/API và kết nối service-to-service.

Tài liệu này là design review có bằng chứng từ code, cấu hình và phép thử local.
Nó không phải chứng nhận tuân thủ. Kết luận hiện tại là: dự án **đúng hướng với
các nguyên tắc cốt lõi**, nhưng mới ở mức **Zero Trust Adaptive Authentication**,
chưa phải một triển khai Zero Trust Architecture đầy đủ hoặc production-ready.

## 1. Tài liệu chuẩn dùng để đối chiếu

- [NIST SP 800-207 - Zero Trust Architecture](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf)
- [NIST SP 800-63B-4 - Authentication and Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
- [OAuth 2.0 Security Best Current Practice - RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)
- [OAuth 2.0 Mutual-TLS Client Authentication - RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html)
- [Keycloak Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/)
- [Keycloak hostname v2](https://www.keycloak.org/server/hostname)
- [Keycloak production configuration](https://www.keycloak.org/server/configuration-production)
- [Keycloak EventListenerProvider API](https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/events/EventListenerProvider.html)

## 2. Ma trận đánh giá

| Yêu cầu/nguyên tắc tham chiếu | Cách dự án thực hiện | Trạng thái | Bằng chứng và việc còn lại |
|---|---|---|---|
| Không tin cậy ngầm theo vị trí mạng; quyết định dựa trên identity và context | Keycloak xác thực user; Risk Service dùng subject, client, device, IP và lịch sử thất bại | Đạt một phần | Login được đánh giá động. Portal resource request chưa được đánh giá lại theo risk context |
| Quyền tối thiểu cho workload | `zerotrust-risk-caller` tách khỏi user và `zerotrust-provisioner`; Full Scope Allowed tắt; ba client role tách theo operation | Đạt | `risk:evaluate`, `risk:device:write`, `risk:events:write`; Risk API kiểm tra `aud`, `azp` và role |
| Policy decision độc lập và có thể giải thích | Risk Service giữ rule/weight/threshold; extension chỉ thu context và thi hành `ALLOW/STEP_UP_MFA/DENY` | Đạt | Priority deny chạy trước weighted score; response có `dataStatus` và `reasons` |
| Thiếu dữ liệu không tạo mức LOW giả | Network provider bị tắt/IP lỗi, temporal cold-start/lỗi DB và Redis lỗi đều làm `INCOMPLETE`, `riskScore=null`, `STEP_UP_MFA` | Đạt | Network và temporal có assessment trạng thái riêng; Redis lỗi tạo `AUTHENTICATION_HISTORY_UNAVAILABLE` |
| MFA thích ứng theo tín hiệu rủi ro | Device state, CIDR network policy, auth history, temporal profile và priority rules có thể kích hoạt allow/MFA/deny | Đạt một phần | Weighted runtime đã mở khi mọi nguồn available; còn phải chạy ma trận E2E với policy CIDR thực tế |
| Giới hạn lần thử xác thực | Keycloak Brute Force Detection được bật; failure counter Redis bổ sung tín hiệu risk | Đạt | Local audit: `failureFactor=5`, wait tăng 60 giây, max wait 900 giây; Redis không thay thế rate limiter của Keycloak |
| Counter ưu tiên theo account, IP là tín hiệu phụ | Subject có ngưỡng thấp hơn source IP; risk lấy mức cao hơn thay vì cộng | Đạt | Baseline subject `3/5`, IP `10/20`; cần hiệu chỉnh để giảm false positive do NAT/shared IP |
| Không tính trùng event và hạn chế dữ liệu nhạy cảm | Redis Lua ghi idempotent theo event ID; subject/IP trong key được HMAC; mọi key có TTL | Đạt | Counter 15 phút, marker chống trùng 1 giờ; Redis là dữ liệu ngắn hạn, không phải audit store |
| Browser client dùng flow hiện đại | SPA dùng Authorization Code + PKCE `S256`; không gửi password vào Portal API | Đạt | Phù hợp OAuth BCP cho public client |
| Access token bị giới hạn đối tượng nhận | Risk token có `aud=zerotrust-risk-api`, `azp=zerotrust-risk-caller`; access token ngắn hạn | Đạt | Signature, `iss`, `exp`, `nbf`, audience, caller và operation role đều được kiểm tra |
| Bảo vệ token khi truyền và giảm replay | Thiết kế production yêu cầu TLS và private network | Đạt một phần | Local đang dùng HTTP. Production nên cân nhắc mTLS/certificate-bound token theo RFC 8705 nếu threat model yêu cầu chống replay mạnh hơn |
| Cookie thiết bị không được coi là authenticator | `ZT_DEVICE_ID` chỉ là ID ngẫu nhiên; trạng thái trust ở server; revoke vẫn hard deny | Đạt | Cookie realm-scoped, HttpOnly, SameSite=Lax, Secure trong secure context; chỉ phát sau MFA và API 204 |
| Extension dùng điểm mở rộng chính thức của Keycloak | Authenticator SPI tham gia authentication flow; Event Listener SPI nhận `LOGIN_ERROR` và `LOGIN` | Đạt | Provider được đăng ký bằng ServiceLoader và đã nạp trong Keycloak 26.7.0 |
| Event processing không làm tăng coupling của transaction xác thực | Listener gọi Risk API đồng bộ với timeout và fail-open cho telemetry | Đạt một phần | Keycloak chạy listener trong transaction; production tải lớn nên chuyển sang after-completion/outbox/broker và worker bất đồng bộ |
| Issuer/endpoint ổn định, không phụ thuộc Host header | Local `start-dev` sinh issuer `8080` hoặc `8180` theo đường gọi | Chưa đạt production | Production phải dùng một canonical HTTPS hostname/issuer, strict hostname và proxy header đúng |
| Secret lifecycle | Secret không ghi log/commit; client riêng cho máy | Đạt một phần | Client secret còn nằm trong Authenticator execution config; production cần secret manager, rotation và quyền vận hành |
| Audit dài hạn và giám sát | Có structured reasons và Redis telemetry ngắn hạn | Chưa hoàn tất | Cần lưu evaluation/security event dài hạn, metric, alert và retention policy; không dùng Redis TTL làm audit log |
| Triển khai Keycloak production | Local dùng container `start-dev`, HTTP và database/dev topology | Chưa đạt production | Cần image bất biến chứa provider JAR, production DB, TLS, hostname cố định, backup và HA phù hợp |

## 3. Authentication-history milestone vừa hoàn thành

Luồng hiện tại:

```text
credential-related LOGIN_ERROR tại Keycloak
-> zerotrust-risk-events
-> POST /internal/v1/authentication-failures
-> JWT cần risk:events:write
-> Redis tăng atomically counter subject/IP có TTL
-> lần evaluation sau đọc hai counter
-> map từng counter vào 0 / medium / high
-> lấy max(subjectRisk, sourceIpRisk)
-> thêm AUTHENTICATION_HISTORY_RISK nếu score dương
-> dải high thêm EXCESSIVE_AUTHENTICATION_FAILURES và bắt buộc MFA
```

Listener chỉ đếm `invalid_user_credentials` và `user_not_found`. Các lỗi
`expired_code`, session và `user_temporarily_disabled` không được gửi sang counter,
tránh biến lỗi kỹ thuật hoặc lần thử trong thời gian lockout thành một credential
failure mới.

Lấy `max` là lựa chọn có chủ đích: một lần nhập sai thường tăng cả counter account
và IP, nên cộng hai score sẽ đếm cùng một sự kiện hai lần. IP có ngưỡng cao hơn vì
nhiều user có thể đi qua cùng NAT/proxy. Nếu Redis tạm ngừng, calculator trả trạng
thái unavailable; hệ thống tiếp tục yêu cầu MFA thay vì hiểu nhầm là lịch sử sạch.

Dải high bắt buộc MFA độc lập với weighted threshold; Keycloak tiếp tục sở hữu
khóa tạm thời nên Risk Service không tạo thêm hard-lock dễ bị lạm dụng để gây DoS.

Các ngưỡng `3/5`, `10/20` và score `50/100` chỉ là baseline development. NIST và
OWASP yêu cầu rate limiting, adaptive signals và quản lý false positive, nhưng
không công bố một bộ số phù hợp cho mọi hệ thống. Trước production cần version hóa
policy, thu metric, thử tải và hiệu chỉnh trên threat model/dữ liệu của tổ chức.

## 4. Successful-login collection và Temporal Profile

Luồng hiện tại:

```text
LOGIN thành công tại Keycloak
-> zerotrust-risk-events
-> POST /internal/v1/authentication-successes
-> JWT cần risk:events:write
-> MySQL lưu event_id + subject + client + authenticated_at + recorded_at
-> unique event_id và INSERT IGNORE chống ghi lặp nguyên tử
-> evaluation sau đọc lịch sử cùng subject/client trong cửa sổ cấu hình
-> tạo baseline theo thứ trong tuần và giờ địa phương
-> map 0/1/2 tín hiệu bất thường thành score 0/medium/high
```

`authenticated_at` đến từ timestamp của Keycloak; `recorded_at` đến từ UTC clock
của Risk Service. Bảng không lưu IP hoặc User-Agent vì hai trường này chưa cần cho
temporal model và sẽ làm tăng dữ liệu nhạy cảm. Flyway V3 thêm index theo
subject/client/thời gian cho đường đọc profile.

Baseline development dùng cửa sổ 90 ngày, tối thiểu 5 và tối đa 200 event, timezone
cấu hình, dung sai giờ vòng 24 giờ và ngưỡng tần suất riêng cho thứ/giờ. Chưa đủ 5
event là `TEMPORAL_PROFILE_COLD_START`; lỗi database là
`TEMPORAL_PROFILE_UNAVAILABLE`. Hai trạng thái này không tạo score thấp giả. Các
ngưỡng và score đều nằm trong cấu hình `TBD`, phải hiệu chỉnh bằng dữ liệu thật
trước production.

## 5. Network Intelligence theo policy CIDR nội bộ

Nguồn network đã chốt cho milestone hiện tại là policy CIDR do operator quản lý,
chạy hoàn toàn trong Risk Service. Provider hỗ trợ IPv4/IPv6, phân loại
`trusted/elevated/high/default` và chọn mức rủi ro cao nhất khi các dải chồng lấn.
Nó không gọi API bên thứ ba, không lưu IP và không chuyển IP ra khỏi ranh giới
Keycloak/Risk Service. SLA vì thế đi cùng Risk Service; đổi policy cần restart hoặc
redeploy, không phụ thuộc SLA của vendor bên ngoài.

Provider mặc định tắt. Trạng thái disabled hoặc IP runtime không hợp lệ tạo
`NETWORK_INTELLIGENCE_UNAVAILABLE` và giữ evaluation `INCOMPLETE`. Chỉ khi provider
được bật, network assessment available, Redis đọc được và Temporal Profile đủ mẫu
thì extractor trả `COMPLETE` để weighted scoring chạy.

Canonical IP vẫn lấy từ `ClientConnection.getRemoteAddr()` của Keycloak. Trước khi
bật ở production, reverse proxy phải là hop được tin cậy, phải xóa/ghi đè header
forwarded do Internet gửi và Keycloak phải cấu hình proxy headers đúng. CIDR VPN,
private hoặc NAT dùng chung không được mặc nhiên xem là trusted: network chỉ là một
tín hiệu, không thay thế identity/device và mọi user cùng egress sẽ nhận cùng tín
hiệu. Nếu sau này cần reputation/geolocation bên thứ ba, phải review lại privacy,
retention, data residency, timeout, circuit breaker và SLA trước khi thay provider.

## 6. Bằng chứng kiểm thử đến ngày 2026-09-18

- Ngày 2026-09-17, Risk Service build lại với `69/69` test đạt; Keycloak extension
  build lại với `66/66` test đạt. Test mới bao phủ migration V2, insert idempotent,
  validation/phân quyền endpoint và JSON ISO-8601 từ Keycloak.
- Sau build, Risk DB và Redis đều healthy, Risk Service health là `UP`, Keycloak
  discovery endpoint trả `200`; request evaluation không token bị chặn `401`.
- Một `LOGIN_ERROR` thật tạo đúng một event marker, một counter subject và một
  counter IP; gửi lại cùng event không tăng lần hai.
- Ba lần sai mật khẩu tạo subject counter `3`; evaluation thật trả
  `AUTHENTICATION_HISTORY_RISK`, `MEDIUM`, `STEP_UP_MFA`, `INCOMPLETE`.
- Trạng thái brute-force test của user đã được reset sau phép thử; Keycloak trở về
  `numFailures=0`, `disabled=false`.
- Token qua issuer không khớp (`8180` so với `8080`) bị từ chối `401`, xác nhận
  validator không nới lỏng issuer.
- Flyway MySQL local lên version 2, Risk Service health `UP`; checksum JAR local
  trùng JAR trong container và log Keycloak xác nhận provider được nạp lại.
- Một login thật bằng password + OTP mở được Portal `/admin` và tạo đúng một row
  `zerotrust-spa` trong `authentication_success_events`. Smoke test gửi trùng event
  hai lần đều nhận `204`, database chỉ có một row và row test đã được dọn.
- Ngày 2026-09-18, Risk Service đạt `86/86` test. Test temporal bao phủ validation
  policy, query đúng subject/client/window, giới hạn mẫu, cold-start, DB outage,
  baseline quen thuộc, một/hai tín hiệu bất thường, timezone cấu hình và khoảng
  giờ qua nửa đêm.
- Flyway V3 được xác minh trên H2 và MySQL 8.0.46 thật; schema local lên version 3,
  index đủ ba cột subject/client/time và Risk Service health trả `UP`.
- Risk Service đạt `101/101` test sau milestone network. Test mới bao phủ validation
  score, provider disabled, default/trusted/elevated/high, IPv4/IPv6, CIDR chồng
  lấn, cấu hình CIDR sai, IP runtime sai, trạng thái `COMPLETE` và network fail-safe.
- Ngày 2026-09-21, Risk Service đạt `105/105` test và Keycloak extension đạt
  `68/68` test sau hardening authentication history. Test xác nhận lỗi hết hạn và
  lockout không tăng counter, high history buộc MFA dù weighted score thấp và
  guardrail không hạ quyết định `DENY` vốn có.

## 7. Kết luận và thứ tự tiếp theo

Đồ án đã có nền tảng đúng cho adaptive authentication: identity do Keycloak quản
lý, policy tập trung tại Risk Service, least privilege cho machine identity, MFA
theo risk, failure telemetry thật và hành vi fail-safe khi thiếu dữ liệu. Không nên
trình bày đây là “tuân thủ đầy đủ NIST Zero Trust” vì policy hiện chỉ chạy lúc login,
network policy thực tế chưa được bật và hạ tầng vẫn là local development.

Thứ tự hợp lý tiếp theo:

1. Viết test/runtime scenario cho đủ `ALLOW`, `STEP_UP_MFA`, `DENY`, Redis/Risk
   Service outage và Keycloak brute-force lockout.
2. Xác minh canonical client IP qua reverse proxy, duyệt CIDR/NAT policy rồi mới
   bật `RISK_NETWORK_INTELLIGENCE_ENABLED` ở môi trường tương ứng.
3. Trước production, cố định canonical Keycloak HTTPS hostname/issuer, đưa secret
   vào secret manager, build immutable Keycloak image và bổ sung audit/monitoring.
4. Sau khi có dữ liệu đo, hiệu chỉnh threshold/weight và lập phiên bản policy;
   chỉ thay bằng network reputation/geolocation ngoài hệ thống sau review SLA,
   privacy, retention và data residency.
