# Đối chiếu kiến trúc với các khung tham chiếu bảo mật

**Ngày rà soát:** 2026-09-17  
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
| Thiếu dữ liệu không tạo mức LOW giả | Network và phép tính temporal chưa có làm `INCOMPLETE`, `riskScore=null`, `STEP_UP_MFA` | Đạt | Successful-login events đã được thu nhưng chưa biến thành factor; Redis lỗi cũng tạo `AUTHENTICATION_HISTORY_UNAVAILABLE` |
| MFA thích ứng theo tín hiệu rủi ro | Device state, auth history và priority rules có thể kích hoạt MFA/deny | Đạt một phần | Network intelligence và phép tính temporal chưa triển khai; nhánh runtime `ALLOW` chưa thể xuất hiện |
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
LOGIN_ERROR tại Keycloak
-> zerotrust-risk-events
-> POST /internal/v1/authentication-failures
-> JWT cần risk:events:write
-> Redis tăng atomically counter subject/IP có TTL
-> lần evaluation sau đọc hai counter
-> map từng counter vào 0 / medium / high
-> lấy max(subjectRisk, sourceIpRisk)
-> thêm AUTHENTICATION_HISTORY_RISK nếu score dương
```

Lấy `max` là lựa chọn có chủ đích: một lần nhập sai thường tăng cả counter account
và IP, nên cộng hai score sẽ đếm cùng một sự kiện hai lần. IP có ngưỡng cao hơn vì
nhiều user có thể đi qua cùng NAT/proxy. Nếu Redis tạm ngừng, calculator trả trạng
thái unavailable; hệ thống tiếp tục yêu cầu MFA thay vì hiểu nhầm là lịch sử sạch.

Các ngưỡng `3/5`, `10/20` và score `50/100` chỉ là baseline development. NIST và
OWASP yêu cầu rate limiting, adaptive signals và quản lý false positive, nhưng
không công bố một bộ số phù hợp cho mọi hệ thống. Trước production cần version hóa
policy, thu metric, thử tải và hiệu chỉnh trên threat model/dữ liệu của tổ chức.

## 4. Successful-login collection cho Temporal Profile

Luồng thu thập mới chỉ tạo dữ liệu nguồn, chưa thay đổi risk score:

```text
LOGIN thành công tại Keycloak
-> zerotrust-risk-events
-> POST /internal/v1/authentication-successes
-> JWT cần risk:events:write
-> MySQL lưu event_id + subject + client + authenticated_at + recorded_at
-> unique event_id và INSERT IGNORE chống ghi lặp nguyên tử
```

`authenticated_at` đến từ timestamp của Keycloak; `recorded_at` đến từ UTC clock
của Risk Service. Bảng không lưu IP hoặc User-Agent vì hai trường này chưa cần cho
temporal model và sẽ làm tăng dữ liệu nhạy cảm. Index theo subject/thời gian chuẩn
bị cho việc tính baseline giờ/ngày ở milestone kế tiếp.

## 5. Bằng chứng kiểm thử ngày 2026-09-16 và build lại ngày 2026-09-17

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

## 6. Kết luận và thứ tự tiếp theo

Đồ án đã có nền tảng đúng cho adaptive authentication: identity do Keycloak quản
lý, policy tập trung tại Risk Service, least privilege cho machine identity, MFA
theo risk, failure telemetry thật và hành vi fail-safe khi thiếu dữ liệu. Không nên
trình bày đây là “tuân thủ đầy đủ NIST Zero Trust” vì policy hiện chỉ chạy lúc login,
hai nguồn feature còn thiếu và hạ tầng vẫn là local development.

Thứ tự hợp lý tiếp theo:

1. Dựng **temporal profile** từ successful-login events đang thu thập: định nghĩa
   cửa sổ lịch sử tối thiểu, baseline theo giờ/ngày và quy tắc cold-start trước khi
   nối factor vào extractor.
2. Viết test/runtime scenario cho đủ `ALLOW`, `STEP_UP_MFA`, `DENY`, Redis/Risk
   Service outage và Keycloak brute-force lockout.
3. Trước production, cố định canonical Keycloak HTTPS hostname/issuer, đưa secret
   vào secret manager, build immutable Keycloak image và bổ sung audit/monitoring.
4. Sau khi có dữ liệu đo, hiệu chỉnh threshold/weight và lập phiên bản policy;
   chỉ thêm network reputation khi xác định được provider, SLA, privacy và cách xử
   lý NAT/proxy.
