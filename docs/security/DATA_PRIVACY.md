[Mục lục tài liệu](../README.md) · [Trang dự án](../../README.md)

# Chính sách kỹ thuật cho IP, thiết bị và dữ liệu vị trí

**Ngày đối chiếu mã:** 2026-10-05. Các quy tắc production/checklist là yêu cầu
cần kiểm chứng, không phải xác nhận toàn bộ đã triển khai.

Tài liệu này mô tả data flow và biện pháp giảm thiểu dữ liệu của luồng adaptive
authentication. Đây là baseline kỹ thuật; đơn vị triển khai vẫn phải duyệt mục
đích xử lý, thông báo quyền riêng tư và thời hạn lưu theo quy định áp dụng.

## 1. Mục đích xử lý

IP, device identifier và Geo-IP chỉ được dùng để phát hiện đăng nhập bất thường,
chống credential abuse và quyết định `ALLOW`, `STEP_UP_MFA` hoặc `DENY`. Không dùng
để theo dõi vị trí ngoài phiên xác thực, quảng cáo hoặc suy luận địa chỉ cá nhân.

## 2. Nguồn và đường đi dữ liệu

1. Kiến trúc production yêu cầu reverse proxy xác định source IP và ghi đè header từ Internet.
2. Keycloak phải chỉ tin header từ proxy đã khai báo; repository không chứng minh deployment proxy hiện tại.
3. Extension lấy canonical IP qua `ClientConnection.getRemoteAddr()`; không tự đọc
   `X-Forwarded-For`.
4. Keycloak gửi IP qua protected Risk API. Production yêu cầu TLS **và** giới hạn
   mạng nội bộ, cùng service token giới hạn audience/client/role.
5. Risk Service dùng IP trong bộ nhớ cho CIDR, GeoLite local và failure counter.

[IpAddressNormalizer](../../risk-scoring-service/src/main/java/com/zerotrust/risk/validation/IpAddressNormalizer.java)
chuẩn hóa cách viết IP cho blocklist và HMAC counter, không tra DNS. Đây là
chuẩn hóa biểu diễn, không xác minh IP đã đi qua proxy tin cậy.

Canonical IP thường là public egress sau NAT/VPN/CGNAT, không phải bằng chứng định
danh người hoặc thiết bị và không phải vị trí vật lý chính xác.

## 3. Data inventory và retention

| Dữ liệu | Nơi xử lý/lưu | Dạng lưu | Retention |
| --- | --- | --- | --- |
| Raw IP trong risk request | Bộ nhớ Keycloak/Risk Service | Plain trong request nội bộ | Chỉ vòng đời request |
| Failure counter theo IP | Redis | HMAC-SHA-256 với pepper | Mặc định 15 phút |
| Event deduplication ID | Redis | HMAC-SHA-256 với pepper | Mặc định 1 giờ |
| Device ID | Cookie HttpOnly/SameSite | Random ID phía browser | Mặc định 30 ngày |
| Device fingerprint | MySQL `known_devices` | HMAC(subject + device ID) | Theo lifecycle thiết bị |
| Successful login history | MySQL | subject/client/timestamp, không IP/User-Agent | Theo retention được duyệt |
| Geo-IP result | Bộ nhớ Risk Service | country/city/timezone/accuracy radius/ASN | Không persist |
| GeoLite database | Filesystem service | Vendor `.mmdb`, không chứa lịch sử user | Theo release/vendor license |

Flyway V4 còn lưu `subject_device_trust` (subject/generation/pending) và
`device_trust_revocations` (operation/requester/subject/thời điểm/số device bị
thu hồi). Đây là audit reset trust, chưa phải audit mọi evaluation.
HMAC là giả danh hóa, vẫn cần access control và retention. Cửa sổ history của
Temporal chỉ giới hạn query, không tự xóa row; chưa có purge job trong mã hiện tại.

Nếu sau này cần Location Profile hoặc impossible travel, phải có migration, mục
đích, retention và access control riêng trước khi persist bất kỳ country/city nào.

## 4. Quy tắc bảo vệ bắt buộc

- Không log raw IP, device ID, token, recovery code, OTP hoặc MaxMind license key.
- Log vận hành chỉ ghi reason/status/correlation ID; nếu buộc hiển thị IP thì mask.
- Không trả city/ASN/accuracy radius trong API public hoặc UI người dùng hiện tại.
- Pepper và service-account secret nằm trong secret manager; không commit `.env`.
- Redis/MySQL, backup và service traffic phải được mã hóa/giới hạn mạng ở production.
- Chỉ role vận hành được xem security event; mọi reset MFA và truy cập audit phải có
  audit trail.
- Job retention phải xóa event hết hạn và có bằng chứng chạy thành công.
- GeoLite chạy local; không gửi IP người dùng tới web service theo request.
- Country/city không được dùng để hard deny nếu chưa có policy được phê duyệt.
- City/latitude là ước tính với accuracy radius, không được trình bày như địa chỉ.

## 5. Canonical IP và chống giả mạo

Production phải đặt Keycloak sau reverse proxy, cấu hình `KC_PROXY_HEADERS` và
`KC_PROXY_TRUSTED_ADDRESSES`, đồng thời chặn kết nối trực tiếp từ Internet tới
Keycloak. Proxy phải overwrite, không append, các forwarded header. Trước khi bật
Network Intelligence phải kiểm thử direct connection bypass và forged header.

## 6. Incident và quyền dữ liệu

- Có owner xử lý yêu cầu truy cập/xóa dữ liệu và sự cố lộ dữ liệu.
- Khi pepper bị lộ: rotate secret, xóa Redis keys cũ và đánh giá credential khác.
- Khi MaxMind license key bị lộ: revoke/rotate tại vendor; key không được dùng ở
  runtime Risk Service.
- Khi GeoLite lookup cần thiết lỗi/không có record: runtime sang dữ liệu thiếu/MFA.
- Khi database quá cũ: operator phải cập nhật và restart Risk. Provider nạp file
  vào memory khi khởi động, chưa có tự reload hoặc kiểm tuổi dữ liệu; health UP
  không chứng minh dữ liệu còn mới hay mọi IP lookup được.
- Ghi nhận phiên bản policy, database build date và thời điểm deploy để điều tra.

## 7. Go-live checklist

- [ ] Privacy notice và mục đích xử lý đã được duyệt.
- [ ] Canonical IP đã được xác minh qua proxy tin cậy.
- [ ] Không có raw IP trong MySQL/Redis key/log ứng dụng.
- [ ] TLS/private service network đã bật.
- [ ] Secret không nằm trong Git, image hoặc IntelliJ shared config.
- [ ] Retention và purge job đã được phê duyệt/kiểm thử.
- [ ] RBAC và audit cho dữ liệu security đã được kiểm thử.
- [ ] GeoLite EULA, update process và data residency đã được review.
