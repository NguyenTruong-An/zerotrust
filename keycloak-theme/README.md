# ZeroTrust Keycloak theme

Theme `zerotrust` kế thừa `keycloak.v2` của Keycloak 26.7.0, tùy biến CSS,
JavaScript, message và footer. Form action, credential handling, OTP và các
authentication flow vẫn do template gốc của Keycloak quản lý. Giao diện dùng
bố cục hai cột trên desktop và header gọn trên điện thoại; hỗ trợ login, OTP,
thiết lập QR, recovery code và lỗi đăng nhập.

## Thời gian khóa tạm thời

`ZeroTrustLoginFormsProvider` trong module `keycloak-risk-extension` bổ sung
`ztLockout.remainingSeconds` cho theme, chỉ khi Keycloak đang hiển thị lỗi
khóa tạm thời của user đã được xác định trong phiên xác thực. Thời gian lấy từ
`UserLoginFailureModel.getFailedLoginNotBefore()` trừ giờ hiện tại của server.
Provider vẫn gọi renderer FreeMarker gốc; master hoặc các theme khác giữ cách
render gốc. Không có API công khai để truy vấn khóa theo username.

Footer hiển thị thời gian; JavaScript đếm ngược theo đồng hồ monotonic trong
browser, tạm vô hiệu hóa submit rồi cho thử lại khi hết thời gian. Đây là
hướng dẫn giao diện: Keycloak vẫn quyết định tài khoản được đăng nhập hay chưa.
Nếu khóa kéo dài từ một lượt khác, thời gian mới được cập nhật ở lần server
render tiếp theo. Không tự đăng nhập, tự mở khóa, hay tự gửi password/OTP.
Khóa vĩnh viễn, user disabled, hoặc không đọc được mốc khóa không có countdown.
Không bật JavaScript vẫn đọc được số giây tại thời điểm trang được tạo.

Countdown cần nạp cả JAR SPI mới lẫn theme. Chỉ chép CSS/JS không tạo được mốc
khóa server. Kết quả kiểm chứng được ghi tại
[báo cáo giao diện và lockout](../docs/reviews/AUTH_UI_LOCKOUT_2026-10-09.md).

## Triển khai local

Từ thư mục gốc repository:

```powershell
.\deploy-keycloak-theme.ps1
```

Script chép theme vào `/opt/keycloak/themes/zerotrust`, đặt Login theme của realm
`DoAn` thành `zerotrust`, bật tiếng Việt/tiếng Anh với mặc định tiếng Việt và
khởi động lại container. Script đợi Keycloak sẵn sàng, dùng một phiên `kcadm`
tạm riêng và tự thử lại tối đa ba lần nếu Admin API trả lỗi tạm thời.

Nếu Keycloak được publish ở địa chỉ khác, truyền URL đó khi chạy:

```powershell
.\deploy-keycloak-theme.ps1 -KeycloakUrl http://localhost:8180
```

Cách triển khai này tồn tại qua thao tác restart, nhưng sẽ mất nếu container bị
xóa và tạo lại. Khi đóng gói môi trường demo/production, hãy copy thư mục theme
vào image Keycloak hoặc mount nó thành volume để việc triển khai có thể lặp lại.

## Chính sách thông báo lỗi

- Sai username hoặc password vẫn dùng một thông báo chung để không tiết lộ tài
  khoản nào tồn tại.
- Tài khoản disabled/temporary lockout/permanent lockout có thông báo riêng.
- OTP sai, phiên hết hạn, action link hết hạn và cookie bị thiếu có thông báo cụ
  thể để người dùng biết cách xử lý.

Không đưa raw exception, internal URL, client secret hoặc chi tiết Risk Service
vào message hiển thị cho người dùng.
