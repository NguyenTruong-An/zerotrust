# ZeroTrust Keycloak theme

Theme `zerotrust` kế thừa `keycloak.v2` của Keycloak 26.7.0 và chỉ ghi đè tài
nguyên giao diện/message. Form action, CSRF, credential handling, OTP và các
authentication flow vẫn do template gốc của Keycloak quản lý.

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
