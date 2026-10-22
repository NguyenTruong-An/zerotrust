# Troubleshooting

| Hiện tượng | Xử lý |
|---|---|
| PowerShell chặn ps1 | Dùng `scripts\demo\demo.cmd`, không đổi global Execution Policy. |
| Docker chưa chạy | Mở Docker Desktop, chọn Linux containers, kiểm tra `docker version`. |
| Build tải dependency lỗi | Đọc build log, kiểm tra DNS/network/disk. Tối đa2 retry cùng lỗi hạ tầng, sau đó chẩn đoán nguyên nhân. |
| HTTPS không tin cậy | Thực hiện bước [CA có chủ đích](DEVELOPMENT_DEMO.md#tls-trên-windows); không bypass cảnh báo. |
| Schannel báo revocation unknown/offline | Kiểm tra service `crl`, port8445 và file CRL chưa quá hạn. `start` refresh CRL. Không tắt revocation check. |
| Port8443/8444/8445 bị chiếm | Xác định ứng dụng đang dùng; không tự stop ứng dụng khác. Giữ cấu hình URL/issuer/redirect/CRL nhất quán. |
| MySQL/Redis permission denied | `init` gán file role cho UID runtime. Kiểm tra bind mounts đúng candidate và `.local-demo`; không chmod777 hoặc in config secret. |
| Keycloak import lỗi tên file | File import phải là `zerotrust-demo-realm.json`; wrapper chuẩn đã đặt đúng. Không import QA DB hoặc đổi realm để lách lỗi. |
| Token200 nhưng API401 | Kiểm tra client scope `basic` cung cấp sub, issuer/audience/expiry và CA/JWKS. Không nới JWT validator. |
| OTP bị từ chối | Kiểm tra đúng seed/tài khoản/đồng hồ; đợi chu kỳ30giây mới, không reset MFA hoặc thử dồn. Verifier có chống reuse cùng counter. |
| LOW vẫn yêu cầu MFA | Cold-start/thiếu lịch sử hoặc device chưa trusted là hợp lệ. Enroll chưa tạo trust; cần một lần OTP thực sau enrollment và history hợp lệ. |
| HIGH không lặp lại | Fixture failure có TTL; high lane phải có đúng actual source/CIDR. Xem Risk reasons thật, không giảm threshold. |
| V5 guard dừng | Giữ writers stopped; lưu backup/schema/Flyway evidence. Không repair/clean/sửa migration checksum. Schema fresh phải bắt đầu với0900_ai_ci. |
| Volume có dữ liệu nhưng init không seed | Đây là behavior giữ dữ liệu. Không tự xóa volume hoặc đổi marker để ép reseed. |

`demo.cmd status`, `demo.cmd logs <service>` chỉ nhắm project `zerotrust-demo`. Không chạy cleanup/prune diện rộng. Runtime restart policy `on-failure:2` giới hạn tự retry khi lỗi startup.
