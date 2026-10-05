[Kế hoạch](TEST_PLAN.md) · [Kịch bản chức năng](FUNCTIONAL_SCENARIOS.md) · [Pentest cơ bản](BASIC_PENTEST.md)

# Mẫu báo cáo kiểm thử ZeroTrust

Sao chép mẫu này sang một báo cáo riêng cho mỗi đợt. Trạng thái hợp lệ: **PASS / FAIL / BLOCKED / NOT_RUN / N/A**. Ghi mỗi biến thể một dòng; không ghi PASS nếu chỉ đọc code hoặc chưa đủ bằng chứng runtime.

## 1. Thông tin lần chạy

| Trường | Giá trị |
|---|---|
| Ngày/giờ, múi giờ | `<Asia/Saigon>` |
| Người kiểm thử | `<tên>` |
| Mã nguồn | `<commit SHA + mô tả working tree; không coi SHA bao gồm thay đổi chưa commit>` |
| Target và phạm vi được phép | `<SPA, Portal, Keycloak, Risk local URL; tài khoản disposable>` |
| Phiên bản/runtime | `<JDK, Keycloak đang chạy, module build, MySQL, Redis, browser>` |
| Profile và cấu hình | `<issuer/audience, caller/role, Browser Flow binding, failure mode, network/GeoIP, ngưỡng, trust TTL; không secret>` |
| Fixture/snapshot | `<nhãn fixture, mapping ID đã che, cách khôi phục>` |
| Ngoài phạm vi | `<production/tải lớn/hệ thống khác>` |

## 2. Nhật ký kết quả

| Case ID | Biến thể / precondition | Thao tác hoặc lệnh | Expected | Actual (HTTP + dữ liệu/state) | Trạng thái | Bằng chứng đã che / finding |
|---|---|---|---|---|---|---|
| `<F-A01>` | `<STUDENT_A, browser mới>` | `<bước>` | `<đúng A, MFA>` | `<chưa chạy>` | NOT_RUN | `<đường dẫn>` |
| `<P05>` | `<JWT đúng chữ ký, sai issuer>` | `<test/runtime>` | `<401>` | `<chưa chạy>` | NOT_RUN | `<đường dẫn>` |

Với 401/403/409, bổ sung kiểm tra không có side effect. Với ca G, ghi mục tiêu riêng, hành vi hiện tại và gap; không đổi expected thành actual để đạt PASS.

## 3. Test tự động thực sự đã chạy

| Module / test selector | Lệnh nguyên văn | Tổng / failure / error / skipped | Exit code | Report của lần chạy |
|---|---|---|---|---|
| `<Portal/Risk/SPI>` | `<Maven command>` | `<số hiện tại>` | `<code>` | `<target/surefire-reports; giữ bản sao đã che>` |

Phân biệt failure assertion với lỗi JDK/dependency/môi trường. Ghi giới hạn MockMvc/H2/Redis mock/realm giả lập. Không lấy số test của báo cáo cũ làm số của lần chạy này.

## 4. Finding mẫu

### ZT-FIND-001 — `<tên vấn đề và trigger cụ thể>`

- **Case/target:** `<ID, endpoint, module, môi trường>`.
- **Mức độ và trạng thái:** `<định tính dựa trên ảnh hưởng / đã xác nhận hay cần xác minh>`.
- **Tiền điều kiện:** `<role, token type, trạng thái device/session; không credential>`.
- **Tái hiện:** `<các bước tối thiểu bằng fixture; request đã che>`.
- **Expected / actual:** `<quyền/dữ liệu/state mong đợi và quan sát>`.
- **Ảnh hưởng:** `<chủ thể/tài sản bị tác động và giới hạn khai thác>`.
- **Bằng chứng:** `<response, state trước/sau, source path và dòng; không token/secret/raw IP/device ID>`.
- **Đề xuất sửa:** `<hành vi cần đổi, regression cần thêm, ảnh hưởng compatibility>`.
- **Retest:** `<ngày, mã nguồn, case/biến thể, kết quả>`.

## 5. Kết luận đợt

- Tổng ca/biến thể: `<PASS/FAIL/BLOCKED/NOT_RUN/N/A>`; P0 chưa đạt: `<ID>`.
- Finding cần xử lý trước demo/phát hành: `<ID, ảnh hưởng>`.
- Giới hạn quan sát: `<SSO/refresh, token cũ, fresh admin MFA, cloned cookie, MySQL/Redis thật chưa kiểm chứng>`.
- Khôi phục sau test: `<dịch vụ/policy/fixture đã phục hồi; login smoke sau phục hồi>`.
- Quyết định: `<đạt phạm vi nào; chưa xác nhận phần nào; việc còn lại có người phụ trách>`.
