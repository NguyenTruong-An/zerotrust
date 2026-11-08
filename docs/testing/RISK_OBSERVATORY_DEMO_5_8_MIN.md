[Mục lục](../README.md) · [Kết quả LIVE-L1](RISK_OBSERVATORY_ACCEPTANCE_2026-11-03.md) · [Bộ hình](../../presentation/risk-observatory-evidence-20261103-L1/README.md)

# Kịch bản demo Risk Observatory — khoảng 7 phút

Phạm vi: trình bày dữ liệu thực của một lần login; giữ B0, flow, account và dữ
liệu. Không dựng fixture để bắt buộc score hoặc OTP. Chuẩn bị sẵn các hình
LIVE-L1 làm bằng chứng có ngày; không giới thiệu chúng thành login mới hôm demo.

## Chuẩn bị trước khi bắt đầu

- Docker canonical đang hoạt động, TLS không có cảnh báo; nếu có cảnh báo thì
  dừng, không bỏ kiểm tra certificate.
- Dùng STUDENT lab có sẵn. Người dùng tự nhập password/OTP; không ghi hình hoặc
  chiếu phần nhập credential/QR/recovery code lên slide.
- Chạy collector ra file demo-defense riêng, không sửa evidence nghiệm thu cũ:

```powershell
python -X utf8 scripts/observation/observe.py --watch-seconds 5 --open --output .local-legacy/risk-observation/defense/index.html
```

- Không dùng `--demo` cho phần gọi là live. Trước login ghi nhận thời gian và
  các ID đã có để phân biệt evaluation mới.
- Nếu đã ở Portal, dùng Đăng xuất rồi đăng nhập lại, giữ profile/cookie để không
  chủ động đổi ngữ cảnh. SSO không có form password phải được nêu đúng là SSO.

## Lịch trình và lời dẫn

| Thời gian | Thao tác | Điều cần giải thích |
|---|---|---|
| 0:00–0:40 | Giới thiệu sơ đồ trách nhiệm | Keycloak xác thực/MFA; Risk thu và chấm ngữ cảnh; Portal phân quyền dữ liệu |
| 0:40–1:20 | Mở Observatory, chỉ mode và model | Dữ liệu log thật, BASELINE_B0; health không đồng nghĩa Browser đã nghiệm thu |
| 1:20–2:20 | Người dùng login qua form | Tự nhập mật khẩu/OTP nếu có; chờ kết quả, không tác động account/counter/history |
| 2:20–3:40 | Chọn evaluation mới, xem D/N/T/H | Đọc trạng thái, nguồn, score, weight, contribution và dữ liệu thiếu thực tế |
| 3:40–4:40 | Giải thích phép tính và decision source | Tự cộng contribution, so ngưỡng, phân biệt mandatory/priority/incomplete |
| 4:40–5:40 | Xem enforcement/MFA/login timeline | Cùng evaluation/correlation; challenge khác hoàn tất MFA; login success khác đăng ký trust |
| 5:40–7:00 | Chỉ giới hạn và ma trận bằng chứng | Live mới / lịch sử / controlled offline / chưa verified; không tuyên bố model accuracy |

### Lời dẫn phần tín hiệu — dùng số thật đang thấy

“D cho biết trạng thái thiết bị từ cookie và bản ghi server. N cho biết IP được
đánh giá theo CIDR, GeoIP hay default. T dùng lịch sử login thành công theo ngày
và giờ. H dùng số thất bại theo tài khoản/IP. Mỗi giá trị được giữ ngay trong
lần chấm điểm, không đọc lại store sau đó để dựng giải thích.”

Nếu trình bày bằng chứng ngày 03/11/2026, nêu rõ **LIVE-L1 đã nghiệm thu**:

| Nhóm | Snapshot LIVE-L1 | Score × weight = contribution |
|---|---|---:|
| D | TRUSTED | 0 × 0,25 = 0 |
| N | NON_PUBLIC → DEFAULT_POLICY | 50 × 0,25 = 12,50 |
| T | 37 mẫu; 8/37 cùng thứ, 9/37 gần giờ | 0 × 0,25 = 0 |
| H | 0 thất bại theo tài khoản/IP | 0 × 0,25 = 0 |

“Tổng 12,50 thấp hơn 40, dữ liệu COMPLETE và không có guard bắt buộc MFA,
nên LOW/ALLOW. Source là SCORE_THRESHOLD. Ngay sau đó Keycloak ghi
RISK_STEP_PASSED, MFA_SUBFLOW_NOT_SELECTED và LOGIN_SUCCESS.”

**Không đặt kỳ vọng login mới phải lặp lại 12,50.** History/counter/thời điểm
thực có thể thay đổi; đọc score/decision mới đúng log, không chỉnh dữ liệu để ép số.
Nếu thiếu dữ liệu, giải thích null và INCOMPLETE thay vì làm tròn thành 0.

### Lời dẫn khi N không có country/city/ASN

“IP ở ca này không public nên GeoIP được bỏ qua. N vẫn có điểm default 50;
COMPLETE không có nghĩa mọi metadata địa lý phải xuất hiện. City và ASN là
tham khảo; mã quốc gia mới là trường GeoIP tham gia policy hiện tại.”

Không tự thay IP bằng IP public của máy hoặc giá trị Postman rồi gọi đó là
Browser evidence. Không hiển thị IP/username/identifiers thô.

### Lời dẫn MFA và trust

“Ca LIVE-L1 không yêu cầu MFA nên không được gọi là MFA đã hoàn tất.
Muốn kết luận OTP/recovery thành công cần execution SUCCESS thực và outcome
tương ứng. Đăng ký thiết bị 204/cấp cookie cũng là các bằng chứng riêng.”

Nếu login mới thực sự yêu cầu OTP, người dùng tự nhập. Chỉ kết luận live MFA
khi có execution proof được nối cùng ca. Nếu không có OTP, dùng A3/A5 có ngày
để minh họa nhánh lịch sử, không ép fixture và không gọi đó là ca vừa chạy.

## Kết thúc và trả lời phản biện

| Câu hỏi | Trả lời đúng bằng chứng |
|---|---|
| Vì sao điểm LOW vẫn có thể MFA? | Guard mandatory; A3 32,50 là bằng chứng lịch sử, không sửa ngưỡng |
| Vì sao DENY có thể không có điểm? | Priority trước weighted scoring; A4 null/NOT_EVALUATED |
| Thiếu history hoặc service lỗi thì sao? | Incomplete khác unavailable; dùng lịch sử/targeted tests đúng nhãn, không gây outage runtime |
| Có chứng minh GeoIP public live không? | LIVE-L1 bỏ qua vì IP không public; public lookup mới là NOT VERIFIED |
| Trace có chứng minh role STUDENT không? | Actor theo owner; trace không có role, database event binding chưa verified vì event store tắt |
| Công thức có chính xác hơn sau khi thêm quan sát? | Chỉ kiểm chứng tính nhất quán và khả năng giải thích; chưa đo độ chính xác phát hiện tấn công |

Khi demo phát sinh lỗi hoặc thiếu trace, ghi **NOT VERIFIED**, giữ evidence,
không đổi policy/restart/reset/seed. Nhấn Ctrl+C dừng collector khi xong.
