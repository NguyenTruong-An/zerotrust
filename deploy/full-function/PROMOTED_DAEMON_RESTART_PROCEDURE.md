# Promoted Risk — kiểm tra daemon/Windows restart

**DRAFT, NOT_EXECUTED, chưa owner phê duyệt.** Phase2.3A-FIX chỉ review quy trình;
không restart Docker Desktop, WSL hoặc Windows. Cold service stop/start không
thay thế kết quả này.

**Phạm vi approval riêng cần có**

Owner phải duyệt maintenance của **toàn Docker Engine/Windows host**, vì restart
ảnh hưởng mọi project đang chạy. Ghi exact Engine/context, project, active
descriptor SHA, selected Risk ID, current container IDs, running intents, cửa sổ
maintenance và người vận hành. Không lấy authorization disposable hoặc approval
cutover cũ làm approval restart host. Không mở public/GCP hoặc ký waiver.

**Preflight bắt buộc**

1. Active controller/context phải được review và cấp quyền riêng; CLI Phase2.3A
   hiện chỉ cho mutation lane disposable. Nếu chưa có binding đó, dừng trước test.
2. Selected state PROMOTED đã commit, journal không RUNNING, đúng candidate
   `sha256:1ec3c4db626d6c232ca9a30c61188d69e883d40eb0005c29bd0d15921258686a`;
   TLS/CRL/data/source còn hợp lệ. Chỉ có một Risk writer.
3. Chụp metadata/running states của mọi project; owner xác nhận phạm vi ảnh hưởng.
   Các Lab/PD-R19 đang dừng phải giữ nguyên. Không tạo lại realm/account/volume.
4. Có checkpoint active mới, encrypted và independent restore-verified theo
   scope được duyệt; key tách riêng/private. Không dùng backup disposable.

**Case R1 — chủ động dừng rồi khởi động qua controller**

1. Dùng operation `stop` của **approved active controller** để đóng ingress trước,
   lưu `running_intent` và dừng đúng owned services. Kiểm journal DONE, state vẫn
   PROMOTED, OLD và candidate không được chọn đều dừng. Không chạy Compose up.
2. Owner restart Docker Desktop hoặc Windows đúng scope đã duyệt. Không dùng
   reset/factory reset, WSL shutdown cưỡng bức, prune hoặc reinstall.
3. Sau daemon ready, xác nhận đúng Engine/context, container IDs/volumes/network,
   descriptor và durable state/HMAC. `status` phải chọn đúng NEW. Unknown/partial
   phải giữ maintenance và yêu cầu recovery mới; không gọi legacy restart.
4. Dùng approved controller `restart`: phục hồi `running_intent`, kiểm internal
   TLS/CRL/JWT/V5/GeoIP và current reset/trust/audit trước khi mở lại ingress.
5. Ghi image/config IDs, một writer, health, credential/generation/pending/audit
   continuity, downtime và running states của các project được bảo vệ.

**Case R2 — daemon tự khởi động lại từ committed running state**

Nếu owner cần acceptance tự khởi động, duyệt thêm case riêng khi PROMOTED đang
healthy và không có operation dở. Sau restart ghi container start times, exact
selected image và writer count; kiểm fail-closed trong warm-up, TLS/CRL/GeoIP,
auth smoke và protected projects. Không suy R1 thành R2 PASS. Không dùng một
interrupted apply/rollback để thử restart host trong cùng lượt.

Theo [Docker restart policy](https://docs.docker.com/engine/containers/start-containers-automatically/),
`unless-stopped` giữ container đã dừng ở trạng thái dừng qua daemon restart. Đây
là cơ sở của fence OLD/ingress, **không phải bằng chứng Windows host đã PASS**.

**Nếu có lỗi**

Giữ ingress đóng; lưu sanitized receipt và durable journal. Chỉ recover đúng
known selected state hoặc rollback có approval với CURRENT DB/Redis. Không xóa
pending, giảm generation, import realm hay tự restore checkpoint. Data restore
là quyết định disaster recovery riêng.

R1, R2 và Windows shutdown/host-power-loss hiện đều **NOT_VERIFIED**. Chỉ nâng
case thực sự đã thực hiện, không đổi D-17/G8 hoặc release locks.
