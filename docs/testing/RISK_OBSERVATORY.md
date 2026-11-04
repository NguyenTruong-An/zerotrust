[Mục lục](../README.md) · [Postman/Wireshark/MMDB](RISK_GEOIP_OBSERVATION_GUIDE.md)

# Xem chi tiết tín hiệu, điểm Risk và kết quả MFA

Ngày cập nhật hướng dẫn: **03/11/2026**, giờ Việt Nam. Các mốc rollout bên dưới
giữ ngày kiểm chứng riêng.

Mốc LIVE-L1 ngày 03/11/2026 đã đối chiếu một lần form login có score 12,50/ALLOW
và không OTP. Báo cáo `RISK_OBSERVATORY_ACCEPTANCE_2026-11-03.md`, kịch bản
`RISK_OBSERVATORY_DEMO_5_8_MIN.md` và bộ hình được giữ cùng hồ sơ demo cục bộ.
Checklist nghiệm thu cho lần vận hành hiện tại nằm trong [RUNBOOK](../operations/RUNBOOK.md).

Chọn một lần xác thực để xem tín hiệu D/N/T/H thực đã sử dụng, điểm/trọng số/đóng
góp, lý do quyết định và bằng chứng MFA. Giữ nguyên B0, công thức, guardrail,
API và quyền service hiện có.

## 1. Mở và sử dụng

Chạy trong PowerShell tại root đồ án. Cần Python 3.11+; không cài thêm package.

### Theo dõi Docker thật, cập nhật mỗi 5 giây

```powershell
.\scripts\observation\Observe-Risk.cmd --watch-seconds 5 --open
```

Công cụ tìm một container có hậu tố `-risk` và một container `-keycloak`,
chỉ đọc `docker ps`/`docker logs`, lọc trường rồi tạo:

```text
.local-legacy/risk-observation/latest/index.html
.local-legacy/risk-observation/latest/index.json
```

Giữ cửa sổ theo dõi chạy, thực hiện đăng nhập trên Portal rồi quay lại trang
quan sát. Trang tự tải lại khi báo cáo mới được ghi; giữ lần đang chọn/bộ lọc
trong phiên trình duyệt. `Ctrl+C` dừng công cụ, không dừng container.

Bản chụp một lần, lấy log hai giờ:

```powershell
.\scripts\observation\Observe-Risk.cmd --open --since 2h
```

Khi có nhiều stack, chỉ định chính xác:

```powershell
.\scripts\observation\Observe-Risk.cmd --watch-seconds 5 --open `
  --risk-container zerotrust-legacy-integration-20261026-risk `
  --keycloak-container zerotrust-legacy-integration-20261026-keycloak
```

### Xem giao diện bằng dữ liệu minh họa riêng

```powershell
.\scripts\observation\Observe-Risk.cmd --demo --open
```

Bản này ở `.local-legacy/risk-observation/preview/index.html`, có banner
**DỮ LIỆU MINH HỌA** và `mode=ILLUSTRATION` trong file xuất. Không dùng làm
bằng chứng đã đăng nhập, tra GeoIP hay hoàn tất MFA.
Không có log thật thì báo cáo Docker thật trống; không tự chèn demo.

### Python trực tiếp hoặc đọc log đã lưu

```powershell
python -X utf8 scripts/observation/observe.py --since 30m --watch-seconds 5 --open
```

```powershell
python -X utf8 scripts/observation/observe.py `
  --risk-log .local-legacy/risk-observation/risk.private.log `
  --keycloak-log .local-legacy/risk-observation/keycloak.private.log
```

Chế độ nhập file ghi `mode=IMPORTED_LOGS`. Giữ log đầu vào riêng tư: collector
lọc đầu ra nhưng không làm sạch file đầu vào. Mặc định lấy tối đa 10.000 dòng
mỗi container và hiển thị 200 lần/sự kiện mới nhất. Xem `--help` để đổi giới hạn.

### PowerShell báo “running scripts is disabled”

Lỗi này chặn file `.ps1` trước khi collector chạy. Dùng `.cmd` hoặc Python
trực tiếp ở trên, không cần quyền quản trị hoặc đổi Execution Policy.
Nguồn: [Microsoft — Execution Policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies).

`--open` mở báo cáo sau khi ghi file thành công, chỉ mở một lần khi theo dõi.
Nếu không tự mở được trình duyệt, collector vẫn chạy và in đường dẫn để mở
thủ công. Cả Python và `.cmd` tự đặt demo ở `preview`, log thật ở `latest`.
Wrapper `.ps1` cũ vẫn dùng được khi chính sách máy cho phép.

Ngày 03/11/2026 đã chạy đạt 13 test collector, gồm kiểm tra chỉ mở một lần,
đường dẫn có khoảng trắng, lỗi trình duyệt và tách file demo/log thật. Đã chạy
`.cmd --demo` và collector Docker thật thành công; test mở trình duyệt dùng
mock, không tự mở cửa sổ trong phiên kiểm tra. Không đổi policy, Java hay Docker runtime.

## 2. Đọc trang quan sát

| Khu vực | Cách đọc |
|---|---|
| Danh sách bên trái | Chọn theo evaluation/correlation; tìm mã hoặc lọc ALLOW/MFA/DENY |
| Tổng quan | Tổng điểm/null, model, mức theo điểm và mức hiệu lực, mã lý do |
| Bảng D/N/T/H | Trạng thái dữ liệu, nguồn, điểm, trọng số và đóng góp |
| Đầu vào từng nhóm | Snapshot lấy ngay trong lần tính toán |
| GeoIP | Trạng thái tra cứu/bỏ qua, quốc gia, city/ASN nếu thực có |
| MFA/kết quả cuối | OTP/recovery, LOGIN, đăng ký thiết bị 204, cấp cookie |
| Diễn biến | Các dòng trace ghép theo mã, theo thứ tự thời gian |
| Giới hạn bằng chứng | Thiếu trace/kết quả cuối hoặc mã mâu thuẫn được ghi rõ |

Nút **Xuất lần đang xem** tải JSON của lần đang chọn, hậu tố `.private.json`.
Giữ nguyên `mode` và các trường thiếu bằng chứng khi lập báo cáo. Trust hiển thị
là quy đổi `100 − Risk`, không phải xác suất an toàn hay mô hình độc lập.
Không có proof hoàn tất MFA nghĩa là **chưa quan sát**, không kết luận OTP sai.
Không có xác nhận đăng ký thiết bị không tự chứng minh đăng nhập thất bại.

## 3. Nguồn và ý nghĩa tín hiệu

| Nhóm | Tín hiệu giữ lại | Nguồn |
|---|---|---|
| D | State, lý do missing/new/pending/trusted/revoked/expiry/reset | [DeviceRecognitionService](../../risk-scoring-service/src/main/java/com/zerotrust/risk/service/DeviceRecognitionService.java) |
| N | Address scope, nhánh lookup/bỏ qua, policy band, unavailable reason, country/city/timezone/accuracy/ASN | [NetworkRiskCalculator](../../risk-scoring-service/src/main/java/com/zerotrust/risk/service/NetworkRiskCalculator.java), [MaxMind](../../risk-scoring-service/src/main/java/com/zerotrust/risk/service/MaxMindGeoIpProvider.java) |
| T | Thời điểm/múi giờ, khoảng lịch sử, số mẫu, ngày/giờ đánh giá, matches, ngưỡng tần suất | [TemporalRiskCalculator](../../risk-scoring-service/src/main/java/com/zerotrust/risk/service/TemporalRiskCalculator.java) |
| H | Hai số đếm thất bại, ngưỡng, TTL cấu hình và cách lấy max điểm | [AuthenticationHistoryRiskCalculator](../../risk-scoring-service/src/main/java/com/zerotrust/risk/service/AuthenticationHistoryRiskCalculator.java) |

Assessment truyền snapshot qua [RiskSignalSnapshot](../../risk-scoring-service/src/main/java/com/zerotrust/risk/domain/RiskSignalSnapshot.java)
và [RiskFeatureEvidence](../../risk-scoring-service/src/main/java/com/zerotrust/risk/domain/RiskFeatureEvidence.java).
[RiskScoreTrace](../../risk-scoring-service/src/main/java/com/zerotrust/risk/trace/RiskScoreTrace.java)
xuất `ZEROTRUST_RISK_SCORE_TRACE`, schema 2, stage `RISK_EVALUATION_DETAILS`.
Không đọc lại database/Redis/MMDB để dựng giải thích sau khi đánh giá xong.

T cold-start có số mẫu thực tế nhưng matches chưa tính để `null`. Điểm và
contribution của nhóm unavailable để `null`, không dùng fallback nội bộ để
trình bày thành số đo an toàn. H unavailable trước khi đủ hai số đếm không
được suy đoán số đếm còn thiếu.

H dùng TTL bộ đếm từ thất bại đầu tiên của chu kỳ, không phải sliding window
chính xác từng event. Nguồn: [RedisAuthenticationFailureStore](../../risk-scoring-service/src/main/java/com/zerotrust/risk/repository/RedisAuthenticationFailureStore.java).

GeoIP chỉ dùng **mã quốc gia** trong scoring. City/ASN/timezone GeoIP là tham
khảo; T dùng múi giờ cấu hình riêng. CIDR giữ ưu tiên và không thêm lookup chỉ
để làm đầy giao diện. Address scope là predicate Java hiện có, không là kiểm
định toàn bộ registry địa chỉ đặc biệt IANA. User-Agent chưa tham gia scoring.

`ip_source=RISK_REQUEST_IP_ADDRESS` chỉ khẳng định đầu vào là trường `ipAddress`
trong request Risk. Với Browser, SPI lấy trường đó từ kết nối Keycloak; request
Postman/lab có thể truyền giá trị kiểm thử. Không tự gắn mọi IP trong Risk trace
thành IP thật của trình duyệt hoặc vị trí của người dùng.

## 4. Nối với Keycloak/MFA

Risk details nối SPI bằng `evaluation_id`; các bước Keycloak nối bằng
`correlation_id`. Không ghép theo subject, IP, device hoặc thời gian gần nhau.

[RiskEvaluationTrace](../../keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/trace/RiskEvaluationTrace.java)
đọc execution thực:

- `OTP_EXECUTION_SUCCESS` / `RECOVERY_EXECUTION_SUCCESS`: execution có trạng thái SUCCESS.
- `CHALLENGE_RENDERED`: đã hiện màn hình, chưa chứng minh hoàn tất MFA.
- `LOGIN_SUCCESS` / `LOGIN_ERROR`: kết quả sự kiện đăng nhập quan sát được.
- `REGISTERED_204` / `COOKIE_ISSUED`: bằng chứng riêng về device trust.

MFA success và login success trình bày riêng. Enrollment không được nâng thành
proof MFA. SSO/refresh không được dựng thành Risk LOW mới; sự kiện không có mã
nối được giữ độc lập. Fallback Risk unavailable không tạo điểm/evaluation ID
hợp lệ giả. Khi IDs/details mâu thuẫn, công cụ cảnh báo và không ghép tùy tiện.

## 5. Quyết định và dữ liệu riêng tư

[RiskEvaluationService](../../risk-scoring-service/src/main/java/com/zerotrust/risk/service/RiskEvaluationService.java)
và [RiskScoringService](../../risk-scoring-service/src/main/java/com/zerotrust/risk/service/RiskScoringService.java)
vẫn quyết định:

- Priority deny không tạo phép cộng hoặc bảng điểm giả.
- Thiếu dữ liệu/cold-start dẫn MFA, tổng `null`.
- Mandatory MFA có thể nâng mức hiệu lực khi điểm LOW; HIGH vẫn DENY.
- B1 opt-in không được bật bởi công cụ quan sát.

Lỗi serializer/logger không thay ALLOW/MFA/DENY. API không thêm trường/cổng/role.
Trace lab schema 2 lưu metadata GeoIP và thống kê tổng hợp đã allowlist; đây
là thay đổi lưu dữ liệu ngữ cảnh trong lab. Không ghi IP thô, subject/device ID,
device hash, cookie, header, OTP/recovery, token, pepper, CIDR hay đường dẫn MMDB.
Chuỗi GeoIP bỏ control character, giới hạn độ dài. Collector lọc lại trường,
không ghi raw Docker logs ra file.

Giữ HTML/JSON trong `.local-legacy/` được Git/Docker build bỏ qua; không hosting
hoặc gửi cho người không có quyền. Trang không tài nguyên ngoài/không gọi mạng,
hiển thị log bằng text node. Docker xoay vòng log theo dung lượng, không bảo
đảm retention theo ngày. `latest` ghi đè; xóa bản xuất riêng khi hết mục đích
demo theo quy định lab. Chưa tự purge theo thời gian hoặc audit đọc file HTML;
không coi đây là dashboard quản trị production.

## 6. Kiểm chứng và runtime

```powershell
python -m unittest discover -s scripts/observation -p test_observe.py -v
node --test scripts/observation/test_viewer.cjs
```

Ngày 02/11/2026: 10 test collector và 4 test DOM đạt; kiểm tra nhầm attempt,
fallback/null, SSO/refresh, conflict, allowlist, script injection, large integer,
hiển thị và lọc. Đã chạy wrapper và thu log Docker thật; không có trace thì
báo cáo thật trống.

Java chạy JDK 17 trong container kiểm thử, không nối database/runtime thật.
Maven báo Risk **709 trường hợp, 0 failure/error, 96 skipped**; SPI **203 trường
hợp, 0 failure/error, 27 skipped**. Test điều kiện/diagnostic skip không được coi
là đã kiểm chứng. Có 8 test mới trong [RiskObservationTests](../../risk-scoring-service/src/test/java/com/zerotrust/risk/audit/RiskObservationTests.java)
về snapshot, contribution/mandatory MFA, CIDR precedence, unavailable, priority
deny, expiry/reset, TTL và lỗi logger.
Sau khi làm rõ nhãn nguồn IP của request, 13 test mục tiêu (8 quan sát và
5 evaluation guardrail) được chạy lại và đều đạt.

Đã build image `zerotrust-legacy-risk:observation-v2-20261102` bằng Dockerfile
Java hiện có. Kết quả rollout/health thực ghi trong mục cập nhật vận hành bên
dưới, không suy ra chỉ từ build.

Trình duyệt tích hợp của phiên làm việc không cho mở HTML cục bộ. Kiểm tra
giao diện ở trên là DOM harness, chưa là screenshot hoặc Browser Flow acceptance.
Để nghiệm thu Browser mới: bật theo dõi, login tài khoản lab, đối chiếu mã,
D/N/T/H, reason, execution MFA và LOGIN; chỉ đánh dấu PASS cho bước có bằng chứng.

### Cập nhật vận hành đã đối chiếu ngày 02/11/2026

- Đã cập nhật riêng container Risk bằng image quan sát v2; alias canonical
  `zerotrust-legacy-risk:20261026-candidate` hiện trỏ cùng image mới.
- Image ID cuối sau rollout bắt đầu `sha256:927cf372ecf4`; class
  `RiskSignalSnapshot` tồn tại trong gói ứng dụng đang chạy.
- Hash snapshot source Risk trong label image đã đối chiếu khớp source hiện tại
  (bắt đầu `395155f1fe0d`); model hiệu lực kiểm tra là `BASELINE_B0`.
- HTTPS health với CA hiện có trả `{"status":"UP"}`; cả 10 dịch vụ healthy.
- Chín container còn lại giữ nguyên ID. Environment, bind mount chỉ đọc, mạng,
  cổng và giới hạn bộ nhớ Risk được đối chiếu giữ nguyên. Không chạy migration,
  không reset tài khoản, sửa counter/history hoặc thay Browser Flow.
- Image cũ được giữ với tag `zerotrust-legacy-risk:rollback-before-observation-v2-20261102`.
  Lượt thử đầu tự hoàn nguyên do phép so sánh mount quá chặt; lượt sau kiểm tra
  đường dẫn thực/quyền chỉ đọc và cập nhật thành công.
- Keycloak không được thay image: JAR đang chạy đã có các dấu vết OTP/recovery
  execution success, nối evaluation và phân biệt SSO/refresh cần cho trang xem.
- Chưa thực hiện Browser login/OTP mới trong đợt thay đổi này. Khi kiểm tra,
  khoảng lấy log không có attempt mới, nên báo cáo Docker có 0 bản ghi.
  Chưa có bằng chứng GeoIP lookup của một login mới hoặc MFA Browser sau rollout.

File kết quả riêng tư nằm trong `.local-legacy/risk-observation/verification/`.
Các kết quả health/class/source test không thay thế Browser acceptance.
