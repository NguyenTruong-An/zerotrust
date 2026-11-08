[Mục lục](../README.md) · [Cách dùng Observatory](RISK_OBSERVATORY.md) · [Demo 7 phút](RISK_OBSERVATORY_DEMO_5_8_MIN.md)

# Risk Observatory — nghiệm thu live và bằng chứng bảo vệ

Ngày thực hiện: **03/11/2026**, GMT+7. Canonical repository và project
`zerotrust-legacy-integration-20261026` được giữ nguyên.

**LIVE VERIFIED trong phạm vi LIVE-L1:** Observatory phản ánh đúng một lần
đăng nhập có form mật khẩu, điểm **12,50 / LOW / ALLOW / COMPLETE**, nguồn
`SCORE_THRESHOLD`. Risk details, SPI response, enforcement, MFA gate và
`LOGIN_SUCCESS` nối được bằng đúng evaluation/correlation ID. Người dùng
xác nhận không có OTP và vào được trang xem điểm.

Đây là **một ca login mới**, không phải 14 lần đăng nhập: 14 điều kiện đối chiếu
đều đạt trong cùng ca. Không mở rộng kết luận thành mọi nhánh đã live PASS,
không coi thêm telemetry là tăng độ chính xác của mô hình.

## 1. Quy ước bằng chứng

| Nhãn | Nghĩa trong báo cáo |
|---|---|
| **LIVE VERIFIED** | Sự kiện/đầu vào được quan sát ở runtime đang chạy trong workflow này; luôn ghi phạm vi, không tự chuyển health/TLS thành Browser PASS |
| **HISTORICAL VERIFIED** | Tái sử dụng kết quả nghiệm thu có ngày A1–A6 và artifact cũ; không phải chạy lại hôm nay |
| **CONTROLLED OFFLINE** | Kiểm thử parser/UI/logic hoặc báo cáo JUnit đã có; không chứng minh Browser live |
| **NOT VERIFIED** | Nhánh chưa xảy ra, dữ liệu không được thu hoặc thiếu mối nối đủ mạnh; không gắn PASS |

Mật khẩu/OTP do người dùng tự thao tác. Không tự đăng nhập bằng password,
không xin/xuất OTP, không gọi token endpoint hoặc API evaluate để tạo ca thay thế.
Không tạo lại fixture A1–A6; không đổi scoring/model/flow/account/data/runtime.

## 2. Preflight và cách chọn ca

Git HEAD đọc được: `1c9fa97`. Working tree có các thay đổi Observatory từ trước;
không checkout/reset/stage/commit/push trong workflow. Source đang chạy được
đánh giá theo source/config/log, không giả định clean checkout.

| Đối chiếu | Kết quả |
|---|---|
| Model hiệu lực và trace | `BASELINE_B0`; live details ghi `BASELINE_B0:1` |
| Weights D/N/T/H | `0,25 / 0,25 / 0,25 / 0,25` |
| Ngưỡng MEDIUM/HIGH | `40 / 75` |
| Container canonical | 10/10 healthy |
| Network/GeoIP flags | Cả hai đang bật |
| Collector | Lấy trực tiếp log đúng Risk/Keycloak; `mode=DOCKER_LOGS` |
| Baseline log trước yêu cầu login | 8 Risk details, 8 SPI evaluations, 21 lần/sự kiện tổng; 0 dòng trace lỗi |
| Trộn demo | Không có ID demo trong capture; không đọc file preview/import làm đầu vào live |

Mốc bắt đầu LIVE-L1: **23:33:28 GMT+7**. Sau khi người dùng báo hoàn tất, capture
tìm được đúng một evaluation có details phát sinh sau mốc và không nằm trong
tập ID trước mốc. Ca được nối bằng ID; thời gian chỉ giới hạn cửa sổ thử,
không dùng thời gian gần nhau để nối hai actor hoặc hai lần đăng nhập.

Tất cả ID thật chỉ giữ trong evidence mới, riêng tư. Tài liệu/hình/CSV dùng
`LIVE-L1`, `E-L1`, `C-L1` và `STUDENT-LIVE`.

## 3. LIVE-L1: tín hiệu thực và phép tính độc lập

Thời điểm phát Risk details: **23:35:07 GMT+7**. Người dùng xác nhận có form
mật khẩu, không OTP, vào trang xem điểm.

| Nhóm | Tín hiệu được ghi ngay lúc tính toán | Điểm | Weight | Contribution | Nguồn |
|---|---|---:|---:|---:|---|
| D | State/reason `TRUSTED` | 0 | 0,25 | 0,00 | Cookie thiết bị + bản ghi server |
| N | `NON_PUBLIC`, `SKIPPED_NON_PUBLIC`, band `DEFAULT` | 50 | 0,25 | 12,50 | `DEFAULT_POLICY` |
| T | 37 mẫu; 8 mẫu cùng thứ; 9 mẫu gần giờ; đánh giá giờ 16 UTC | 0 | 0,25 | 0,00 | Successful-login history trong MySQL |
| H | Subject failures=0; source-IP failures=0 | 0 | 0,25 | 0,00 | Failure counters trong Redis |

T có đủ 37 ≥ 5 mẫu trong cửa sổ query 90 ngày, tối đa 200 mẫu:

- `8/37 = 21,62% ≥ 10%` cho thứ trong tuần.
- `9/37 = 24,32% ≥ 20%` cho giờ với dung sai 1 giờ.
- Theo B0, hai điều kiện không bất thường nên T=0.

H=0 vì hai số đếm hiện tại dưới các ngưỡng MEDIUM tương ứng 3 và 10.
Không diễn giải thành tài khoản/IP chưa từng đăng nhập sai trong toàn bộ lịch sử.
Cấu hình TTL bộ đếm 900 giây bắt đầu từ thất bại đầu tiên của chu kỳ; không phải
sliding window chính xác trên từng event.

Phép kiểm tra độc lập dùng Decimal, không lấy tổng do giao diện tự hiển thị:

```text
R = round_HALF_UP_2(0,25×0 + 0,25×50 + 0,25×0 + 0,25×0)
  = 12,50
Σ weights = 1,00
12,50 < 40 → LOW
Không mandatory override → effective LOW → ALLOW
```

Từng phép nhân khớp contribution trong Risk details; tổng khớp Risk Score
trong cả Risk details và SPI response. `Decision Source=SCORE_THRESHOLD`
là trường phát ra trực tiếp từ trace mới, không được suy ngược từ score.
Trust quy đổi 87,50 = 100 − Risk, không phải xác suất an toàn độc lập.

N=50 có dữ liệu đánh giá theo default policy dù không có GeoIP metadata.
`COMPLETE` nghĩa là bốn nhóm đủ dữ liệu theo policy hiện tại; không có nghĩa
mọi trường quốc gia/thành phố/ASN đều phải có. Không có lookup GeoIP public
trong LIVE-L1, nên không đánh dấu live GeoIP lookup PASS.

## 4. Live enforcement và outcome

Các dòng dưới cùng `E-L1/C-L1`; mốc t=0 là lúc phát Risk details, không phải
lúc người dùng bắt đầu nhập mật khẩu hoặc độ trễ login end-to-end.

| Mốc tương đối | Stage | Kết quả thực |
|---:|---|---|
| 0,000 ms | `RISK_EVALUATION_DETAILS` | Score 12,50; COMPLETE; LOW/ALLOW |
| +37,411 ms | `RISK_EVALUATION` | SPI nhận `EVALUATED`, cùng score/decision |
| +38,565 ms | `KEYCLOAK_ENFORCEMENT` | `RISK_STEP_PASSED` |
| +39,189 ms | `MFA_GATE` | `MFA_SUBFLOW_NOT_SELECTED` |
| +39,629 ms | `MFA_GATE` | Đi qua bước, `mfa_execution=NOT_OBSERVED` |
| +39,767 ms | `DEVICE_REGISTRATION` | `NOT_ELIGIBLE` |
| +52,400 ms | `AUTHENTICATION_EVENT` | `LOGIN_SUCCESS` |

Không có STEP_UP_REQUIRED, OTP challenge, execution success, REGISTERED_204 hoặc
COOKIE_ISSUED cho ca này. Vì MFA không được chọn, **không gắn nhãn “MFA hoàn tất”**.
Người dùng báo không OTP là phù hợp log; LOGIN_SUCCESS không được dùng thay proof OTP.
Không có bằng chứng tạo trust/cookie mới; snapshot `known_devices` giữ nguyên.

### Giới hạn role và API

Người dùng làm theo hướng dẫn dùng STUDENT và xác nhận vào trang điểm. Trace
không xuất role. Readback cho thấy realm event store đang tắt và EVENT_ENTITY
không có LOGIN row để nối evaluation/correlation trực tiếp với role trong database.

Vì vậy **automated STUDENT role binding qua database event là NOT VERIFIED**.
Không bật event store, không suy role từ score/correlation, không gắn PASS cho
mối nối thiếu. Kết quả Browser/actor theo xác nhận owner được phân biệt với
chứng cứ log tự động. HTTP GET điểm với user JWT/RBAC không được thử lại; các
ca RBAC cũ giữ trạng thái lịch sử.

## 5. Guardrail và A1–A6

| Ca/phạm vi | Risk thực được ghi trước đây | Phân loại dùng lần này | Giới hạn |
|---|---|---|---|
| A1 | 25,00 / ALLOW / COMPLETE | HISTORICAL VERIFIED | Form login; không snapshot feature v2 |
| A2 | 12,50 / ALLOW / COMPLETE | HISTORICAL VERIFIED | Trusted relogin; không nhầm SSO |
| A3 Mandatory MFA | 32,50 / STEP_UP_MFA / COMPLETE | HISTORICAL VERIFIED | OTP execution SUCCESS; score thấp vẫn MFA do guard |
| A4 setup 2 — Incomplete | null / STEP_UP_MFA / INCOMPLETE | HISTORICAL VERIFIED | Cold-start; OTP SUCCESS; setup enrollment đầu không tự là proof OTP |
| A4 Priority | null / DENY / NOT_EVALUATED | HISTORICAL VERIFIED | REVOKED_DEVICE trước scoring, không phải weighted HIGH |
| A5 Threshold MEDIUM | 50,00 / STEP_UP_MFA / COMPLETE | HISTORICAL VERIFIED | Browser B0 có owned fixture; đã cleanup |
| A6 Threshold HIGH | 82,50 / DENY / COMPLETE | HISTORICAL VERIFIED | Actual score 82,50; fixture cũ đã cleanup |
| Service Unavailable | Null/fallback và fail-safe theo cấu hình | CONTROLLED OFFLINE | Tái sử dụng targeted JUnit; không gây outage live |
| Các nhánh trên ở login mới | Không phát sinh trong LIVE-L1 | NOT VERIFIED | Không làm fixture/revoke/brute-force/stop service để ép nhánh |

Đã đọc các mục A1/A2/A3/A4 setup/priority trong
[ADAPTIVE_AUTH_ACCEPTANCE_REPORT](../../ADAPTIVE_AUTH_ACCEPTANCE_REPORT.md), A5 mục
17.4, A6 mục 18.5 và cleanup 18.6 trong
[TRUST_SCORE_RESEARCH_AND_EXPERIMENT_PLAN](../../TRUST_SCORE_RESEARCH_AND_EXPERIMENT_PLAN.md).
Các artifact lịch sử được đọc/hash, không chỉnh sửa hoặc tái thực thi helper fixture.
Các trường feature/Decision Source chưa emit ở runtime cũ không được trình bày
như snapshot v2 đã đo. Ví dụ nguồn quyết định A6 trong báo cáo cũ là inferred
từ contract/source và bằng chứng trial, không phải field trace đo trực tiếp.

### Kiểm thử có kiểm soát

- Chạy mới: **13 test collector + 4 test DOM viewer**, 0 failure/error.
  Có ca chống trộn attempt/demo, challenge không thành MFA success, fallback không
  tạo evaluation/score giả, SSO/refresh, conflict, lọc bí mật và script injection.
- Tái sử dụng 4 báo cáo Java, **40 ca, 0 failure/error/skip**: RiskEvaluationServiceTests
  (5), RiskObservationTests (8), RiskEvaluationTraceTest (22), RiskDecisionHandlerTest (5).
  Đây là báo cáo kiểm thử đã có, không phải 40 ca chạy mới.
- Priority, Mandatory, Incomplete và Service Unavailable có source/targeted test
  evidence; các kết quả đó giữ nhãn CONTROLLED OFFLINE, không đổi thành Live Browser.
- Không build/restart/recreate hoặc tạo container thử mới để chạy lại Maven.

Nguồn: [RiskEvaluationServiceTests](../../risk-scoring-service/src/test/java/com/zerotrust/risk/service/RiskEvaluationServiceTests.java),
[RiskObservationTests](../../risk-scoring-service/src/test/java/com/zerotrust/risk/audit/RiskObservationTests.java),
[SPI trace tests](../../keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/trace/RiskEvaluationTraceTest.java),
[decision handler tests](../../keycloak-risk-extension/src/test/java/com/zerotrust/keycloak/risk/policy/RiskDecisionHandlerTest.java).

## 6. TLS/CRL và hậu kiểm

Đây là kiểm tra readiness/transport **riêng**, không dùng thay bằng chứng login:

| Phạm vi trước/sau | Kết quả |
|---|---|
| Windows native Schannel Portal/Discovery | HTTP 200, không insecure/cacert override/no-revoke |
| Windows X509Chain | Gateway/Keycloak Online, ExcludeRoot, NoFlag, không status lỗi |
| CRL hiện hành | Chữ ký/issuer hợp lệ; 0 entry thu hồi; NextUpdate 06/11/2026 09:30:48 GMT+7 |
| CDP host và Docker | HTTP thành công; cùng bytes/hash với CRL đang phục vụ |
| Served leaf | Khớp leaf mounted; còn hạn; ServerAuth; không bị thu hồi |
| Fresh JVM HTTPS probes | 4/4 đạt mã mong đợi; thấy fetch CRL và Returning 1 CRLs |

Các cờ revocation/CRLDP bật **chỉ trên tiến trình probe mới**, không sửa JVM args
của service. Không suy cấu hình revocation mặc định của service từ probe đó.
Không xóa cache, cài CA, cấp lại cert hoặc thay CRL. CRLNumber cụ thể mà native
Windows cache chọn chưa được chứng minh; mục đó giữ NOT VERIFIED.

| Bảo toàn trước/sau | Kết quả |
|---|---|
| 10 container | Cùng IDs/images/config/mount definitions/restart count; healthy |
| Scoring/source và runtime file hashes | Không đổi; B0 và weights/thresholds giữ nguyên |
| School/mappings | Mọi row và schema đã snapshot giữ nguyên |
| Keycloak user/credential/role/flow/client/config | Các bảng ổn định đã snapshot giữ nguyên |
| Risk device/state/revocation/Flyway | Giữ nguyên row/schema fingerprints |
| Risk success history | **105 → 106**, thêm 1 row hash, không mất/sửa row cũ, schema không đổi |
| Redis | 0 key trước/sau; không SET/DEL hoặc fixture |
| Evidence lịch sử | Hashes các file cũ giữ nguyên |

Một history row mới phù hợp sự kiện LOGIN_SUCCESS và tác động tự nhiên của
login được người dùng cho phép; không phải dữ liệu do agent seed. Không dùng
đelta này để thay thế mối nối role/evaluation còn thiếu.
SQL dùng transaction READ ONLY và ROLLBACK; Redis chỉ SCAN/DUMP/PTTL.

## 7. Bộ hình/bảng đã lọc

[Thư mục bằng chứng cho slide](../../presentation/risk-observatory-evidence-20261103-L1/README.md):

1. [Bảng tín hiệu/điểm](../../presentation/risk-observatory-evidence-20261103-L1/01_live_signal_scorecard.png)
2. [Chuỗi thực thi](../../presentation/risk-observatory-evidence-20261103-L1/02_live_journey.png)
3. [Ma trận phân loại](../../presentation/risk-observatory-evidence-20261103-L1/03_evidence_matrix.png)
4. [Contribution PNG](../../presentation/risk-observatory-evidence-20261103-L1/04_live_contributions.png),
   [SVG chỉnh sửa được](../../presentation/risk-observatory-evidence-20261103-L1/04_live_contributions.svg)

Có CSV yếu tố/timeline/lịch sử và JSON đã lọc. PNG 1920×1080, đã xem kiểm tra bố cục.
Hình dựng từ log đã audit, **không phải screenshot Browser**. Không xuất raw
evaluation/correlation/subject/device IDs, username, IP, cookie, token, mật khẩu,
OTP hoặc private runtime paths vào bộ public. Không sửa PowerPoint bảo vệ đã có.

Evidence mới có mốc trước/sau và alias map được giữ riêng trong thư mục phiên
acceptance; không sửa evidence A1–A6 hay các report nghiệm thu cũ.

## 8. Kết luận có thể dùng khi bảo vệ

“Trong một lần đăng nhập thực mới, hệ thống ghi đủ bốn nhóm tín hiệu và giải thích
được tổng điểm 12,50. SPI nhận cùng điểm/quyết định; Keycloak cho qua Risk, không
chọn MFA và ghi nhận đăng nhập thành công. Các bằng chứng nối bằng mã đánh giá
và mã tương quan, được đối chiếu với thao tác người dùng. Các nhánh khác được
trình bày đúng là lịch sử hoặc kiểm thử có kiểm soát.”

Không kết luận live GeoIP lookup/MFA mới/outage/deny từ ca ALLOW này. Không khẳng
định B1 tốt hơn hoặc mô hình có độ chính xác phát hiện tấn công đã đo.
