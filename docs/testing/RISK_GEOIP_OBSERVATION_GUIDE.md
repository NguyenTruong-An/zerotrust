[Mục lục tài liệu](../README.md) · [Hướng dẫn vận hành canonical](../operations/LEGACY_INTEGRATION.md)

# Hướng dẫn quan sát dữ liệu tính Risk và GeoIP

**Ngày đối chiếu:** 02/11/2026, giờ Việt Nam.

**Môi trường:** Windows PowerShell, Docker canonical `zerotrust-legacy-integration-20261026`.
**Mục đích:** xem bằng chứng của một lần đăng nhập, hiểu dữ liệu nào tạo nên Risk Score, sử dụng đúng Postman/Wireshark và kiểm tra database GeoIP.

**Cập nhật quan sát v2 ngày 02/11/2026:** đã bổ sung source trace schema 2 và trang
xem tín hiệu/điểm/quyết định/MFA tại [RISK_OBSERVATORY](RISK_OBSERVATORY.md).
Các ghi nhận JAR thiếu trace bên dưới là mốc ban đầu trước cập nhật v2, không dùng
để kết luận phiên bản đang chạy sau rollout. Xem hướng dẫn mới để đối chiếu runtime.

Tài liệu giữ hướng dẫn log/Postman/Wireshark/MMDB và ghi nhận ban đầu, không phải
nghiệm thu Browser mới. Postman cần đường truy cập lab phù hợp; canonical không
mở cổng Risk ra Windows.

## Đọc nhanh: nên bắt đầu ở đâu?

1. Làm mục **3–4** để xem điểm tổng, quyết định, MFA và kết quả của một lần đăng nhập thật.
2. Làm mục **5** để hiểu bốn nhóm D/N/T/H và lý do chưa thấy toàn bộ đầu vào trong log.
3. Làm mục **6** nếu muốn kiểm tra riêng GeoIP, bao gồm đọc quốc gia/thành phố từ file `.mmdb`.
4. Đọc mục **7** trước khi dùng Postman. Không gửi thử vào một địa chỉ giả định chưa truy cập được.
5. Làm mục **8** để quan sát mạng bằng Wireshark. Bắt gói không tự làm xuất hiện các biến tính toán bên trong Risk.
6. Dùng mục **9–11** để ghi bằng chứng, xử lý lỗi và chuẩn bị demo.

## 1. Công cụ nào xem được dữ liệu nào?

| Công cụ | Có thể xem | Giới hạn trong đồ án hiện tại |
|---|---|---|
| Log Keycloak SPI | Risk Score, level, decision, data status, reasons, enforcement, MFA và login outcome | Không có toàn bộ điểm D/N/T/H, counter và thông tin quốc gia/thành phố |
| Risk Score Trace | V2 có trạng thái, điểm/weight/contribution, snapshot D/N/T/H và GeoIP metadata thực có | JAR cũ thiếu trace; đối chiếu v2 theo [hướng dẫn mới](RISK_OBSERVATORY.md); CIDR có thể bỏ qua GeoIP |
| Postman | Tạo request kiểm thử và đọc JSON API phản hồi | Chỉ thấy các trường API cung cấp; không tự đọc Redis/MySQL hoặc biến Java nội bộ |
| Browser DevTools | Các request Browser gửi Gateway/Keycloak, status và timing | Không thấy trực tiếp lời gọi từ server Keycloak sang Risk |
| Wireshark | Kết nối, địa chỉ/cổng, TLS handshake và timing của lưu lượng bắt được | HTTPS mã hóa nội dung; tra cứu `.mmdb` cục bộ không tạo request GeoIP trên mạng |
| Công cụ đọc `.mmdb` | Quốc gia, thành phố, múi giờ, ASN… có trong database cho một IP | Không chứng minh lần đăng nhập thật đã dùng IP đó hoặc đã đi vào nhánh GeoIP |

**Ba loại bằng chứng cần tách riêng:**

- **Browser:** chứng minh Risk tham gia một lần đăng nhập cụ thể và Keycloak thực thi quyết định.
- **API/lab:** chứng minh hành vi với request kiểm thử có kiểm soát.
- **MMDB độc lập:** chứng minh file GeoIP có thể tra cứu một IP; không phải nghiệm thu luồng đăng nhập.

## 2. Hiện trạng đã kiểm tra và ranh giới dữ liệu

Các quan sát chỉ đọc ngày 02/11/2026:

| Nội dung | Quan sát | Không được suy rộng thành |
|---|---|---|
| Docker canonical | 10 container đang chạy, healthy | Mọi chức năng đã được nghiệm thu lại |
| Risk health nội bộ | `GET https://risk:8443/actuator/health` trả `{"status":"UP"}` | Đã tra cứu thành công mọi IP hoặc ASN của mọi IP đều có |
| Network và GeoIP | Hai cờ môi trường đều `true` | Mọi lần login đều sử dụng GeoIP |
| City/ASN | Hai file cấu hình đều đọc được trong container | Nội dung database mới nhất hoặc mọi record đều đầy đủ |
| Country policy | Ba danh sách trusted/elevated/high đều có 0 phần tử trong môi trường được kiểm tra | Có chính sách đang phân biệt rủi ro theo từng quốc gia |
| Kết nối Risk từ host | Không có cổng được publish | Có thể gọi `https://localhost:8443` từ Postman |
| Trace chi tiết Risk | Không có `RiskScoreTrace.class` tại vị trí class ứng dụng trong image hiện tại | Source trace đã được deploy |

B0 tiếp tục là baseline vận hành theo báo cáo hiện có; B1 là ứng viên source/offline. Hướng dẫn này không thay model, trọng số, ngưỡng, Browser Flow, dữ liệu hoặc cấu hình Docker.

### Các địa chỉ cần phân biệt

| Mục đích | Địa chỉ |
|---|---|
| Portal từ Windows/Browser | `https://localhost:28443/` |
| OIDC discovery từ Windows | `https://localhost:28444/realms/DoAn/.well-known/openid-configuration` |
| Token endpoint từ Windows | `https://localhost:28444/realms/DoAn/protocol/openid-connect/token` |
| Health của Risk trong mạng Docker | `https://risk:8443/actuator/health` |
| API đánh giá trong mạng Docker | `POST https://risk:8443/internal/v1/risk/evaluations` |

`risk` là tên dịch vụ nội bộ. Cổng 28443 của Gateway không phải một cổng chuyển tiếp tùy ý tới Risk API. Không lấy topology synthetic/local cũ thay cho bảng này.

## 3. Chuẩn bị một phiên quan sát

Các lệnh dưới đây chạy từ gốc repository. Dùng cùng một cửa sổ PowerShell cho các mục 3–4 và phần GeoIP tùy chọn để giữ các biến đã khai báo.

```powershell
Set-Location '<repo-root>'

$riskContainer = 'zerotrust-legacy-integration-20261026-risk'
$keycloakContainer = 'zerotrust-legacy-integration-20261026-keycloak'
$since = (Get-Date).ToUniversalTime().ToString('o')
$evidenceDir = Join-Path (Get-Location).Path (
    '.local-legacy\risk-observation\' + (Get-Date -Format 'yyyyMMdd-HHmmss')
)
New-Item -ItemType Directory -Force -Path $evidenceDir | Out-Null

docker ps --format '{{.Names}} {{.Status}}'
```

Thư mục `.local-legacy/` đã nằm trong `.gitignore`. Đây là nơi lưu bằng chứng riêng tư, không phải nơi lưu ảnh/log để công bố trực tiếp.

### 3.1. Kiểm tra Risk health

```powershell
docker exec $riskContainer curl --silent --show-error --fail `
    --cacert /run/demo/ca.crt --connect-timeout 3 --max-time 5 `
    https://risk:8443/actuator/health
```

Mốc đối chiếu đã nhận `{"status":"UP"}`. Lệnh dùng CA hiện có, không tắt xác minh chứng chỉ. Nó không chạy evaluation và không thực hiện login. Đây không phải kiểm tra thu hồi chứng chỉ mới; kiểm tra TLS/CRL trước demo theo [runbook canonical](../operations/LEGACY_INTEGRATION.md).

Nếu container/công cụ/CA khác ở một bản triển khai sau, dừng để đối chiếu cấu hình, không sửa tên máy chủ hoặc tắt TLS chỉ để làm lệnh trả thành công.

### 3.2. Kiểm tra cờ GeoIP mà không in toàn bộ môi trường

```powershell
$riskInspect = (docker inspect $riskContainer | ConvertFrom-Json)[0]

$riskInspect.Config.Env | Where-Object {
    $_ -match '^(RISK_NETWORK_INTELLIGENCE_ENABLED|RISK_GEOIP_ENABLED)='
}

foreach ($entry in $riskInspect.Config.Env) {
    if ($entry -match '^(RISK_GEOIP_CITY_DATABASE_PATH|RISK_GEOIP_ASN_DATABASE_PATH)=(.+)$') {
        $settingName = $Matches[1]
        $databasePath = $Matches[2]
        docker exec $riskContainer test -r $databasePath
        [pscustomobject]@{
            Setting = $settingName
            Readable = ($LASTEXITCODE -eq 0)
        }
    }
}
```

Không chạy `docker inspect` hoặc `printenv` rồi đưa toàn bộ kết quả lên màn chiếu: cấu hình có thể chứa secret. Đoạn trên chỉ xuất hai cờ và khả năng đọc file.

Các cờ trong Env chưa loại trừ mọi override từ file hoặc JVM arguments. Để khẳng định cấu hình hiệu lực ở một deployment khác, cần đối chiếu các nguồn cấu hình và image của deployment đó.

### 3.3. Kiểm tra khả năng xuất trace chi tiết của image

```powershell
docker exec $riskContainer sh -c 'if test -f /app/unpacked/BOOT-INF/classes/com/zerotrust/risk/trace/RiskScoreTrace.class; then echo RISK_DETAILS_TRACE_CLASS_PRESENT; else echo RISK_DETAILS_TRACE_CLASS_ABSENT; fi'
```

Mốc đối chiếu nhận `RISK_DETAILS_TRACE_CLASS_ABSENT`. Lệnh dựa vào cách đóng gói image hiện tại; nếu Dockerfile đổi, vị trí class cũng có thể đổi. `PRESENT` chỉ chứng minh class có trong image, chưa chứng minh nó đã phát một trace của login thật.

## 4. Xem một lần đăng nhập thật bằng log Keycloak

### 4.1. Theo dõi trực tiếp

```powershell
docker logs --follow --since $since $keycloakContainer 2>&1 |
    Select-String 'ZEROTRUST_RISK_TRACE '
```

Lệnh chờ các dòng mới. Để cửa sổ này mở rồi thao tác Browser:

1. Vào Portal ở cổng 28443 bằng tài khoản được phép dùng để demo.
2. Nếu đang có phiên, nhấn Đăng xuất trên Portal và hoàn tất bước xác nhận của Keycloak nếu có.
3. Đăng nhập lại, xác nhận có form mật khẩu. Nhập mật khẩu/OTP trực tiếp trong Browser.
4. Ghi lại giờ Việt Nam, alias tài khoản, có OTP không và kết quả cuối.
5. Trở lại PowerShell. Nhấn `Ctrl+C` khi đã thu đủ dòng. Việc này chỉ dừng theo dõi log, không dừng container.

Không tạo lần sai mật khẩu/OTP, xóa cookie, reset MFA, revoke thiết bị hay tái tạo fixture A5/A6 chỉ để tạo một điểm số mong muốn. Login thật có thể thêm history/trust/counter theo hành vi bình thường; việc xem log không làm các tác động đó biến mất.

### 4.2. Đọc các trường quan trọng

| Trường | Cách sử dụng |
|---|---|
| `at` | Thời điểm phát trace, dạng UTC; phân biệt với giờ Việt Nam khi ghi chép |
| `evaluated_at` | Thời điểm Risk đánh giá khi response có trường này |
| `evaluation_id` | Ghép kết quả Risk với enforcement/MFA/outcome tương ứng |
| `correlation_id` | Ghép các bước của cùng flow khi trace cung cấp |
| `stage` / `outcome` | Bước đã đi tới và kết quả quan sát được |
| `risk_score` | Điểm tổng khi dữ liệu có score; `null` không được đổi thành 0 |
| `risk_level` / `decision` | Mức hiệu lực và hành động Risk gửi về |
| `data_status` | Phân biệt `COMPLETE`, `INCOMPLETE`, `NOT_EVALUATED` |
| `reason_codes` | Các nguyên nhân có trong response; không phải toàn bộ giá trị đặc trưng |
| `evaluation_source` | Phân biệt response Risk hợp lệ với lỗi không nhận được response |
| `risk_execution` | `CORRELATED`, `NOT_RUN_SSO_COOKIE`, `NOT_RUN_REFRESH`… khi có |
| `mfa_execution` | Ví dụ `OTP_EXECUTION_SUCCESS` khi trace quan sát được execution thành công |
| `failure_type` | Nhóm lỗi đã lọc, ví dụ `TIMEOUT`; không phải numeric HIGH |

`subject_tag` là HMAC tag trong producer hiện có, không phải tên tài khoản. Nó không cần đưa vào báo cáo công khai. Không dùng subject tag để ghép người dùng qua mọi lần restart vì khóa tag có vòng đời riêng của producer.

### 4.3. Đọc chuỗi sự kiện thay vì chỉ nhìn điểm

| Trường hợp | Chuỗi cần tìm | Kết luận có thể ghi |
|---|---|---|
| ALLOW | `RISK_EVALUATION` có decision ALLOW → `KEYCLOAK_ENFORCEMENT`/`RISK_STEP_PASSED` → `LOGIN_SUCCESS` cùng correlation phù hợp | Risk cho qua và flow đã hoàn tất trong attempt đó |
| MFA | Decision STEP_UP_MFA → `STEP_UP_REQUIRED` → MFA gate/form → `OTP_EXECUTION_SUCCESS` → `LOGIN_SUCCESS` | MFA đã thực hiện và login hoàn tất; chỉ thấy form OTP chưa đủ |
| Đăng ký trust | MFA thật thành công → `REGISTERED_204` → `COOKIE_ISSUED` | Registration thành công trong attempt đó; chưa tự chứng minh lần relogin sau nhận diện được trust |
| DENY do policy | Decision DENY từ response Risk → `ACCESS_DENIED` | Keycloak thực thi từ chối; ghép thêm Browser/session/history khi cần kết luận không có phiên mới |
| Risk không khả dụng | `SERVICE_UNAVAILABLE_DENY`, `NO_VALID_RISK_RESPONSE`, score/evaluation có thể null | Fail-closed vì lỗi gọi dịch vụ, không ghi là HIGH do điểm ≥75 |
| SSO/refresh | `NOT_RUN_SSO_COOKIE` hoặc `NOT_RUN_REFRESH` | Không đếm là một lần evaluation LOW mới |

Các tên stage/outcome ở đây được đối chiếu source. Một số bổ sung source, như timing chi tiết, có thể chưa xuất hiện trên image đang chạy. Không coi thiếu một dòng bổ sung là login thất bại.

### 4.4. Lưu bản JSON đã lọc

Sau khi dừng follow, chạy trong cùng cửa sổ PowerShell:

```powershell
$traceRows = @(docker logs --since $since $keycloakContainer 2>&1 |
    ForEach-Object {
        $message = $_.ToString()
        $marker = 'ZEROTRUST_RISK_TRACE '
        $offset = $message.IndexOf($marker)
        if ($offset -lt 0) { return }
        try {
            $message.Substring($offset + $marker.Length) | ConvertFrom-Json
        } catch {
            # Dòng không parse được không được dùng làm bằng chứng có cấu trúc.
        }
    })

$allowedFields = @(
    'at', 'evaluated_at', 'stage', 'outcome', 'correlation_id',
    'evaluation_id', 'risk_score', 'risk_level', 'decision',
    'data_status', 'reason_codes', 'evaluation_source',
    'risk_execution', 'mfa_execution', 'failure_type'
)
$filteredRows = @($traceRows | Select-Object -Property $allowedFields)
$tracePath = Join-Path $evidenceDir 'keycloak-risk.filtered.private.json'
ConvertTo-Json -InputObject $filteredRows -Depth 8 |
    Set-Content -LiteralPath $tracePath -Encoding utf8

Write-Output ('Trace rows: ' + $filteredRows.Count)
```

Đây là allowlist cho schema trace hiện có. Nếu producer thay đổi schema, review lại danh sách trước khi chia sẻ. File chưa có dòng evaluation không phải kết quả PASS/FAIL của thuật toán.

### 4.5. Tách một attempt để đọc

```powershell
$lastEvaluation = $traceRows |
    Where-Object { $_.stage -eq 'RISK_EVALUATION' } |
    Sort-Object at |
    Select-Object -Last 1

if ($null -eq $lastEvaluation) {
    Write-Output 'Chưa quan sát được RISK_EVALUATION trong cửa sổ thu log.'
} elseif ([string]::IsNullOrWhiteSpace($lastEvaluation.correlation_id)) {
    $lastEvaluation | Select-Object -Property $allowedFields | Format-List
    Write-Output 'Thiếu correlation: chưa ghép được toàn bộ flow.'
} else {
    $traceRows |
        Where-Object { $_.correlation_id -eq $lastEvaluation.correlation_id } |
        Sort-Object at |
        Select-Object -Property $allowedFields |
        Format-List
}
```

Nếu nhiều người login cùng lúc, chọn đúng attempt dựa thời gian/correlation đã thu; không mặc định dòng cuối thuộc người đang demo. Trong báo cáo công khai có thể đặt nhãn ngắn như `E1` sau khi giữ mapping correlation riêng tư.

## 5. Dữ liệu thật sự dùng để tính B0

Với dữ liệu COMPLETE:

```text
R = round_HALF_UP_2(0,25D + 0,25N + 0,25T + 0,25H)
```

Trọng số 0,25 và ngưỡng 40/75 là cấu hình baseline đã ghi nhận, chưa phải tham số tối ưu đã hiệu chỉnh bằng nhãn tấn công thực tế.

| Nhóm | Đầu vào thực sự | Điểm B0 theo baseline hiện có | Điểm cần chú ý khi quan sát |
|---|---|---|---|
| D: Device | Identifier từ cookie, subject, trạng thái và `trustedAt` trong Risk | Missing 80; new 60; pending 50; trusted 0; expired/MFA-reset reauthentication 60; security-revoked có priority DENY | Thiếu identifier khác với lỗi không lấy được dữ liệu; HMAC identifier không phải nhận dạng phần cứng |
| N: Network | IP mà Keycloak quan sát, CIDR; khi đủ điều kiện mới tra country từ GeoIP | Trusted 0; default/elevated 50; high 100 | Có điểm N không chứng minh đã dùng GeoIP; phải biết nguồn CIDR/GEOIP/DEFAULT_POLICY |
| T: Temporal | Lịch sử thành công của subject + client trước thời điểm đánh giá | Bình thường 0; một nhóm ngày/giờ bất thường 50; cả hai 100 | Cửa sổ 90 ngày, tối đa 200 event, tối thiểu 5; UTC; giờ lân cận ±1 |
| H: Authentication History | Counter thất bại theo subject và IP trong Redis | Subject <3:0, 3–4:50, ≥5:100; IP <10:0, 10–19:50, ≥20:100; lấy max | TTL 15 phút tính từ lần INCR đầu, không phải sliding window chính xác; IP có thể dùng chung vì NAT |

Trước khi tính/áp ngưỡng, pipeline còn có priority rules, dữ liệu thiếu và mandatory MFA:

- Priority/reset pending/security revoke có thể DENY với score null, `NOT_EVALUATED`.
- Dữ liệu thiếu/cold-start tạo `INCOMPLETE`, score null và MFA.
- Khi COMPLETE, score ≥75 tạo DENY; mandatory guard vẫn là mức bảo vệ tối thiểu MFA khi score chưa HIGH.
- Vì vậy `R <40` không tự đảm bảo ALLOW, và OTP xuất hiện không tự chứng minh `40 ≤ R <75`.

Log SPI vẫn cho biết điểm tổng/reasons. Risk trace v2 bổ sung snapshot D/N/T/H,
counter, day/hour matches và city/ASN khi nhánh GeoIP thực sự cung cấp. Xem
[RISK_OBSERVATORY](RISK_OBSERVATORY.md). Không nội suy ngược các nhóm từ tổng;
JAR chưa có trace là ghi nhận trước cập nhật v2.

## 6. Quan sát GeoIP đúng cách

### 6.1. Khi nào Risk gọi GeoIP?

Thứ tự trong [NetworkRiskCalculator](../../risk-scoring-service/src/main/java/com/zerotrust/risk/service/NetworkRiskCalculator.java):

1. Network provider phải được bật.
2. Kiểm tra CIDR theo thứ tự high → elevated → trusted. Nếu khớp thì kết luận từ CIDR, không tra GeoIP.
3. Nếu GeoIP bị tắt hoặc địa chỉ thuộc nhóm không public theo bộ kiểm tra hiện có, dùng default policy.
4. IP public chưa khớp CIDR mới đi vào `GeoIpProvider.lookup`.
5. Có record và country phù hợp thì so country với policy; không khớp country list dùng default score với nguồn GEOIP.
6. Lookup không có record, gặp lỗi hoặc có `countryCode=null` làm Network unavailable; không tự gán điểm an toàn. Country hợp lệ nhưng không nằm trong policy list vẫn dùng default score như bước 5.

Ở controller, priority/reset có thể kết thúc trước nhánh Network. Phải xét cả pipeline khi giải thích một attempt.

### 6.2. Những thông tin nào có và được dùng?

| Thông tin từ GeoIP | Vai trò hiện tại |
|---|---|
| `countryCode` | Trường GeoIP được Network calculator dùng để đối chiếu country policy |
| `cityName`, `timeZone`, `accuracyRadiusKm` | Metadata provider có thể đọc; chưa dùng để tính Network Score |
| `autonomousSystemNumber`, `autonomousSystemOrganization` | Metadata ASN tùy theo record/database; chưa dùng để tính điểm |
| Vị trí đăng nhập trước, khoảng cách địa lý, impossible travel | Chưa triển khai trong mô hình hiện tại |

Temporal dùng lịch sử và timezone cấu hình của Temporal, không tự lấy timezone từ GeoIP để thay đổi cách tính.

Ba country list rỗng nghĩa là hiện chưa có phân biệt mức rủi ro theo quốc gia trong các list đó. Một lookup public thành công vẫn có thể trả N=50 với nguồn GEOIP vì rơi vào default band.

### 6.3. Đọc reasons mà không kết luận quá mức

- `NETWORK_RISK`: có điểm Network dương; chưa đủ kết luận nguồn GeoIP.
- `GEOLOCATION_RISK`: extractor thêm reason khi nguồn là GEOIP và điểm N dương. Không tự có nghĩa quốc gia bị block hoặc IP thuộc danh sách high.
- `HIGH_RISK_NETWORK`: Network band HIGH; cần đối chiếu nguồn/policy để biết do CIDR hay country.
- `GEOIP_INTELLIGENCE_UNAVAILABLE`: nhánh lookup GeoIP không có dữ liệu dùng được.
- Không có `GEOLOCATION_RISK` chưa đủ chứng minh GeoIP không được tra: country trusted có thể cho điểm 0.

Nguồn: [feature extractor](../../risk-scoring-service/src/main/java/com/zerotrust/risk/feature/DatabaseBackedRiskFeatureExtractor.java).

### 6.4. Vì sao đổi Wi-Fi hoặc dùng VPN có thể không làm thay đổi điểm?

SPI lấy IP từ `context.getConnection().getRemoteAddr()`. Docker NAT/proxy có thể khiến Keycloak nhìn thấy một địa chỉ private/đường mạng dùng chung. Đổi mạng ở Browser không đảm bảo IP mà Keycloak quan sát thay đổi.

Không lấy IP hiển thị bởi một website bên ngoài thay cho IP đầu vào thật của Risk. Không sửa `X-Forwarded-For`, spoof header hoặc thay policy để gọi đó là bằng chứng Browser GeoIP.

### 6.5. Tùy chọn: đọc City/ASN từ đúng database đang mount

Phần này chạy **ngoài ứng dụng**, với IP public minh họa `8.8.8.8`. Nó chỉ chứng minh database tra cứu được dữ liệu. Không phải IP người dùng đã quan sát, không phải điểm Network và không phải một ca login.

**a. Lấy đường dẫn của đúng hai file qua Env đã lọc, rồi copy ra thư mục riêng**

```powershell
$riskInspect = (docker inspect $riskContainer | ConvertFrom-Json)[0]
$geoPaths = @{}
foreach ($entry in $riskInspect.Config.Env) {
    if ($entry -match '^(RISK_GEOIP_CITY_DATABASE_PATH|RISK_GEOIP_ASN_DATABASE_PATH)=(.+)$') {
        $geoPaths[$Matches[1]] = $Matches[2]
    }
}
$cityContainerPath = $geoPaths['RISK_GEOIP_CITY_DATABASE_PATH']
$asnContainerPath = $geoPaths['RISK_GEOIP_ASN_DATABASE_PATH']
if ([string]::IsNullOrWhiteSpace($cityContainerPath) -or
    [string]::IsNullOrWhiteSpace($asnContainerPath)) {
    throw 'Chưa xác định được cả hai đường dẫn database. Đối chiếu cấu hình trước.'
}

$cityCopy = Join-Path $evidenceDir 'city.private.mmdb'
$asnCopy = Join-Path $evidenceDir 'asn.private.mmdb'
docker cp "${riskContainer}:$cityContainerPath" $cityCopy
if ($LASTEXITCODE -ne 0) { throw 'Không copy được City database.' }
docker cp "${riskContainer}:$asnContainerPath" $asnCopy
if ($LASTEXITCODE -ne 0) { throw 'Không copy được ASN database.' }
Get-FileHash -LiteralPath $cityCopy -Algorithm SHA256 | Select-Object Algorithm, Hash
Get-FileHash -LiteralPath $asnCopy -Algorithm SHA256 | Select-Object Algorithm, Hash
```

`docker cp` ở đây chỉ đọc file nguồn và tạo bản copy trên host. Không sửa database đang mount, không tải/cập nhật GeoLite và không thay file của container. Giữ các bản copy trong thư mục riêng, không đưa vào Git hoặc bản bàn giao công khai.

Provider Java hiện mở database theo chế độ `MEMORY` khi khởi tạo. Nếu file đã bị thay thế sau lúc process khởi động, bản copy tại đường dẫn đó chưa chắc là đúng nội dung Risk đang giữ trong bộ nhớ. Ghi phiên bản/hash và thời điểm cập nhật/startup khi đối chiếu; hướng dẫn này không restart canonical để đồng bộ lại dữ liệu.

**b. Chuẩn bị công cụ Python độc lập, chỉ khi chưa có reader phù hợp**

Yêu cầu Python 3 đã cài trên Windows. Các lệnh sau tạo môi trường tooling riêng trong `.local-legacy`, không cài vào Python dùng chung hoặc image ứng dụng:

```powershell
$geoVenv = Join-Path (Get-Location).Path '.local-legacy\risk-observation\geoip-venv'
if (-not (Test-Path -LiteralPath (Join-Path $geoVenv 'Scripts\python.exe'))) {
    python -m venv $geoVenv
    if ($LASTEXITCODE -ne 0) { throw 'Không tạo được môi trường Python cho tooling.' }
}
$geoPython = Join-Path $geoVenv 'Scripts\python.exe'
& $geoPython -m pip install maxminddb
if ($LASTEXITCODE -ne 0) { throw 'Không cài được MaxMind reader trong môi trường tooling.' }
& $geoPython -m pip show maxminddb
```

Ghi phiên bản reader để tái hiện. Tài liệu này không yêu cầu cài reader vào Risk Service. Nếu lab không cho tải dependency, dùng reader đã có hoặc bỏ qua bước độc lập này.

**c. Tạo script chỉ đọc record và xuất các trường cần quan sát**

```powershell
$geoScript = Join-Path $evidenceDir 'lookup_geoip.private.py'
@'
import argparse
import ipaddress
import json
import sys
import maxminddb

p = argparse.ArgumentParser()
p.add_argument('--city', required=True)
p.add_argument('--asn', required=True)
p.add_argument('--ip', required=True)
args = p.parse_args()

try:
    address = str(ipaddress.ip_address(args.ip))
    with maxminddb.open_database(args.city) as reader:
        city_record = reader.get(address)
        city_database_type = reader.metadata().database_type
    with maxminddb.open_database(args.asn) as reader:
        asn_record = reader.get(address)
        asn_database_type = reader.metadata().database_type

    city = city_record or {}
    asn = asn_record or {}
    names = city.get('city', {}).get('names', {})
    location = city.get('location', {})
    country_code = city.get('country', {}).get('iso_code')
    result = {
        'evidence_type': 'STANDALONE_MMDB_LOOKUP_NOT_LOGIN',
        'city_database_type': city_database_type,
        'asn_database_type': asn_database_type,
        'city_record_found': city_record is not None,
        'country_code': country_code,
        'country_present': bool(country_code),
        'city_name': names.get('en') or names.get('vi'),
        'time_zone': location.get('time_zone'),
        'accuracy_radius_km': location.get('accuracy_radius'),
        'asn_record_found': asn_record is not None,
        'asn': asn.get('autonomous_system_number'),
        'asn_organization': asn.get('autonomous_system_organization'),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
except Exception as exc:
    print(json.dumps({'error_type': type(exc).__name__}), file=sys.stderr)
    sys.exit(1)
'@ | Set-Content -LiteralPath $geoScript -Encoding utf8

& $geoPython -X utf8 $geoScript --city $cityCopy --asn $asnCopy --ip '8.8.8.8'
```

Không điền sẵn quốc gia/thành phố mong đợi vào báo cáo: kết quả tùy phiên bản database và record thực có. Record/field null là một kết quả cần ghi nhận, không thay bằng tên thành phố tự đoán. `accuracy_radius_km` mô tả sai số của dữ liệu, không phải tọa độ GPS thiết bị.

Reader Python là công cụ kiểm tra file độc lập, không thay [MaxMindGeoIpProvider Java](../../risk-scoring-service/src/main/java/com/zerotrust/risk/service/MaxMindGeoIpProvider.java) và không thực thi CIDR, country policy hoặc guard của pipeline.

### 6.6. Khi nào đủ bằng chứng GeoIP đã tham gia login?

Cần ghép được tối thiểu:

1. Login có password form và một evaluation mới.
2. IP thực mà Keycloak quan sát được đã được phân loại đúng, không lấy từ request giả lập hoặc website kiểm tra IP.
3. Không có priority/CIDR/private-IP branch kết thúc trước lookup.
4. Nguồn Network của chính evaluation là `GEOIP`; trạng thái lookup/country và điểm N có bằng chứng tương ứng.
5. Có quyết định cuối và enforcement cùng evaluation/correlation.

Trace đang chạy chưa xuất đầy đủ các mục này. Có thể quan sát reason liên quan, nhưng chưa đủ để tự khẳng định toàn bộ GeoIP Browser case đã nghiệm thu. Phần cần bổ sung được mô tả ở mục 10.

## 7. Dùng Postman để kiểm thử API

### 7.1. Điều kiện trước khi gửi evaluation

Chỉ tiếp tục khi có cả:

1. Một đường truy cập lab tới Risk được cấu hình hợp lệ, đúng DNS/chứng chỉ và quyền mạng.
2. Tài khoản/subject test được quản lý rõ; biết history/trust nào đang dùng.
3. Quyền sử dụng confidential client `zerotrust-risk-caller` và secret được cấp riêng tư.
4. CA của môi trường lab, issuer/audience/role đúng hợp đồng.

**Canonical hiện chưa đáp ứng điều kiện truy cập Risk từ Postman trên Windows.** Không gán `risk_base_url=https://localhost:8443`, không thêm route Gateway hoặc publish cổng Docker theo suy đoán. Chuẩn bị đường truy cập lab là một thay đổi vận hành riêng, không phải hành động được hướng dẫn này thực hiện.

Nếu chưa có đường truy cập đó, dùng log ở mục 4 và reader ở mục 6.5. Có thể đọc cấu hình Postman dưới đây trước, nhưng không ghi là API đã test PASS.

**Evaluation không phải một phép đọc hoàn toàn không có tác động:** controller gọi snapshot/lifecycle; [DeviceTrustStateRepository](../../risk-scoring-service/src/main/java/com/zerotrust/risk/repository/DeviceTrustStateRepository.java) dùng `INSERT IGNORE` để bảo đảm có trạng thái subject và khóa bản ghi. Với subject chưa có trạng thái, có thể phát sinh bản ghi generation 0. Không gửi GUID/subject tùy tiện vào canonical để thử cho tiện.

### 7.2. Cấu hình chứng chỉ

Trong Postman:

1. Mở **Settings → Certificates**.
2. Thêm CA công khai của đúng môi trường, bật sử dụng CA đó.
3. Giữ **SSL certificate verification** bật.
4. Dùng hostname nằm trong SAN của chứng chỉ và có thể resolve từ nơi Postman chạy.

CA công khai khác private key/server keystore và khác client secret. Không nhập private key của server vào Postman để thay cho CA. Không mặc định cần client certificate nếu môi trường không yêu cầu mTLS.

Nguồn chính thức: [Postman Certificates](https://learning.postman.com/docs/getting-started/installation/settings/certificates).

### 7.3. Tạo environment dành cho lab

| Biến | Giá trị/cách xác định |
|---|---|
| `token_url` | Token endpoint thực của Keycloak lab; canonical hiện là `https://localhost:28444/realms/DoAn/protocol/openid-connect/token` khi gọi từ Windows |
| `risk_base_url` | Base URL lab đã truy cập được và có TLS hợp lệ; không tự giả định từ cổng Portal |
| `risk_caller_client_id` | `zerotrust-risk-caller`, trừ khi cấu hình lab được xác nhận khác |
| `test_subject_id` | Subject test hiện có, đúng danh tính đã quản lý |
| `test_authentication_session_id` | ID cho request API thử, không tự gọi là session Browser thật |
| `test_client_id` | `zerotrust-spa`, khi kiểm thử hợp đồng của Portal này |
| `test_ip_address` | IP fixture của ca API, ghi rõ là giá trị đưa vào request |

Client secret/access token dùng vùng lưu trữ bí mật/local phù hợp của Postman. Không đưa chúng vào collection, environment export hoặc ảnh minh họa. Không lấy token ADMIN/STUDENT, provisioner hoặc portal-risk-admin thay cho caller đánh giá.

### 7.4. Lấy service token bằng OAuth 2.0

Trong **Authorization → OAuth 2.0 → Get New Access Token**:

| Trường | Cấu hình |
|---|---|
| Grant Type | `Client Credentials` |
| Access Token URL | `{{token_url}}` |
| Client ID | `{{risk_caller_client_id}}` |
| Client Secret | Secret được cấp cho caller, nhập/lưu riêng tư |
| Client Authentication | `Send client credentials in body`, phù hợp cơ chế caller hiện có |
| Scope | Theo scope đã provision; không tự thêm `openid` hoặc tên role để coi là đã được cấp quyền |
| Add authorization data to | Request Headers, dạng Bearer |

Sau khi lấy token, chọn **Use Token**. Token phải có:

- Issuer đúng cấu hình Risk.
- Audience chứa `zerotrust-risk-api`.
- `azp` đúng `zerotrust-risk-caller`.
- Client role `risk:evaluate` trong resource access của Risk audience.
- Thời hạn và chữ ký hợp lệ.

Nhập một scope vào Postman không tự tạo audience mapper hoặc cấp client role. Không sửa realm để làm một token sai quyền được chấp nhận. Đối chiếu [RISK_API_SECURITY](../security/RISK_API_SECURITY.md).

Nguồn thao tác Postman: [OAuth 2.0 / Client Credentials](https://learning.postman.com/docs/use/send-requests/authorization/oauth-20/).

### 7.5. Tạo request đánh giá

```http
POST {{risk_base_url}}/internal/v1/risk/evaluations
Content-Type: application/json
Authorization: Bearer <service token do Postman quản lý>
```

Trong **Body → raw → JSON**:

```json
{
  "subjectId": "{{test_subject_id}}",
  "authenticationSessionId": "{{test_authentication_session_id}}",
  "clientId": "{{test_client_id}}",
  "ipAddress": "{{test_ip_address}}",
  "userAgent": "Postman-lab-controlled-request",
  "deviceId": null
}
```

Các chuỗi `{{...}}` là biến cần điền, không phải dữ liệu thử đã nghiệm thu. Mẫu cố ý để `deviceId=null`: đó là ngữ cảnh thiếu identifier, không phải trusted relogin. Không sao chép cookie thiết bị thật vào collection.

Payload không nhận trực tiếp D/N/T/H, counter thất bại, history, trọng số hoặc thời điểm đánh giá. Risk tự lấy dữ liệu từ kho của nó và dùng thời điểm nhận request. `userAgent` có trong context nhưng hiện chưa phải đặc trưng chấm điểm của bốn calculator.

Nếu đổi `ipAddress` trong Postman, bạn đang kiểm thử một ngữ cảnh khai báo của caller được cấp quyền. Đó không phải bằng chứng Browser thật đã đăng nhập từ IP/mạng đó.

### 7.6. Đọc response

Khi request hợp lệ và pipeline hoàn tất, API trả HTTP 200 cùng các trường theo [RiskEvaluationResponse](../../risk-scoring-service/src/main/java/com/zerotrust/risk/dto/response/RiskEvaluationResponse.java):

| Trường | Ý nghĩa |
|---|---|
| `evaluationId` | Mã lần đánh giá API |
| `subjectId`, `authenticationSessionId` | Context được gắn với request, giữ riêng tư |
| `riskScore` | Điểm tổng hoặc null theo data status |
| `riskLevel`, `decision` | Mức hiệu lực và quyết định |
| `dataStatus`, `reasons` | Đủ/thiếu dữ liệu và các nguyên nhân |
| `evaluatedAt` | Thời điểm phía server |
| `trustGeneration` | Generation được dùng trong contract trust |

HTTP 200 không đồng nghĩa ALLOW; JSON hợp lệ có thể là MFA hoặc DENY. API hiện không trả `countryCode`, `cityName`, ASN, từng điểm D/N/T/H hoặc raw counter.

Request Postman không chạy Browser Flow/OTP và không tự tạo `LOGIN_SUCCESS` của người dùng. Không lấy kết quả `ALLOW` từ API thay cho bằng chứng đã đăng nhập Portal.

### 7.7. Các lỗi thường gặp với Postman

| Hiện tượng | Kiểm tra trước |
|---|---|
| Không resolve được `risk` | Đây là DNS nội bộ Docker; xác nhận đường truy cập lab |
| Connection refused/timeout | Base URL, cổng, mạng; canonical chưa publish cổng Risk |
| TLS/certificate error | CA đúng, hostname/SAN, thời hạn và chuỗi chứng chỉ; không tắt verification |
| Token endpoint trả `invalid_client` | Đúng client, secret và cơ chế client authentication được provision |
| HTTP 401 | Token, chữ ký, issuer, audience, exp/nbf |
| HTTP 403 | `azp`, client role đúng audience; plaintext còn có thể bị `HTTPS_REQUIRED` |
| HTTP 400 | Body/subject/IP theo validation; biến Postman đã được thay giá trị chưa |
| HTTP 200 nhưng score null | Đọc `dataStatus` và `reasons`, không điền 0 thay null |

## 8. Dùng Wireshark để quan sát mạng

### 8.1. Bắt lưu lượng Browser từ Windows

1. Cài/mở Wireshark với Npcap hỗ trợ loopback.
2. Chọn adapter loopback, thường có tên liên quan `Adapter for loopback traffic capture` hoặc `Npcap Loopback Adapter`.
3. Bắt đầu capture trước thao tác Browser.
4. Mở Portal, thực hiện một lần login có form mật khẩu và ghi giờ quan sát.
5. Dừng capture sau khi kết thúc ca thử.

Có thể đặt **capture filter** trước khi bắt:

```text
tcp port 28443 or tcp port 28444
```

Hoặc dùng **display filter** sau khi đã bắt:

```text
tcp.port == 28443 || tcp.port == 28444
```

Xem riêng TLS:

```text
tls && (tcp.port == 28443 || tcp.port == 28444)
```

Capture filter và display filter dùng cú pháp khác nhau. Nếu không thấy gói, xác nhận đúng adapter và có request mới; đừng coi không có packet là dịch vụ không hoạt động.

Nguồn: [Wireshark Loopback](https://wiki.wireshark.org/CaptureSetup/Loopback), [TLS](https://wiki.wireshark.org/TLS).

### 8.2. Tại sao chưa thấy JSON Keycloak → Risk?

Có hai giới hạn độc lập:

- Lưu lượng Keycloak → Risk chạy trong mạng Docker, không phải lời gọi Browser. Capture loopback trên host không đảm bảo nhìn thấy luồng nội bộ ấy.
- Kể cả bắt đúng luồng, HTTPS vẫn mã hóa application data.

Muốn phân tích luồng nội bộ phải chọn đúng điểm capture trong mạng Docker/WSL và có quyền/cấu hình lab tương ứng. Hướng dẫn này không tạo capture container đặc quyền, sửa mạng hoặc dừng dịch vụ canonical.

GeoIP dùng City/ASN `.mmdb` local nên không có HTTP request tới MaxMind cho từng login. Wireshark không thấy được các thao tác đọc Redis/MySQL/biến Java như một bảng đầu vào Risk đã giải mã sẵn.

Nếu Wireshark có chức năng GeoIP/name resolution riêng, vị trí nó hiển thị là kết quả của công cụ đó; không tự coi là dữ liệu Risk Service đã dùng.

### 8.3. Tùy chọn lab: giải mã TLS của Browser

Chỉ cần phần này khi mục tiêu là xem nội dung Browser ↔ Gateway/Keycloak trong môi trường kiểm thử được phép. Key log cùng capture có thể giải mã thông tin đăng nhập/token trong phiên đó, vì vậy giữ riêng tư và không đưa vào Git/slide.

1. Dùng tài khoản lab và một profile Browser riêng. Profile mới làm thay đổi cookie/device context, nên không dùng kết quả này như đối chứng cùng thiết bị của A2.
2. Đặt `SSLKEYLOGFILE` trước khi khởi động một process Browser mới có hỗ trợ xuất TLS secrets.
3. Bắt capture từ trước handshake.
4. Trong Wireshark, mở **Edit → Preferences → Protocols → TLS**, chọn file key log tại trường **(Pre)-Master-Secret log filename** hoặc tên tương đương của phiên bản đang dùng.
5. Đọc packet được giải mã trong phiên tương ứng. Nếu không giải mã được, kiểm tra key log có được Browser tạo và có khớp phiên capture không.

Ví dụ PowerShell cho Chrome, chạy sau khi đã chuẩn bị `$evidenceDir` ở mục 3. Đổi `$browserExe` nếu Chrome cài ở vị trí khác; đây không phải lệnh được tài liệu tự thực hiện:

```powershell
$browserExe = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
if (-not (Test-Path -LiteralPath $browserExe)) {
    throw 'Điền đường dẫn Browser lab đã cài trước khi tiếp tục.'
}
$tlsKeyLog = Join-Path $evidenceDir 'browser-tls-keys.private.log'
$captureProfile = Join-Path $evidenceDir 'browser-profile.private'
$previousKeyLog = $env:SSLKEYLOGFILE
try {
    $env:SSLKEYLOGFILE = $tlsKeyLog
    & $browserExe "--user-data-dir=$captureProfile" '--no-first-run' `
        'https://localhost:28443/'
} finally {
    $env:SSLKEYLOGFILE = $previousKeyLog
}
```

Đây là Browser tương tác để người thực hiện nhập credential; không phải một tác vụ login tự động. Process con nhận biến môi trường lúc khởi động. Dùng profile riêng để tránh chuyển URL sang một process Browser cũ chưa nhận biến đó.

**Khóa TLS của Browser không giải mã tự động luồng Java Keycloak → Risk.** Muốn giải mã luồng Java cần khả năng xuất secrets của chính client/server Java trong lab; hướng dẫn này không bật cơ chế đó. Cũng không có cơ sở cho rằng chỉ có CA certificate hoặc private key là đủ giải mã mọi TLS session hiện đại.

Nguồn: [Wireshark TLS Decryption](https://wiki.wireshark.org/TLS).

### 8.4. Dùng Browser DevTools như nguồn bổ sung

Mở F12 → Network và có thể bật Preserve log trước ca thử. Ghi tên request, HTTP status, timing, redirect/login/logout ở mức cần thiết. Browser không thấy trực tiếp request SPI → Risk.

Không xuất HAR toàn bộ hoặc chụp request body/header rồi đưa vào báo cáo: chúng có thể chứa password, OTP, token, code và cookie. Bản chia sẻ chỉ giữ các trường đã chọn. Không sửa request hoặc replay một payload login thật để gọi đó là một lần Browser acceptance mới.

## 9. Ghi bằng chứng và kết luận đúng phạm vi

### 9.1. Mẫu ghi một ca quan sát

Điền kết quả thực tế sau khi làm, không điền PASS sẵn:

| Trường | Nội dung cần ghi |
|---|---|
| Mã ca | Ví dụ nhãn riêng `OBS-01`, không dùng lại A1/A6 để ngụ ý cùng ca đã nghiệm thu |
| Loại bằng chứng | Browser / API lab / MMDB độc lập / capture mạng |
| Ngày/giờ | Giờ Việt Nam và mốc UTC để ghép log |
| Actor | Alias tài khoản test, không ghi thông tin định danh cá nhân |
| Model/runtime | B0 và image/config thực đã đối chiếu; nếu chưa đối chiếu ghi chưa xác nhận |
| Context | Password form có/không, cùng profile hay profile lab mới, OTP có/không |
| Ghép attempt | Evaluation/correlation lưu riêng; báo cáo có thể dùng alias `E1` |
| Risk | Score/null, level, decision, data status, reasons đúng trace |
| Enforcement/outcome | Risk step/MFA gate/OTP success/registration/login outcome thực có |
| Network/GeoIP | Nguồn có quan sát được không; nếu chưa có ghi `NOT OBSERVED`, không mặc định GEOIP |
| Artifacts | Đường dẫn file riêng tư và bản đã lọc dùng để trình bày |
| Kết luận | PASS trong phạm vi nào, FAIL hoặc NOT VERIFIED, các giới hạn |

Các mốc A1=25/ALLOW, A2=12,5/ALLOW, A3=32,5/MFA, A4 score-null/DENY, A5=50/MFA, A6=82,5/DENY là bằng chứng lịch sử theo [báo cáo nghiệm thu](../../ADAPTIVE_AUTH_ACCEPTANCE_REPORT.md) và [nghiên cứu](../../TRUST_SCORE_RESEARCH_AND_EXPERIMENT_PLAN.md). Không đặt kỳ vọng lần login hôm nay phải lặp lại đúng các score đó.

### 9.2. Bộ ca quan sát nhỏ, có thể làm theo từng mức

| Ca | Thực hiện | Bằng chứng cần giữ | Giới hạn |
|---|---|---|---|
| OBS-01 | Kiểm tra container, Risk health và cờ GeoIP | Trạng thái, cờ đã lọc, file readable | Không là lookup hoặc Browser PASS |
| OBS-02 | Login thật theo mục 4 | Trace mới ghép evaluation/enforcement/outcome | Không tạo dữ liệu để ép score |
| OBS-03 | Quan sát SSO/refresh nếu phát sinh tự nhiên | `NOT_RUN_SSO_COOKIE` / `NOT_RUN_REFRESH` khi có | Không đếm thành evaluation LOW |
| OBS-04 | Tra IP public minh họa qua đúng MMDB | Record/field thực và phiên bản công cụ | Không phải GeoIP Browser acceptance |
| OBS-05 | Postman evaluation trong lab đã có đường mạng và subject test | Request context và response đã lọc | Có thể có state initialization; không chạy Browser/MFA |
| OBS-06 | Bắt gói host và đối chiếu giờ login | Capture private, tên kết nối/TLS/timing | Không tự thấy nội bộ Docker/đầu vào tính toán |

Hướng dẫn không tạo các ca HIGH bằng revoke, brute force, sửa counter/history hoặc spoof IP. Dùng evidence A4–A6 đã có để minh họa các nhánh khó tái hiện an toàn trên dữ liệu canonical.

## 10. Risk Explanation: đề xuất ban đầu và bản v2

**Bảng dưới là phạm vi đề xuất ban đầu.** V2 đã triển khai snapshot, trace và
trang quan sát cục bộ; trạng thái/giới hạn thực tế ở [RISK_OBSERVATORY](RISK_OBSERVATORY.md).
Trường chưa có, ví dụ trust age chi tiết hoặc chứng minh nguồn Browser/API độc
lập, không được tự suy ra.

| Nhóm | Trường đề xuất | Yêu cầu diễn giải |
|---|---|---|
| Context | Evaluation ID, correlation, model version, thời điểm, nguồn Browser/API | Ghép đúng attempt; không chứa password/OTP/token/cookie/raw subject/device ID |
| D | Trạng thái nhận diện, trust age/expiry, điểm, weight/contribution | Không coi cookie còn hạn là đủ điều kiện ALLOW |
| N | Nguồn CIDR/GEOIP/DEFAULT_POLICY, nhóm địa chỉ public/private/loopback, trạng thái lookup, country, điểm/weight/contribution | Không log raw IP hoặc raw CIDR/policy lists; ghi rõ bypass do CIDR/private hay lỗi lookup |
| Geo metadata | City, timezone, accuracy radius, ASN/org khi có và được phép hiển thị | Gắn nhãn metadata chưa dùng để chấm điểm; không tự thêm các trường này vào scoring |
| T | Số event được chọn, day/hour match hoặc tần suất, timezone, cold-start, score/contribution | Chỉ dùng history trước evaluation; ghi rõ thiếu dữ liệu |
| H | Counter subject/IP, TTL còn lại khi đo được, score/contribution | Phân biệt counter hết hạn và lỗi store; không in khóa Redis chứa định danh |
| Decision | Score, calculated/effective level, data status, mandatory/priority, decision source, enforcement/outcome | Không chế tạo feature/score cho priority exit; log lỗi không được đổi kết quả auth |

Một công cụ quan sát có thể chỉ đọc log đã lọc qua quyền quản trị phù hợp, thay vì trả thêm mọi dữ liệu vào API mà SPI dùng. Nếu thay DTO/API phải kiểm tra cả hai phía và phân quyền. Không mở log nội bộ cho STUDENT chỉ để tiện demo.

Triển khai phần quan sát cần giữ B0, công thức, ngưỡng, caller/roles và semantics MFA/trust hiện có; không tự đổi policy. Kiểm tra diff, tests phù hợp, runtime plan và Browser correlation là công việc riêng sau khi phạm vi triển khai được chốt. Source trace đã có không tự xác nhận deploy; thêm log không tự chứng minh thuật toán tốt hơn.

## 11. Troubleshooting và kịch bản demo ngắn

### 11.1. Bảng chẩn đoán nhanh

| Vấn đề | Cách xử lý/diễn giải |
|---|---|
| Không có dòng `ZEROTRUST_RISK_TRACE` mới | Kiểm tra đúng container/cửa sổ thời gian, có password form, có evaluation mới; tránh nhầm SSO. Không mặc định ALLOW |
| Có score nhưng không thấy D/N/T/H | SPI chỉ có tổng; dùng trang v2 và kiểm tra có Risk details cùng evaluation ID trong khoảng log, không đọc ngược các nhóm từ tổng |
| Không thấy quốc gia/thành phố | API không thêm metadata; trên trang v2 xem geoip_status: CIDR/IP không public có thể bỏ qua lookup; record thiếu hoặc lookup lỗi được giữ nguyên |
| GeoIP bật nhưng không có geolocation reason | Có thể CIDR/private/default, hoặc GeoIP score 0; cần evidence nguồn, không kết luận chỉ từ cờ |
| N=50 dù đổi IP trong lab | Country lists có thể rỗng hoặc vẫn default/elevated; đối chiếu request và nguồn thực |
| GeoIP lỗi nhưng form yêu cầu OTP | Có thể INCOMPLETE/MFA; đọc reason/data status, không gọi numeric MEDIUM |
| Score dưới 40 vẫn MFA | Mandatory guard có thể nâng effective level; đây không tự là lỗi công thức |
| DENY với score null | Phân biệt priority response và service-unavailable bằng data status/evaluation source/failure type |
| Trace mới không có `decision_source` | Bản runtime có thể chưa phát field này; nếu suy từ response/policy phải ghi là đối chiếu/inferred |
| Wireshark không có nội dung JSON | Kiểm tra đúng điểm capture và TLS secrets của đúng process; Browser key log không phải Java key log |
| Login thành công nhưng không có cookie trust mới | Kiểm tra OTP thực, enrollment pending, eligibility, generation và registration 204 |
| Điểm thay đổi giữa hai lần login | History, counter TTL, giờ đánh giá và trust có thể đổi; hai lần login không phải cùng immutable snapshot |

### 11.2. Kịch bản demo 5–7 phút

1. **Trạng thái:** cho thấy danh sách healthy và giải thích đây là kiểm tra sẵn sàng, không phải toàn hệ thống PASS.
2. **Một login thật:** mở stream trace, login bình thường, chọn một evaluation và chỉ ra score/decision/data status.
3. **Enforcement:** ghép bước Keycloak và outcome. Nếu có MFA thì chỉ rõ challenge khác OTP success.
4. **GeoIP:** giải thích N có ba nguồn; cho xem một lookup MMDB độc lập đã thu bằng công cụ lab, gắn nhãn rõ. Không gọi lookup đó là IP/vị trí của login nếu chưa chứng minh.
5. **Giới hạn và hướng tiếp:** API/log hiện chưa có đủ feature details. Trình bày bảng Risk Explanation đề xuất và phạm vi đã triển khai.

Chỉ trình chiếu bản đã lọc, không mở Postman Console/raw token response, raw pcap/HAR/key log hoặc toàn bộ thư mục runtime. Việc dùng packet capture để minh họa TLS là phần bổ sung, không cần giải mã credential để chứng minh Adaptive Authentication.

## 12. Nguồn đối chiếu và phạm vi kiểm tra tài liệu

### Nguồn repository

- [ARCHITECTURE](../../ARCHITECTURE.md): ranh giới Keycloak/Risk/Portal, hiện trạng và giới hạn.
- [ADAPTIVE_AUTH_ACCEPTANCE_REPORT](../../ADAPTIVE_AUTH_ACCEPTANCE_REPORT.md): SPI trace và Browser evidence theo ngày.
- [TRUST_SCORE_RESEARCH_AND_EXPERIMENT_PLAN](../../TRUST_SCORE_RESEARCH_AND_EXPERIMENT_PLAN.md): cấu hình B0, A5/A6, source/runtime và nghiên cứu offline.
- [LEGACY_INTEGRATION](../operations/LEGACY_INTEGRATION.md): topology canonical, TLS/CRL và demo chỉ đọc.
- [RISK_API_SECURITY](../security/RISK_API_SECURITY.md), [DATA_PRIVACY](../security/DATA_PRIVACY.md): caller/role và ranh giới dữ liệu.
- [KeycloakLoginContextExtractor](../../keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/context/KeycloakLoginContextExtractor.java): IP/context của Browser Flow.
- [RiskEvaluationTrace](../../keycloak-risk-extension/src/main/java/com/zerotrust/keycloak/risk/trace/RiskEvaluationTrace.java): schema trace SPI.
- [RiskScoreTrace](../../risk-scoring-service/src/main/java/com/zerotrust/risk/trace/RiskScoreTrace.java): khả năng giải thích từng nhóm trong source.
- [RiskEvaluationRequest](../../risk-scoring-service/src/main/java/com/zerotrust/risk/dto/request/RiskEvaluationRequest.java), [RiskEvaluationResponse](../../risk-scoring-service/src/main/java/com/zerotrust/risk/dto/response/RiskEvaluationResponse.java): contract API.
- [RiskEvaluationController](../../risk-scoring-service/src/main/java/com/zerotrust/risk/controller/RiskEvaluationController.java), [DeviceTrustStateRepository](../../risk-scoring-service/src/main/java/com/zerotrust/risk/repository/DeviceTrustStateRepository.java): lifecycle snapshot và tác động khởi tạo state.
- [NetworkRiskCalculator](../../risk-scoring-service/src/main/java/com/zerotrust/risk/service/NetworkRiskCalculator.java), [MaxMindGeoIpProvider](../../risk-scoring-service/src/main/java/com/zerotrust/risk/service/MaxMindGeoIpProvider.java), [feature extractor](../../risk-scoring-service/src/main/java/com/zerotrust/risk/feature/DatabaseBackedRiskFeatureExtractor.java): GeoIP/CIDR/reasons.

### Tài liệu chính thức của công cụ

- [Postman OAuth 2.0](https://learning.postman.com/docs/use/send-requests/authorization/oauth-20/).
- [Postman Certificates](https://learning.postman.com/docs/getting-started/installation/settings/certificates).
- [Postman Shared Responsibility](https://www.postman.com/security/shared-responsibility/): bảo vệ secret và SSL validation.
- [Wireshark TLS](https://wiki.wireshark.org/TLS): decryption và session secrets.
- [Wireshark Loopback](https://wiki.wireshark.org/CaptureSetup/Loopback): capture loopback trên Windows/Npcap.
- [MaxMind DB Reader Python](https://github.com/maxmind/MaxMind-DB-Reader-python/blob/main/README.rst): `open_database`, `get` và cài reader.

### Phạm vi thực sự đã kiểm tra khi viết

- Đã đối chiếu code/config/report và contract liên quan; đã đọc trạng thái 10 container, hai cờ GeoIP/Network, file readable, country-list counts, published ports và vị trí class trace trong image.
- Đã thực hiện GET health nội bộ bằng CA đang có, nhận UP; không gọi evaluation, token endpoint hoặc đăng nhập người dùng trong nhiệm vụ viết tài liệu.
- Đã kiểm tra đường dẫn liên kết và cú pháp các block PowerShell/Python/JSON trong tài liệu.
- Chưa thực hiện lại Browser acceptance, Postman lab request, cài tooling/lookup MMDB bằng script mẫu hoặc capture/giải mã TLS. Không đánh dấu các quy trình tùy chọn đó PASS.
- Không sửa application source, realm, model/policy, dữ liệu, Docker topology hoặc deployment. Lệnh tạo tooling/profile/capture là hướng dẫn cho lab, chưa được tự chạy.
