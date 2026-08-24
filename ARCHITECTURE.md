# Kiến trúc chuẩn của đồ án Zero Trust

**Trạng thái:** Đã chấp nhận (Accepted)  
**Ngày cập nhật:** 2026-08-24

**Phạm vi:** Kiến trúc đích và nguyên tắc triển khai bắt buộc của toàn bộ đồ án

## 1. Phạm vi đã chốt

Đồ án sử dụng kiến trúc **Zero Trust Adaptive Authentication** với một **Risk Scoring Service** độc lập. Risk Scoring Service đánh giá rủi ro đăng nhập dựa trên ngữ cảnh hiện tại, lịch sử xác thực và các chính sách bảo mật.

Các thành phần, ranh giới dịch vụ, luồng xác thực và ba loại quyết định `ALLOW`, `STEP_UP_MFA`, `DENY` trong tài liệu này đã được chốt.

Mô hình tính điểm chi tiết, trọng số của từng nhóm đặc trưng và ngưỡng số giữa các mức `LOW`, `MEDIUM`, `HIGH` **chưa được chốt**.

## 2. Sơ đồ kiến trúc hệ thống

```mermaid
flowchart TB
    USER["Internet / Người dùng"] --> RP["Reverse Proxy<br/>TLS Termination"]

    subgraph ACCESS["Lớp truy cập"]
        RP --> GW["API Gateway<br/>Routing · Rate Limit"]
    end

    subgraph PORTAL["Hệ thống nghiệp vụ"]
        GW --> APP["Portal API<br/>Spring Boot Resource Server"]
        APP --> PDB[("Portal DB · MySQL<br/>Người dùng · Lớp · Môn · Điểm")]
    end

    subgraph IAM["Xác thực và quản lý danh tính"]
        RP --> KC["Keycloak<br/>IAM · Realm · Clients · MFA"]
        KC --> PA["Primary Authentication<br/>Username + Password"]
        PA --> SPI["Custom Authenticator<br/>Keycloak SPI"]
        KC --> EL["Keycloak Event Listener<br/>Ghi nhận đăng nhập thất bại"]
    end

    subgraph RISK["Hệ thống đánh giá rủi ro"]
        SPI --> RS["Risk Scoring Service<br/>Spring Boot API"]
        EL --> RS
        RS --> RDB[("Risk DB · MySQL<br/>Thiết bị · Lịch sử · Audit")]
        RS --> REDIS[("Redis<br/>Cache · Failure Counter · Velocity")]
    end

    APP -. "Xác minh JWT bằng JWKS" .-> KC
```

## 3. Luồng xác thực và đánh giá rủi ro

```mermaid
flowchart TB
    LOGIN["Login Attempt"] --> PRIMARY["Keycloak kiểm tra<br/>username + password"]

    PRIMARY -->|"Sai"| EVENT["Keycloak Event Listener"]
    EVENT --> COUNTER["Cập nhật failure counter trong Redis<br/>và audit trong Risk DB"]
    COUNTER --> REJECT["Từ chối đăng nhập"]

    PRIMARY -->|"Đúng"| CONTEXT["Context Collection"]

    CONTEXT --> DEVICE["Device / Fingerprint"]
    CONTEXT --> NETWORK["IP / Geolocation"]
    CONTEXT --> TIME["Login Time"]
    CONTEXT --> FAILURE["Failed Attempts"]

    DEVICE --> FEATURES["Feature Calculation"]
    NETWORK --> FEATURES
    TIME --> FEATURES
    FAILURE --> FEATURES
    HISTORY[("Risk DB + Redis<br/>Hồ sơ hành vi lịch sử")] --> FEATURES

    FEATURES --> RULES["Priority Security Rules"]

    RULES -->|"Vi phạm luật bắt buộc"| HARD["Hard Deny"]
    RULES -->|"Không vi phạm"| SCORE["Policy-based Weighted<br/>Risk Scoring"]

    SCORE --> RESULT["Risk Score<br/>Trust Score"]
    RESULT --> POLICY["Decision Policy"]

    POLICY -->|"LOW"| ALLOW["ALLOW"]
    POLICY -->|"MEDIUM"| MFA["STEP-UP OTP / MFA"]
    POLICY -->|"HIGH"| DENY["DENY"]

    MFA -->|"MFA thành công"| ALLOW
    MFA -->|"MFA thất bại"| DENY

    ALLOW --> TOKEN["Keycloak phát hành JWT"]
    HARD --> AUDIT["Lưu kết quả và Audit Log"]
    DENY --> AUDIT
    TOKEN --> AUDIT

    TOKEN --> API["Client gọi Portal API bằng JWT"]
```

## 4. Những nội dung đã chốt trong Risk Scoring

Pipeline đánh giá rủi ro gồm:

1. Thu thập ngữ cảnh đăng nhập hiện tại.
2. Đọc hồ sơ hành vi và lịch sử xác thực từ Risk DB và Redis.
3. Tính các đặc trưng rủi ro.
4. Kiểm tra Priority Security Rules.
5. Nếu không bị Hard Deny, thực hiện Policy-based Weighted Risk Scoring.
6. Phân loại kết quả thành `LOW`, `MEDIUM` hoặc `HIGH`.
7. Ánh xạ mức rủi ro sang `ALLOW`, `STEP_UP_MFA` hoặc `DENY`.
8. Lưu kết quả và Audit Log.

Các nhóm đặc trưng cấp cao đã xác định:

- Device Risk.
- Network / Location Risk.
- Temporal Risk.
- Authentication History Risk.

Priority Security Rules chạy trước weighted scoring. Một vi phạm bắt buộc có thể dẫn đến `Hard Deny` mà không phụ thuộc vào điểm tổng hợp.

## 5. Những nội dung chưa chốt

Các nội dung sau vẫn là quyết định thiết kế mở:

- Công thức tính điểm chi tiết.
- Cách chuẩn hóa từng đặc trưng.
- Trọng số của từng đặc trưng hoặc nhóm đặc trưng.
- Thang điểm chính thức của Risk Score và Trust Score.
- Ngưỡng số phân chia `LOW`, `MEDIUM`, `HIGH`.
- Danh sách đầy đủ và tham số của Priority Security Rules.
- Cách hiệu chỉnh trọng số và ngưỡng bằng dữ liệu thực nghiệm.

Không được tự sử dụng các trọng số `30% / 25% / 15% / 30%` hoặc các ngưỡng `0–29 / 30–69 / 70–100` làm giá trị chính thức. Đây chỉ là ví dụ từng được đề xuất và hiện không thuộc kiến trúc đã chốt.

Cho đến khi chủ đồ án phê duyệt, code không được hard-code trọng số hoặc ngưỡng giả định. Nếu cần tạo cấu trúc kỹ thuật trước, các giá trị phải nằm trong cấu hình và được đánh dấu `TBD`.

## 6. Phân chia trách nhiệm

### Reverse Proxy

- Là điểm vào từ Internet.
- TLS termination.
- Chuyển traffic đến API Gateway hoặc Keycloak.

### API Gateway

- Routing đến Portal API.
- Rate limiting và chính sách bảo vệ tại biên.

### Keycloak

- Quản lý tài khoản, mật khẩu, realm role, clients và MFA.
- Thực hiện primary authentication.
- Phát hành JWT sau khi authentication flow thành công.

### Custom Authenticator

- Là Keycloak SPI trong authentication flow.
- Thu thập context đăng nhập.
- Gọi Risk Scoring Service.
- Chuyển quyết định thành allow, step-up MFA hoặc deny.
- Không tự chứa công thức, trọng số hoặc ngưỡng chấm điểm.

### Keycloak Event Listener

- Ghi nhận các sự kiện không đi tiếp qua Custom Authenticator, đặc biệt là login failure và MFA failure.
- Cập nhật dữ liệu cần thiết cho Redis và Risk DB.

### Risk Scoring Service

- Là Spring Boot service tách biệt với Portal.
- Trích xuất đặc trưng rủi ro.
- Áp dụng Priority Security Rules.
- Thực hiện Policy-based Weighted Risk Scoring sau khi mô hình được phê duyệt.
- Trả về mức rủi ro, quyết định và lý do.

### Redis

- Lưu failure counter theo cửa sổ thời gian.
- Lưu login velocity, rate limit và dữ liệu ngắn hạn.
- Cache dữ liệu thiết bị, IP hoặc hồ sơ cần truy cập nhanh.

### Risk DB

- Lưu thiết bị và hồ sơ hành vi rủi ro.
- Lưu authentication event, kết quả đánh giá, quyết định và lý do.
- Lưu audit dài hạn.

### Portal API

- Xử lý nghiệp vụ người dùng, sinh viên, lớp hành chính, môn học và điểm.
- Là OAuth2 Resource Server stateless.
- Xác minh JWT của Keycloak bằng JWKS.
- Kiểm tra realm role và quyền trên từng tài nguyên.
- Không kiểm tra mật khẩu và không tự chấm điểm rủi ro đăng nhập.

### Portal DB

- Chỉ lưu hồ sơ người dùng và dữ liệu nghiệp vụ quản lý điểm.
- Không lưu mật khẩu.
- Tách biệt khỏi Risk DB.

## 7. Kiểm soát quyền trong Portal

JWT hợp lệ chỉ xác nhận danh tính. Portal vẫn phải kiểm tra:

- `STUDENT` chỉ được xem điểm của chính mình.
- `ADMIN` được quản lý người dùng, môn học và điểm của toàn hệ thống theo policy.
- Việc nhập và sửa điểm chỉ do `ADMIN` thực hiện; hệ thống không quản lý tài khoản giảng viên hoặc lớp học phần.

Portal xác minh chữ ký, issuer, expiration và audience của JWT bằng JWKS. Portal không gọi Keycloak để introspect mỗi API request.

## 8. Các ràng buộc không được tự ý thay đổi

- Không gộp Risk Scoring Service vào Portal.
- Không đặt logic chấm điểm trong controller hoặc Keycloak SPI.
- Không gộp Portal DB và Risk DB thành một miền dữ liệu.
- Không lưu mật khẩu tại Portal DB.
- Không để Risk Scoring Service đọc trực tiếp dữ liệu nghiệp vụ Portal DB.
- Không bỏ qua Reverse Proxy, API Gateway, Keycloak hoặc bước xác minh JWT/JWKS trong kiến trúc đích.
- Không tự chọn trọng số, ngưỡng hoặc công thức chấm điểm khi chưa được phê duyệt.
- Không thay mô hình policy-based weighted scoring bằng ML hoặc mô hình khác khi chưa có chấp thuận rõ ràng.
- Không thay đổi ranh giới dịch vụ hoặc luồng xác thực nếu chưa cập nhật tài liệu này và được chủ đồ án chấp thuận.

## 9. Quy tắc thay đổi kiến trúc

Mọi đề xuất thay đổi phải:

1. Nêu rõ vấn đề của kiến trúc hiện tại.
2. Phân tích tác động và phương án thay thế.
3. Được chủ đồ án chấp thuận rõ ràng.
4. Cập nhật tài liệu này trước hoặc cùng lúc với code.

Nếu không có chấp thuận, kiến trúc trong tài liệu này là nguồn sự thật duy nhất để thiết kế, hướng dẫn và triển khai đồ án.
