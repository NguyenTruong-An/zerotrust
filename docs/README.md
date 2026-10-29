# Tài liệu ZeroTrust Portal

**Phạm vi hiện tại, xác nhận 27/10/2026:** web xem điểm sinh viên, chỉ có ADMIN và STUDENT.
Student xem dữ liệu của mình; Admin quản lý tài khoản/danh mục và nhập/sửa điểm.
Teacher, phân công và lịch học đã được gỡ. Các báo cáo cũ có phần đó là bằng chứng lịch sử,
không phải yêu cầu hoặc điều kiện nghiệm thu hiện tại. Nguồn chính sách: [ARCHITECTURE](../ARCHITECTURE.md).

Đợt đồng bộ source hai role với Docker và cleanup hiện tại được ghi trong một
[báo cáo tổng hợp](../ZEROTRUST_FINAL_CONSOLIDATION_REPORT.md); đọc các trạng thái
PASS/FAIL/BLOCKED/NOT VERIFIED tại đó trước khi sử dụng kết quả runtime lịch sử.

Nghiệm thu Risk/MFA, Trusted Device và quyền theo phiên thật được đối chiếu riêng trong
[ADAPTIVE_AUTH_ACCEPTANCE_REPORT](../ADAPTIVE_AUTH_ACCEPTANCE_REPORT.md), gồm checklist
owner, cấu hình đang chạy và các mục chưa đủ bằng chứng; không coi source tests là Browser PASS.

Nghiên cứu mô hình tiếp theo: [Trust Score và thiết kế thực nghiệm](../TRUST_SCORE_RESEARCH_AND_EXPERIMENT_PLAN.md).
Thiết kế B1 đã được duyệt và triển khai/kiểm thử trong source, B0 vẫn mặc định;
chưa deploy Docker hoặc tạo fixture A5/A6. Không thay thế kết quả Browser đã nghiệm thu.

## Runtime canonical hiện tại

Dùng project `zerotrust-legacy-integration-20261026`, [hướng dẫn vận hành](operations/LEGACY_INTEGRATION.md)
và [báo cáo tổng hợp](../ZEROTRUST_FINAL_CONSOLIDATION_REPORT.md). Không tạo môi trường mới
hoặc khởi động cấu hình synthetic để thay cho canonical.

## Tài liệu đóng gói synthetic lịch sử

[Setup từ đầu](setup/DEVELOPMENT_DEMO.md) · [Kiến trúc runtime](architecture/SYSTEM.md) · [Runbook](demo/DEMO_RUNBOOK.md) · [Troubleshooting](setup/TROUBLESHOOTING.md) · [Bảo vệ/giới hạn](security/DEMO_SECURITY.md) · [Completion và cleanup](demo/COMPLETION_REPORT.md).

`docs/qa-audit`, `docs/qa-fixes`, `docs/qa-postfix`, các evidence và review theo ngày là lịch sử được giữ nguyên ở nơi đang có. Một số QA evidence chỉ có trong original dirty checkout, không nằm trong baseline clone và không copy vào candidate. Không dùng các cổng/volume/secret trong lịch sử để khởi động Demo mới. [Archive policy](archive/README.md).

[← Trang dự án](../README.md)

## Nên đọc theo thứ tự nào?

1. **Hiểu đề tài:** [Kiến trúc](../ARCHITECTURE.md) — sơ đồ mã hiện có và kiến trúc đích, ranh giới, phần đã chốt/còn thiếu.
2. **Hiểu đăng nhập:** [Login, PKCE và phiên](authentication/LOGIN_FLOW.md), rồi [Reset MFA và thiết bị tin cậy](authentication/MFA_RESET_LIFECYCLE.md).
3. **Vận hành hiện tại:** [Canonical Docker](operations/LEGACY_INTEGRATION.md), xem trạng thái nghiệm thu và build/start/stop trong [báo cáo tổng hợp](../ZEROTRUST_FINAL_CONSOLIDATION_REPORT.md).
4. **Đọc mã và kiểm thử:** [Giải thích class theo luồng](development/CODE_FLOW_WALKTHROUGH.md) — frontend, SPI, scoring/history/device và học vụ Portal; [Các bước kiểm tra](development/DEVELOPMENT_CHECKS.md).
   Bộ kịch bản thực hành: [Kế hoạch kiểm thử và pentest](testing/TEST_PLAN.md), [40 ca chức năng](testing/FUNCTIONAL_SCENARIOS.md), [24 ca pentest cơ bản](testing/BASIC_PENTEST.md).
5. **Đánh giá giới hạn:** [Rà soát ngày 02/10/2026](reviews/ADAPTIVE_AUTH_REVIEW_2026-10-02.md), [Đối chiếu bảo mật](security/SECURITY_REFERENCE_REVIEW.md).

## Tra cứu theo mục đích

| Bạn muốn… | Đọc tài liệu |
|---|---|
| Biết kiến trúc và phạm vi đề tài | [ARCHITECTURE](../ARCHITECTURE.md) |
| Hiểu login, refresh token, logout | [LOGIN_FLOW](authentication/LOGIN_FLOW.md) |
| Hiểu thu hồi trust, reset MFA và phục hồi lỗi | [MFA_RESET_LIFECYCLE](authentication/MFA_RESET_LIFECYCLE.md) |
| Cấu hình service token, audience, role của Risk API | [RISK_API_SECURITY](security/RISK_API_SECURITY.md) |
| Biết dữ liệu nhạy cảm được xử lý ra sao | [DATA_PRIVACY](security/DATA_PRIVACY.md) |
| Đối chiếu với các tài liệu bảo mật tham chiếu | [SECURITY_REFERENCE_REVIEW](security/SECURITY_REFERENCE_REVIEW.md) |
| Tìm điểm vào và luồng xử lý trong mã | [CODE_FLOW_WALKTHROUGH](development/CODE_FLOW_WALKTHROUGH.md) |
| Chạy test và hiểu phạm vi CI | [DEVELOPMENT_CHECKS](development/DEVELOPMENT_CHECKS.md) |
| Thực hiện kiểm thử và pentest cơ bản | [TEST_PLAN](testing/TEST_PLAN.md), [FUNCTIONAL_SCENARIOS](testing/FUNCTIONAL_SCENARIOS.md), [BASIC_PENTEST](testing/BASIC_PENTEST.md) |
| Tự thực hiện pentest sâu về luồng và trạng thái | [ADVANCED_PENTEST](testing/ADVANCED_PENTEST.md) — 6 kịch bản chi tiết, chưa thực hiện |
| Ghi kết quả, finding và kiểm thử lại | [REPORT_TEMPLATE](testing/REPORT_TEMPLATE.md) |
| Khởi động các dịch vụ trên máy local | [DEVELOPMENT_DEMO](setup/DEVELOPMENT_DEMO.md) |
| Xem kết quả kiểm chứng và thiếu sót đã ghi nhận | [ADAPTIVE_AUTH_REVIEW_2026-10-02](reviews/ADAPTIVE_AUTH_REVIEW_2026-10-02.md) |
| Xem thay đổi và giới hạn của Geo-IP | [GEOIP_PRODUCTION_CHANGELOG](reviews/GEOIP_PRODUCTION_CHANGELOG.md) |

## Cấu trúc thư mục

```text
docs/
├── README.md           # Mục lục và hướng dẫn đọc
├── authentication/     # Login, MFA, vòng đời thiết bị
├── security/           # Quyền truy cập, riêng tư, đối chiếu bảo mật
├── development/        # Đọc mã, kiểm thử và CI
├── testing/            # Kịch bản chức năng, pentest và mẫu báo cáo
├── setup/              # Development/Demo và troubleshooting hiện tại
├── architecture/       # Topology Development/Demo
├── demo/               # Runbook và completion report
├── archive/            # Hướng dẫn lịch sử và chính sách bảo toàn
├── operations/         # Cấu hình và chạy hệ thống
└── reviews/            # Báo cáo, kết quả kiểm chứng theo thời điểm
```

## Tài liệu từng module

- [Risk Scoring Service](../risk-scoring-service/README.md)
- [Keycloak Risk Extension](../keycloak-risk-extension/README.md)
- [Keycloak Theme](../keycloak-theme/README.md)

## Cách cập nhật tài liệu

Tài liệu mô tả mã chính đã được đối chiếu ngày 2026-10-05. Không đồng nhất ngày
cập nhật diễn giải với ngày chấp thuận kiến trúc hoặc ngày triển khai. Cấu hình
realm/flow/proxy và các kết quả trong README module, báo cáo cũ phải kiểm tra
lại trước demo. Các link class trong hướng dẫn đọc mã dẫn trực tiếp tới nguồn.

- Giữ `ARCHITECTURE.md` ở gốc để dễ tìm các quyết định kiến trúc.
- Đặt hướng dẫn chi tiết trong nhóm phù hợp; README của module giữ cạnh mã nguồn.
- Thêm tài liệu mới vào bảng tra cứu này; dùng liên kết tương đối để đọc được trên Git và máy local.
- Ghi rõ ngày, môi trường, kết quả và phần chưa kiểm chứng trong báo cáo. Kết quả cũ không xác nhận trạng thái triển khai hiện tại.
- Phân biệt kiến trúc đích, mã đã triển khai và kết quả đã chạy thực tế. Khi khác nhau, ghi rõ giới hạn thay vì mặc định mọi phần đã hoàn thành.
- Các đường dẫn mã nguồn và lệnh trong nội dung được hiểu từ gốc repository, trừ chỉ dẫn riêng. Thanh điều hướng dùng đường dẫn tương đối theo vị trí tài liệu.
- Khi đổi tên hoặc di chuyển tài liệu, cập nhật cả mục lục, liên kết và tham chiếu trong script/cấu hình.

- [Legacy-data integration candidate](operations/LEGACY_INTEGRATION.md) — source/build readiness, pending execution approval.
