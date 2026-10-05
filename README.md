# ZeroTrust Portal

Đồ án xác thực thích ứng với Keycloak, Risk Scoring Service và Portal API. Frontend sử dụng Authorization Code Flow + PKCE; Risk đánh giá ngữ cảnh để cho phép, yêu cầu MFA hoặc từ chối đăng nhập.

## Bắt đầu

- **[Mục lục và thứ tự đọc tài liệu](docs/README.md)**
- [Chạy hệ thống local](docs/operations/LOCAL_SETUP.md)
- [Kiến trúc và phạm vi đã chốt](ARCHITECTURE.md)
- [Giải thích class và luồng hệ thống bằng tiếng Việt](docs/development/CODE_FLOW_WALKTHROUGH.md)
- [Reset MFA, generation và vòng đời thiết bị](docs/authentication/MFA_RESET_LIFECYCLE.md)
- [Chạy kiểm thử](docs/development/DEVELOPMENT_CHECKS.md)
- [Báo cáo rà soát ngày 02/10/2026](docs/reviews/ADAPTIVE_AUTH_REVIEW_2026-10-02.md) — kết quả tại thời điểm kiểm tra, gồm các mục chưa kiểm chứng.

## Thành phần

| Thành phần | Vị trí / tài liệu |
|---|---|
| Portal API — Spring Boot | `src/`, `pom.xml` |
| Frontend SPA | `frontend/` |
| Risk Scoring Service | [README](risk-scoring-service/README.md) |
| Keycloak extension | [README](keycloak-risk-extension/README.md) |
| Giao diện Keycloak | [README](keycloak-theme/README.md) |

Các lệnh trong tài liệu mặc định chạy từ thư mục gốc repository, trừ khi có chỉ dẫn khác. Cấu hình local xem `.env.example`; không đưa secret vào tài liệu hoặc Git.

Tài liệu mô tả mã được đối chiếu ngày 2026-10-05; kiến trúc đích và hiện trạng
triển khai được trình bày riêng. Compose chỉ dựng Risk DB/Redis. Kết quả vận hành
có ngày là mốc lịch sử, không chứng minh môi trường hiện tại đã cấu hình đầy đủ.
