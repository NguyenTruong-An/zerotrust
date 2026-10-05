# Chọn công cụ theo câu hỏi

| Câu hỏi | Kiểm chứng phù hợp |
|---|---|
| Quyền endpoint/contract/state transition | rg, code/config/test, test mục tiêu nếu cần |
| JWT | Decoder/validator và authorization riêng; không chỉ MockMvc JWT giả lập |
| Dependency/CVE | POM, dependency tree module; scanner Java/dependency nếu liên quan |
| Secrets | Đường truyền dữ liệu, tên property; Gitleaks nếu sẵn có và phù hợp phạm vi |
| SAST Java | Rules Java/Spring nếu Semgrep/công cụ tương đương đã có |
| Lua/MySQL locking/Keycloak flow | Integration local/staging trong phạm vi; nêu giới hạn mock/H2 |

Không bắt buộc scanner trước manual review. Không cài công cụ, thêm CI, quét mọi lịch sử Git hoặc tải auto rules chỉ vì skill kích hoạt. Nếu cần cài/network/gửi code ra dịch vụ, xác định nhu cầu/quyền trước. Bandit không phục vụ Java; npm audit chỉ khi npm/frontend nằm trong yêu cầu; nmap/pentest không là bước mặc định.

Ba POM độc lập, wrapper gốc với -f, không -pl/-am. Ví dụ chọn theo vấn đề, không phải chuỗi bắt buộc:

```powershell
.\mvnw.cmd --batch-mode --no-transfer-progress -f risk-scoring-service/pom.xml '-Dtest=RiskApiSecurityTests' test
.\mvnw.cmd --batch-mode --no-transfer-progress -f keycloak-risk-extension/pom.xml '-Dtest=RiskDecisionHandlerTest,TrustedDeviceRegistrationAuthenticatorTest' test
.\mvnw.cmd --batch-mode --no-transfer-progress -f pom.xml '-Dtest=AdminControllerSecurityTest' test
```

Nếu cần dependency:tree, chọn POM liên quan; Maven có thể tải plugin từ mạng. Theo [DEVELOPMENT_CHECKS.md](../../../../docs/development/DEVELOPMENT_CHECKS.md). RiskApiSecurityTests hiện dùng JWT ký RSA và JWKS loopback, có case sai issuer/audience/thời hạn/chữ ký và caller/role: kiểm tra coverage sẵn có trước khi đề xuất thêm decoder test. Test này không chứng minh cấu hình realm thật. Không thêm Testcontainers chỉ để review; integration thật cần khi kết luận phụ thuộc semantics MySQL/Redis/Keycloak.

Tìm credential bằng tên property/vị trí; tránh in toàn bộ .env/log/realm export. Báo cáo redact; không đọc private key/mật khẩu/dữ liệu thật nếu không cần. Finding scanner phải trace đường thực thi; POM/tên API không chứng minh exploit. CVE cần advisory chính thức đúng artifact/phiên bản, không dùng trí nhớ như dữ liệu hiện hành.

Ghi lệnh thực chạy, kết quả/môi trường và giới hạn. Không dùng báo cáo test cũ như lần chạy mới.
