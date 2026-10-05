---
name: security-reviewer-zerotrust
description: Review bảo mật backend ZeroTrust khi được yêu cầu audit hoặc kiểm tra lỗ hổng API, phân quyền, JWT, Keycloak SPI, Risk/MFA và device trust. Báo cáo bằng chứng và cách sửa; không tự áp dụng cho mọi thay đổi Java, review nghiệp vụ thông thường hay tác vụ chỉ viết tài liệu.
license: MIT
metadata:
  author: https://github.com/Jeffallan
  upstream-version: "1.1.1"
  upstream-repository: https://github.com/Jeffallan/claude-skills
  upstream-path: skills/security-reviewer
  upstream-commit: "1be15d8064f88fc25216442406d40add8fd23b53"
  scope: review
  output-format: report
---

# Security review cho ZeroTrust

Bản điều chỉnh từ security-reviewer của Jeffallan, không phải skill chính thức của OpenAI. Giữ [license MIT](LICENSE); xem [nguồn và điều chỉnh](references/upstream.md) khi cần truy xuất nguồn. Mặc định review chỉ đọc và kiểm chứng trong phạm vi yêu cầu; không tự sửa code, provision realm hoặc triển khai.

## Xác định biên cần review

Đọc POM module, entrypoint, security config, service/client và test liên quan. Repository có ba POM độc lập:

| Module | Baseline cần xác nhận lại | Vai trò |
|---|---|---|
| Portal, pom.xml | Java 17, Spring Boot 3.5.7, Keycloak admin-client 26.0.11 | Resource server, nghiệp vụ và reset MFA orchestration |
| risk-scoring-service | Java 17, Spring Boot 3.5.7 | Scoring, history, device trust, MySQL/Flyway/Redis |
| keycloak-risk-extension | Java release 17, Keycloak SPI 26.7.0 | Authenticator, conditional MFA, event listener, HTTP client; không có Spring context |

Ràng buộc thiết kế nằm trong [ARCHITECTURE.md](../../../ARCHITECTURE.md). Tài liệu đích và báo cáo cũ không chứng minh code hay realm đang chạy. Không kết luận lỗ hổng chỉ vì phiên bản hai dependency Keycloak khác nhau; xác minh đường gọi và ảnh hưởng.

## Review theo bằng chứng

1. Xác định tài sản, caller, ranh giới tin cậy và đường xử lý bị tác động. Nếu phạm vi chưa rõ, review phần có bằng chứng trước và nêu giới hạn.
2. Trace request/token/event qua authorization, service, remote call và persistence. Chọn mục liên quan trong [checklist backend](references/backend-checklist.md), không áp mọi mục cho mọi request.
3. Chọn kiểm chứng theo [hướng dẫn công cụ](references/tools.md). Scanner tùy chọn theo câu hỏi; manual review không cần chờ scanner. Không cài/chạy scanner Python, Node, network hoặc cloud cho mọi review Java.
4. Đối chiếu test với hành vi thực; dùng test mục tiêu hoặc PoC local cô lập khi cần phân biệt lỗi với giả thuyết. Đánh giá điều kiện khai thác và tác động trước khi gán mức độ. Không lấy CVSS/CVE từ ví dụ; nếu dùng CVSS, ghi phiên bản và vector có căn cứ, nếu không thì mô tả định tính.
5. Báo cáo theo [khung kết quả](references/report-template.md), ưu tiên finding có thể hành động; không biến review thành chứng nhận toàn hệ thống an toàn.

Yêu cầu review đã cho phép đọc repository trong phạm vi đó, không cần xác nhận lại từng file. Trước kiểm thử chủ động lên hệ thống đang chạy, xác định target, môi trường, tài khoản và phạm vi đã cho phép; hỏi phần còn thiếu nếu cần. Code review không tự cho phép đổi Browser Flow, reset người dùng thật, quét mạng hoặc thử tải gây gián đoạn. Không mở rộng sang production hoặc tiếp tục retry khi có dấu hiệu tác động ngoài phạm vi.

## Ranh giới khi đề xuất cách sửa

- Keycloak xác thực password/MFA và phát token; Portal là resource server stateless; SPI gọi Risk thay vì tự scoring. Không đề xuất password store/login hoặc JWT issuer riêng trong Portal.
- Risk/MFA cần review caller, guardrail và state transition; không tự chốt trọng số/ngưỡng. Policy đã chốt khác baseline development trong cấu hình.
- User/SPA, provisioner, risk-caller và portal-risk-admin có trách nhiệm riêng; không dùng một danh tính để chữa lỗi quyền của danh tính khác.
- Không in secret, password, token, cookie device hoặc raw IP/danh tính thật trong báo cáo; dùng vị trí code, mô tả loại dữ liệu và ví dụ giả.
- Cách sửa tương thích Java 17 và module hiện có. DB transaction không rollback remote Keycloak/Risk call; xét cả timeout sau remote commit.

Bàn giao kết luận, bằng chứng, ảnh hưởng và giới hạn kiểm chứng. Thiếu bằng chứng thì ghi giả thuyết/câu hỏi cần xác minh, không khẳng định finding đã xác nhận.
