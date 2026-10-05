---
name: architecture-docs
description: Viết và cập nhật tài liệu kiến trúc ZeroTrust bằng Markdown, sơ đồ Mermaid và ADR từ bằng chứng trong code/config/test. Dùng khi mô tả hiện trạng, luồng liên dịch vụ, so sánh phương án hoặc ghi quyết định; phân biệt kiến trúc đã chốt, phần đã triển khai, vận hành đã kiểm chứng và đề xuất.
---

# Tài liệu kiến trúc ZeroTrust

Viết bằng ngôn ngữ người dùng yêu cầu; mặc định tiếng Việt theo tài liệu hiện có. Tạo tài liệu phù hợp phạm vi yêu cầu, không tự sửa code, realm hoặc hạ tầng khi chỉ được yêu cầu viết tài liệu. Đường dẫn nguồn dưới đây tính từ gốc repository.

## Đọc nguồn đúng mục đích

- `ARCHITECTURE.md`: kiến trúc đích đã chấp nhận, ranh giới và các quyết định còn mở. Đây là nguồn chính sách thiết kế; không phải bằng chứng mọi thành phần đã được triển khai/vận hành.
- `README.md`, `docs/README.md` và README từng module: bản đồ tài liệu; giữ `ARCHITECTURE.md` ở gốc, tài liệu chi tiết trong nhóm thích hợp và bổ sung mục lục khi tạo tài liệu thật.
- Build: ba POM độc lập, Java 17; Portal/Risk dùng Spring Boot 3.5.7, SPI dùng Keycloak 26.7.0, Portal admin client 26.0.11. Xác nhận lại POM khi viết, không ghi hai phiên bản Keycloak thành một.
- `docs/authentication/LOGIN_FLOW.md`, `docs/authentication/MFA_RESET_LIFECYCLE.md`: login/PKCE, phiên, reset MFA và device trust. Đối chiếu controller/security/service Portal, authenticator/listener SPI và API/service Risk.
- `docs/security/RISK_API_SECURITY.md`, `docs/security/DATA_PRIVACY.md`: service caller, role/audience và dữ liệu nhạy cảm; xác nhận bằng config/converter/entity/migration của module liên quan.
- `docs/operations/LOCAL_SETUP.md`, `compose.yaml`, profile configuration và script khởi động: môi trường local. Compose hiện khai báo MySQL và Redis, không phải manifest triển khai toàn bộ kiến trúc đích.
- `docs/development/DEVELOPMENT_CHECKS.md`, `.github/workflows/ci.yml`, test và `docs/reviews/`: phạm vi test, mốc kiểm chứng và giới hạn. Không coi báo cáo theo ngày là trạng thái runtime hiện tại.

Chỉ đọc nguồn liên quan đến câu hỏi. Trace một luồng từ entrypoint qua controller/authenticator, service, client và persistence; đối chiếu DTO, security và test trước khi khẳng định contract. Khi nguồn mâu thuẫn, nêu rõ code hiện tại làm gì, thiết kế đã chốt yêu cầu gì và phần nào chưa xác nhận, không sửa lịch sử để che chênh lệch.

## Phân biệt trạng thái

Mọi khẳng định quan trọng cần trạng thái và nguồn, nhất là thành phần trên sơ đồ:

| Trạng thái | Bằng chứng cần có |
|---|---|
| Kiến trúc đã chốt / đích | Quyết định trong `ARCHITECTURE.md` hoặc ADR Accepted có căn cứ |
| Đã triển khai trong mã | File/lớp/config/migration thực hiện hành vi; kể cả nếu nằm trong working tree chưa commit |
| Đã kiểm chứng vận hành | Kết quả thực chạy, ngày, môi trường và phạm vi xác nhận |
| Đề xuất / chưa quyết định | Phương án cần đánh giá, chưa được coi là hành vi hiện tại |
| Chưa kiểm chứng / thiếu bằng chứng | Không đủ nguồn để kết luận; ghi câu hỏi hoặc cách xác minh |

Một thành phần có thể có cả trạng thái thiết kế và triển khai. Tách sơ đồ hiện trạng và sơ đồ đích/đề xuất khi khác nhau. Reverse Proxy/API Gateway có trong kiến trúc đích không tự chứng minh local đã triển khai chúng; code provisioning không tự chứng minh live realm đã cấu hình. Test H2/mock không tự chứng minh MySQL/Redis/Keycloak production.

## Viết Markdown và Mermaid

- Dùng [mẫu tài liệu kiến trúc](assets/architecture-template.md) khi cần tài liệu mới. Đây là khung có thể rút gọn; bỏ phần không liên quan và thay toàn bộ chỗ điền trước bàn giao.
- Mô tả mục đích, phạm vi, trách nhiệm, ranh giới tin cậy/dữ liệu, contract và luồng thành công/lỗi quan trọng. Chỉ đưa chi tiết giúp người đọc đánh giá kiến trúc.
- Mermaid nằm trong fenced block `mermaid`. Dùng `flowchart` cho thành phần hoặc C4 context/container bằng node/subgraph thường; `sequenceDiagram` cho login, scoring, registration hoặc revoke. Tránh phụ thuộc plugin Mermaid C4 riêng nếu chưa có renderer hỗ trợ.
- Dùng node ID ổn định, quote nhãn flowchart, ghi giao thức và caller trên cạnh. Chỉ đặt service call/JWKS/token/event đúng chiều được xác nhận; không vẽ connection trực tiếp SPI→DB/Redis khi mã gọi Risk API.
- Với đề xuất, đặt nhãn và chú giải rõ; không để nét đứt hoặc màu là dấu hiệu duy nhất. Chú thích dưới sơ đồ nguồn và phần chưa kiểm chứng.
- Dẫn nguồn bằng liên kết Markdown tương đối tới code/config/test từ vị trí tài liệu. Tên lớp và đường dẫn tính từ gốc có thể ghi trong nội dung nhưng link phải resolve được. Không đưa secret, token hoặc thông tin cá nhân vào ví dụ.

## Ghi ADR

Dùng [mẫu ADR](assets/adr-template.md) cho quyết định có tác động kiến trúc. Theo vị trí/đánh số ADR hiện có; nếu chưa có và task cần ADR, dùng `docs/adr/NNNN-ten-quyet-dinh.md`, chọn số tiếp theo không ghi đè. Không tạo ADR cho mỗi chỉnh sửa nhỏ hoặc khi chỉ cần mô tả hiện trạng.

ADR ghi bối cảnh, phương án, đánh đổi, quyết định, tác động, trạng thái và kế hoạch kiểm chứng. Đề xuất mới mặc định `Proposed`. Chỉ ghi `Accepted` khi có quyết định rõ ràng từ người dùng hoặc nguồn đã chấp nhận; ghi nguồn chấp thuận. ADR hồi cứu phải nói rõ nó ghi lại quyết định có từ trước, không suy ra chấp thuận chỉ vì code tồn tại. Theo dõi trạng thái triển khai riêng với trạng thái quyết định. Khi thay thế ADR, liên kết hai chiều và giữ lịch sử.

Trọng số/ngưỡng/công thức Risk còn mở trong `ARCHITECTURE.md`: số ví dụ hoặc mặc định cấu hình không phải quyết định đã chốt. Giữ ranh giới Portal/Risk/Keycloak và ba quyết định `ALLOW`, `STEP_UP_MFA`, `DENY`. Đề xuất thay đổi được viết và đánh giá trong phạm vi tài liệu; việc thực thi thay đổi kiến trúc phải có chấp thuận rõ ràng theo tài liệu dự án, kể cả khi một ADR mới đã được soạn.

## Kiểm tra trước bàn giao

Đối chiếu mọi node/cạnh quan trọng và contract với nguồn, kiểm tra link/file tồn tại và Mermaid có cú pháp phù hợp renderer. Render sơ đồ nếu công cụ có sẵn; nếu chỉ đọc cú pháp thì báo rõ chưa render. Không cài dependency hoặc chạy toàn bộ backend chỉ để xác nhận một chỉnh sửa tài liệu thông thường.

Kiểm tra không lẫn Proposed với Accepted, thiết kế đích với code, hoặc code với runtime. Cập nhật `docs/README.md` và liên kết bị ảnh hưởng khi task tạo/di chuyển tài liệu thật. Bàn giao file đã viết, điểm chính, nguồn xác nhận và giới hạn còn lại; việc tạo skill này không yêu cầu tạo tài liệu/ADR thực tế ngay.
