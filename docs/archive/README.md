# Archive và phân loại repository

| Phân loại | Phạm vi | Hành động |
|---|---|---|
| KEEP | Backend/Risk/Gateway/SPI source, Flyway V1–V5, security regression tests | Giữ nguyên contract, không xóa. |
| KEEP | Thiết kế học thuật, `ARCHITECTURE.md`, authentication/security docs có nội dung riêng | Giữ, bổ sung đường dẫn hiện trạng mới. |
| KEEP/PRESERVE | `docs/qa-audit`, `docs/qa-fixes`, `docs/qa-postfix`, evidence, review theo ngày | Giữ nguyên tại vị trí cũ để không phá nguồn chứng cứ; không đưa vào quick start. |
| UPDATE | README, docs index, Compose, env examples, frontend scripts/build config | Một đường setup chính cho Development/Demo. |
| ARCHIVE | Local setup trước packaging | Nội dung giữ tại `LEGACY_LOCAL_SETUP.md`, đường cũ thành trang chuyển tiếp. |
| DELETE | `frontend/vite.config.ts`, `frontend/.openai/hosting.json` | Chỉ phục vụ vinext/Sites cũ; native Next scripts/build không còn tham chiếu. Có thể khôi phục từ baseline Git. |
| DELETE dependency | Vinext/Vite/Cloudflare/Sites tooling và override liên quan | npm lock được cập nhật; không xóa Next/React/Keycloak dependencies đang dùng. |

Không xóa toàn bộ output/evidence/backup hoặc original dirty checkout. Các thao tác khôi phục bootstrap tạm được lưu ngoài clean candidate tại bộ evidence bàn giao, không trở thành đường setup mặc định. Historical docs có thể chứa đường dẫn máy/cổng cũ; đó là snapshot lịch sử, không cấu hình đang được hỗ trợ.
