# Nguồn và điều chỉnh

- Repository: [Jeffallan/claude-skills](https://github.com/Jeffallan/claude-skills).
- Commit đã tải: `1be15d8064f88fc25216442406d40add8fd23b53`.
- Entrypoint nguồn: [skills/security-reviewer/SKILL.md tại commit cố định](https://github.com/Jeffallan/claude-skills/blob/1be15d8064f88fc25216442406d40add8fd23b53/skills/security-reviewer/SKILL.md).
- Phiên bản metadata nguồn: `1.1.1`.
- License: [MIT nguyên văn](../LICENSE), lấy từ [LICENSE cùng commit](https://github.com/Jeffallan/claude-skills/blob/1be15d8064f88fc25216442406d40add8fd23b53/LICENSE).
- Cài ngày 2026-10-05 bằng install-skill-from-github.py với ref trên, dest .agents/skills và name security-reviewer-zerotrust.

Kế thừa quy trình scope → review/kiểm chứng → phân loại → báo cáo của nguồn; đã viết lại entrypoint và references cho ZeroTrust. Đổi cả tên frontmatter, giữ author upstream và commit trong metadata. Bỏ allowed-tools Read/Grep/Glob của Claude vì không phải danh sách công cụ Codex của môi trường này; quyền vẫn theo phiên làm việc, không do skill cấp.

Thay yêu cầu scanner trước mọi review bằng lựa chọn theo phạm vi; bỏ catalog Python/Node/cloud/pentest không phục vụ backend này. Không giữ các CVSS/CVE, password policy hoặc PoC ví dụ như yêu cầu dự án. References local thay bằng checklist backend, công cụ và khung báo cáo; giữ MIT cho phần phái sinh.

Nội dung repo-specific dựa trên code/config/test và tài liệu ngày cài, kể cả working tree chưa commit. Xác nhận lại nguồn khi dùng. Không tự cập nhật từ main làm mất điều chỉnh; khi được yêu cầu cập nhật, so sánh commit mới, giữ license và ghi commit thực sự áp dụng.
