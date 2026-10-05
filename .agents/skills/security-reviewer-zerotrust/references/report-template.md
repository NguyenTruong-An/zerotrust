# Kết quả review

Review nhỏ chỉ cần finding và phạm vi kiểm chứng, không bắt buộc file/báo cáo dài. Khi được yêu cầu báo cáo, viết Markdown tiếng Việt mặc định.

Mỗi finding nêu mức độ/tên vấn đề, file/line hiện tại, trigger/call chain, điều kiện khai thác, tác động, cách sửa tối thiểu và test regression. Phân biệt kết quả quan sát với suy luận từ code; ghi giả định/giới hạn, redact dữ liệu thật.

Ưu tiên theo tác động/khả năng khai thác; dùng nhãn môi trường review hoặc Critical/High/Medium/Low có lý do. Không gán số CVSS giả. Chỉ ghi CVSS khi đủ căn cứ nêu phiên bản/vector. Đề xuất cải tiến, nợ kỹ thuật và câu hỏi chưa xác minh không lẫn finding đã xác nhận.

Nếu không có finding đủ căn cứ, nói không tìm thấy trong phạm vi đã đọc và nêu giới hạn có ý nghĩa; không khẳng định toàn hệ thống an toàn. Test/lệnh phải là lần thực chạy, không lấy surefire/log cũ làm bằng chứng mới.
