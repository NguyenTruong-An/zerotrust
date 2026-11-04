# Đề xuất dọn dẹp — 04/11/2026

Đây là đề xuất, **chưa xóa file, image hoặc volume nào**. Chạy lại
`scripts\ops\zt.cmd cleanup-report` ngay trước quyết định dọn vì tài nguyên có thể đổi.
Kết quả máy đọc ở `.local-legacy/maintenance/cleanup-inventory.json`.

## Allowlist đề nghị duyệt

Hai thư mục build thử thất bại, không phải runtime hoặc dữ liệu DB:

| Đường dẫn tương đối từ canonical repository | Số byte |
|---|---:|
| `.build-artifacts/1c9fa972c992-09f92f9cdd49-lab` | 4.850.633 |
| `.build-artifacts/1c9fa972c992-3d361810d179-lab` | 4.850.481 |

Tổng 9.701.114 byte (~9,25 MiB). Cả hai chỉ có context, log backend và
manifest build thất bại. Không có image ID đầu ra trong hai manifest.
Kiểm kê lại ngay trước khi thực hiện và chỉ xử lý hai đường dẫn đã được duyệt.

Giữ bản build thành công `1c9fa972c992-10ea4a912eb6-lab` và bản kiểm tra cấu hình
`1c9fa972c992-f00af9888778-lab` để truy vết. Có thể dọn `target`, `.next` và cache
build sau khi không cần báo cáo test; không xóa hàng loạt các thư mục chưa phân loại.

## Image đã rà soát

Image không có tag từng được đánh dấu `review_unused`:

`sha256:c7a80805605b101b05b699a6b0376ae121d6f19f5e573d20df9bf0e1784e550e`

Hồ sơ `.local-legacy/risk-observation/verification/rollout.private.json` tham
chiếu đúng ID này ở trường `old_image`. Công cụ kiểm kê hiện giữ image theo
tham chiếu rollback đó, manifest backup, lock và manifest build. Allowlist
đợt này gồm hai thư mục build ở trên, **0 image và 0 volume**.

## Giữ lại

| Nguồn | Lý do |
|---|---|
| `../runtime/lab` | Runtime đang hoạt động, chứa secret và CA |
| Bốn volume `zerotrust-legacy-integration-20261026_*data` | Dữ liệu MySQL/Redis đang dùng |
| `../backups` | Bản sao lưu và bằng chứng phục hồi cô lập |
| `.local-legacy/phase3-runtime` | Kế hoạch, kiểm kê và cấu hình quay lui |
| `.local-legacy/maintenance` | Báo cáo kiểm kê và bản CRL trước/sau gia hạn |
| `zerotrust-legacy-preservation` | Backup/import/evidence lịch sử và runtime quay lui; không còn live mount nhưng vẫn có vai trò |
| `zt-release-source-20261026` | Kiểm tra Git thực tế còn **65 mục thay đổi**; phải lưu/đối chiếu trước khi xóa |
| `zt-release-empty-runtime-20261026` | Input kiểm chứng lịch sử; chưa xác nhận không chứa bản duy nhất |
| `output` | Junction tới archive; không xóa đệ quy theo đường dẫn này |
| `deploy/demo` | Vẫn có helper được Dockerfile hiện hành COPY; không phải toàn bộ đã cũ |
| `compose.legacy.yaml`, `scripts/legacy`, `deploy/legacy` | Công cụ migration/CA/backup và khả năng tương thích còn được sử dụng |
| Container và volume thử `zt-restore-20261104*` | Đã dừng, giữ theo danh sách tài nguyên trong [báo cáo phục hồi](RESTORE_VERIFICATION_REPORT.md) |

## Checkout release cũ

HEAD `8e10c1f902f3efeb899792cb91dc4cbfaa0e3708` có đúng 65 mục staged,
không có thay đổi unstaged hoặc untracked tại lần rà soát.

| Nhóm | Số mục |
|---|---:|
| Cấu hình và đóng gói | 16 |
| Source ứng dụng | 15 |
| Test | 13 |
| Công cụ vận hành | 9 |
| Tài liệu | 8 |
| Schema/migration | 4 |

So Git blob của từng mục với canonical baseline `1c9fa972c992` và worktree
tại lúc rà soát: **46 khớp canonical HEAD, 19 khác hoặc thiếu**. Danh sách từng
path, trạng thái và blob ID nằm trong
`.local-legacy/maintenance/release-staged-review.json`. Giữ nguyên checkout
cho tới khi 19 mục được đối chiếu, bảo toàn hoặc có quyết định loại bỏ riêng.
