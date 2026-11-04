# Build chuẩn hóa — giai đoạn 2

Áp dụng từ 04/11/2026. Build tạo image kiểm chứng cho cấu hình lab; triển khai
image vào container hiện có là một bước vận hành riêng.

## Công cụ và nguồn cấu hình

| Công cụ | Phiên bản/nguồn |
|---|---|
| Java | Java 17 cho cả bốn module; Docker dùng Temurin có digest cố định |
| Maven | Wrapper trong repository, hiện 3.9.16 |
| Node.js | 24.16.0 trong `.node-version`, frontend engines, lockfile, CI và Docker |
| Python | 3.11+ cho script build; CI dùng 3.13 |
| Docker | Docker Desktop Linux containers hoặc Docker Linux, Buildx hỗ trợ `--check` |

Trên máy lập trình, cấu hình IntelliJ Project SDK/Maven runner là Java 17 và
chọn Node theo `.node-version`. Build Docker tự dùng Java/Node trong image,
không phụ thuộc Java đang đứng đầu PATH của Windows. Không dùng Java 8 để chạy Maven.
`@types/node` là dependency TypeScript riêng, không phải bộ runtime Node được cài.

Dockerfile dùng chung nằm trong [deploy/docker](../../deploy/docker).
`deploy/demo` còn các helper, fixture và script tương thích; không đổi tên mount
`/run/demo` hoặc chuyển runtime trong giai đoạn này. Dockerfile import dữ liệu
vẫn ở `deploy/legacy` và không thuộc sáu build thường ngày.

## Các lệnh build

Từ repository, dùng được trong PowerShell dù máy chặn `.ps1`:

```powershell
# Kiểm tra Dockerfile, không tạo image
.\scripts\build\images.cmd --check

# Build sáu image: backend, risk, gateway, frontend, keycloak, crl
.\scripts\build\images.cmd

# Build phát hành từ byte đã commit tại HEAD
.\scripts\build\images.cmd --committed

# Build một hoặc nhiều service
.\scripts\build\images.cmd --service gateway
.\scripts\build\images.cmd --service backend --service frontend
```

Tương đương: `python -X utf8 scripts/build/images.py [options]`.
Lệnh không đọc env riêng tư hoặc kết nối vào mạng/database lab; không push,
khởi động container ứng dụng hay gắn volume dữ liệu. Docker build cần tải các
base image và dependency khi chưa có cache.

## Mã nguồn và phiên bản image

Script lấy các file Git theo dõi cùng file mới chưa bị ignore trong các vùng
đầu vào build đã khai báo: source/module, frontend, deploy, database, Maven wrapper,
Compose build, phiên bản Node và chính script build. Nó bỏ generated output, env riêng tư, private files
và khóa riêng. Không lấy toàn bộ thư mục người dùng hoặc kho preservation.
`--committed` dùng Git blobs của HEAD, loại các thay đổi chưa commit khỏi
snapshot. Manifest ghi `source_mode` để phân biệt hai cách build.

Các byte đầu vào được đóng thành `context.tar` với metadata cố định và SHA-256.
Timestamp cố định phải lớn hơn zero để Maven chép resource vào đích chưa tồn tại.
Cả sáu build đọc cùng archive, nên việc sửa code sau đó không làm mỗi service
nhận một phiên bản mã khác nhau. Từ giai đoạn 3, định nghĩa build nằm riêng tại
`compose.build.yaml`; `compose.lab.yaml` chỉ dùng cho runtime. Đối số frontend lấy từ Compose build trong archive,
bao gồm Keycloak URL/realm và API base URL; không phụ thuộc default `.env`.

Image mới có dạng:

```text
zerotrust-build/backend:<git-12>-<snapshot-12>-lab
zerotrust-build/risk:<git-12>-<snapshot-12>-lab
zerotrust-build/gateway:<git-12>-<snapshot-12>-lab
zerotrust-build/frontend:<git-12>-<snapshot-12>-lab
zerotrust-build/keycloak:<git-12>-<snapshot-12>-lab
zerotrust-build/crl:<git-12>-<snapshot-12>-lab
```

Các tag này khác tag candidate đang triển khai. Image có labels revision, snapshot,
version và trạng thái working tree dirty. Git SHA là HEAD; khi có thay đổi chưa
commit, SHA-256 snapshot mới xác định đúng nội dung đã build. Digest nguồn không
cam kết image bit-for-bit giống nhau: công cụ/package tải từ mạng và thời gian
đóng gói vẫn có thể ảnh hưởng image cuối. Image ID thực được ghi sau mỗi build.

Kết quả nằm tại `.build-artifacts/<version>/`, được Git/Docker ignore:

| File | Ý nghĩa |
|---|---|
| context.tar | Archive mã nguồn thực đã đưa vào Docker |
| build-manifest.json | Revision, snapshot, hash từng file, build args, tag và image ID của lần gọi |
| check-manifest.json | Kết quả `--check`; không phải bằng chứng image đã build |
| service.log | Log build và test tương ứng |
| service.check.log | Log kiểm tra Dockerfile, không ghi đè log build/test |
| service.metadata.json | Metadata Buildx của image đã tạo |

Manifest có `repo_digests` nếu Docker cung cấp. Image local chưa push có thể không
có registry digest; image ID và registry digest là hai khái niệm khác nhau.
Lỗi test/build trả mã khác 0 và dừng; không tự bỏ test hoặc thay image đang chạy.

## Các kiểm tra tự động

- Dockerfile Java chạy `mvn verify` cho module đã chọn; SPI cũng chạy `verify`.
- Frontend chạy lint, typecheck, hai nhóm Node tests hiện có và Next production build.
- CI có bốn module Java: Portal, Risk, Keycloak SPI và Gateway.
- CI frontend dùng `.node-version`, `npm ci`, checks, tests và build.
- CI kiểm tra script build, bộ lệnh ops, Compose portability và sáu Dockerfile.
- `verify-project.ps1 -Scope Backend` đã có Gateway; scope Frontend kiểm tra
  phiên bản Node trước khi lint/typecheck. Full production build dùng lệnh ở trên.

Kiểm tra nhanh các contract build:

```powershell
python -X utf8 -m unittest discover -s scripts/build -p test_images.py -v
python -X utf8 -m unittest discover -s scripts/legacy -p test_portability.py -v
```

CI GitHub chỉ chạy sau khi thay đổi được push. Build local không tương đương
nghiệm thu Browser/MFA hoặc triển khai; xem [vận hành hiện hành](../operations/CURRENT_RUNTIME.md).

## Kết quả kiểm chứng ngày 04/11/2026

Đã chạy `python -X utf8 scripts/build/images.py` và lệnh tương ứng có `--check`
trên cùng bản chụp `1c9fa972c992-10ea4a912eb6-lab` (473 file đầu vào).
Sáu image backend, risk, gateway, frontend, keycloak và crl đều build thành công;
labels revision/snapshot đã được đối chiếu với manifest. Sáu BuildKit checks đạt,
không có warning. Các image chỉ được nạp vào Docker local, chưa push hoặc triển khai.

| Phạm vi | Kết quả thực chạy |
|---|---|
| Portal — Maven verify | 327 test đạt, 0 bỏ qua |
| Risk — Maven verify | 613 test đạt, 96 bỏ qua |
| Gateway — Maven verify | 20 test đạt, 0 bỏ qua |
| Keycloak SPI — Maven verify và Keycloak build | 176 test đạt, 27 bỏ qua |
| Frontend | 15 Node test đạt; lint, typecheck và production build đạt |
| Công cụ build | 5 test đạt |
| Công cụ vận hành | 8 test đạt với Docker giả lập |
| Compose portability | 3 test đạt; không tạo container hoặc chạy migration |
| Workflow | YAML parse hợp lệ; chưa chạy trên GitHub |

Không có failure/error trong các suite Java. Tổng cộng 1.136 Java test đạt và
123 bị bỏ qua theo điều kiện đã có trong source: các nhóm audit/điều tra cần
system properties như `qa.*.audit` hoặc `postfix03a.gateB`. Không đổi điều kiện
hoặc bật các kiểm thử dùng dịch vụ/dữ liệu ngoài trong đợt build này.
Frontend còn một ESLint warning có sẵn tại `postcss.config.mjs` về anonymous
default export, không có lint error.

Log, archive và manifest ở `.build-artifacts/1c9fa972c992-10ea4a912eb6-lab/`.
Working tree có cả thay đổi chức năng tồn tại trước đợt chuẩn hóa; manifest ghi
`working_tree_dirty: true` và hash từng file để truy vết đúng mã đã kiểm chứng.
Hai lần build thử đầu lỗi do timestamp archive khiến Maven không chép test
resources; bản chụp trên đã sửa lỗi này và chạy lại toàn bộ suite thành công.

Kiểm tra `python -X utf8 scripts/ops/zt.py status` sau build xác nhận đủ 10
container lab vẫn dừng như trước. Không chuyển runtime, đổi project/volume,
chạy migration, cập nhật database hoặc thay image của container hiện hữu.
Tách môi trường Compose và chuẩn hóa vị trí runtime là công việc giai đoạn sau.
