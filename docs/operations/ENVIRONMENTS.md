# Môi trường và runtime — chuẩn hóa giai đoạn 3

Trạng thái vận hành mới hơn sau giai đoạn 3: [RUNBOOK](RUNBOOK.md). Lab đã được
khởi động và sao lưu; các trạng thái “chưa chạy” bên dưới mô tả thời điểm chuyển mount.

## Bố trí thư mục

```text
<project-parent>\
├── zerotrust\                 # Git repository, mở trong IntelliJ/Codex
│   ├── compose.lab.yaml       # 10 service lab hiện hành, không build/import
│   ├── compose.dev.yaml       # Môi trường synthetic riêng
│   ├── compose.build.yaml     # Định nghĩa build sáu image cho lab
│   ├── compose.yaml           # Không khai báo service; yêu cầu chọn môi trường
│   ├── deploy\docker\         # Dockerfile dùng chung
│   └── scripts\ops\           # Vận hành và chuyển runtime
└── runtime\
    └── lab\                   # Cấu hình/khóa riêng, nằm ngoài Git
        ├── compose.private.env
        ├── images.private.yaml
        ├── backend\, risk\, gateway\, keycloak\
        ├── school\, risk-db\, keycloak-db\, redis\
        ├── public-ca\
        └── authority\         # CA management được bảo toàn, không mount vào app
```

Mã nguồn và cấu hình vận hành cùng nằm dưới thư mục `zerotrust` bên ngoài,
nhưng runtime không nằm trong Git repository. Mật khẩu, private key và chứng chỉ
được sao chép nguyên byte; không tạo lại credentials hoặc CA. Quyền truy cập
thư mục runtime mới giới hạn ở tài khoản thực hiện, SYSTEM và Administrators.

MySQL/Redis vẫn lưu dữ liệu trong Docker named volumes, không chuyển dữ liệu DB
sang thư mục runtime. Kho `zerotrust-legacy-preservation` được giữ nguyên cho
archive, import lịch sử và rollback; không xóa các checkout/evidence cũ trong giai đoạn này.

## Chọn môi trường rõ ràng

| Phạm vi | File | Project / dữ liệu | Cổng host |
|---|---|---|---|
| Lab có dữ liệu đã bảo toàn | [compose.lab.yaml](../../compose.lab.yaml) | `zerotrust-legacy-integration-20261026`; bốn volume hiện hữu | 28443, 28444, 28445, chỉ localhost |
| Dev synthetic | [compose.dev.yaml](../../compose.dev.yaml) | `zerotrust-demo`; volume demo và `.local-demo` riêng | 8443, 8444, 8445, chỉ localhost |
| Build lab | [compose.build.yaml](../../compose.build.yaml) | Công cụ build đọc định nghĩa, tạo tag riêng | Không mở cổng |
| Import/migration lịch sử | [compose.legacy.yaml](../../compose.legacy.yaml) | Chỉ phục vụ quy trình bảo trì có chủ đích | Không dùng cho start thường ngày |

`compose.lab.yaml` là manifest độc lập, không kế thừa dev. Nó không có bootstrap,
import hoặc Flyway job; Risk giữ `SPRING_FLYWAY_ENABLED=false` và giới hạn
memory 640 MiB / memory+swap 1280 MiB đang dùng. Bốn volume và hai network được
khai báo `external: true` với tên chính xác. Nếu thiếu tài nguyên, Compose báo lỗi
thay vì tạo database trống. Bind mounts có `create_host_path: false`.

`images.private.yaml` khóa cả mười service vào image ID đã kiểm kê khi chuyển
runtime. Giai đoạn này không triển khai image build ở giai đoạn 2. Khi nâng cấp
ứng dụng sau này cần cập nhật khóa image có chủ đích và thực hiện nghiệm thu riêng.

`compose.yaml` không còn tự chọn cấu hình synthetic. Lệnh thiếu `-f` không khởi
động service. `compose.dev.yaml` giữ topology/fixtures của demo cũ, được kiểm tra
cấu hình nhưng chưa được khởi động hoặc nghiệm thu lại trong giai đoạn 3.

## Lệnh thường dùng

Từ thư mục Git repository:

```powershell
.\scripts\ops\zt.cmd status
.\scripts\ops\zt.cmd doctor
.\scripts\ops\zt.cmd config-check
.\scripts\ops\zt.cmd start
.\scripts\ops\zt.cmd stop
.\scripts\build\images.cmd
```

`config-check` đọc cấu hình lab và image lock, đối chiếu với Docker, chỉ in kết
quả tóm tắt. Không chia sẻ output thô của `docker compose config`: nó có thể
chứa giá trị env riêng tư. `status/start/stop/logs` vẫn dùng tên container đã
kiểm tra danh tính; không tự tạo môi trường nếu container thiếu.

Dev synthetic có entrypoint riêng: `scripts/demo/demo.cmd status|build|start|stop`.
`start` của dev có thể tạo dữ liệu mẫu, nên không dùng thay lệnh `zt.cmd start`
của lab. Không bật dev như một phần của việc chuyển runtime lab.

## Cách chuyển và quay lui

[relocate_runtime.py](../../scripts/ops/relocate_runtime.py) có bốn bước rõ ràng:

1. `prepare`: yêu cầu cả mười container dừng, kiểm tra danh tính, volume/network,
   image, môi trường, lệnh khởi động và tài nguyên. Ghi hash 87 file cấu hình/CA,
   bản kiểm kê và Compose quay lui trong `.local-legacy/phase3-runtime` được bảo vệ.
2. `apply`: kiểm tra lại kế hoạch, sao chép file sang thư mục mới và xác nhận hash;
   tạo lại container bằng `compose create --no-build --pull never`, không chạy service.
3. `verify`: đối chiếu image, cấu hình container, volume, network và hash runtime
   trước/sau; chỉ chấp nhận khi tất cả vẫn dừng và bind mounts trỏ đúng runtime mới.
4. `rollback`: chỉ khi cần quay lui và các container đều dừng. Tạo lại container
   từ cấu hình/image đã lưu, gắn lại runtime cũ, kiểm tra cấu hình tương đương.

Ví dụ gọi công cụ: `python -X utf8 scripts/ops/relocate_runtime.py verify`.
Không gọi `prepare`/`apply` lần nữa khi đợt chuyển đã hoàn thành. Quay lui không
khôi phục ID container hoặc log cũ; các cấu hình và dữ liệu volume được giữ.
Không dùng `down -v`, xóa volume, import realm hoặc migration để đổi đường dẫn.

Container cần được tạo lại vì bind mount là cấu hình lúc tạo container. Thay file
env hoặc copy thư mục không tự thay mount của container hiện hữu. `create` tạo
container nhưng không khởi động tiến trình; dữ liệu trong named volumes không
được ứng dụng đọc/ghi trong bước chuyển này.

## Phạm vi kiểm chứng

Ngày triển khai: 04/11/2026. Trước chuyển: 10 container đều dừng. Đã kiểm tra
29 test công cụ (18 ops/môi trường, 5 build, 3 portability, 3 fixtures), cấu hình
Compose dev/lab và sáu BuildKit checks. Không sửa logic Java/frontend trong đợt này.

Đã chuyển thực tế và đối chiếu thành công 87 file, 10 image/cấu hình container,
bốn volume và đường dẫn bind mounts. Doctor không có lỗi; 10 container chưa chạy.
Kết quả được ghi ở [CURRENT_RUNTIME](CURRENT_RUNTIME.md) và file
`.local-legacy/phase3-runtime/verification.json`. Không suy ra health hoặc Browser/MFA
đạt từ việc kiểm tra cấu hình của container đang dừng. Việc bật hệ thống, kiểm tra
TLS/CRL và nghiệm thu ứng dụng vẫn là một đợt vận hành riêng.

Cấu hình quay lui đã được Compose đọc lại và đối chiếu thành công với image,
env và mount gốc; chưa thực hiện rollback thật. Kho preservation vẫn giữ nguyên.

Tham chiếu chính thức: [Compose create](https://docs.docker.com/reference/cli/docker/compose/create/),
[external volumes](https://docs.docker.com/reference/compose-file/volumes/),
[external networks](https://docs.docker.com/reference/compose-file/networks/).
