# Vận hành môi trường hiện tại

Ngày đối chiếu: **04/11/2026**. `lab` là tên gọi trong bộ lệnh mới cho project
Docker hiện có được khai báo trong cấu hình Lab; không tạo project mới.
Nguồn đối chiếu: Docker inspect của 10 container, Compose trong repository và
manifest triển khai riêng tư. Đây là tài liệu vận hành hiện hành; các báo cáo
nghiệm thu theo ngày vẫn giữ giá trị trong phạm vi và thời điểm của chúng.

Giai đoạn 3 đã chuyển bind mounts sang `<lab-runtime-root>`.
Mười container được tạo lại bằng đúng image cũ; dữ liệu vẫn ở bốn volume cũ.
Nghiệm thu vận hành ngày 04/11/2026 xác nhận **10/10 healthy**, B0, HTTPS,
OIDC, các kết nối nội bộ và Risk Observatory. Browser ADMIN/STUDENT cần
người vận hành nhập password/OTP và ghi kết quả. [RUNBOOK](RUNBOOK.md).
Backup đã khôi phục và đọc được cả bốn DB thử. Đối chiếu nhất quán Keycloak còn
hai khác biệt. [RESTORE_VERIFICATION_REPORT](RESTORE_VERIFICATION_REPORT.md).
Chi tiết thiết kế và quay lui: [ENVIRONMENTS](ENVIRONMENTS.md).

## Bắt đầu tại đây

Mở PowerShell tại gốc repository, dùng Python 3.11+ và Docker Desktop Linux containers:

```powershell
.\scripts\ops\zt.cmd status
.\scripts\ops\zt.cmd doctor
.\scripts\ops\zt.cmd config-check
.\scripts\ops\zt.cmd start
.\scripts\ops\zt.cmd smoke
.\scripts\ops\zt.cmd logs --service backend --tail 100
.\scripts\ops\zt.cmd stop
```

Mặc định là `lab`; có thể ghi rõ `--environment lab`. `zt.cmd` dùng được khi máy
chặn `.ps1`. Wrapper tùy chọn `zt.ps1 status -Environment lab` dành cho máy cho
phép PowerShell script. Hoặc dùng Python trực tiếp, không cần đổi execution policy:

```powershell
python -X utf8 scripts/ops/zt.py status
python -X utf8 scripts/ops/zt.py doctor
python -X utf8 scripts/ops/zt.py inventory
python -X utf8 scripts/ops/zt.py logs --service risk --tail 100 --follow
```

`start` kiểm tra danh tính container, bind mount, khóa image, Compose và ánh xạ
volume trước khi gọi bộ vận hành cũ. Nó bật container hiện có
theo thứ tự và chờ healthcheck. `stop` dừng theo thứ tự ngược. Chỉ hỗ trợ `lab`;
chưa có môi trường `dev` mới. Start/stop không build, import, migrate hoặc reset.
Script cũ [operate.py](../../scripts/legacy/operate.py) vẫn tương thích.

`doctor` trả mã 1 nếu thiếu tài nguyên/cấu hình bắt buộc. Container đang dừng và
đường dẫn Compose lịch sử không tồn tại là cảnh báo; sức khỏe lưu trên container
đã dừng không phải trạng thái kiểm tra live. Doctor không kiểm tra nội dung mật
khẩu, hạn TLS/CRL, dữ liệu DB hoặc luồng Browser/MFA. `inventory` chỉ xuất metadata
được chọn: IDs, image, đường dẫn, volume, network, port; không xuất Config.Env.
Log ứng dụng có thể chứa dữ liệu người dùng, chỉ chia sẻ sau khi kiểm tra nội dung.

## Nguồn cấu hình chính xác

| Thành phần | Nguồn | Cách sử dụng |
|---|---|---|
| Source hiện hành | Repository đang mở trong IntelliJ/Codex | Build code tại đây |
| Compose chính | [compose.lab.yaml](../../compose.lab.yaml) | 10 service lab; không build/import/migrate |
| Khóa image | `../runtime/lab/images.private.yaml` | Image ID chính xác của cả 10 service |
| Runtime env | `../runtime/lab/compose.private.env` | Chọn `ZT_LAB_RUNTIME`; không dùng env cũ |
| Tài nguyên Risk | `compose.lab.yaml`: memory 640 MiB, memory+swap 1280 MiB | Đã hợp nhất override riêng trước đây |
| Dockerfiles | [deploy/docker](../../deploy/docker) | Dùng chung khi build; đã chuẩn hóa trong giai đoạn 2 |
| Bộ lệnh hiện hành | [zt.cmd](../../scripts/ops/zt.cmd), [zt.ps1](../../scripts/ops/zt.ps1), [zt.py](../../scripts/ops/zt.py) | Vận hành container hiện có |

Trên máy hiện tại, vùng riêng tư nằm tại:

```text
<lab-runtime-root>\
  compose.private.env
  images.private.yaml
  backend\, risk\, gateway\, keycloak\
  school\, risk-db\, keycloak-db\, redis\, public-ca\
```

`compose.private.env` chọn runtime; `images.private.yaml` khóa image đã triển khai.
Khi thao tác Compose trực tiếp, cần chỉ rõ project, thư mục repository, env file và
cả hai file `compose.lab.yaml` + image lock. `zt.cmd config-check` làm việc này
để kiểm tra cấu hình mà không xuất secret. Các lệnh `zt.cmd start/stop` vẫn thao tác
container hiện hữu, không tạo lại container. Đây là đường dẫn máy đã kiểm kê,
không phải giá trị phải sao chép sang máy khác.
Build hiện hành xem [BUILD_PIPELINE](../development/BUILD_PIPELINE.md).
Manifest `CANONICAL_COMPOSE_ENTRYPOINT.json` trong preservation và override Risk
trong `.local-legacy/risk-observation` là hồ sơ trước chuyển, không còn là entrypoint
deployment hiện hành. Nâng cấp image là tác vụ riêng, không dùng lệnh build để
tự thay image lock hoặc tái triển khai ứng dụng.

## Ranh giới runtime và dữ liệu

Lab gồm 10 dịch vụ. Cấu hình runtime được gắn chỉ đọc. Database, Redis và Risk giữ trong mạng riêng. Các cổng dành cho kiểm thử tại máy chỉ bind loopback. Bốn named volumes lưu dữ liệu. Bảng ánh xạ giữa host, container, mạng và volumes được giữ trong hồ sơ vận hành riêng. Dùng [Compose Lab](../../compose.lab.yaml) để xem hợp đồng cấu hình trong source.

## File lịch sử và file phục vụ bảo trì

| Nguồn | Trạng thái |
|---|---|
| compose.yaml | File rỗng service, yêu cầu chọn môi trường rõ ràng |
| compose.dev.yaml, scripts/demo, .env.example | Cấu hình synthetic riêng; chưa khởi động lại trong giai đoạn 3 |
| compose.build.yaml | Đầu vào công cụ build, tách khỏi runtime |
| compose.legacy.yaml | Cấu hình tích hợp/import trước đây; không dùng cho start lab hiện hành |
| compose.primary.example.yaml | Mẫu tương lai, chưa được triển khai |
| .env.legacy.example, .env.runtime.example | Mẫu/tham chiếu, không phải bí mật runtime thực |
| deploy/legacy và profile migration | Công cụ chuẩn bị/kiểm tra/chuyển dữ liệu; không chạy trong start thông thường |
| zt-release-source-20261026 | Checkout kiểm chứng phát hành cũ; có 65 mục staged tại lần kiểm kê |
| zt-release-empty-runtime-20261026 | Input kiểm chứng lịch sử; không có bind mount từ các container hiện tại |
| zerotrust-legacy-preservation | Archive/backup và runtime cũ phục vụ quay lui; container hiện tại không mount từ đây |

Không chạy `docker compose up` thiếu lựa chọn file/project/env: file mặc định
không khai báo service. Dùng bộ lệnh ở đầu tài liệu cho vận hành thường ngày.

## Kiểm chứng giai đoạn 3 — 04/11/2026

- 87 file runtime/CA/credentials được copy và đối chiếu SHA-256 thành công.
- 10 container tạo lại với image ID, lệnh chạy, env, cổng, giới hạn tài nguyên,
  healthcheck, quyền và volume mapping tương đương trước chuyển; cả 10 chưa chạy.
- Không chạy database, migration, import, nâng cấp image hoặc môi trường synthetic.
- Bốn named volumes và hai network hiện hữu được sử dụng lại; 9 bind mounts
  trỏ runtime mới. Docker Desktop có thể hiển thị đường dẫn host dạng
  `/run/desktop/mnt/host/c/...`; công cụ ops chuyển về `C:/...` để kiểm tra file.
- 29 test công cụ đạt; sáu BuildKit checks đạt. Compose dev/lab hợp lệ;
  `config-check` và `doctor` đạt, doctor chỉ có 10 cảnh báo dịch vụ chưa chạy.
- Kết quả máy đọc: `.local-legacy/phase3-runtime/verification.json`. Bản kiểm kê,
  kế hoạch và Compose quay lui chứa thông tin riêng tư, không đưa vào Git.
- Chưa kiểm thử khởi động lại ứng dụng hoặc luồng Browser/MFA trong giai đoạn này.

## Kiểm chứng giai đoạn 1 — lịch sử trước chuyển

- Kiểm kê thực tế ngày 04/11/2026: đủ 10 container lab, cả 10 đang dừng;
  xác nhận 9 bind mounts runtime, 4 named volumes và 3 cổng host cấu hình.
- 8 tests bằng Docker giả lập đạt cho kiểm tra danh tính, bảo vệ secret,
  từ chối start khi thiếu cấu hình và sai volume; không bật/tắt database để test.
  Chạy lại: `python -X utf8 -m unittest discover -s scripts/ops -p test_zt.py -v`.
- `zt.cmd doctor` và `zt.cmd status` đã chạy thực tế, exit code 0: doctor không có
  lỗi, có 10 cảnh báo stopped và 4 cảnh báo đường dẫn Compose worktree lịch sử.
  Windows chặn `.ps1` theo execution policy; wrapper `.cmd` đã kiểm chứng hoạt động.
- Start/stop/logs được kiểm tra trong phạm vi các tests nêu trên và tái sử dụng
  bộ vận hành cũ; chưa thực hiện start/stop hoặc nghiệm thu ứng dụng trong đợt này.
- Giai đoạn 2 chuẩn hóa build được mô tả trong BUILD_PIPELINE; giai đoạn 3 đã chuyển
  runtime và tách môi trường Compose. Project/volume giữ nguyên tên để bảo toàn dữ liệu.
  Không diễn giải trạng thái stopped thành Browser FAIL/PASS.
