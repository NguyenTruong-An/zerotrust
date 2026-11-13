# GCP fast-track — fresh D-10 strict (V9) full-function

Profile cài **mới hoàn toàn** bản full-function DoAn ở trạng thái D-10 strict (schema V1→V9, B0 live, Network v2 SHADOW) cho VM `zt-academic-private` với hostname `portal/auth.35.253.233.81.sslip.io`. Quyết định owner và rủi ro chấp nhận: [GCP_FAST_TRACK](../../docs/production-readiness/GCP_FAST_TRACK.md).

## Nguyên tắc

- CA nội bộ, realm DoAn, mật khẩu DB, client secret, tài khoản synthetic **sinh mới trên máy đích** (`gcp.py install`). Không copy dữ liệu, secret hay volume từ Lab hoặc runtime local.
- Image: 4 image D-10 đã seal (`binding.phase3.json`) + frontend build lại cho hostname GCP + migrator V1–V5 `zt-pd-r22/risk:rc1` (checksum V5 `661092940`). V6–V9 chạy bằng migrator candidate đã dùng trong cutover local.
- Ingress chỉ publish `127.0.0.1:<loopback_port>`; mở 443 là bước riêng cần owner duyệt.
- Helper `native_admin`/`native_acceptance` đã seal được chạy qua `adapt.py`: chỉ thay 2 origin `*.full-function.test:39443` bằng origin sslip trong bộ nhớ, không sửa file seal.

## Lệnh

```bash
python3 deploy/gcp-fast-track/build_frontend.py --config <cfg>.json   # build frontend cho hostname
python3 deploy/gcp-fast-track/gcp.py validate --config <cfg>.json      # read-only: image/ownership/network
python3 deploy/gcp-fast-track/gcp.py install  --config <cfg>.json      # fresh V1->V9 + realm + strict provisioning
python3 deploy/gcp-fast-track/gcp.py accept   --config <cfg>.json      # 14 native strict cases + B0/SHADOW, chạy một lần
python3 deploy/gcp-fast-track/gcp.py status   --config <cfg>.json
```

`rehearsal.json` là lane disposable trên máy local (`destroy-rehearsal` chỉ dùng cho lane này).

## Giới hạn đã biết

- CA nội bộ 30 ngày, leaf 14 ngày, **CRL 7 ngày** (theo generator full-function). Demo dài hơn 7 ngày cần phát hành lại CRL trước hạn, nếu không các kiểm tra revocation sẽ fail-closed.
- `accept` xóa client bootstrap tạm thời ở cuối, nên chỉ chạy được một lần cho mỗi lần cài.
- VM cần: Docker Engine + Compose plugin, Python 3.11+ với `cryptography`, `keytool` (OpenJDK 17).
