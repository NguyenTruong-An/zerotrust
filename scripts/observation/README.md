# Quan sát Risk/MFA trong lab

Tại root repository:

```powershell
.\scripts\observation\Observe-Risk.cmd --watch-seconds 5 --open
```

Xem dữ liệu minh họa riêng:

```powershell
.\scripts\observation\Observe-Risk.cmd --demo --open
```

[Hướng dẫn đầy đủ](../../docs/testing/RISK_OBSERVATORY.md): nguồn tín hiệu,
ghép mã, trạng thái thiếu bằng chứng, runtime và bảo vệ dữ liệu.
Cần Python 3.11+; dùng thư viện chuẩn. Báo cáo mặc định ở `.local-legacy/`,
không có web server/API mới và không ghi raw logs.

Nếu PowerShell báo `running scripts is disabled` với file `.ps1`, dùng lệnh
`.cmd` trên hoặc Python trực tiếp; không cần đổi Execution Policy:

```powershell
python -X utf8 scripts/observation/observe.py --watch-seconds 5 --open
```
