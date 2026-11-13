# Cấp tài khoản và chuẩn bị Google Cloud private rehearsal

Ngày 11/11/2026, Asia/Saigon. Owner đã duyệt mô hình truy cập. Quy trình cấp tài khoản và các lệnh Cloud bên dưới là phần chuẩn bị, chưa được chạy. D-17 PENDING/BLOCKED, risk acceptance còn DRAFT, D-04 chờ IP/DNS/TLS, G8 Internet NO-GO. [Trạng thái chính thức](../../../docs/production-readiness/PUBLIC_DEMO_ROADMAP.md)

## 1. Mô hình truy cập đã duyệt

Sau release acceptance, trình duyệt thông thường truy cập Portal/Auth qua HTTPS công khai. Giảng viên dùng tài khoản demo riêng và Keycloak/MFA/Risk, không cần tài khoản GCP, IAP, VPN hoặc IP cố định. IAP/OS Login phục vụ operator. Portal có thể hiển thị trang đăng nhập công khai, dữ liệu/API vẫn yêu cầu JWT và quyền đúng. OIDC discovery/auth/token/logout/login-actions và resources trên Auth phải hoạt động cho browser. Keycloak `/admin`, master realm và management tiếp tục private. ADMIN/STUDENT là hai business role, khác với quyền quản trị Keycloak.

Trong private rehearsal, chỉ dùng origin loopback qua tunnel quản trị. Public overlay 443 và NGINX ACME 80 được chuẩn bị cho giai đoạn có phê duyệt riêng. [Ingress hiện có](../../public-demo/INGRESS_CONTRACT.md)

## 2. Điều đã có và khoảng trống cấp tài khoản

- `deploy/demo/fixtures.py` sinh ADMIN/STUDENT synthetic, `registrationAllowed=false`, `CONFIGURE_TOTP`, mật khẩu fixture `temporary=false`. Flow có Risk REQUIRED và OTP CONDITIONAL. Đây là hành vi fixture đã kiểm.
- RC tạo sẵn ba user, không nhận danh sách giảng viên tùy ý. `academic_demo.configure_auth` hạ `zerotrust-provisioner` xuống `query-users`. Linux driver bỏ bootstrap-admin khỏi config trước import. Vì vậy runtime Portal không phải công cụ operator cấp user, và fresh RC chưa tự cấp danh tính quản trị riêng cho operator.
- `scripts/public_demo/account_contract.py` kiểm contract, không tạo account. `KeycloakUserClient.createUser` là chức năng backend chung, dùng mật khẩu permanent và required actions TOTP/recovery. Academic public write-deny không cho dùng chức năng đó để cấp account qua Portal.
- Keycloak hỗ trợ password temporary/UPDATE_PASSWORD. Kết hợp UPDATE_PASSWORD + CONFIGURE_TOTP trên exact custom flow còn cần targeted acceptance bằng user synthetic mới, trước cấp người dùng thật. Expiry trong thuộc tính user chỉ là metadata nếu chưa có job thực thi.

[Fixtures](../../demo/fixtures.py) · [RC auth configuration](../../academic-demo/academic_demo.py) · [Linux preparation](../linux_demo.py) · [Account contract](../../public-demo/account-contract.json) · [Keycloak Admin Guide](https://www.keycloak.org/docs/latest/server_admin/index.html)

## 3. Runbook operator cấp, giao và thu hồi account

1. Chốt roster ngoài Git gồm người nhận, alias synthetic, đúng một role ADMIN hoặc STUDENT, người cấp, thời điểm bắt đầu/hết hạn và kênh giao riêng. Nếu một người cần trải nghiệm hai role, cấp hai account tách biệt có cùng owner trong roster. Không dùng account chung. Chốt D-05/D-07/D-10 về số lượng, TTL/expiry và trách nhiệm.
2. Dùng realm/stores/secrets mới trên VM rehearsal. Chuẩn bị quyền quản trị Keycloak bằng thủ tục bootstrap/recovery native trong maintenance window riêng, mọi node Keycloak của **VM rehearsal** đã dừng. Tài khoản bootstrap là tạm thời, tạo danh tính operator giới hạn quyền realm cần thiết rồi xóa tài khoản bootstrap. Runtime service clients và user demo không nhận quyền quản trị này. Lệnh cụ thể/CLI có sẵn trong DHI cần kiểm trên VM trước thao tác. [Keycloak bootstrap admin](https://www.keycloak.org/server/bootstrap-admin-recovery)
3. Operator dùng Admin CLI/REST trong Docker network private của VM rehearsal, chứng thư được xác minh tới `https://keycloak:8443`; hostname này là tên service nội bộ, không phải DNS public để mở từ laptop. Public NGINX không route Admin API. Không dùng bỏ kiểm TLS hoặc mở `/admin` qua public để thao tác. Credential operator/token chỉ lưu trong vị trí ngoài repo, thư mục0700/file0600, quyền đọc theo operator. Không truyền mật khẩu/token qua command arguments hay ghi raw response vào báo cáo.
4. Tạo user disabled, alias synthetic duy nhất, gắn đúng một realm role ADMIN/STUDENT, không cấp realm-management/service-account roles. UUID Keycloak phải ánh xạ đúng vào `users.keycloak_user_id` và user/student/score synthetic. Dùng installer riêng trong cửa sổ seed, giữ app writers dừng; tài khoản School runtime vẫn SELECT-only. Nếu bước ánh xạ lỗi thì user tiếp tục disabled. RC seed hiện chỉ có ba fixture, cần chuẩn bị input/installer cohort riêng trước mở roster lớn hơn, không ghi tay dữ liệu vào Lab.
5. Đặt mật khẩu ban đầu riêng từng người từ nguồn random bảo mật ngoài Git. Cấu hình dự kiến là password `temporary=true`, required actions `UPDATE_PASSWORD` và `CONFIGURE_TOTP`. Chỉ dùng sau khi targeted flow test đạt; nếu không tương thích thì dừng issuance và review, không bỏ MFA hoặc yêu cầu đổi mật khẩu để vượt lỗi. Recovery codes theo policy D-10 được duyệt, không tự thêm/xóa required action của user có sẵn.
6. Xác nhận role/mapping/required actions/expiry/registrationAllowed=false qua readback, rồi enable và giao URL + alias + credential qua kênh riêng đã chốt. Người nhận tự đổi password, tự enroll OTP; operator không lưu seed. Roster và dữ liệu bí mật tách khỏi báo cáo/Git. Native login-actions phải đi qua Auth ingress.
7. Nghiệm thu với ít nhất hai STUDENT và một ADMIN synthetic. Kiểm first-login password change + enrollment, OTP sai/đúng, own-data/RBAC/write-deny và logout. LOW đủ điều kiện trust/assurance tiếp tục ALLOW, MEDIUM yêu cầu step-up, HIGH DENY. Giữ mandatory enrollment, priority/missing/fail-closed, không chuyển OTP thành REQUIRED vô điều kiện trên mọi LOW login. Trusted Device chỉ hình thành theo guard và Risk registration hiện có, không suy từ việc vừa enroll OTP. SSO/refresh tiếp tục theo session policy hiện hành.
8. Khi hết hạn/thu hồi, operator disable user rồi gọi native user logout, thu hồi offline sessions nếu có và revoke trusted-device state bằng API Risk private qua đúng client/authority được cấu hình. API revocation có operation ID và trạng thái pending/completion; phải theo lifecycle/reconciliation hiện hữu, không gọi reset MFA hoặc tự cấp quyền mới cho ADMIN. Đối chiếu trạng thái trước/sau, ghi audit loại thao tác/kết quả mà không ghi secrets. JWT tự chứa có thể còn được backend chấp nhận đến `exp`; disable/logout không chứng minh access token mất hiệu lực tức thời. TTL và cửa sổ còn hiệu lực cần owner chốt trong D-10. Trường hợp cần containment tức thời có thể đóng access toàn demo theo quyền incident đã duyệt.
9. Chuẩn bị timer/job expiry trên host và một operator chịu trách nhiệm kiểm job/ack. Job phải có roster UUID/expiry rõ, quyền tối thiểu và test account synthetic; chưa có scheduler expiry trong RC hiện tại. Tới hạn kiểm disable/login/refresh/trust và giữ evidence theo retention. Sensitive ADMIN MFA reset giữ policy D-10 hiện tại, quy trình này không tự cấp thêm quyền reset.

Các native endpoint phục vụ bước trên là `POST /admin/realms/{realm}/users`, `POST .../users/{id}/role-mappings/realm`, `PUT .../users/{id}/reset-password`, `PUT .../users/{id}`, `POST .../users/{id}/logout`. Ưu tiên client hỗ trợ nhập kín/protected payload, không sao chép ví dụ chứa password literal vào shell history. [Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/index.html)

## 4. Cloud preflight chỉ đọc và sizing

**Live Cloud NOT_VERIFIED.** Máy hiện không tìm thấy `gcloud` hoặc config Cloud CLI, connector/browser được kết nối không cung cấp phiên Google Cloud. Trial $300 và budget alert500.000 VND là thông tin owner cung cấp. Project, billing linkage/credit còn lại, region/zone/quota và quyền IAM chưa được xác minh trực tiếp.

Đề xuất để owner chọn là `us-central1`, một zone còn capacity, `e2-custom-4-8192`, Ubuntu24.04 LTS amd64 thường, disk40GiB `pd-balanced`. Singapore là phương án theo độ trễ, cần báo giá riêng. Evidence local ghi RAM đỉnh khoảng1.985MiB, tổng limits4.192MiB và CPU đỉnh3,06 lõi, nên 4vCPU/8GiB có headroom cho demo nhỏ. [Capacity đã có](../../../docs/production-readiness/evidence/ACADEMIC_DEMO_RELEASE.md#capacity-local)

Ước tính tham chiếu Iowa on-demand ngày11/11/2026, chưa gồm thuế/egress/backup: CPU `4×$0.02290217/h` + RAM `8×$0.003069707/h` = **$0.116166336/h**. Disk40GiB khoảng$4/730h; IPv4 static gắn VM $0.005/h. Tổng chạy liên tục730h khoảng **$92.45**, hoặc14ngày khoảng **$42.55**. Nếu chỉ chạy40h trong14ngày, giữ disk/IP đủ14ngày, khoảng **$8.17**. Đây là phép tính tham chiếu, báo giá theo project/region/tiền tệ thực tế còn phải kiểm. [Compute](https://cloud.google.com/products/compute/pricing/general-purpose) · [Disk](https://cloud.google.com/compute/disks-image-pricing) · [IPv4](https://cloud.google.com/vpc/network-pricing)

Dừng VM tiết kiệm compute; disk và static IP vẫn phát sinh phí. IP reserved chưa gắn resource có giá$0.01/h, IP gắn VM vẫn được tính in-use khi VM dừng. Trial credit$300 có thời hạn90ngày, cần đọc ngày hết hạn/số dư thực tế trong Billing. Budget alert không phải spending cap. Build ở máy chuẩn bị rồi chuyển bundle, giới hạn cửa sổ chạy VM để tiết kiệm. [Trial](https://docs.cloud.google.com/free/docs/free-cloud-features) · [Stop/start](https://docs.cloud.google.com/compute/docs/instances/stop-start-instance)

Operator chạy các lệnh đọc sau ở Cloud Shell/CLI đã đăng nhập, điền inputs thực từ `cloud.env.example`. Không tự bật API nếu bị từ chối.

```bash
gcloud auth list --filter=status:ACTIVE --format='value(account)'
gcloud projects describe "$PROJECT_ID" --format='yaml(projectId,lifecycleState)'
gcloud billing projects describe "$PROJECT_ID" --format='yaml(billingEnabled)'
gcloud services list --enabled --project="$PROJECT_ID" --format='value(config.name)'
gcloud compute project-info describe --project="$PROJECT_ID" --format='json(quotas)'
gcloud compute regions describe "$REGION" --project="$PROJECT_ID" --format='json(status,quotas,zones)'
gcloud compute zones describe "$ZONE" --project="$PROJECT_ID" --format='yaml(status,region,availableCpuPlatforms)'
gcloud compute addresses list --project="$PROJECT_ID" --format='table(name,region,status)'
gcloud compute networks list --project="$PROJECT_ID"
gcloud compute firewall-rules list --project="$PROJECT_ID"
```

Kiểm `E2_CPUS` còn ít nhất4, global CPU quota nếu áp dụng, ít nhất1 instance/address và40GiB disk tương ứng. `zone UP`/quota đủ chưa bảo đảm cấp VM thành công. Kiểm cả firewall/hierarchical policies kế thừa và các account được phép IAP/OS Login. Billing UI mới là nguồn kiểm trial credit/expiry. Không đưa account email/billing identifier vào Git hoặc log công khai.

## 5. Kế hoạch provisioning tương lai — chưa thực thi

Các lệnh này chỉ dành cho lượt đã được owner duyệt tạo tài nguyên. Tên bên dưới là tên dự kiến, kiểm không tồn tại trước khi dùng. Project/region/zone/CIDR vẫn phải chốt. `cloud.env.example` chứa biến trống cho các giá trị chưa có.

```bash
: "${PROJECT_ID:?}" "${REGION:?}" "${ZONE:?}" "${SUBNET_CIDR:?}"
: "${NETWORK:?}" "${SUBNET:?}" "${ADDRESS_NAME:?}" "${VM_NAME:?}"
gcloud compute networks create "$NETWORK" --subnet-mode=custom --project="$PROJECT_ID"
gcloud compute networks subnets create "$SUBNET" --network="$NETWORK" --range="$SUBNET_CIDR" --region="$REGION" --project="$PROJECT_ID"
gcloud compute firewall-rules create zt-academic-iap-ssh --network="$NETWORK" --direction=INGRESS --allow=tcp:22 --source-ranges=35.235.240.0/20 --target-tags=zt-academic-iap --project="$PROJECT_ID"
gcloud compute addresses create "$ADDRESS_NAME" --region="$REGION" --ip-version=IPV4 --project="$PROJECT_ID"
STATIC_EXTERNAL_IP=$(gcloud compute addresses describe "$ADDRESS_NAME" --region="$REGION" --project="$PROJECT_ID" --format='value(address)')
gcloud compute instances create "$VM_NAME" --project="$PROJECT_ID" --zone="$ZONE" \
  --machine-type=e2-custom-4-8192 --network="$NETWORK" --subnet="$SUBNET" --address="$STATIC_EXTERNAL_IP" \
  --image-project=ubuntu-os-cloud --image-family=ubuntu-2404-lts-amd64 \
  --boot-disk-type=pd-balanced --boot-disk-size=40GB --no-boot-disk-auto-delete \
  --tags=zt-academic-iap --metadata=enable-oslogin=TRUE,block-project-ssh-keys=TRUE \
  --no-service-account --no-scopes
gcloud compute ssh "$VM_NAME" --project="$PROJECT_ID" --zone="$ZONE" --tunnel-through-iap
```

Custom VPC chỉ có IAP SSH ingress ở bước này. Không tạo rule80/443, không dùng allow-http/https tags. Egress cần cho cập nhật/pull images, static IP cho phép egress trực tiếp nên không cần Cloud NAT trả phí. VM/app chưa cần Google API nên đề xuất **không gắn service account**. Nếu sau này bật Monitoring/Logging hoặc backup GCS, cấp SA riêng với đúng vai trò/destination được duyệt. Không gắn default Editor SA.

Operator cần IAP Tunnel Resource Accessor và OS Admin Login để quản trị sudo, cùng các quyền compute read cần thiết theo scope VM. Quyền tạo network/firewall/IP/VM chỉ cấp cho principal provisioning theo phạm vi được duyệt, không cấp cho app hoặc giảng viên. IAP/OS Login external-user requirements còn tùy organization policy. [IAP](https://docs.cloud.google.com/iap/docs/using-tcp-forwarding) · [Service accounts](https://docs.cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances)

Sau khi host được duyệt, cài Docker/Compose, dependencies theo RC README và state0700/file secrets0600 mới. Cổng ứng dụng chỉ `127.0.0.1:34443`. Tunnel quản trị ví dụ `gcloud compute ssh ... --tunnel-through-iap -- -N -L 34443:127.0.0.1:34443`; browser phải dùng đúng hostname/SNI và trust rehearsal phù hợp. IAP peer IP không phải bằng chứng client IP public. Issuer/redirect/CORS phải khớp mode đang thử. Ưu tiên reuse frontend rehearsal đã khóa khi thử lane `.test`, chỉ build frontend FQDN thật sau khi IP có thật và deployment inputs đã được duyệt.

## 6. Inputs và gate còn thiếu

| Input/điều kiện | Trạng thái |
|---|---|
| Project, region/zone, quota, billing/credit/IAM live | NOT_VERIFIED. Có bộ lệnh đọc và kế hoạch, chưa có phiên Cloud để kiểm. |
| Static IP, Portal/Auth sslip.io, public TLS HTTP-01 | Chờ tài nguyên thật và scope cấp chứng chỉ/cổng80 riêng. `prepare.py` chỉ render khi có IP hợp lệ, không build frontend tự động. |
| Issuer/redirect/logout/CORS, frontend args | Có renderer/template hiện hữu. Auth URL `/realms/academic-demo`, redirect Portal `/` và `/silent-check-sso.html`, exact origin và PKCE S256. |
| Candidate images | D-14 technical PASS, D-17 risk DRAFT. Các digest trong handoff chưa được promote vào RC lock. Driver RC hiện kiểm tag/pin cũ; cần package/manifest và điều chỉnh candidate adapter được review cho host mới trước chạy candidate trên Cloud. Không dùng harness khóa Engine canonical cho Engine GCE. |
| Account issuance | Runbook đã chuẩn bị. Còn operator-private admin identity, cohort installer/mapping, UPDATE_PASSWORD+OTP test, expiry job và token-lifetime acceptance. |
| D-17/G8 | D-17 PENDING/BLOCKED, G8 Internet NO-GO. Authorization private VM là quyết định riêng với public release. Khi review waiver DRAFT, control về access cần được đối chiếu access model mới trong SSOT; không tự suy thành yêu cầu IAP/VPN cho giảng viên hoặc risk acceptance đã ký. |

## 7. Checklist nghiệm thu target

- [ ] Browser thường tin HTTPS, đúng SAN/issuer/redirect/logout/CORS và PKCE S256. Discovery/auth/token/login-actions/resources công khai đúng chức năng, `/admin`/master/management private.
- [ ] First-login password update/enrollment đạt, OTP sai/đúng, mandatory MFA, LOW ALLOW khi đủ điều kiện, MEDIUM step-up, HIGH DENY và unavailable fail-closed. Giữ SSO/refresh semantics. HIGH browser chỉ PASS khi thực sự chạy đúng fixture.
- [ ] ADMIN/STUDENT RBAC/ownership, School runtime SELECT-only, academic write API/public provisioning bị chặn. Theo dõi lại lỗi STUDENT đọc điểm lần đầu đã ghi trong handoff.
- [ ] Signup tắt, danh sách account riêng, tối thiểu quyền, brute-force/rate limits được xác minh, expiry/logout/refresh/trust và residual access-token window đã chốt.
- [ ] Cloud firewall chỉ mở dịch vụ theo stage, MySQL/Redis/Risk/Docker API không public. Kiểm direct/forged forwarded headers và canonical IP đường thật khi được phép nghiệm thu ngoài VM.
- [ ] Backup mã hóa/offsite/key custody, restore/rollback, cảnh báo và người xử lý/expiry đã nghiệm thu theo scope.

Reuse evidence local/CI đã PASS theo đúng digest. Case thay hostname/config hoặc required action phải kiểm đúng phần ảnh hưởng. G8 chỉ được review sau mandatory gates, quyền public cần quyết định riêng.
