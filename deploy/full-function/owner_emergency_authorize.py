"""Owner private console only: one approval, two signatures binding exact recovery+extension.
Never invoked by Codex; no passphrase/key is read by the agent. No executor call.
"""
import base64
import json
import sys
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import network_v2_rollout as n
import network_v2_emergency as e
import owner_shadow_authorize as owner


def main():
    owner.old.owner_console();ctx=e.EmergencyContext();proof=ctx.preflight()
    print('EMERGENCY: khôi phục zt-full-function-20261111b BASELINE trên CURRENT schemaV7.')
    print('Risk1ec3 + Keycloak29f9; giữ dữ liệu/MFA/trust/TLS; không restore/migrate/APPLY.')
    print('Candidate Risk1068e1b1... và Keycloak7bf62848... vẫn dừng, không khởi chạy.')
    print('Descriptor emergency: '+proof['emergency_descriptor_sha256'])
    print('Descriptor parent: '+ctx.digest)
    print('Codex sẽ thực thi recovery một lần sau khi bạn tự ký; request TTL10phút.')
    owner.old.approve('RECOVER '+e.OP+' BASELINE V7')
    signer=owner.key()  # Hidden interactive passphrase, entered only by owner.
    n.legacy.owner_acl(n.ANCHOR);anchor=n.r.json_bytes(n.ANCHOR.read_bytes())
    n.need(n.sha(signer.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))==anchor['public_key_sha256'],
           'EMERGENCY_OWNER_KEY_MISMATCH')
    core_payload=n.payload(ctx.m,'recover',recover_of=e.OP,recover_target='BASELINE')
    core={'payload':core_payload,'signature':base64.b64encode(signer.sign(n.canonical(core_payload))).decode()}
    ext_payload=e.extension_payload(core,ctx.em)
    extension={'payload':ext_payload,'signature':base64.b64encode(signer.sign(n.canonical(ext_payload))).decode()}
    ctx.extension=extension;ctx.authorize(core,'recover')
    del signer
    folder=n.ANCHOR.parent/'requests';folder.mkdir(exist_ok=True);owner.old.secure(folder)
    path=folder/('emergency-recover-'+core_payload['id']+'.json')
    n.need(not path.exists(),'EMERGENCY_REQUEST_EXISTS_NO_OVERWRITE')
    owner.old.x.jwrite(path,{'request':core,'extension':extension});owner.old.secure(path)
    pointer=n.ANCHOR.parent/'latest-emergency-recover.path'
    owner.old.x.atomic(pointer,(str(path)+'\n').encode());owner.old.secure(pointer)
    print('Đã ký request mới. Không thay anchor/journal/runtime. Codex có thể tiếp tục từ pointer local.')


if __name__=='__main__':
    if hasattr(sys.stdout,'reconfigure'):sys.stdout.reconfigure(encoding='utf-8')
    try:main()
    except (KeyboardInterrupt,EOFError):print('Đã dừng; chưa tự recovery.');raise SystemExit(1)
    except Exception as error:
        print('REJECTED: '+(str(error) if isinstance(error,n.r.Rejected) else type(error).__name__));raise SystemExit(1)
