"""Owner-operated private console only. Reuse the owner's encrypted key, never the old anchor/packet."""
import argparse,base64,getpass,json,sys,time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key,Encoding,PublicFormat
import owner_authorize as old
import network_v2_rollout as n

def key():
    old.owner_console();old.c.owner_acl(old.KEY)
    password=getpass.getpass('Passphrase key owner hiện có (không hiện): ')
    try:value=load_pem_private_key(old.KEY.read_bytes(),password.encode())
    except Exception:raise n.r.Rejected('SHADOW_OWNER_KEY_UNLOCK_FAILED') from None
    finally:del password
    n.need(isinstance(value,Ed25519PrivateKey),'SHADOW_OWNER_KEY_TYPE');return value

def review():
    m=n.descriptor();print('Project: '+n.PROJECT)
    print('Descriptor SHA256: '+n.r.sha_file(n.DESCRIPTOR));print('Packet SHA256: '+n.r.sha_file(n.PACKET))
    print('Binding revision3; new owner anchor: '+str(n.ANCHOR))
    print('Historical v1/v2 state/journals/anchors remain unchanged; enrol v3, never reuse historical requests.')
    for role,image in n.NEW.items():print(role+': '+image)
    print('Keycloak core26.8.2; SHADOW only; retention disabled; validated V7 no-op, no DDL/DB restore/public/waiver.')
    return m

def setup():
    old.owner_console();m=review();n.Context().validate(True)
    n.need(not n.ANCHOR.exists(),'SHADOW_ANCHOR_EXISTS_NO_OVERWRITE')
    old.approve('ENROL NETWORK V2 BACKUP RESTORE ONLY')
    signer=key();public=signer.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    n.ANCHOR.parent.mkdir(parents=True,exist_ok=True);old.secure(n.ANCHOR.parent)
    anchor={'kind':'OWNER_CONTROLLED_NETWORK_V2_SHADOW_ONLY','project':n.PROJECT,'owner_sid':m['owner_sid'],'issuer':n.ISSUER,
            'descriptor_sha256':n.r.sha_file(n.DESCRIPTOR),'packet_sha256':n.r.sha_file(n.PACKET),
            'operations':['backup-only','restore-verify'],'expires':int(time.time())+6*3600,
            'public_key':base64.b64encode(public).decode(),'public_key_sha256':n.sha(public)}
    old.x.jwrite(n.ANCHOR,anchor);old.secure(n.ANCHOR);old.c.owner_acl(n.ANCHOR)
    print('Anchor mới đã enrol. Old key/anchor/packet không đổi; chưa ký hoặc execute operation.')

def scope(checkpoint,renew=False):
    old.owner_console();review();ctx=n.Context();old.c.owner_acl(n.ANCHOR);anchor=n.r.json_bytes(n.ANCHOR.read_bytes())
    n.need(anchor['descriptor_sha256']==ctx.digest and anchor['packet_sha256']==n.r.sha_file(n.PACKET),'SHADOW_ANCHOR_REVIEW_REQUIRED')
    if not renew:ctx.executor.load_checkpoint(checkpoint,True)
    print('Mỗi apply/restart/rollback/recover vẫn cần chữ ký riêng. Recover BASELINE cho phép trả cả hai image về baseline, giữ CURRENT DB/schema.')
    old.approve('RENEW NETWORK V2 SCOPE' if renew else 'AUTHORIZE NETWORK V2 CUTOVER SIGNING')
    signer=key();n.need(n.sha(signer.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))==anchor['public_key_sha256'],'SHADOW_OWNER_KEY_MISMATCH')
    if not renew:anchor['operations']=list(n.OPERATIONS)
    anchor['expires']=int(time.time())+6*3600;old.x.jwrite(n.ANCHOR,anchor);old.secure(n.ANCHOR)
    print('Signing scope cập nhật; không ký hoặc execute.')

def sign(operation,checkpoint,recover_of,recover_target):
    old.owner_console();review();ctx=n.Context()
    if operation=='apply':ctx.candidate_preflight()
    if operation in ('apply','restore-verify'):
        cp=ctx.executor.load_checkpoint(checkpoint,operation=='apply')
        n.need(time.time()-cp['created']<1800,'SHADOW_CHECKPOINT_EXPIRED_NEW_BACKUP_REQUIRED')
    if operation=='apply':n.need(time.time()-cp['created']<1200,'SHADOW_RESERVE_TEN_MINUTES_FOR_APPLY_GET_FRESH_BACKUP')
    old.approve('SIGN NETWORK V2 '+operation.upper()+(' '+recover_target if recover_target else ''))
    signer=key();anchor=n.r.json_bytes(n.ANCHOR.read_bytes())
    n.need(n.sha(signer.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))==anchor['public_key_sha256'],'SHADOW_OWNER_KEY_MISMATCH')
    p=n.payload(ctx.m,operation,checkpoint,recover_of,recover_target)
    envelope={'payload':p,'signature':base64.b64encode(signer.sign(n.canonical(p))).decode()};ctx.authorize(envelope,operation)
    folder=n.ANCHOR.parent/'requests';folder.mkdir(exist_ok=True);old.secure(folder)
    path=folder/(operation+'-'+p['id']+'.json');n.need(not path.exists(),'SHADOW_REQUEST_COLLISION')
    old.x.jwrite(path,envelope);old.secure(path)
    pointer=n.ANCHOR.parent/('latest-'+operation+'.path');old.x.atomic(pointer,(str(path)+'\n').encode());old.secure(pointer)
    print('Đã ký một request, TTL10phút; chưa execute. Pointer: '+str(pointer))

def scope_recovery(recover_of,recover_target):
    """Owner can authorize recovery signing without a nonexistent checkpoint.

    This grants no APPLY/restart and never signs or executes a recovery. BASELINE
    still requires rollback scope in the unchanged request verifier.
    """
    old.owner_console();review();ctx=n.Context();ctx.validate(False)
    pending=ctx.executor.unfinished()
    target=next((j for j in pending if j['id']==recover_of),None)
    n.need(target is not None and target['manifest']==ctx.digest,'SHADOW_RECOVERY_EXACT_PENDING_OPERATION_REQUIRED')
    old.c.owner_acl(n.ANCHOR);anchor=n.r.json_bytes(n.ANCHOR.read_bytes())
    n.need(anchor.get('kind')=='OWNER_CONTROLLED_NETWORK_V2_SHADOW_ONLY' and anchor.get('project')==n.PROJECT
           and anchor.get('owner_sid')==ctx.m['owner_sid'] and anchor.get('issuer')==n.ISSUER
           and anchor.get('descriptor_sha256')==ctx.digest and anchor.get('packet_sha256')==n.r.sha_file(n.PACKET),
           'SHADOW_ANCHOR_REVIEW_REQUIRED')
    old.approve('AUTHORIZE NETWORK V2 RECOVERY '+recover_of+' '+recover_target)
    signer=key();n.need(n.sha(signer.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))==anchor['public_key_sha256'],'SHADOW_OWNER_KEY_MISMATCH')
    operations=set(anchor['operations']);n.need(operations<=set(n.OPERATIONS),'SHADOW_UNKNOWN_SIGNING_SCOPE')
    operations.add('recover')
    if recover_target=='BASELINE':operations.add('rollback')
    anchor['operations']=sorted(operations);anchor['expires']=int(time.time())+6*3600
    # Stop if a different operation completed/changed while the owner was reviewing.
    n.need(target in ctx.executor.unfinished(),'SHADOW_RECOVERY_PENDING_CHANGED')
    old.x.jwrite(n.ANCHOR,anchor);old.secure(n.ANCHOR);old.c.owner_acl(n.ANCHOR)
    print('Owner recovery signing scope updated; no request signed or operation executed.')

def main():
    p=argparse.ArgumentParser(description=__doc__);s=p.add_subparsers(dest='action',required=True)
    s.add_parser('review');s.add_parser('setup');s.add_parser('renew')
    t=s.add_parser('scope-cutover');t.add_argument('--checkpoint',required=True)
    t=s.add_parser('scope-recovery');t.add_argument('--recover-of',required=True);t.add_argument('--recover-target',required=True,choices=('BASELINE','SHADOW','STOPPED'))
    t=s.add_parser('sign');t.add_argument('operation',choices=n.OPERATIONS);t.add_argument('--checkpoint');t.add_argument('--recover-of');t.add_argument('--recover-target',choices=('BASELINE','SHADOW','STOPPED'))
    a=p.parse_args()
    if a.action=='review':review()
    elif a.action=='setup':setup()
    elif a.action=='renew':scope(None,True)
    elif a.action=='scope-cutover':scope(a.checkpoint)
    elif a.action=='scope-recovery':scope_recovery(a.recover_of,a.recover_target)
    else:sign(a.operation,a.checkpoint,a.recover_of,a.recover_target)

if __name__=='__main__':
    if hasattr(sys.stdout,'reconfigure'):sys.stdout.reconfigure(encoding='utf-8')
    try:main()
    except (KeyboardInterrupt,EOFError):print('Dừng, không tự execute.');raise SystemExit(1)
    except Exception as error:print('REJECTED: '+(str(error) if isinstance(error,n.r.Rejected) else type(error).__name__));raise SystemExit(1)
