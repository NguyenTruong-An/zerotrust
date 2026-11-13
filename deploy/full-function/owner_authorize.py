"""OWNER-EXECUTED ONLY: enrol encrypted Ed25519 key, then sign one scoped request.

No executor invocation. Setup grants backup/restore signing scope only; cutover
scope/signing require separate owner review/confirmation. Do not run setup/scope/
sign from Codex, redirected input, automation or a transcript. Private material
is written only outside Git under the fixed owner root; never printed.
"""
import argparse
import base64
import getpass
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (Encoding,PrivateFormat,PublicFormat,
    BestAvailableEncryption,load_pem_private_key)
import promotion_context as c
import promotion_executor as x
import risk_promotion as r

DESCRIPTOR_SHA='50f92863d913eb30199d2f1aebde8204a3520c3c43bb3d85d65b8fed7f497b2d'
PACKET_SHA='f94c9d96c7b2b650d5e375ad99b4eaa08f4ed026d333e9152ffe5b781ce304d3'
OWNER_ROOT=c.OWNER_ANCHOR.parent
KEY=OWNER_ROOT/'signing-key.pem'
ALLOWED=('backup-only','restore-verify')
CUTOVER=('apply','restart','rollback','recover')


def frozen():
    r.need(r.sha_file(c.DESCRIPTOR)==DESCRIPTOR_SHA and r.sha_file(c.PACKET)==PACKET_SHA,'REVIEWED_ARTIFACT_HASH_MISMATCH')
    m=r.json_bytes(c.DESCRIPTOR.read_bytes())
    r.need(m['owner_sid']==c.current_sid(),'WRONG_WINDOWS_OWNER')
    r.need(all(r.sha_file(c.HERE/p)==sha for p,sha in m['implementation_sha256'].items()),'FROZEN_CONTROLLER_CODE_DRIFT')
    return m


def owner_console():
    r.need(sys.stdin.isatty() and sys.stdout.isatty(),'OWNER_MUST_RUN_IN_PRIVATE_INTERACTIVE_TERMINAL')


def approve(words):
    owner_console()
    r.need(input('Gõ chính xác '+words+' để đồng ý: ').strip()==words,'OWNER_DID_NOT_CONFIRM')


def secure(path):
    r.need(os.name=='nt' and not path.is_symlink(),'WINDOWS_OWNER_PATH_REQUIRED')
    sid=c.current_sid();rights='(OI)(CI)F' if path.is_dir() else 'F'
    p=subprocess.run(['icacls',str(path),'/inheritance:r','/grant:r','*'+sid+':'+rights,'*S-1-5-18:'+rights],capture_output=True)
    r.need(p.returncode==0,'OWNER_PATH_ACL_FAILED')


def binding_review(operation=None,checkpoint=None,cutover=False):
    print('Project: '+r.PROJECT)
    print('Descriptor SHA256: '+DESCRIPTOR_SHA)
    print('Packet SHA256: '+PACKET_SHA)
    print('Chỉ recovery signing scope; không APPLY/restart/rollback, không tự execute.' if cutover=='recovery' else
          'Cutover signing scope: apply/restart/rollback/recover; mỗi operation cần xác nhận riêng, không tự execute.' if cutover
          else 'Chỉ backup-only / restore-verify. Không APPLY, reset MFA, đổi image hoặc public access.')
    if operation:
        print('Operation: '+operation)
        if checkpoint:print('Checkpoint: '+checkpoint)


def setup():
    owner_console();m=frozen();binding_review()
    r.need(not KEY.exists() and not c.OWNER_ANCHOR.exists(),'OWNER_KEY_OR_ANCHOR_ALREADY_EXISTS_NO_OVERWRITE')
    r.need(not c.ACTIVE_PRIVATE.exists(),'ACTIVE_STATE_ALREADY_EXISTS_REVIEW_OWNER_ENROLLMENT')
    print('Key mã hóa PKCS8, ngoài Git; ACL chỉ Windows owner + SYSTEM. Anchor hiệu lực 6 giờ.')
    approve('ENROL BACKUP RESTORE ONLY')
    first=getpass.getpass('Passphrase mới (ít nhất 12 ký tự, không hiện): ')
    second=getpass.getpass('Nhập lại passphrase: ')
    r.need(first==second and len(first)>=12,'PASSPHRASE_MISMATCH_OR_TOO_SHORT')
    key=Ed25519PrivateKey.generate()
    encrypted=key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,BestAvailableEncryption(first.encode('utf-8')))
    del first,second
    r.need(not OWNER_ROOT.is_symlink() and not OWNER_ROOT.parent.is_symlink(),'OWNER_ROOT_LINK_REJECTED')
    OWNER_ROOT.mkdir(parents=True,exist_ok=True);secure(OWNER_ROOT)
    x.atomic(KEY,encrypted);secure(KEY);c.owner_acl(KEY)
    pub=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    anchor={'kind':'OWNER_CONTROLLED_ACTIVE_ONLY','project':r.PROJECT,'owner_sid':m['owner_sid'],
        'issuer':'OWNER_EXPLICIT_ACTIVE_AUTHORIZATION','descriptor_sha256':DESCRIPTOR_SHA,'packet_sha256':PACKET_SHA,
        'expires':int(time.time())+6*3600,'operations':list(ALLOWED),'public_key':base64.b64encode(pub).decode(),
        'public_key_sha256':r.sha(pub)}
    x.jwrite(c.OWNER_ANCHOR,anchor);secure(c.OWNER_ANCHOR);c.owner_acl(c.OWNER_ANCHOR)
    print('Đã enrol. Không có active operation nào được ký hoặc chạy. Giữ passphrase riêng; không gửi chat.')


def payload(m,operation,checkpoint=None,now=None,ident=None):
    r.need(operation in ALLOWED,'OWNER_HELPER_OPERATION_OUT_OF_SCOPE')
    if operation=='restore-verify':
        r.need(type(checkpoint) is str and re.fullmatch('[0-9a-f]{32}',checkpoint) is not None,'EXACT_CHECKPOINT_ID_REQUIRED')
    else:r.need(checkpoint is None,'BACKUP_REQUEST_MUST_NOT_REFERENCE_CHECKPOINT')
    now=int(time.time()) if now is None else now
    return {'id':ident or uuid.uuid4().hex,'project':r.PROJECT,'operation':operation,'descriptor_sha256':DESCRIPTOR_SHA,
        'packet_sha256':PACKET_SHA,'old_image':r.OLD,'new_image':r.NEW,'config_sha256':r.sha(c.canonical(m['proposed'])),
        'dataset_sha256':r.sha(c.canonical(m['geoip'])),'policy_sha256':r.sha(c.canonical(m['policy'])),
        'maintenance':list(x.WRITERS),'checkpoint':checkpoint,'checkpoint_rules_sha256':r.sha(c.canonical(m['checkpoint_rules'])),
        'rollback':r.OLD,'issued':now,'expires':now+600,'issuer':'OWNER_EXPLICIT_ACTIVE_AUTHORIZATION',
        'owner_sid':m['owner_sid'],'recover_of':None,'recover_target':None}


def sign(operation,checkpoint):
    owner_console();m=frozen()
    ctx=c.Context('active');ctx.preflight()  # read-only admission checks, never initializes active state
    anchor=c.load_owner_anchor()
    r.need(set(anchor['operations'])==set(ALLOWED),'OWNER_ANCHOR_SCOPE_CHANGED')
    if operation=='restore-verify':
        r.need(type(checkpoint) is str and re.fullmatch('[0-9a-f]{32}',checkpoint) is not None,'EXACT_CHECKPOINT_ID_REQUIRED')
        cp=ctx.engine.load_checkpoint(checkpoint)
        r.need(not cp['restore_verified'],'CHECKPOINT_ALREADY_RESTORE_VERIFIED_NO_REPEAT')
        r.need(time.time()-cp['created']<1800,'CHECKPOINT_TOO_OLD_FOR_FAST_TRACK_APPLY')
    pointer=OWNER_ROOT/('latest-'+operation+'.path')
    if pointer.exists():
        oldpath=Path(pointer.read_text().strip())
        r.need(oldpath.parent==OWNER_ROOT/'requests','OWNER_REQUEST_POINTER_OUT_OF_SCOPE')
        if oldpath.is_file():
            old=r.json_bytes(oldpath.read_bytes())['payload']
            used=(c.ACTIVE_PRIVATE/'used'/(old['id']+'.json')).exists()
            r.need(used or old['expires']<=time.time(),'PREVIOUS_SIGNED_REQUEST_STILL_PENDING_USE_OR_WAIT_EXPIRY')
    binding_review(operation,checkpoint)
    if operation=='backup-only':print('Cho phép tạm dừng owned writers, encrypted consistent checkpoint và verified resume; không APPLY.')
    else:print('Chỉ restore-verify sang storage disposable mới, không import vào active databases.')
    approve('SIGN '+operation.upper())
    c.owner_acl(KEY)
    secret=getpass.getpass('Passphrase key (không hiện): ')
    try:key=load_pem_private_key(KEY.read_bytes(),secret.encode('utf-8'))
    except Exception:raise r.Rejected('OWNER_KEY_UNLOCK_FAILED') from None
    finally:del secret
    r.need(isinstance(key,Ed25519PrivateKey),'OWNER_KEY_IS_NOT_ED25519')
    pub=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    r.need(r.sha(pub)==anchor['public_key_sha256'],'PRIVATE_KEY_DOES_NOT_MATCH_OWNER_ANCHOR')
    p=payload(m,operation,checkpoint)
    envelope={'payload':p,'signature':base64.b64encode(key.sign(c.canonical(p))).decode()}
    ctx.authorize(envelope,operation)  # verifies signature/bindings; does not consume or execute
    requests=OWNER_ROOT/'requests';requests.mkdir(exist_ok=True);secure(requests)
    request=requests/(operation+'-'+p['id']+'.json')
    x.jwrite(request,envelope);secure(request)
    x.atomic(pointer,(str(request)+'\n').encode());secure(pointer)
    print('Đã ký request một lần, hết hạn sau 10 phút; chưa thực thi.')
    print('Request path: '+str(request))
    print('Pointer: '+str(pointer))


def cutover_payload(m,operation,checkpoint=None,recover_of=None,recover_target=None,now=None):
    r.need(operation in CUTOVER,'CUTOVER_OPERATION_OUT_OF_SCOPE')
    p=payload(m,'backup-only',now=now)
    if operation=='apply':
        r.need(type(checkpoint) is str and re.fullmatch('[0-9a-f]{32}',checkpoint) is not None,'EXACT_CHECKPOINT_ID_REQUIRED')
    else:r.need(checkpoint is None,'UNEXPECTED_CUTOVER_CHECKPOINT')
    if operation=='recover':
        r.need(type(recover_of) is str and re.fullmatch('[0-9a-f]{32}',recover_of) is not None,'EXACT_INTERRUPTED_OPERATION_ID_REQUIRED')
        r.need(recover_target in ('BASELINE','PROMOTED','STOPPED'),'EXPLICIT_RECOVERY_TARGET_REQUIRED')
    else:r.need(recover_of is None and recover_target is None,'UNEXPECTED_RECOVERY_SCOPE')
    p.update(operation=operation,checkpoint=checkpoint,recover_of=recover_of,recover_target=recover_target)
    return p


def reviewed_checkpoint(ctx,checkpoint):
    r.need(type(checkpoint) is str and re.fullmatch('[0-9a-f]{32}',checkpoint) is not None,'EXACT_CHECKPOINT_ID_REQUIRED')
    cp=ctx.engine.load_checkpoint(checkpoint,True)
    # Additional owner-runbook buffer; the frozen engine limit remains1800s.
    r.need(time.time()-cp['created']<1200,'LESS_THAN_10_MIN_CHECKPOINT_MARGIN_STOP_AND_REVIEW')
    return cp


def scope(mode,checkpoint):
    owner_console();frozen();ctx=c.Context('active')
    if mode=='recovery':
        ctx.engine.validate();r.need(bool(ctx.engine.unfinished()),'NO_INTERRUPTED_OPERATION_FOR_RECOVERY_SCOPE')
    elif mode=='backup':ctx.preflight()
    else:
        status=ctx.engine.validate();r.need(not ctx.engine.unfinished(),'RESOLVE_PENDING_OPERATION_BEFORE_CUTOVER_SCOPE')
        if status['mode']=='BASELINE':ctx.preflight();reviewed_checkpoint(ctx,checkpoint)
        else:r.need(status['mode']=='PROMOTED' and checkpoint is None,'KNOWN_PROMOTED_STATE_REQUIRED_FOR_POST_CUTOVER_SCOPE')
    anchor=c.load_owner_anchor()
    if mode!='cutover':r.need(checkpoint is None,'BACKUP_OR_RECOVERY_SCOPE_HAS_NO_CHECKPOINT')
    binding_review(checkpoint=checkpoint,cutover='recovery' if mode=='recovery' else mode=='cutover')
    print('Chỉ đổi owner allowlist/expiry ngoài Git, không ký hoặc thực thi operation.')
    words={'cutover':'ALLOW CUTOVER REQUESTS','backup':'ALLOW BACKUP RESTORE REQUESTS','recovery':'ALLOW RECOVERY REQUESTS'}
    approve(words[mode])
    anchor.update(operations=list(CUTOVER if mode=='cutover' else ('recover',) if mode=='recovery' else ALLOWED),expires=int(time.time())+6*3600)
    x.jwrite(c.OWNER_ANCHOR,anchor);secure(c.OWNER_ANCHOR);c.owner_acl(c.OWNER_ANCHOR)
    print('Đã cập nhật owner signing scope; chưa ký/chạy operation nào.')


def sign_cutover(operation,checkpoint,recover_of,recover_target):
    owner_console();m=frozen();ctx=c.Context('active');anchor=c.load_owner_anchor()
    r.need(set(anchor['operations'])==set(CUTOVER) or operation=='recover' and set(anchor['operations'])=={'recover'},'CUTOVER_SIGNING_SCOPE_NOT_AUTHORIZED')
    cutover_payload(m,operation,checkpoint,recover_of,recover_target)  # shape only
    if operation=='apply':ctx.preflight();reviewed_checkpoint(ctx,checkpoint)
    elif operation in ('restart','rollback'):
        status=ctx.engine.validate()
        r.need(not ctx.engine.unfinished() and status['mode']=='PROMOTED','KNOWN_COMMITTED_PROMOTED_STATE_REQUIRED')
        if operation=='rollback':
            r.need(all(v['running'] for v in status['runtime'].values()),'ROLLBACK_RUNNING_INTENT_NOT_VERIFIED_STOP_FOR_REVIEW')
    else:
        ctx.engine.validate()
        j=ctx.module.sealed_read(ctx.engine.journal(recover_of))
        r.need(j['status']=='RUNNING' and j['manifest']==ctx.digest,'NO_MATCHING_INTERRUPTED_OPERATION')
        current=ctx.engine.state()
        if j['operation']=='apply':
            committed=current['mode']=='PROMOTED' and current.get('operation')==j['id']
            r.need(recover_target==('PROMOTED' if committed else 'BASELINE'),'APPLY_RECOVERY_TARGET_DOES_NOT_MATCH_COMMIT')
        if j['operation']=='rollback' and current['mode']=='BASELINE' and current.get('operation')==j['id']:
            r.need(recover_target=='BASELINE','COMMITTED_ROLLBACK_REQUIRES_BASELINE_RECOVERY')
        if j['operation'] in ('backup-only','restore-verify','restart','stop'):
            r.need(recover_target==j['before']['mode'] or recover_target=='STOPPED' and j['operation'] in ('backup-only','restart','stop'),
                   'RECOVERY_TARGET_DOES_NOT_MATCH_ORIGINAL_STATE')
        if recover_target=='STOPPED':r.need(j['operation'] in ('backup-only','restart','stop'),'STOPPED_RECOVERY_NOT_ALLOWED_FOR_THIS_OPERATION')
        print('Interrupted operation: '+j['operation']+' / '+j['stage']+'; requested target: '+recover_target)
    pointer=OWNER_ROOT/('latest-'+operation+'.path')
    if pointer.exists():
        oldpath=Path(pointer.read_text().strip());r.need(oldpath.parent==OWNER_ROOT/'requests','OWNER_REQUEST_POINTER_OUT_OF_SCOPE')
        if oldpath.is_file():
            old=r.json_bytes(oldpath.read_bytes())['payload']
            r.need((c.ACTIVE_PRIVATE/'used'/(old['id']+'.json')).exists() or old['expires']<=time.time(),
                   'PREVIOUS_SIGNED_REQUEST_STILL_PENDING_USE_OR_WAIT_EXPIRY')
    binding_review(operation,checkpoint,cutover='recovery' if set(anchor['operations'])=={'recover'} else True)
    print('OLD: '+r.OLD+'\nNEW: '+r.NEW+'\nRollback/recovery giữ CURRENT DB/Redis; không restore snapshot.')
    approve('SIGN '+operation.upper())
    c.owner_acl(KEY);secret=getpass.getpass('Passphrase key (không hiện): ')
    try:key=load_pem_private_key(KEY.read_bytes(),secret.encode('utf-8'))
    except Exception:raise r.Rejected('OWNER_KEY_UNLOCK_FAILED') from None
    finally:del secret
    r.need(isinstance(key,Ed25519PrivateKey),'OWNER_KEY_IS_NOT_ED25519')
    pub=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    r.need(r.sha(pub)==anchor['public_key_sha256'],'PRIVATE_KEY_DOES_NOT_MATCH_OWNER_ANCHOR')
    if operation=='apply':reviewed_checkpoint(ctx,checkpoint)  # recheck after owner review/password
    p=cutover_payload(m,operation,checkpoint,recover_of,recover_target)
    envelope={'payload':p,'signature':base64.b64encode(key.sign(c.canonical(p))).decode()}
    ctx.authorize(envelope,operation)
    requests=OWNER_ROOT/'requests';requests.mkdir(exist_ok=True);secure(requests)
    request=requests/(operation+'-'+p['id']+'.json');x.jwrite(request,envelope);secure(request)
    x.atomic(pointer,(str(request)+'\n').encode());secure(pointer)
    print('Đã ký request một lần, hết hạn sau10phút; chưa execute. Request path: '+str(request))


def main():
    a=argparse.ArgumentParser(description=__doc__);sub=a.add_subparsers(dest='action',required=True)
    sub.add_parser('review');sub.add_parser('setup')
    s=sub.add_parser('sign');s.add_argument('operation',choices=ALLOWED);s.add_argument('--checkpoint')
    s=sub.add_parser('scope');s.add_argument('mode',choices=('backup','cutover','recovery'));s.add_argument('--checkpoint')
    s=sub.add_parser('sign-cutover');s.add_argument('operation',choices=CUTOVER);s.add_argument('--checkpoint')
    s.add_argument('--recover-of');s.add_argument('--recover-target',choices=('BASELINE','PROMOTED','STOPPED'))
    args=a.parse_args()
    if args.action=='review':frozen();binding_review();print('Read-only. Không tạo key, anchor hoặc request.')
    elif args.action=='setup':setup()
    elif args.action=='scope':scope(args.mode,args.checkpoint)
    elif args.action=='sign-cutover':sign_cutover(args.operation,args.checkpoint,args.recover_of,args.recover_target)
    else:sign(args.operation,args.checkpoint)


if __name__=='__main__':
    # Windows redirected stdout can default to a legacy code page. Key input
    # still uses getpass; only public prompts/metadata go through these streams.
    if hasattr(sys.stdout,'reconfigure'):sys.stdout.reconfigure(encoding='utf-8')
    if hasattr(sys.stderr,'reconfigure'):sys.stderr.reconfigure(encoding='utf-8')
    try:main()
    except (KeyboardInterrupt,EOFError):print('Đã dừng; không tự thực thi active operation.');raise SystemExit(1)
    except Exception as exc:
        print('REJECTED: '+(str(exc) if type(exc) is r.Rejected else type(exc).__name__));raise SystemExit(1)
