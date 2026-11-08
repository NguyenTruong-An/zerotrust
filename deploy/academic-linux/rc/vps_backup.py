"""Back up an approved production-demo, or restore its checkpoint into fresh volumes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re

from rc import ROOT, Smoke, base, check, configure, fresh, linux, stop
from backup import REDIS_IMAGE, WRITERS, encrypt_stream
from recovery import restore

ARCHIVES=('sql.age','redis.age','state.age')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def private_path(path):
    check(path.is_absolute() and path.resolve()==path and not path.is_relative_to(ROOT),
          'Use an absolute protected path outside source')
    return path


def backup(c,project,manifest,out,recipients):
    check((c['state']/'installed').read_text()==sha(manifest),'Installed release lock mismatch')
    linux.prepare(c,linux.load_pki(c))
    check(not out.exists() and not out.is_relative_to(c['state']),'Use a new backup directory outside state')
    check(recipients.is_file() and recipients.stat().st_size<4096,'Age recipient file required')
    keys=recipients.read_text().splitlines()
    check(1<=len(keys)<=2 and all(re.fullmatch(r'age1[0-9a-z]{58}',key) for key in keys),'Invalid age recipients')
    running=set(base.compose('ps','--services','--status','running').stdout.splitlines())
    check('mysql' in running and not running&{*WRITERS,'redis','keycloak-init','mysql80','migrate','migrate80'},
          'Close ingress and quiesce writers and Redis before backup')
    ident=base.compose('ps','-q','mysql').stdout.strip()
    check(re.fullmatch(r'[a-f0-9]{12,64}',ident),'MySQL container not available')
    out.mkdir(mode=0o700)
    encrypt_stream(['docker','exec',ident,'mysqldump','--defaults-extra-file=/fixture/root.cnf',
        '--single-transaction','--set-gtid-purged=OFF','--no-tablespaces','--hex-blob','--add-drop-database',
        '--databases',*(f'pd_production_{name}' for name in ('school','risk','keycloak'))],recipients,out/'sql.age')
    encrypt_stream(['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','--user','999:999',
        '--mount',f'type=volume,source={project}_redis-data,target=/data,readonly','--entrypoint','tar',
        REDIS_IMAGE,'-C','/data','-cf','-','.'],recipients,out/'redis.age')
    encrypt_stream(['tar','-C',str(c['state']),'-cf','-','.'],recipients,out/'state.age')
    receipt={'lock_sha256':sha(manifest),'project':project,'config':linux.state_identity(c),
             'proxy_ip':c['proxy_ip'],'archives':{name:sha(out/name) for name in ARCHIVES}}
    (out/'checkpoint.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
    print('PASS encrypted checkpoint written. Keep its receipt and age identity in separate custody.')


def restore_checkpoint(c,project,manifest,checkpoint,identity):
    check(identity.is_file() and identity.stat().st_mode&0o077==0,'Age identity requires a protected file')
    receipt=json.loads((checkpoint/'checkpoint.json').read_text())
    expected=linux.state_identity(c)
    check(receipt['lock_sha256']==sha(manifest) and receipt['project']!=project
          and set(receipt['archives'])==set(ARCHIVES),'Checkpoint release or project mismatch')
    check(set(receipt['config'])==set(expected)
          and all(receipt['config'][k]==v for k,v in expected.items() if k!='core_subnet'),
          'Checkpoint requires matching hostname, HTTPS ports and schema')
    check(all(sha(checkpoint/name)==value for name,value in receipt['archives'].items()),
          'Checkpoint archive hash mismatch')
    linux.load_pki(c)
    fresh(c,project)
    try:
        restore({'proxy_ip':receipt['proxy_ip']},c,project,checkpoint,identity)
        Smoke(c).infrastructure()
        base.save('.','installed',sha(manifest))
        print('PASS isolated restore and origin smoke. Keep access closed pending operator identity checks.')
    finally:
        stop()


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('backup','restore'))
    p.add_argument('--config',required=True,type=Path)
    p.add_argument('--project',required=True)
    p.add_argument('--manifest',required=True,type=Path)
    p.add_argument('--checkpoint',required=True,type=Path)
    p.add_argument('--recipients',type=Path)
    p.add_argument('--identity',type=Path)
    a=p.parse_args()
    c,_,_,_=configure(a.config,a.manifest,a.project,allow_production=True)
    check(c['mode']=='production-demo','Use rehearsal recovery for synthetic rehearsals')
    checkpoint=private_path(a.checkpoint)
    if a.action=='backup':
        check(a.recipients is not None and a.identity is None,'Backup requires only the recipient file')
        backup(c,a.project,a.manifest,checkpoint,private_path(a.recipients))
    else:
        check(a.identity is not None and a.recipients is None,'Restore requires only the protected identity')
        restore_checkpoint(c,a.project,a.manifest,checkpoint,private_path(a.identity))


if __name__=='__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('VPS checkpoint stopped: '+(str(error) if type(error) is RuntimeError else type(error).__name__)) from None
