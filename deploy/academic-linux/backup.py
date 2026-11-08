"""Create encrypted SQL and Redis backups for the verified Linux Academic Demo project."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

from linux_demo import HEALTHY, PROJECT, ROOT, activate, base, check, compose_contract, load_config, read_lock

REDIS_IMAGE='redis@sha256:ec1c2d3603c3d7d65b153bedda0248b641aa3bd7684503406b27b9e870ac0796'
WRITERS=('ingress','gateway','backend','risk','keycloak')


def encrypt_stream(command, recipients, destination):
    destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    check(not destination.exists(),'Backup already exists')
    with tempfile.NamedTemporaryFile(prefix='.encrypt-',dir=destination.parent) as output:
        with subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL) as source:
            try:
                p=subprocess.run(['age','-R',str(recipients)],stdin=source.stdout,stdout=output,
                                 stderr=subprocess.DEVNULL,timeout=240)
            finally:
                source.stdout.close()
                if source.poll() is None:
                    try:
                        source.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        source.terminate()
            check(p.returncode==0 and source.wait(timeout=10)==0,'Backup stream failed')
        output.flush()
        os.fsync(output.fileno())
        os.link(output.name,destination)
    with destination.open('rb') as f:
        print(destination.name,hashlib.file_digest(f,'sha256').hexdigest(),flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',required=True,type=Path)
    p.add_argument('--manifest',required=True,type=Path)
    p.add_argument('--recipients',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--rehearse',action='store_true',help='Quiesce and restart only the isolated rehearsal stack')
    a=p.parse_args()
    c=load_config(a.config)
    activate(c)
    compose_contract(c)
    base.verify_boundary()
    read_lock(c,a.manifest)
    check((c['state']/'installed').is_file(),'Profile not installed')
    out=a.output.absolute()
    check(out.resolve()==out and not out.exists() and not out.is_relative_to(ROOT)
          and not out.is_relative_to(c['state']),'Use a new encrypted backup directory outside source and runtime state')
    check(a.recipients.is_file() and a.recipients.stat().st_size<4096,'Age recipient file required')
    values=a.recipients.read_text().splitlines()
    check(1<=len(values)<=2 and all(re.fullmatch(r'age1[0-9a-z]{58}',v) for v in values),'Invalid age recipients')
    check(not a.rehearse or c['mode']=='rehearsal','Rehearsal flag is only for isolated synthetic state')
    running=set(base.compose('ps','--services','--status','running').stdout.splitlines())
    check(a.rehearse or 'mysql' in running and not (running & {*WRITERS,'redis'}),
          'Quiesce runtime writers and Redis, keep MySQL running before backup')
    out.mkdir(mode=0o700)
    # Use the already verified MySQL container and owned Redis volume. No Compose environment needed in this pipe.
    sql_prefix='pd_'+c['schema_env']+'_'
    try:
        if a.rehearse:
            base.compose('stop','--timeout','40',*WRITERS,'redis')
        ident=base.compose('ps','-q','mysql').stdout.strip()
        check(re.fullmatch(r'[0-9a-f]{12,64}',ident),'MySQL container is not running')
        encrypt_stream(['docker','exec',ident,'mysqldump','--defaults-extra-file=/fixture/root.cnf',
            '--single-transaction','--set-gtid-purged=OFF','--no-tablespaces','--databases',
            *(sql_prefix+n for n in ('school','risk','keycloak'))],a.recipients,out/'academic.sql.age')
        encrypt_stream(['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL',
            '--user','999:999','--mount',f'type=volume,source={PROJECT}_redis-data,target=/data,readonly',
            '--entrypoint','tar',REDIS_IMAGE,'-C','/data','-cf','-','.'],a.recipients,out/'redis.tar.age')
        print('Encrypted SQL and Redis backups written.',flush=True)
    finally:
        if a.rehearse:
            base.compose('up','-d','--wait','--wait-timeout','200',*HEALTHY)
            print('Isolated stack healthy after backup.',flush=True)


if __name__=='__main__':
    try:
        main()
    except (RuntimeError,ValueError,OSError,subprocess.SubprocessError) as error:
        detail=str(error) if type(error) is RuntimeError else type(error).__name__
        raise SystemExit('Backup stopped: '+detail) from None
