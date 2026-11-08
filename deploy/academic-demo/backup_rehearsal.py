"""Encrypt a consistent synthetic SQL backup and rehearse logical restore on isolated MySQL 8.4."""
import datetime as dt
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys

from academic_demo import ROOT, STATE, compose, require, verify_boundary

sys.path.insert(0,str(ROOT/'scripts/public_demo'))
from backup_encryption import decrypt, encrypt

DATABASES=('pd_staging_school','pd_staging_risk','pd_staging_keycloak')
MATCH_SQL="""SELECT
(SELECT COUNT(*) FROM pd_staging_school.students),
(SELECT COUNT(*) FROM pd_staging_school.scores),
(SELECT COUNT(*) FROM pd_staging_keycloak.REALM),
(SELECT COUNT(*) FROM pd_staging_keycloak.USER_ENTITY),
(SELECT COUNT(*) FROM pd_staging_keycloak.CREDENTIAL),
(SELECT COUNT(*) FROM pd_staging_risk.known_devices),
(SELECT checksum FROM pd_staging_risk.flyway_schema_history WHERE version='5' AND success=1)"""


def tool(name):
    path = shutil.which(name)
    if not path and os.name=='nt':
        candidate=ROOT/f'target/pd-02-06/toolchain/age/{name}.exe'
        path=str(candidate) if candidate.is_file() else None
    require(path,f'{name} is required')
    return path


def sql(service, statement):
    return compose('exec','-T',service,'mysql','--defaults-extra-file=/fixture/root.cnf','-Nse',statement).stdout.strip()


def run():
    verify_boundary()
    require((STATE/'installed').is_file(),'Academic Demo not bootstrapped')
    now=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    run_dir=STATE/'backups'/now
    run_dir.mkdir(mode=0o700,parents=True)
    key_dir=STATE/'backup-key'
    key_dir.mkdir(mode=0o700,exist_ok=True)
    identity=key_dir/'identity'
    recipients=key_dir/'recipients'
    if not identity.exists():
        p=subprocess.run([tool('age-keygen'),'-o',str(identity)],capture_output=True)
        require(p.returncode==0,'Age key generation failed')
        identity.chmod(0o600)
    p=subprocess.run([tool('age-keygen'),'-y',str(identity)],capture_output=True)
    require(p.returncode==0,'Cannot derive age recipient')
    recipients.write_bytes(p.stdout)
    dump=run_dir/'temporary.sql'
    restored=run_dir/'restore.sql'
    archive=run_dir/'academic-mysql.sql.age'
    # Only explicitly named services from the preflight-verified Compose project.
    try:
        compose('stop','--timeout','30','ingress','gateway','backend','risk','keycloak')
        expected=sql('mysql',MATCH_SQL)
        require(expected.split()[-1]=='661092940','Original V5 ledger invalid')
        payload=compose('exec','-T','mysql','mysqldump','--defaults-extra-file=/fixture/root.cnf',
            '--single-transaction','--set-gtid-purged=OFF','--no-tablespaces','--databases',*DATABASES).stdout
        require(len(payload)>100000,'Synthetic dump incomplete')
        dump.write_text(payload,encoding='utf-8',newline='\n')
        dump.chmod(0o600)
        encrypt(tool('age'),dump,recipients,archive)
        decrypt(tool('age'),archive,identity,restored)
        require(dump.read_bytes()==restored.read_bytes(),'Encrypted archive roundtrip mismatch')
        print('Encrypted School, Risk, Keycloak archive SHA-256',hashlib.sha256(archive.read_bytes()).hexdigest(),flush=True)
        compose('up','-d','--wait','--wait-timeout','120','mysql-restore')
        schemas=sql('mysql-restore',"SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME IN ('pd_staging_school','pd_staging_risk','pd_staging_keycloak')")
        require(schemas=='0','Recovery database already contains data; preserved')
        compose('exec','-T','mysql-restore','mysql','--defaults-extra-file=/fixture/root.cnf',
                data=restored.read_text(encoding='utf-8'))
        version=sql('mysql-restore','SELECT VERSION()')
        require(version=='8.4.13' and sql('mysql-restore',MATCH_SQL)==expected,'MySQL 8.4 logical restore invariants differ')
        print('PASS MySQL 8.4.13 logical restore, row counts, Keycloak credentials and V5 checksum 661092940',flush=True)
    finally:
        for temporary in (dump,restored,*run_dir.glob('restore.sql.partial-*')):
            temporary.unlink(missing_ok=True)
        compose('stop','--timeout','30','mysql-restore',check=False)
        compose('up','-d','--wait','--wait-timeout','180')
        print('Original Academic Demo healthy after rehearsal.',flush=True)


if __name__=='__main__':
    run()
