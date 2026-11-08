"""Restore an encrypted combined RC checkpoint into a distinct synthetic project."""
import argparse
import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time
import uuid

from rc import HEALTHY, HERE, PREFIX, V5, base, check, configure, fresh, linux, run, sql, stop
from backup import REDIS_IMAGE, WRITERS, encrypt_stream
from smoke import Smoke


def risk_helpers():
    import risk_smoke
    return importlib.reload(risk_smoke)


def seed():
    r=risk_helpers()
    active,revoked,high=[str(uuid.uuid4()) for _ in range(3)]
    token=r.issue(r.CLIENT)
    for subject in (active,revoked,high):
        r.seed_history(token,subject,offset=2 if subject==high else 0)
    for subject in (active,revoked):
        row=r.evaluate(token,subject,'198.51.100.22')
        check(r.api('/trusted-devices',{'subjectId':subject,'deviceId':r.DEVICE,
            'trustGeneration':row['trustGeneration']},token)[0]==204,'Unable to seed trusted device')
    operation={'operationId':str(uuid.uuid4()),'requestedBy':'rc-recovery'}
    path=f'/subjects/{revoked}/trusted-devices/revocations'
    admin=r.issue('zerotrust-portal-risk-admin')
    check(r.api(path,operation,admin)[0]==204 and r.api(path+'/completion',operation,admin)[0]==204,'Unable to seed revoke')
    for _ in range(5):
        check(r.api('/authentication-failures',{'eventId':str(uuid.uuid4()),'subjectId':high,
            'sourceIp':'203.0.113.4'},token)[0]==204,'Unable to seed Redis counter')
    return active,revoked,high


def decisions(subjects):
    r=risk_helpers()
    token=r.issue(r.CLIENT)
    active,revoked,high=subjects
    return [(x['riskLevel'],x['decision'],x['riskScore']) for x in (
        r.evaluate(token,active,'198.51.100.22'),r.evaluate(token,revoked,'198.51.100.22'),
        r.evaluate(token,high,'203.0.113.4',None))]


def witness(smoke):
    status,raw,_=smoke.request(smoke.client(),smoke.oidc+'certs')
    check(status==200,'Realm JWKS missing')
    ids=sorted(k['kid'] for k in json.loads(raw)['keys'])
    counts={table:sql('mysql',f'SELECT COUNT(*) FROM {PREFIX}{table}') for table in (
        'school.students','school.scores','keycloak.CREDENTIAL','risk.authentication_success_events',
        'risk.known_devices','risk.device_trust_revocations')}
    check(ids and all(int(n)>0 for n in counts.values()),'Recovery state is incomplete')
    return ids,counts,sql('mysql',V5)


def encrypt_snapshot(c,project,work,identity):
    recipients=work/'recipients'
    subprocess.run(['age-keygen','-o',str(identity)],check=True,capture_output=True)
    recipients.write_bytes(subprocess.check_output(['age-keygen','-y',str(identity)]))
    base.compose('stop','--timeout','45',*WRITERS,'redis')
    ident=base.compose('ps','-q','mysql').stdout.strip()
    check(ident,'Source MySQL is not running')
    encrypt_stream(['docker','exec',ident,'mysqldump','--defaults-extra-file=/fixture/root.cnf',
        '--single-transaction','--set-gtid-purged=OFF','--no-tablespaces','--hex-blob','--add-drop-database','--databases',
        *(PREFIX+n for n in ('school','risk','keycloak'))],recipients,work/'sql.age')
    encrypt_stream(['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','--user','999:999',
        '--mount',f'type=volume,source={project}_redis-data,target=/data,readonly','--entrypoint','tar',
        REDIS_IMAGE,'-C','/data','-cf','-','.'],recipients,work/'redis.age')
    encrypt_stream(['tar','-C',str(c['state']),'-cf','-','.'],recipients,work/'state.age')


def decrypted(work,name,identity):
    data=subprocess.run(['age','-d','-i',str(identity),str(work/name)],check=True,capture_output=True).stdout
    check(0<len(data)<64*1024*1024,'Unexpected synthetic restore payload size')
    return data


def safe_tar(data):
    archive=tarfile.open(fileobj=io.BytesIO(data),mode='r:')
    check(all((m.isfile() or m.isdir()) and not Path(m.name).is_absolute() and '..' not in Path(m.name).parts
              for m in archive.getmembers()),'Unsafe backup archive entries')
    return archive


def restore(src,c,project,work,identity):
    prefix='pd_'+c['schema_env']+'_'
    v5=f"SELECT checksum,success FROM {prefix}risk.flyway_schema_history WHERE version='5'"
    target=c['state']
    target.mkdir(mode=0o700)
    with safe_tar(decrypted(work,'state.age',identity)) as archive:
        archive.extractall(target,members=[m for m in archive.getmembers()
            if m.name.removeprefix('./')!='installed'],filter='data')
    target.chmod(0o700)
    for role,name in (('keycloak','keycloak.conf'),('installer','keycloak.conf'),('gateway','application.properties')):
        path=target/role/name
        path.write_text(path.read_text().replace(src['proxy_ip']+'/32',c['proxy_ip']+'/32'))
    (target/'linux-profile').write_text(json.dumps(linux.state_identity(c),sort_keys=True))
    if c['mode']=='production-demo':
        linux.prepare(c,linux.load_pki(c))
    base.compose('run','--rm','--no-deps','materialize')
    base.compose('up','-d','--wait','--wait-timeout','150','mysql')
    check(sql('mysql',f"SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA IN ('{prefix}risk','{prefix}keycloak')")=='0',
          'Restore target already has Risk or Keycloak data')
    ident=base.compose('ps','-q','mysql').stdout.strip()
    check(ident,'Restore target MySQL is not running')
    subprocess.run(['docker','exec','-i',ident,'mysql','--defaults-extra-file=/fixture/root.cnf','--binary-mode'],
        input=decrypted(work,'sql.age',identity),check=True,capture_output=True,timeout=150)
    check(sql('mysql',v5)=='661092940\t1','Restored Flyway ledger mismatch')
    base.compose('create','redis')
    data=decrypted(work,'redis.age',identity)
    with safe_tar(data) as archive:
        check(any('.aof' in m.name for m in archive.getmembers()),'Redis archive lacks AOF')
    result=subprocess.run(['docker','run','--rm','-i','--network','none','--read-only','--cap-drop','ALL',
        '--user','999:999','--mount',f'type=volume,source={project}_redis-data,target=/data',
        '--entrypoint','sh',REDIS_IMAGE,'-ec','test -z "$(ls -A /data)"; tar -C /data -xf -'],
        input=data,capture_output=True,timeout=90)
    check(result.returncode==0,'Redis restore failed or destination is not empty')
    run('docker','volume','create','--label',f'com.docker.compose.project={project}',
        '--label','com.docker.compose.volume=mysql-bootstrap-data',project+'_mysql-bootstrap-data')
    base.compose('up','-d','--wait','--wait-timeout','230',*HEALTHY)


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',required=True,type=Path)
    p.add_argument('--source',default=HERE/'rehearsal.json',type=Path)
    p.add_argument('--destination',required=True,type=Path)
    p.add_argument('--source-project',default='zt-pd-r22')
    p.add_argument('--project',default='zt-pd-r22-restore')
    a=p.parse_args()
    src,_,_,_=configure(a.source,a.manifest,a.source_project)
    check(a.project!=a.source_project,'Restore requires an independent project')
    work=Path(tempfile.mkdtemp(prefix='zt-r22-encrypted-'))
    identity=Path(tempfile.mkdtemp(prefix='zt-r22-age-key-'))/'identity'
    print('Protected recovery output:',work,flush=True)
    s=Smoke(src)
    s.infrastructure()
    subjects=seed()
    before=decisions(subjects)
    check([row[1] for row in before]==['ALLOW','STEP_UP_MFA','DENY'],'Unexpected pre-backup security state')
    source_witness=witness(s)
    try:
        encrypt_snapshot(src,a.source_project,work,identity)
    finally:
        stop()
    dest,_,_,_=configure(a.destination,a.manifest,a.project)
    fresh(dest,a.project)
    started=time.monotonic()
    try:
        restore(src,dest,a.project,work,identity)
        smoke=Smoke(dest)
        smoke.infrastructure()
        check(witness(smoke)==source_witness,'Recovered data, signing keys, credentials or ledger differ')
        check(decisions(subjects)==before,'Recovered B0/counters/revocation state differs')
        client,tokens=smoke.auth_flow(smoke.accounts()['student_b'])
        check(smoke.request(client,smoke.portal+'/api/students/me/scores',token=tokens['access_token'])[0]==200,
              'Recovered enrolled STUDENT cannot sign in/read data')
        base.save('.','installed',linux.digest(a.manifest))
        print(f'PASS encrypted full restore, MFA/JWKS/School/Risk/Redis/V5 and revoke preserved, seconds={time.monotonic()-started:.1f}',flush=True)
    finally:
        stop()


if __name__=='__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('Recovery stopped: '+(str(error) if type(error) is RuntimeError else type(error).__name__)) from None
