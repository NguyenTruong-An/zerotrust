"""Rehearse fallback to Quay using a checkpoint created by that exact image."""
import argparse
import json
import os
from pathlib import Path
import tempfile
import time

from rc import HEALTHY, HERE, Smoke, base, bootstrap, check, configure, fresh, image_id, linux, run, stop
from recovery import decisions, encrypt_snapshot, restore, seed, witness

QUAY='zt-pd02-candidate/keycloak:pd-r11-c401e17'
QUAY_ID='sha256:e06bec13a903df01c1fd80b590d328db99ecbc4b00ee6ce3baa6f10f5f142615'


def lane(base_config,work,tag,network):
    name='zt-pd-r22-'+tag
    path=work/(tag+'.json')
    conf=json.loads(base_config.read_text())
    conf.update(state_dir='/tmp/zerotrust-pd-r22-'+tag,core_subnet=network)
    path.write_text(json.dumps(conf))
    return path,name


def quay(config,manifest,project,override):
    c,_,cmd,env=configure(config,manifest,project)
    check(image_id(QUAY)==QUAY_ID,'Quay rollback image ID mismatch')
    env['AD_RC_KC']=QUAY
    def compose(*args,check=True,data=None,timeout=420):
        return run(*cmd,'-f',str(override),*args,check_result=check,data=data,env=env,timeout=timeout)
    base.compose=compose
    base.verify_boundary()
    model=json.loads(compose('--profile','*','config','--format','json').stdout)
    for service in ('keycloak','keycloak-init'):
        config=model['services'][service]
        check(config['image']==QUAY and config['user']=='1000:1000','Rollback recipe drift')
    return c


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',required=True,type=Path)
    p.add_argument('--dhi-config',required=True,type=Path)
    p.add_argument('--dhi-project',required=True)
    p.add_argument('--resume-seed',action='store_true',help='Reuse a healthy previously installed Quay seed, with a fresh fallback target')
    a=p.parse_args()
    work=Path(tempfile.mkdtemp(prefix='zt-r22-quay-checkpoint-'))
    identity=Path(tempfile.mkdtemp(prefix='zt-r22-quay-key-'))/'identity'
    override=work/'quay.yaml'
    override.write_text(f'''services:
  materialize:
    volumes:
      - "{linux.LOCAL/'materialize.sh'}:/script/materialize.sh:ro"
  keycloak:
    user: "1000:1000"
  keycloak-init:
    user: "1000:1000"
''')
    quay_lock=work/'quay-lock.json'
    quay_lock.write_text(json.dumps({'image':QUAY,'id':QUAY_ID,'mysql':'8.4.13',
        'deployment_lock_sha256':linux.digest(a.manifest)}))
    qcfg,qproject=lane(a.dhi_config,work,'quayseed','172.31.239.0/27')
    if a.resume_seed:
        dcfg,dproject=lane(a.dhi_config,work,'quayrestore2','172.31.242.0/27')
    else:
        dcfg,dproject=lane(a.dhi_config,work,'quayrestore','172.31.240.0/27')
    src=quay(qcfg,a.manifest,qproject,override)
    try:
        if a.resume_seed:
            check((src['state']/'installed').read_text()==linux.digest(quay_lock),'Quay seed was not installed from this lock')
            base.compose('up','-d','--wait','--wait-timeout','230',*HEALTHY)
        else:
            bootstrap(src,qproject,quay_lock)
        smoke=Smoke(src)
        client,tokens=smoke.auth_flow(smoke.accounts()['student_b'])
        check(smoke.request(client,smoke.portal+'/api/students/me/scores',token=tokens['access_token'])[0]==200,'Quay preflight login failed')
        subjects=seed()
        expected=decisions(subjects)
        record=witness(smoke)
        encrypt_snapshot(src,qproject,work,identity)
    finally:
        stop()
    print('PASS captured checkpoint under exact Quay and MySQL 8.4 before simulated promotion.',flush=True)

    dhi,_,_,_=configure(a.dhi_config,a.manifest,a.dhi_project)
    check((dhi['state']/'installed').read_text()==linux.digest(a.manifest),'DHI candidate install marker drift')
    try:
        base.compose('up','-d','--wait','--wait-timeout','230',*HEALTHY)
        Smoke(dhi).infrastructure()
    finally:
        stop()
    print('PASS simulated DHI promotion lane, stopped before fallback.',flush=True)

    dest=quay(dcfg,a.manifest,dproject,override)
    fresh(dest,dproject)
    start=time.monotonic()
    try:
        restore(src,dest,dproject,work,identity)
        smoke=Smoke(dest)
        smoke.infrastructure()
        check(witness(smoke)==record and decisions(subjects)==expected,'Quay checkpoint state changed')
        client,tokens=smoke.auth_flow(smoke.accounts()['student_b'])
        check(smoke.request(client,smoke.portal+'/api/students/me/scores',token=tokens['access_token'])[0]==200,
              'Quay fallback login/read failed')
        base.save('.','installed',linux.digest(quay_lock))
        print(f'PASS rollback DHI to compatible Quay checkpoint, fresh volumes, seconds={time.monotonic()-start:.1f}',flush=True)
    finally:
        stop()


if __name__=='__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('Rollback stopped: '+(str(error) if type(error) is RuntimeError else type(error).__name__)) from None
