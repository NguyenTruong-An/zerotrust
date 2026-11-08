"""Install the combined DHI/MySQL Academic Demo with a locked Linux profile."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent))
import linux_demo as linux
from linux_demo import HEALTHY, ROOT, base, check, image_id, run
sys.path.insert(0,str(HERE.parent))
from smoke import Smoke

MYSQL84='mysql:8.4.13@sha256:72c368d898861f3b3a07af0e6d690400f44f048799ed46822783d9224cc2c86d'
MYSQL80=next(ref for ref in linux.IMAGE_PINS if ref.startswith('mysql:'))
REGISTRY=tuple(ref for ref in linux.IMAGE_PINS if '@sha256:' in ref)+(MYSQL84,)
SERVICES=('keycloak','backend','risk','gateway','frontend')
PREFIX='pd_staging_'
V5=f"SELECT checksum,success FROM {PREFIX}risk.flyway_schema_history WHERE version='5'"


def deployment_hashes():
    files=linux.deployment_inputs()
    files.update((HERE/name).relative_to(ROOT).as_posix() for name in (
        'rc.py','build.py','Dockerfile.keycloak-dhi','compose.rc.yaml','materialize.sh','rehearsal.json',
        'production.example.json','vps_backup.py'))
    files.update('deploy/academic-linux/'+name for name in ('smoke.py','backup.py'))
    return {name:linux.digest(ROOT/name) for name in sorted(files)}


def lock(build_dir, path, config):
    from build import inputs
    revision=run('git','rev-parse','HEAD').stdout.strip()
    builds={name:json.loads((build_dir/(name+'.json')).read_text()) for name in SERVICES}
    for name,build in builds.items():
        check(re.fullmatch(r'[a-f0-9]{40}',build['revision']) and build['inputs']==inputs(name),'App build source changed')
        check(re.fullmatch(r'zt-pd-r22/'+name+r':rc[0-9]+',build['image']),'Invalid app image reference')
        snapshot=hashlib.sha256(json.dumps(build['inputs'],sort_keys=True).encode()).hexdigest()
        check(build['snapshot']==snapshot,'App source snapshot mismatch')
        check(image_id(build['image'])==build['id'],'App build image changed')
        labels=run('docker','image','inspect','--format',
            '{{index .Config.Labels "org.opencontainers.image.revision"}} {{index .Config.Labels "io.zerotrust.source.snapshot"}}',
            build['image']).stdout.split()
        check(labels==[build['revision'],snapshot],'Image source labels differ from its build receipt')
    verify_frontend(config,builds['frontend'])
    pins={ref:ref.split('@')[1] for ref in REGISTRY}
    for ref,ident in pins.items():
        check(image_id(ref)==ident,'Missing exact registry image')
    with path.open('x',encoding='utf-8') as f:
        json.dump({'revision':revision,'platform':'linux/amd64','mode':config['mode'],'builds':builds,'registry':pins,
                   'deployment_hashes':deployment_hashes()},f,indent=2,sort_keys=True)
        f.write('\n')


def verify_frontend(c, frontend):
    front=frontend['build_args']
    check(front['SITE_URL']==c['portal_url'] and front['KEYCLOAK_URL']==c['auth_url']
          and front['KEYCLOAK_REALM']==base.REALM and front['KEYCLOAK_CLIENT_ID']=='zerotrust-spa'
          and front['PORTAL_MODE']=='public-demo' and front['API_BASE_URL']=='','Frontend hostname, issuer or mode drift')


def configure(config, manifest, project, *, allow_production=False):
    c=linux.load_config(config)
    if c['mode']=='rehearsal':
        check(re.fullmatch(r'zt-pd-r22(?:-[a-z0-9]{1,20})?',project)
              and c['state'].parent==Path('/tmp'),'Use the dedicated RC rehearsal namespace')
    else:
        check(allow_production and re.fullmatch(r'zt-academic-prod(?:-[a-z0-9]{1,20})?',project)
              and c['state'].parent==Path('/var/lib/zerotrust'),'Use the dedicated Academic Demo production namespace')
    check(c['state'].name==project.replace('zt-','zerotrust-',1),'State directory does not match project')
    m=json.loads(manifest.read_text())
    check(m['platform']=='linux/amd64' and m.get('mode','rehearsal')==c['mode']
          and deployment_hashes()==m['deployment_hashes'],'Deployment files or mode changed')
    check(set(m['builds'])==set(SERVICES) and set(m['registry'])==set(REGISTRY),'Image lock set mismatch')
    refs={name:b['image'] for name,b in m['builds'].items()}
    for name,b in m['builds'].items():
        check(re.fullmatch(r'zt-pd-r22/'+name+r':rc[0-9]+',b['image']) and image_id(b['image'])==b['id'],
              'Application image drift')
    for ref,ident in m['registry'].items():
        check(ident==ref.split('@')[1] and image_id(ref)==ident,'Registry image drift')
    verify_frontend(c,m['builds']['frontend'])
    c['frontend_image']=refs['frontend']
    linux.PROJECT=linux.SCOPE=project
    linux.activate(c)
    base.VOLUMES.add('mysql-bootstrap-data')
    base.EXACT_IMAGES={b['image']:b['id'].split(':')[1] for b in m['builds'].values()}
    env={k:v for k,v in os.environ.items() if not k.upper().startswith(('COMPOSE_','AD_'))}
    env.update(ACADEMIC_STATE=str(c['state']),AD_BIND_PORT=str(c['bind_port']), AD_PORTAL_HOST=c['portal_host'],
        AD_EXTERNAL_PORT=str(c['external_port']),AD_INGRESS_IP=c['proxy_ip'],AD_CORE_SUBNET=c['core_subnet'],
        AD_FRONTEND_IMAGE=refs['frontend'], AD_RC_PROJECT=project, AD_RC_KC=refs['keycloak'],
        AD_RC_BACKEND=refs['backend'], AD_RC_RISK=refs['risk'], AD_RC_GATEWAY=refs['gateway'])
    cmd=['docker','compose','-p',project,'--project-directory',str(linux.LOCAL),
        '-f',str(linux.LOCAL/'compose.academic-demo.yaml'),'-f',str(HERE.parent/'compose.production-demo.yaml'),
        '-f',str(HERE/'compose.rc.yaml')]

    def compose(*args,check=True,data=None,timeout=420):
        result=run(*cmd,*args,check_result=False,env=env,data=data,timeout=timeout)
        if check and result.returncode:
            tokens=re.findall(r'\b(?:[A-Za-z]+Exception|UNREVIEWED_MYSQL_VERSION|V5_[A-Z0-9_]+|unhealthy|permission denied)\b',
                              result.stdout+'\n'+result.stderr)
            raise RuntimeError(f'RC Compose {args[0]} exit={result.returncode}; {sorted(set(tokens))}')
        return result

    base.compose=compose
    base.verify_boundary()
    model=json.loads(compose('--profile','*','config','--format','json').stdout)
    sv=model['services']
    check(model['name']==project and all(s['labels']['io.zerotrust.scope']==project for s in sv.values()),'RC ownership mismatch')
    check(all(not x.get('external') and x['name'].startswith(project+'_') for group in ('networks','volumes')
              for x in model[group].values()),'RC references a foreign network or volume')
    binds={(n,m['source'],m.get('read_only')) for n,s in sv.items() for m in s.get('volumes',[]) if m['type']=='bind'}
    check(binds=={('materialize',str(c['state']),True),('materialize',str(HERE/'materialize.sh'),True)},'Foreign bind mount')
    check(set(sv['mysql80']['networks'])=={'recovery'} and set(sv['migrate80']['networks'])=={'recovery'}
          and sv['mysql80']['profiles']==['bootstrap80'] and sv['migrate80']['profiles']==['bootstrap80']
          and set(sv['mysql']['networks'])=={'core'},'MySQL bootstrap isolation failed')
    check(set(sv['ingress']['networks'])=={'core','edge'}
          and all('edge' not in s.get('networks',{}) for n,s in sv.items() if n!='ingress'),
          'Only ingress may join the edge network')
    check(all(sv[n]['user']=='65532:65532' and sv[n]['cap_drop']==['ALL']
              and 'no-new-privileges:true' in sv[n]['security_opt'] for n in ('keycloak','keycloak-init')),
          'DHI permissions drift')
    return c,m,cmd,env


def sql(service,query,profile='root'):
    return linux.sql(service,query,profile)


def ledger(service,prefix):
    return sql(service,f'SELECT version,checksum,success FROM {prefix}risk.flyway_schema_history ORDER BY installed_rank')


def schema(service,prefix):
    return sql(service,"SELECT TABLE_NAME,COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,COALESCE(COLLATION_NAME,'') "
        f"FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='{prefix}risk' ORDER BY TABLE_NAME,ORDINAL_POSITION")


def fresh(c,project):
    check(not c['state'].exists(),'Existing state requires its original successful installation')
    check(not run('docker','volume','ls','-q','--filter',f'label=com.docker.compose.project={project}').stdout.strip(),
          'Fresh installation requires empty volumes')
    check(not run('docker','ps','-aq','--filter',f'label=com.docker.compose.project={project}').stdout.strip(),
          'Fresh installation requires a new project')


def bootstrap(c,project,manifest):
    fresh(c,project)
    prefix='pd_'+c['schema_env']+'_'
    v5=f"SELECT checksum,success FROM {prefix}risk.flyway_schema_history WHERE version='5'"
    linux.prepare(c,linux.load_pki(c))
    base.compose('run','--rm','--no-deps','materialize')
    try:
        base.compose('up','-d','--wait','--wait-timeout','150','mysql80')
        check(sql('mysql80','SELECT VERSION()')=='8.0.46','Bootstrap MySQL version drift')
        base.compose('run','--rm','--no-deps','migrate80')
        expected=ledger('mysql80',prefix)
        expected_schema=schema('mysql80',prefix)
        check([line.split('\t')[0] for line in expected.splitlines()]==list('12345')
              and all(line.endswith('\t1') for line in expected.splitlines()) and sql('mysql80',v5)=='661092940\t1',
              'Bootstrap ledger mismatch')
        dump=base.compose('exec','-T','mysql80','mysqldump','--defaults-extra-file=/fixture/root.cnf',
            '--single-transaction','--set-gtid-purged=OFF','--no-tablespaces','--skip-add-drop-table',prefix+'risk').stdout
        check('CREATE TABLE' in dump,'Risk bootstrap export is empty')
    finally:
        base.compose('stop','--timeout','45','mysql80')
    base.compose('up','-d','--wait','--wait-timeout','150','mysql','redis')
    check(sql('mysql','SELECT VERSION()')=='8.4.13','Target MySQL version drift')
    check(not schema('mysql',prefix),'Destination Risk schema must be empty')
    base.compose('exec','-T','mysql','mysql','--defaults-extra-file=/fixture/root.cnf',prefix+'risk',data=dump)
    check(ledger('mysql',prefix)==expected and schema('mysql',prefix)==expected_schema,'Restored schema/ledger differs')
    check(sql('mysql',f'SELECT COUNT(*) FROM {prefix}school.students')=='2','Synthetic School seed differs')
    check(sql('mysql',"SHOW SESSION STATUS LIKE 'Ssl_cipher'",'school').split('\t')[-1].startswith(('TLS_','ECDHE-')),
          'School connection did not negotiate TLS')
    print('PASS fresh MySQL 8.0.46 V1–V5, logical transfer, schema/ledger match on 8.4.13 and School TLS.',flush=True)
    base.compose('up','-d','--wait','--wait-timeout','380','keycloak-init')
    base.compose('stop','--timeout','60','keycloak-init')
    exitcode=run('docker','inspect','--format','{{.State.ExitCode}}',project+'-keycloak-init-1').stdout.strip()
    check(exitcode in ('0','143'),'Keycloak installer failed to stop gracefully')
    check(sql('mysql',f"SELECT COUNT(*) FROM {prefix}keycloak.REALM WHERE NAME='{base.REALM}'")=='1','Realm import missing')
    base.compose('up','-d','--wait','--wait-timeout','220',*HEALTHY)
    check(ledger('mysql',prefix)==expected,'Risk runtime changed migration ledger')
    base.save('.','installed',linux.digest(manifest))
    print('PASS combined DHI Keycloak and MySQL 8.4.13: eight healthy services, validated Flyway ledger.',flush=True)


def stop():
    base.compose('stop','--timeout','45','ingress','gateway','frontend','backend','risk','keycloak','keycloak-init')
    base.compose('stop','--timeout','45','redis','mysql','mysql80')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('lock','validate','start','status','stop','smoke','exercise'))
    p.add_argument('--manifest',required=True,type=Path)
    p.add_argument('--config',type=Path,default=HERE/'rehearsal.json')
    p.add_argument('--project',default='zt-pd-r22')
    p.add_argument('--build-dir',type=Path)
    a=p.parse_args()
    if a.action=='lock':
        check(a.build_dir is not None,'Build receipts required')
        lock(a.build_dir,a.manifest,linux.load_config(a.config))
        return
    c,_,_,_=configure(a.config,a.manifest,a.project,allow_production=a.action!='exercise')
    if a.action=='validate':
        linux.load_pki(c)
        print('PASS exact images, frontend origins, project boundary, Compose and PKI preflight.')
    elif a.action=='start':
        if c['mode']=='production-demo':
            check(shutil.which('keytool') is not None,'Install OpenJDK 17 keytool on the host')
            parent=c['state'].parent
            check(parent.is_dir() and parent.stat().st_uid==os.getuid() and parent.stat().st_mode&0o077==0,
                  'Prepare /var/lib/zerotrust owned by the deployment account, mode 0700')
        marker=c['state']/'installed'
        if marker.is_file():
            check(marker.read_text()==linux.digest(a.manifest),'Existing state belongs to a different release lock')
            linux.prepare(c,linux.load_pki(c))
            base.compose('up','-d','--wait','--wait-timeout','220',*HEALTHY)
        else:
            bootstrap(c,a.project,a.manifest)
    elif a.action=='stop':
        stop()
    elif a.action=='status':
        print(base.compose('ps','-a').stdout,end='')
    elif a.action=='smoke':
        Smoke(c).infrastructure()
    elif a.action=='exercise':
        s=Smoke(c)
        s.infrastructure()
        s.browser_protocol()
        s.faults()
        s.recovery()


if __name__=='__main__':
    try:
        main()
    except (RuntimeError,ValueError,OSError,KeyError,subprocess.SubprocessError) as error:
        raise SystemExit('RC stopped: '+(str(error) if type(error) is RuntimeError else type(error).__name__)) from None
