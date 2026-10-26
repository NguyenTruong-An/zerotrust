"""Generate a separate legacy profile from the committed Docker packaging, without starting it."""
import copy
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PROJECT = 'zerotrust-legacy-integration-20261026'
STATE = '${LEGACY_STATE_DIR:?Set LEGACY_STATE_DIR to the prepared private runtime directory}'


def generate():
    # A generated Compose file is source, not the host-resolved model used at runtime.
    # Keep relative paths and canonical scalar formatting. Read the public example,
    # not an operator's default .env or private service env files.
    result = subprocess.run(['docker', 'compose', '--project-directory', str(ROOT),
                             '--env-file', str(ROOT/'.env.example'),
                             '-f', str(ROOT/'compose.yaml'), 'config', '--no-path-resolution',
                             '--no-env-resolution', '--format', 'json'],
                            cwd=ROOT, capture_output=True, check=True)
    base = json.loads(result.stdout)
    runtime = {'restart': 'no', 'profiles': ['legacy'], 'networks': ['core'],
               'labels': {'app.owner': PROJECT}, 'stop_grace_period': '35s',
               'logging': {'driver': 'json-file', 'options': {'max-size': '5m', 'max-file': '2'}}}
    health = {'interval': '10s', 'timeout': '5s', 'retries': 24, 'start_period': '60s'}
    def private(role):
        return {'type':'bind', 'source':STATE+'/'+role, 'target':'/run/demo', 'read_only':True}
    def volume(name, target):
        return {'type':'volume', 'source':name, 'target':target, 'volume':{'nocopy':True}}
    services = {}
    for name, image, memory in [
        ('school', 'mysql:9.1.0@sha256:0255b469f0135a0236d672d60e3154ae2f4538b146744966d96440318cc822c6', '768m'),
        ('risk-db', 'mysql:8.0.46@sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b', '768m'),
        ('keycloak-db', 'mysql:8.4.13@sha256:76f0358884cb92d9a086d24e5671c38048d3fef40f2588703d73eb55392d6b69', '640m')]:
        service = {**copy.deepcopy(runtime), 'container_name':PROJECT+'-'+name, 'image':image, 'mem_limit':memory,
                   'entrypoint':['docker-entrypoint.sh'],
                   'command':['mysqld','--defaults-extra-file=/run/demo/server.cnf'],
                   'environment':{'MYSQL_ROOT_PASSWORD_FILE':'/run/demo/root-password'},
                   'volumes':[volume(name+'-data','/var/lib/mysql'), private(name)],
                   'healthcheck':{'test':['CMD-SHELL', 'umask 077; cp /run/demo/client.cnf /tmp/legacy-client.cnf; chmod 600 /tmp/legacy-client.cnf; mysql --defaults-extra-file=/tmp/legacy-client.cnf --batch --skip-column-names -e "SELECT 1" | grep -q 1'], **health}}
        if name == 'school': service['command'].append('--lower-case-table-names=1')
        if name == 'keycloak-db': service['command'].append('--sql-generate-invisible-primary-key=OFF')
        services[name] = service
    for name in ['redis','risk','backend','frontend','gateway','crl']:
        service = copy.deepcopy(base['services'][name])
        for key in ['depends_on','volumes','networks','ports','profiles','labels','logging','restart']:
            service.pop(key, None)
        service.update(copy.deepcopy(runtime));service['container_name'] = PROJECT+'-'+name
        service['image'] = 'zerotrust-legacy-'+name+':20261026-candidate'
        if name == 'redis':
            service['image'] = base['services']['redis']['image']
            service['volumes'] = [volume('redis-data','/data'),private(name)]
        elif name == 'crl':
            service['build']={'context':'.','dockerfile':'deploy/demo/Dockerfile.tools'};service['image']='zerotrust-legacy-tools:20261026-candidate'
            service['volumes']=[{'type':'bind','source':STATE+'/public-ca','target':'/public-ca','read_only':True}]
            service['networks']=['core','edge'];service['ports']=['127.0.0.1:28445:8080']
        elif name != 'frontend':service['volumes']=[private(name)]
        if name == 'gateway':
            service['networks']=['core','edge'];service['ports']=['127.0.0.1:28443:8443']
        if name == 'frontend':
            service['build']['args']={'KEYCLOAK_URL':'https://localhost:28444','KEYCLOAK_REALM':'DoAn','KEYCLOAK_CLIENT_ID':'zerotrust-spa'}
        if name == 'risk':
            service['env_file']=[STATE+'/risk/legacy-policy.env']
            # Only the explicitly approved migration job may apply schema changes.
            # Ordinary application start validates JPA mappings without running Flyway.
            service.setdefault('environment',{})['SPRING_FLYWAY_ENABLED']='false'
        services[name]=service
    services['keycloak']={**copy.deepcopy(runtime),'container_name':PROJECT+'-keycloak',
        'image':'zerotrust-legacy-keycloak:20261026-candidate',
        'build':{'context':'.','dockerfile':'deploy/demo/Dockerfile.keycloak'},
        'entrypoint':['/opt/keycloak/bin/kc.sh'],
        'command':['--config-file=/run/demo/keycloak.conf','start','--optimized'],
        'mem_limit':'768m','volumes':[private('keycloak')], 'environment':{'KC_HTTP_MANAGEMENT_SCHEME':'http','JAVA_OPTS_APPEND':'@/run/demo/jvm.args -Xmx384m'},
        'networks':['core','edge'],'ports':['127.0.0.1:28444:28444'],
        'extra_hosts':{'host.docker.internal':'127.0.0.1'},
        'healthcheck':copy.deepcopy(base['services']['keycloak']['healthcheck'])}
    # No init service, no import-realm startup switch, no bootstrap admin or synthetic users.
    for name in ['school-migrate','risk-migrate','keycloak-import','keycloak-export']:
        services[name]={**copy.deepcopy(runtime),'profiles':['migration'],'container_name':PROJECT+'-'+name,
                        'restart':'no','mem_limit':'512m','read_only':True}
    services['school-migrate'].update({'image':'zerotrust-legacy-tools:20261026-candidate','build':{'context':'.','dockerfile':'deploy/demo/Dockerfile.tools'},
        'entrypoint':['/opt/tools/bin/python'],'command':['/candidate/scripts/legacy/school_migrate.py','apply',
            '--config','/run/demo/migration.private.json','--baseline','/run/demo/baseline.private.json',
            '--migration','/candidate/database/migrations/school/V20261026_01__legacy_teacher_schedule.sql',
            '--approval','/approval/owner-approval.private.json'],
        'volumes':[private('school'),{'type':'bind','source':'.','target':'/candidate','read_only':True},
                   {'type':'bind','source':STATE+'/approval','target':'/approval','read_only':True}]})
    services['risk-migrate'].update({'image':'zerotrust-legacy-risk:20261026-candidate',
        'entrypoint':['java','@/run/demo/jvm.args','-cp','/app/tools:/app/unpacked/BOOT-INF/classes:/app/unpacked/BOOT-INF/lib/*',
                      'MigrateLegacyRisk','/run/demo/migration.properties'], 'volumes':[private('migrate')]})
    for name, command in [('keycloak-import',['import','--optimized','--dir','/imports','--override','true']),
                           ('keycloak-export',['export','--optimized','--dir','/evidence/keycloak-post-import','--users','realm_file'])]:
        services[name].update({'image':'zerotrust-legacy-keycloak-import:20261026-candidate',
            'build':{'context':'.','dockerfile':'deploy/legacy/Dockerfile.keycloak-import',
                     'secrets':['legacy-provider','legacy-theme']},
            'entrypoint':['/opt/keycloak/bin/kc.sh'],
            'command':['--config-file=/run/demo/keycloak.conf']+command,
            'read_only':False, 'environment':{'JAVA_OPTS_APPEND':'@/run/demo/jvm.args -Xmx384m'}, 'volumes':[private('keycloak'),{'type':'bind','source':STATE+'/migration-inputs/keycloak/original-export','target':'/imports','read_only':True},
                 {'type':'bind','source':STATE+'/evidence','target':'/evidence'}]})
    # Application starts are orchestrated only after migrations/model checks; no automatic fixture bootstrap.
    services['risk']['depends_on']={k:{'condition':'service_healthy'} for k in ['risk-db','redis','keycloak']}
    services['backend']['depends_on']={k:{'condition':'service_healthy'} for k in ['school','risk','keycloak']}
    services['gateway']['depends_on']={k:{'condition':'service_healthy'} for k in ['backend','frontend','crl']}
    services['keycloak']['depends_on']={'keycloak-db':{'condition':'service_healthy'}}
    result={'name':PROJECT,'services':services,
        'networks':{'core':{'name':PROJECT+'_core','internal':True,'labels':{'app.owner':PROJECT}},
                    'edge':{'name':PROJECT+'_edge','labels':{'app.owner':PROJECT}}},
        'volumes':{name:{'name':PROJECT+'_'+name,'labels':{'app.owner':PROJECT}}
                   for name in ['school-data','risk-db-data','keycloak-db-data','redis-data']},
        'secrets':{'legacy-provider':{'file':STATE+'/import-assets/keycloak-risk-extension.jar'},
                   'legacy-theme':{'file':STATE+'/import-assets/legacy-theme.tar'}}}
    for service in services.values():
        build = service.get('build')
        if build:
            context = build['context']
            assert context == '.', 'BUILD_CONTEXT_MUST_BE_REPOSITORY_RELATIVE'
            dockerfile = Path(build['dockerfile'])
            assert not dockerfile.is_absolute() and '..' not in dockerfile.parts, 'UNPORTABLE_DOCKERFILE'
    (ROOT/'compose.legacy.yaml').write_bytes((json.dumps(result,indent=2)+'\n').encode())
    print('Generated legacy profile. No Docker resource created or started.')


if __name__=='__main__':generate()
