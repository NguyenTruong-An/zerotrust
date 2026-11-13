"""Disposable Phase3 deployment rehearsal; never invokes a live mutation or the Network controller."""
import argparse,hashlib,json,os,secrets,shutil,subprocess,sys,time,uuid
from pathlib import Path
from executor import Executor,ROOT,REHEARSAL,REHEARSAL_FINAL,REHEARSAL_FINAL2,canonical,inspect,need,projection,run,sha,write
LANE=os.environ.get('D10_REHEARSAL_LANE','development');need(LANE in ('development','final','final2'),'REHEARSAL_LANE')
OUT=ROOT/('target/d10-phase3-20261113/rehearsal-'+LANE if LANE!='development' else 'target/d10-phase3-20261113/rehearsal');PRIVATE=OUT/'private';PROJECT={'development':REHEARSAL,'final':REHEARSAL_FINAL,'final2':REHEARSAL_FINAL2}[LANE];SUBNET={'development':'10.253.232.0/27','final':'10.253.230.0/27','final2':'10.253.228.0/27'}[LANE];BOOTSUBNET={'development':'10.253.231.0/27','final':'10.253.229.0/27','final2':'10.253.227.0/27'}[LANE];PROXY_IP=SUBNET.rsplit('.',1)[0]+'.25'
P2=ROOT/'target/d10-phase2-20261113';HERE=Path(__file__).resolve().parent
def compose(*args,timeout=240):return run('docker','compose','-p',PROJECT,'-f',str(OUT/'source.compose.json'),*args,timeout=timeout)
def save(name,value):write(OUT/name,value)
def sql(statement):return compose('exec','-T','mysql','mysql','--defaults-extra-file=/fixture/root.cnf','-Nse',statement).decode().strip()
def prepare():
    need(not PRIVATE.exists(),'REHEARSAL_ALREADY_PREPARED');OUT.mkdir(parents=True,exist_ok=True)
    need((P2/'private/owner').read_text()== 'zt-d10-offline-20261113','NOT_SYNTHETIC_SOURCE')
    import ipaddress
    for name in run('docker','network','ls','--format','{{.Name}}').decode().split():
        for entry in json.loads(run('docker','network','inspect',name))[0].get('IPAM',{}).get('Config') or []:
            if entry.get('Subnet'):
                block=ipaddress.ip_network(entry['Subnet']);need(block.version!=4 or not block.overlaps(ipaddress.ip_network(SUBNET)),'REHEARSAL_SUBNET_OVERLAP')
    PRIVATE.mkdir();roles=('mysql','redis','keycloak','installer','risk','backend','gateway','migrate','ingress','crl')
    for role in roles:shutil.copytree(P2/'private'/role,PRIVATE/role)
    for name in ('accounts.json','ca.crt','ca-with-crl.pem'):shutil.copyfile(P2/'private'/name,PRIVATE/name)
    (PRIVATE/'owner').write_text(PROJECT)
    for file in PRIVATE.rglob('*'):
        if file.is_file() and file.suffix in ('.conf','.properties','.args','.sh','.sql'):
            text=file.read_text();text=text.replace('10.253.234.',SUBNET.rsplit('.',1)[0]+'.')
            text='\n'.join(line for line in text.splitlines() if not line.strip().startswith('app.security.authority.'))+'\n'
            file.write_text(text,newline='\n')
    realm=json.loads((PRIVATE/'installer/DoAn-realm.json').read_text())
    reverse={'d10-cookie':'auth-cookie','d10-password':'auth-username-password-form','d10-otp':'auth-otp-form','d10-recovery':'auth-recovery-authn-code-form'}
    for flow in realm['authenticationFlows']:
        flow['authenticationExecutions']=[e for e in flow['authenticationExecutions'] if e.get('authenticator')!='d10-auth-ticket']
        for e in flow['authenticationExecutions']:e['authenticator']=reverse.get(e.get('authenticator'),e.get('authenticator')) if 'authenticator'in e else None
    removed={'zerotrust-issuer-security','zerotrust-gateway-security','zerotrust-portal-security','zerotrust-native-security'}
    realm['clients']=[c for c in realm['clients'] if c['clientId']not in removed];realm['users']=[u for u in realm['users'] if u.get('serviceAccountClientId')not in removed]
    realm.get('roles',{}).get('client',{}).pop('zerotrust-native-security',None)
    realm['roles']['client']['zerotrust-risk-api']=[r for r in realm['roles']['client']['zerotrust-risk-api'] if not r['name'].startswith('security:')]
    (PRIVATE/'installer/DoAn-realm.json').write_text(json.dumps(realm))
    with (PRIVATE/'risk/application.properties').open('a') as f:f.write('\nrisk.network-v2.mode=SHADOW\nrisk.network-v2.retention-enabled=false\nrisk.policy.model=BASELINE_B0\n')
    original=json.loads((P2/'compose.json').read_text());live=json.loads((ROOT/'target/d10-phase3-20261113/live-preflight.json').read_text())
    model={'services':{},'volumes':original['volumes'],'networks':{'core':{'internal':True,'ipam':{'config':[{'subnet':SUBNET}]}},'bootstrap':{'internal':True,'ipam':{'config':[{'subnet':BOOTSUBNET}]}}}}
    for role in ('materialize','mysql','mysql80','crl','redis','migrate','migrate80','keycloak-init','keycloak','risk','backend','gateway','frontend','ingress','check'):
        service=original['services'][role];service['labels']={'io.zerotrust.scope':PROJECT};service.pop('healthcheck',None)
        if role=='mysql':service['networks']={'core':{'aliases':['mysql']}}
        elif role=='mysql80':service['networks']={'bootstrap':{'aliases':['mysql']}}
        elif role=='migrate80':service['networks']=['bootstrap']
        elif role=='crl':service['networks']={n:{'aliases':['crl.full-function.test']} for n in ('core','bootstrap')}
        elif role=='ingress':service['networks']={'core':{'ipv4_address':PROXY_IP,'aliases':['portal.full-function.test','auth.full-function.test']}}
        elif role=='materialize':service.pop('networks',None)
        else:service['networks']=['core']
        if role in ('keycloak','keycloak-init'):service['image']=live['inventory']['keycloak']['image'];service['environment']={k:v for k,v in service['environment'].items() if not k.startswith('ZT_SECURITY_')}
        elif role in ('risk','backend','gateway','frontend'):service['image']=live['inventory'][role]['image']
        elif role=='migrate':service['image']=live['inventory']['risk']['image']
        elif role=='migrate80':service['image']=live['inventory']['risk']['image']
        if 'volumes'in service:
            service['volumes']=[v.replace(str(P2/'private'),str(PRIVATE)).replace(str(P2),str(OUT)) for v in service['volumes']]
        if role=='check':
            service['volumes']=[str(PRIVATE)+':/private:ro',str(HERE)+':/scripts:ro',str(OUT/'public')+':/public:ro',str(OUT)+':/results'];service['networks']={'core':{}}
        model['services'][role]=service
    (OUT/'public').mkdir();shutil.copyfile(PRIVATE/'ca-with-crl.pem',OUT/'public/internal-ca-with-crl.pem');shutil.copyfile(PRIVATE/'ca.crt',OUT/'public/browser-root.crt')
    save('source.compose.json',model);print('PASS fresh disposable V7 rehearsal model; exact old pins, no host ports, no owner data',flush=True)
def start():
    compose('run','--no-deps','materialize');compose('up','-d','mysql','mysql80','crl','redis')
    deadline=time.monotonic()+150
    while True:
        try:need(sql('SELECT 1')=='1','MYSQL_WAIT');compose('exec','-T','mysql80','mysql','--defaults-extra-file=/fixture/root.cnf','-Nse','SELECT 1');break
        except Exception:need(time.monotonic()<deadline,'REHEARSAL_MYSQL_START');time.sleep(1)
    # V5 explicitly requires MySQL8.0; current live is already V7 on8.4.
    # Bootstrap only this fresh fixture on8.0, then transfer its V7 schema to8.4.
    compose('run','--no-deps','migrate80',timeout=180)
    legacy=compose('exec','-T','mysql80','mysqldump','--defaults-extra-file=/fixture/root.cnf','--single-transaction','--set-gtid-purged=OFF','--no-tablespaces','pd_staging_risk')
    run('docker','compose','-p',PROJECT,'-f',str(OUT/'source.compose.json'),'exec','-T','mysql','mysql','--defaults-extra-file=/fixture/root.cnf','pd_staging_risk',data=legacy)
    need(sql('SELECT MAX(CAST(version AS UNSIGNED)) FROM pd_staging_risk.flyway_schema_history')=='7','REHEARSAL_NOT_V7');compose('stop','mysql80')
    compose('up','-d','keycloak-init')
    deadline=time.monotonic()+180
    while True:
        x=inspect(PROJECT+'-keycloak-init-1');need(x['State']['Running'],'REHEARSAL_IMPORT_EXITED')
        p=subprocess.run(['docker','exec',x['Name'],'bash','/run/secrets/ready.sh'],capture_output=True)
        if p.returncode==0:break
        need(time.monotonic()<deadline,'REHEARSAL_IMPORT_TIMEOUT');time.sleep(2)
    compose('stop','--timeout','30','keycloak-init');compose('up','-d','keycloak','risk','backend','gateway','frontend','ingress','check')
    # Two explicitly synthetic V7 pending rows reproduce the live preservation contract.
    actors=json.loads((PRIVATE/'accounts.json').read_text());orphan=str(uuid.uuid4());subject=actors['student_b']['id'];ops=[str(uuid.uuid4()),str(uuid.uuid4())]
    for sid,op,generation in [(subject,ops[0],1),(orphan,ops[1],2)]:
        sql("INSERT INTO pd_staging_risk.subject_device_trust(subject_id,generation,pending_operation_id) VALUES('%s',%d,'%s'); INSERT INTO pd_staging_risk.device_trust_revocations(operation_id,subject_id,requested_by,generation,revoked_count,revoked_at) VALUES('%s','%s','d10-rehearsal',%d,0,UTC_TIMESTAMP(6))"%(sid,generation,op,op,sid,generation))
    print('PASS V7 baseline started; native old flow, two synthetic existing pending subjects',flush=True)
def make_plan():
    model=json.loads((OUT/'source.compose.json').read_text());roles=('mysql','redis','crl','keycloak','risk','backend','gateway','frontend','ingress')
    source={r:projection(PROJECT+'-'+r+'-1') for r in roles};config={r:PROJECT+'_'+r+'-config' for r in ('mysql','redis','crl','keycloak','risk','backend','gateway','ingress','migrate')}
    volumes=list(config.values())+[PROJECT+'_redis-data'];files={}
    for role,names in {'keycloak':['/run/secrets/keycloak.conf'],'risk':['/run/demo/application.properties','/run/demo/jvm.args'],'backend':['/run/demo/application.properties','/run/demo/jvm.args'],'gateway':['/run/demo/application.properties','/run/demo/jvm.args'],'ingress':['/run/demo/nginx.conf']}.items():files[role]={name:run('docker','exec',source[role]['name'],'sha256sum',name).decode().split()[0] for name in names}
    release=json.loads((HERE/'binding.offline.json').read_text());runid=uuid.uuid4().hex[:16]
    plan={'version':1,'project':PROJECT,'run_id':runid,'approval_nonce':secrets.token_hex(24),'output':OUT.relative_to(ROOT).as_posix()+'/run-'+runid,'source':source,'configuration_hashes':files,'config_volumes':config,'source_volumes':volumes,'core_network':PROJECT+'_core','maintenance_network':PROJECT+'_core','ingress_core_ip':'10.253.232.25','candidate_images':{r:x['id'] for r,x in release['images'].items()},'utility_image':'redis@sha256:ec1c2d3603c3d7d65b153bedda0248b641aa3bd7684503406b27b9e870ac0796','pending_count':2,'trust_state_sha256':sha(sql("SELECT subject_id,generation,COALESCE(pending_operation_id,'') FROM pd_staging_risk.subject_device_trust ORDER BY subject_id").encode()),'live_authorized':False}
    plan['ingress_core_ip']=PROXY_IP
    updated=ROOT/'target/d10-phase3-20261113/frontend-artifact.json'
    if updated.exists():plan['candidate_images']['frontend']=json.loads(updated.read_text())['id']
    plan['trust_rows']=json.loads(sql("SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT('subject',subject_id,'generation',generation,'pending',pending_operation_id)),JSON_ARRAY()) FROM pd_staging_risk.subject_device_trust"))
    plan['designated_ids']=[a['id'] for key,a in json.loads((PRIVATE/'accounts.json').read_text()).items() if key in ('admin','student_a')]
    save('execution-plan.json',plan);return plan
def inputs(plan):
    path=OUT/'new-service-inputs.dpapi';entropy=plan['run_id'].encode();from executor import dpapi
    if path.exists():return json.loads(dpapi(path.read_bytes(),entropy,True))
    values={name:secrets.token_urlsafe(36) for name in ('zerotrust-issuer-security','zerotrust-portal-security','zerotrust-gateway-security')};values.update(bootstrap_client='d10-maintenance-'+plan['run_id'],bootstrap_secret=secrets.token_urlsafe(40),run_id=plan['run_id']);path.write_bytes(dpapi(canonical(values),entropy));return values
def rpc(plan,action):
    values=inputs(plan);values['action']=action;values['source_browser_alias']='zerotrust-browser-recovery'
    response=subprocess.run(['docker','compose','-p',PROJECT,'-f',str(OUT/'source.compose.json'),'exec','-T','check','/opt/tools/bin/python','/scripts/native_admin.py'],input=canonical(values),capture_output=True,timeout=240)
    result=json.loads(response.stdout);need(result['status']=='PASS','NATIVE_ADMIN_'+result.get('reason','FAILED'));save('native-'+action+'.json',result);return result
def execute():
    plan=json.loads((OUT/'execution-plan.json').read_text()) if (OUT/'execution-plan.json').exists() else make_plan();e=Executor(plan,'rehearsal');values=inputs(plan)
    if e.j['phase']=='PREPARED':e.quiesce();print('PASS quiesced all rehearsal writers and direct/API ingress',flush=True)
    if e.j['phase']=='QUIESCED':e.checkpoint();print('PASS encrypted consistent checkpoint with fresh DPAPI key',flush=True)
    if e.j['phase']=='CHECKPOINTED':e.maintenance();print('PASS maintenance ingress started closed',flush=True)
    if e.j['phase']=='MAINTENANCE':e.verify_restore();print('PASS independent isolated restore exact content',flush=True)
    if e.j['phase']=='RESTORE_VERIFIED':e.install_artifacts(values);print('PASS additive V9 + strict candidates installed under maintenance',flush=True)
    if e.j['phase']=='ARTIFACTS_INSTALLED':e.bootstrap(values);print('PASS native issuer/authority bootstrap',flush=True)
    if e.j['phase']=='ISSUER_AUTHORITY_STARTED':
        result=rpc(plan,'provision');e.record('NATIVE_PROVISIONED',result);print('PASS exact native flow clone, dedicated roles, disabled unmanaged user attributes',flush=True)
    if e.j['phase']=='NATIVE_PROVISIONED':e.start_api_private();print('PASS all five candidates behind private acceptance ingress; public remains closed',flush=True)
    print('REHEARSAL_STAGE '+e.j['phase'],flush=True)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=('prepare','start','execute'));args=p.parse_args()
    try:globals()[args.action]()
    except Exception as e:print('FAIL '+(str(e) if type(e).__name__ in ('Blocked','RuntimeError') else type(e).__name__),file=sys.stderr);sys.exit(1)
