"""D10 disposable native fixture. No active controller, binding, data or host port."""
import argparse,hashlib,ipaddress,json,os,secrets,shutil,subprocess,sys,time,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
OUT=ROOT/'target/d10-phase2-20261113'
STATE=OUT/'private'
PROJECT='zt-d10-offline-20261113'
SUBNET='10.253.234.0/27'
IMAGES={'risk':'zt-d10/risk:offline-20261113','keycloak':'zt-d10/keycloak:offline-20261113','backend':'zt-d10/backend:offline-20261113','gateway':'zt-d10/gateway:offline-20261113'}
MYSQL84='sha256:8afece5fe884d21fc2944b5f200daa9c94a00ba98c196a5765ae2bb665a7ee80'
MYSQL80='sha256:1c9444499b0ab9000f008ce719c7fc2c2c279c97aae542356c9a1a7c03819f5d'
REDIS='redis@sha256:ec1c2d3603c3d7d65b153bedda0248b641aa3bd7684503406b27b9e870ac0796'
NGINX='nginx:1.30.6-alpine@sha256:bb8f722b4be005fcd7827816a136ab779fd40185d85b5171be915cc7fc0575c7'
V7='sha256:85a7e95acf33156571d4cc37d1e30c327d715b668bef65b4323e724b8a463fe7'
def need(ok,reason):
    if not ok:raise RuntimeError(reason)
def run(*args,data=None,check=True,timeout=300):
    p=subprocess.run(args,cwd=ROOT,input=data,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=timeout)
    if check and p.returncode:raise RuntimeError('COMMAND_FAILED_'+args[0]+'_'+str(p.returncode)+'_DETAILS_WITHHELD')
    return p
def save(name,value):
    OUT.mkdir(parents=True,exist_ok=True);temp=OUT/(name+'.tmp');temp.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8');temp.replace(OUT/name)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def snapshot():
    ids=run('docker','ps','-aq').stdout.split()
    fmt='{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"started":{{json .State.StartedAt}},"running":{{json .State.Running}},"restarts":{{json .RestartCount}}}'
    return {r['name']:r for r in (json.loads(line) for line in run('docker','inspect','--format',fmt,*ids).stdout.splitlines()) if not r['name'].startswith('/'+PROJECT+'-')}
def compose(*args,data=None,check=True,timeout=300):
    need(PROJECT=='zt-d10-offline-20261113' and str(OUT.resolve()).endswith('target\\d10-phase2-20261113') if os.name=='nt' else OUT.name=='d10-phase2-20261113','FIXTURE_SCOPE_DRIFT')
    return run('docker','compose','-p',PROJECT,'-f',str(OUT/'compose.json'),*args,data=data,check=check,timeout=timeout)
def owned():
    model=json.loads((OUT/'compose.json').read_text())
    for s in model['services'].values():
        need(not s.get('ports') and s.get('labels',{}).get('io.zerotrust.scope')==PROJECT,'FOREIGN_OR_PUBLISHED_SERVICE')
        for m in s.get('volumes',[]):
            source=m.split(':',1)[0] if not (os.name=='nt' and len(m)>1 and m[1]==':') else m.rsplit(':',2)[0]
            need(source in model['volumes'] or str(OUT) in m or str(HERE) in m,'FOREIGN_MOUNT')
    ids=run('docker','ps','-aq','--filter','label=com.docker.compose.project='+PROJECT).stdout.split()
    if ids:
        fmt='{{.Name}} {{index .Config.Labels "io.zerotrust.scope"}} {{json .HostConfig.PortBindings}}'
        for line in run('docker','inspect','--format',fmt,*ids).stdout.splitlines():
            need(line.startswith('/'+PROJECT+'-') and (' '+PROJECT+' ') in line and line.endswith(('null','{}')),'CONTAINER_SCOPE_DRIFT')
def prepare():
    need(not STATE.exists(),'EXISTING_FIXTURE_PRIVATE_STATE')
    save('preservation-before.json',snapshot())
    for name in run('docker','network','ls','--format','{{.Name}}').stdout.split():
        for c in json.loads(run('docker','network','inspect',name).stdout)[0].get('IPAM',{}).get('Config') or []:
            if c.get('Subnet'):
                block=ipaddress.ip_network(c['Subnet'],strict=False)
                need(block.version!=4 or all(not block.overlaps(ipaddress.ip_network(candidate)) for candidate in (SUBNET,'10.253.233.0/27')),'SUBNET_OVERLAP')
    import operate as full
    b=full.base
    full.PROJECT=PROJECT;full.OUT=OUT;full.STATE=STATE;full.SUBNET=SUBNET;full.PROXY_IP='10.253.234.25';full.HIGH_TEST_IP='10.253.234.27'
    b.STATE=STATE;b.PROJECT=b.SCOPE=PROJECT;b.SUBNET=ipaddress.ip_network(SUBNET)
    b.PORT=39443;b.PORTAL_HOST=full.PORTAL_HOST;b.AUTH_HOST=full.AUTH_HOST;b.REALM='DoAn'
    b.PORTAL='https://portal.full-function.test:39443';b.AUTH='https://auth.full-function.test:39443'
    b.ISSUER=b.AUTH+'/realms/DoAn';b.JWK='https://keycloak:8443/realms/DoAn/protocol/openid-connect/certs';b.TOKEN='https://keycloak:8443/realms/DoAn/protocol/openid-connect/token'
    full.prepare() # generates ONLY this fresh namespace; never invokes configure/install
    doc=json.loads((STATE/'installer/DoAn-realm.json').read_text())
    credentials={c:secrets.token_urlsafe(36) for c in ('zerotrust-issuer-security','zerotrust-portal-security','zerotrust-gateway-security')}
    doc['roles']['client'].setdefault('zerotrust-risk-api',[]).extend({'name':r} for r in ('security:authorize','security:issue','security:reset'))
    doc['roles']['client']['zerotrust-native-security']=[{'name':'security:reset-native'}]
    doc['clients'].append({'clientId':'zerotrust-native-security','enabled':True,'bearerOnly':True,'protocol':'openid-connect'})
    for name,secret in credentials.items():
        audiences=['zerotrust-risk-api']+(['zerotrust-native-security'] if name=='zerotrust-portal-security' else [])
        doc['clients'].append({'clientId':name,'enabled':True,'publicClient':False,'secret':secret,'serviceAccountsEnabled':True,'standardFlowEnabled':False,'directAccessGrantsEnabled':False,'protocol':'openid-connect','defaultClientScopes':['basic','roles'],
            'protocolMappers':[{'name':'d10-audience-'+a,'protocol':'openid-connect','protocolMapper':'oidc-audience-mapper','config':{'included.client.audience':a,'access.token.claim':'true','id.token.claim':'false'}} for a in audiences]})
        roles={'zerotrust-risk-api':['security:authorize']+(['security:issue'] if name=='zerotrust-issuer-security' else ['security:reset'] if name=='zerotrust-portal-security' else [])}
        if name=='zerotrust-portal-security':roles['zerotrust-native-security']=['security:reset-native']
        doc['users'].append({'username':'service-account-'+name,'enabled':True,'serviceAccountClientId':name,'clientRoles':roles})
    actors=json.loads((STATE/'accounts.json').read_text())
    for actor in actors.values():
        # Fixture-only OTP bytes; never read a credential from the owner realm.
        actor['otp']=secrets.token_hex(16)
        u=next(u for u in doc['users'] if u.get('id')==actor['id'])
        u['requiredActions']=[];u['totp']=True
        u.setdefault('credentials',[]).append({'type':'otp','userLabel':'d10-disposable','secretData':json.dumps({'value':actor['otp']}),'credentialData':json.dumps({'subType':'totp','digits':6,'counter':0,'period':30,'algorithm':'HmacSHA1'})})
    b.save('.','accounts.json',json.dumps(actors))
    for flow in doc['authenticationFlows']:
        for e in flow.get('authenticationExecutions',[]):
            replace={'auth-cookie':'d10-cookie','auth-username-password-form':'d10-password','auth-otp-form':'d10-otp','auth-recovery-authn-code-form':'d10-recovery'}
            if e.get('authenticator') in replace:e['authenticator']=replace[e['authenticator']]
        # Tail is in the forms branch; SSO is gated separately by the cookie and token hooks.
        if any(e.get('authenticator')=='d10-password' for e in flow.get('authenticationExecutions',[])):
            flow['authenticationExecutions'].append({'authenticator':'d10-auth-ticket','authenticatorFlow':False,'requirement':'REQUIRED','priority':1000,'userSetupAllowed':False})
    for c in doc['clients']:
        if c['clientId']=='zerotrust-spa':c['redirectUris'].append(b.PORTAL+'/d10/callback')
    # Reserved receipt attributes must not be writable through native Account Profile.
    doc.setdefault('attributes',{})['d10.fixture']='true'
    b.save('installer','DoAn-realm.json',json.dumps(doc))
    for role in ('installer','keycloak'):
        b.save(role,'d10-security-secret',credentials['zerotrust-issuer-security'])
        p=STATE/role/'keycloak.conf';b.save(role,p.name,p.read_text()+'\nlog-level=info,org.keycloak.events:error\n')
    for role,client in (('backend','zerotrust-portal-security'),('gateway','zerotrust-gateway-security')):
        b.save(role,'d10-security-secret',credentials[client]);p=STATE/role/'application.properties'
        b.save(role,p.name,p.read_text()+f'\napp.security.authority.base-url=https://risk:8443\napp.security.authority.token-endpoint={b.TOKEN}\napp.security.authority.client-id={client}\napp.security.authority.secret-file=/run/demo/d10-security-secret\napp.security.authority.native-effects-url=https://keycloak:8443/realms/DoAn/d10-security/effects\n')
    b.save('.','d10-service-credentials.json',json.dumps(credentials))
    services={};volumes={}
    for role in ('mysql','redis','keycloak','installer','risk','backend','gateway','migrate','ingress','crl'):volumes[role+'-config']={}
    for role in ('mysql-data','mysql80-data','redis-data'):volumes[role]={}
    def common(image):return dict(image=image,platform='linux/amd64',pull_policy='never',restart='no',labels={'io.zerotrust.scope':PROJECT},networks=['core'])
    for name in ('mysql','mysql80'):
        services[name]={**common(MYSQL84 if name=='mysql' else MYSQL80),'mem_limit':'768m','environment':{'MYSQL_ROOT_PASSWORD_FILE':'/fixture/root-password'},'entrypoint':['bash','-ec'],
            'command':['cp /fixture/init.sql /docker-entrypoint-initdb.d/10-d10.sql; chmod 0444 /docker-entrypoint-initdb.d/10-d10.sql; exec docker-entrypoint.sh mysqld --require-secure-transport=ON --ssl-ca=/fixture/ca.crt --ssl-cert=/fixture/server.crt --ssl-key=/fixture/server.key --default-time-zone=+00:00 --innodb-buffer-pool-size=64M'],
            'volumes':['mysql-config:/fixture:ro',('mysql-data' if name=='mysql' else 'mysql80-data')+':/var/lib/mysql'],
            'healthcheck':{'test':['CMD-SHELL',"mysql --defaults-extra-file=/fixture/school.cnf -Nse 'SELECT 1' | grep -qx 1"],'interval':'3s','timeout':'4s','retries':45},'networks':{'core' if name=='mysql' else 'bootstrap':{'aliases':['mysql']}}}
    services['materialize']={**common(REDIS),'network_mode':'none','user':'0','entrypoint':['sh','/script/materialize.sh'],'tmpfs':['/data'],'volumes':[str(HERE/'materialize.sh')+':/script/materialize.sh:ro',str(STATE)+':/in:ro']+[r+'-config:/out/'+r for r in ('mysql','redis','keycloak','installer','risk','backend','gateway','migrate','ingress','crl')]};del services['materialize']['networks']
    services['crl']={**common(NGINX),'user':'101:101','read_only':True,'tmpfs':['/tmp:mode=1777','/var/cache/nginx:mode=1777'],'entrypoint':['nginx','-c','/run/demo/crl.conf','-g','daemon off;'],'volumes':['crl-config:/run/demo:ro'],'networks':{n:{'aliases':['crl.full-function.test']} for n in ('core','bootstrap')},'mem_limit':'64m'}
    services['redis']={**common(REDIS),'mem_limit':'96m','command':['redis-server','/fixture/redis.conf'],'volumes':['redis-config:/fixture:ro','redis-data:/data']}
    for name in ('migrate','migrate80'):
        services[name]={**common(IMAGES['risk'] if name=='migrate' else V7),'mem_limit':'384m','entrypoint':['java','@/run/demo/jvm.args','-cp','/app/unpacked/BOOT-INF/classes:/app/unpacked/BOOT-INF/lib/*:/app/tools','Migrate'],'volumes':['migrate-config:/run/demo:ro'],'networks':['core' if name=='migrate' else 'bootstrap']}
    for name in ('keycloak','keycloak-init'):
        role='installer' if name.endswith('init') else 'keycloak'
        services[name]={**common(IMAGES['keycloak']),'user':'65532:65532','mem_limit':'640m','cap_drop':['ALL'],'security_opt':['no-new-privileges:true'],
            'environment':{'PUBLIC_DEMO_RISK_CALLER_SECRET_FILE':'/run/secrets/risk-caller-client-secret','ZT_SECURITY_AUTHORITY':'https://risk:8443','ZT_SECURITY_TOKEN_ENDPOINT':b.TOKEN,'ZT_SECURITY_SECRET_FILE':'/run/secrets/d10-security-secret','ZT_SECURITY_REALM':'DoAn','JAVA_OPTS_APPEND':'-Xms96m -Xmx320m -XX:ActiveProcessorCount=2 -Dcom.sun.net.ssl.checkRevocation=true -Dcom.sun.security.enableCRLDP=true'},
            'command':['--config-file=/run/secrets/keycloak.conf','start','--optimized']+(['--import-realm'] if role=='installer' else []),'volumes':[role+'-config:/run/secrets:ro']+(['installer-config:/opt/keycloak/data/import:ro'] if role=='installer' else []),'healthcheck':{'test':['CMD','bash','/run/secrets/ready.sh'],'interval':'4s','timeout':'4s','retries':75,'start_period':'20s'}}
    for role in ('risk','backend','gateway'):
        services[role]={**common(IMAGES[role]),'mem_limit':'512m','user':'10001:10001','read_only':True,'tmpfs':['/tmp:mode=1777'],'volumes':[role+'-config:/run/demo:ro']}
    services['ingress']={**common(NGINX),'mem_limit':'64m','user':'101:101','read_only':True,'tmpfs':['/tmp:mode=1777','/var/cache/nginx:mode=1777'],'entrypoint':['nginx','-c','/run/demo/nginx.conf','-g','daemon off;'],'volumes':['ingress-config:/run/demo:ro'],'networks':{'core':{'ipv4_address':'10.253.234.25','aliases':['portal.full-function.test','auth.full-function.test']}}}
    services['frontend']={**common(NGINX),'mem_limit':'32m'}
    services['check']={**common('zt-full-function/browser:20261111-1'),'mem_limit':'1g','shm_size':'256m','entrypoint':['sleep','infinity'],'volumes':[str(STATE)+':/private:ro',str(HERE)+':/tests:ro',str(OUT)+':/results']}
    save('compose.json',{'services':services,'networks':{'core':{'internal':True,'ipam':{'config':[{'subnet':SUBNET}]}},'bootstrap':{'internal':True,'ipam':{'config':[{'subnet':'10.253.233.0/27'}]}}},'volumes':volumes})
    owned();need(snapshot()==json.loads((OUT/'preservation-before.json').read_text()),'ACTIVE_CHANGED')
    print('PASS fresh D10 fixture configuration; no host ports or owner credentials',flush=True)
def build():
    for role in IMAGES:
        work=OUT/'build'/role;work.mkdir(parents=True,exist_ok=True)
        jars={'risk':'risk-scoring-service/target/risk-scoring-service-0.0.1-SNAPSHOT.jar','keycloak':'keycloak-risk-extension/target/keycloak-risk-extension.jar','backend':'target/zerotrust-0.0.1-SNAPSHOT.jar','gateway':'gateway/target/zerotrust-gateway-0.0.1-SNAPSHOT.jar'}
        jar=ROOT/jars[role];shutil.copyfile(jar,work/'application.jar')
        if role=='keycloak':
            shutil.copytree(ROOT/'keycloak-theme/zerotrust',work/'theme',dirs_exist_ok=True)
            dockerfile='FROM dhi.io/keycloak@sha256:ba20b9bd0ecd48047240249acaff19aa882db5480a03659fcdf14d4b7bd9d424\nCOPY --chown=65532:65532 application.jar /opt/keycloak/providers/keycloak-risk-extension.jar\nCOPY --chown=65532:65532 theme/ /opt/keycloak/themes/zerotrust/\nUSER 65532:65532\nRUN --network=none /opt/keycloak/bin/kc.sh build --db=mysql --health-enabled=true\n'
        else:
            bases={'risk':'zt-full-function/risk:phase2-locking-20261111-1','backend':'zt-pd-r22/backend:rc1','gateway':'zt-pd-r22/gateway:rc1'}
            pins={'risk':'sha256:1ec3c4db626d6c232ca9a30c61188d69e883d40eb0005c29bd0d15921258686a','backend':'sha256:f7d37dea934560fe61c0f4b0548aefbc4e5b0896ffeff7fa7f9cdb5be8e4c690','gateway':'sha256:7c2c692e807c985d05a83a11cddd33606186a660cf2a22f89754514a7196fb69'}
            need(run('docker','image','inspect','--format','{{.Id}}',bases[role]).stdout.strip()==pins[role],'BUILD_BASE_DRIFT')
            dockerfile='FROM '+bases[role]+'\nCOPY application.jar /app/application.jar\n'
            if role=='risk':
                with zipfile.ZipFile(jar) as z:z.extractall(work/'unpacked')
                dockerfile+='COPY unpacked/ /app/unpacked/\n'
        dockerfile+='LABEL io.zerotrust.scope="'+PROJECT+'"\n';(work/'Dockerfile').write_text(dockerfile)
        result=run('docker','build','--network','none','--pull=false','--tag',IMAGES[role],str(work),check=False,timeout=420)
        (OUT/(role+'-build.log')).write_text(result.stdout+result.stderr)
        need(result.returncode==0,'BUILD_FAILED_'+role)
        save(role+'-artifact.json',{'image':IMAGES[role],'id':run('docker','image','inspect','--format','{{.Id}}',IMAGES[role]).stdout.strip(),'jar_sha256':sha(jar)})
        print('PASS isolated image '+role,flush=True)
def sql(service,statement,data=None):return compose('exec','-T',service,'mysql','--defaults-extra-file=/fixture/root.cnf','-Nse',statement,data=data).stdout.strip()
def start():
    owned();compose('run','--no-deps','materialize',timeout=90);compose('up','-d','crl')
    compose('up','-d','--wait','--wait-timeout','180','mysql80',timeout=200)
    compose('run','--no-deps','migrate80',timeout=150)
    before=sql('mysql80','SELECT version,checksum,success FROM pd_staging_risk.flyway_schema_history ORDER BY installed_rank')
    need([x.split('\t')[0] for x in before.splitlines()]==list('1234567'),'BASELINE_NOT_V7')
    dump=compose('exec','-T','mysql80','mysqldump','--defaults-extra-file=/fixture/root.cnf','--single-transaction','--set-gtid-purged=OFF','--no-tablespaces','pd_staging_risk').stdout
    compose('stop','--timeout','45','mysql80');compose('up','-d','--wait','--wait-timeout','180','mysql',timeout=200)
    compose('exec','-T','mysql','mysql','--defaults-extra-file=/fixture/root.cnf','pd_staging_risk',data=dump);compose('run','--no-deps','migrate',timeout=150)
    after=sql('mysql','SELECT version,checksum,success FROM pd_staging_risk.flyway_schema_history ORDER BY installed_rank')
    need(after.startswith(before+'\n') and after.splitlines()[-1].startswith('9\t'),'V7_COMPATIBILITY_FAILED')
    save('migration.json',{'status':'PASS','scope':'fresh synthetic V7 then additive V8; never active data','before':before,'after':after})
    compose('up','-d','redis','risk');compose('up','-d','--wait','--wait-timeout','360','keycloak-init',timeout=390)
    compose('stop','--timeout','60','keycloak-init');compose('up','-d','--wait','--wait-timeout','240','keycloak',timeout=260)
    compose('up','-d','backend','gateway','frontend','ingress','check');owned()
    print('PASS isolated native services started',flush=True)
def check():
    owned()
    proc=subprocess.Popen(['docker','compose','-p',PROJECT,'-f',str(OUT/'compose.json'),'exec','-T','check','/opt/tools/bin/python','/tests/d10_native_check.py'],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8',errors='replace')
    handled=set();deadline=time.monotonic()+1000
    while proc.poll() is None:
        need(time.monotonic()<deadline,'NATIVE_CHECK_TIMEOUT')
        control=OUT/'control.json'
        if control.exists():
            request=json.loads(control.read_text())
            if request['id'] not in handled:
                need(request['action'] in ('stop-risk','start-risk','stop-redis','start-redis','readonly-mysql','writable-mysql','stop-backend','start-backend'),'UNKNOWN_FIXTURE_CONTROL')
                owned();verb,role=request['action'].split('-')
                if verb=='readonly':sql('mysql','SET GLOBAL super_read_only=ON')
                elif verb=='writable':sql('mysql','SET GLOBAL super_read_only=OFF; SET GLOBAL read_only=OFF')
                elif verb=='stop':compose('stop','--timeout','20',role)
                else:compose('up','-d',role)
                save('control-ack.json',{'id':request['id']});handled.add(request['id'])
        time.sleep(.2)
    stdout,stderr=proc.communicate(timeout=15)
    safe='\n'.join(x for x in stdout.splitlines() if x.startswith(('PASS ','FAIL ')))+'\n';(OUT/'native.log').write_text(safe);print(safe,end='',flush=True)
    need(proc.returncode==0,'NATIVE_TEST_FAILED_SEE_SANITIZED_RECEIPT')
def preservation():
    after=snapshot();before=json.loads((OUT/'preservation-before.json').read_text());save('preservation-after.json',after)
    need(after==before,'PROTECTED_RUNTIME_CHANGED');print('PASS non-D10 container identities, pins, start times and restart counts unchanged',flush=True)
def refresh():
    """Rebuild/reload ONLY the explicitly owned disposable fixture, never the active project."""
    owned();build();compose('stop','--timeout','20','risk');compose('run','--no-deps','migrate',timeout=150)
    maintenance=STATE/'d10-maintenance.json'
    if not maintenance.exists():
        compose('stop','--timeout','20','keycloak')
        credential={'client_id':'d10-fixture-maintenance','secret':secrets.token_urlsafe(36)}
        env=dict(os.environ);env['D10_FIXTURE_BOOT_SECRET']=credential['secret']
        command=['docker','compose','-p',PROJECT,'-f',str(OUT/'compose.json'),'run','--no-deps','--env','D10_FIXTURE_BOOT_SECRET','keycloak-init','--config-file=/run/secrets/keycloak.conf','bootstrap-admin','service','--optimized','--no-prompt','--client-id',credential['client_id'],'--client-secret:env','D10_FIXTURE_BOOT_SECRET']
        result=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=150)
        need(result.returncode==0,'DISPOSABLE_MAINTENANCE_BOOTSTRAP_FAILED')
        maintenance.write_text(json.dumps(credential),encoding='utf-8')
    ledger=sql('mysql','SELECT version,checksum,success FROM pd_staging_risk.flyway_schema_history ORDER BY installed_rank')
    save('migration-latest.json',{'status':'PASS','scope':'disposable fixture only','ledger':ledger})
    compose('up','-d','--no-deps','--wait','--wait-timeout','150','keycloak','risk','backend','gateway',timeout=180)
    compose('restart','ingress') # fixture Nginx must resolve the recreated fixture upstream addresses
    preservation()
def proxy():
    """Test-only TLS fault proxy; absent from candidate images and any deployment binding."""
    owned();need((STATE/'owner').read_text()==PROJECT and STATE.resolve()==STATE,'PRIVATE_FIXTURE_SCOPE')
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
    import datetime as dt
    folder=STATE/'d10-proxy';folder.mkdir(exist_ok=True)
    if not (folder/'server.crt').exists():
        ca=x509.load_pem_x509_certificate((STATE/'ca.crt').read_bytes());ca_key=serialization.load_pem_private_key((STATE/'ca.key').read_bytes(),None)
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048);now=dt.datetime.now(dt.timezone.utc)
        cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'d10-fixture')])).issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=7))
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.SubjectAlternativeName([x509.DNSName('d10-fixture')]),False)
            .add_extension(x509.KeyUsage(True,False,True,False,False,False,False,False,False),True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),False).add_extension(x509.CRLDistributionPoints([x509.DistributionPoint([x509.UniformResourceIdentifier('http://crl.full-function.test:39445/ca.crl')],None,None,None)]),False).sign(ca_key,hashes.SHA256()))
        (folder/'server.crt').write_bytes(cert.public_bytes(serialization.Encoding.PEM));(folder/'server.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    model=json.loads((OUT/'compose.json').read_text())
    model['services']['check']['networks']={'core':{'aliases':['d10-fixture']}}
    for role in ('keycloak','keycloak-init'):model['services'][role]['environment']['ZT_SECURITY_AUTHORITY']='https://d10-fixture:8444'
    config=STATE/'backend/application.properties';text=config.read_text();text=text.replace('app.security.authority.native-effects-url=https://keycloak:8443/realms/DoAn/d10-security/effects','app.security.authority.native-effects-url=https://d10-fixture:8444/realms/DoAn/d10-security/effects');config.write_text(text)
    save('compose.json',model);owned()
    compose('run','--no-deps','materialize',timeout=90)
    compose('up','-d','--no-deps','check','keycloak',timeout=150);compose('restart','backend','ingress')
    preservation()
def frontend_build():
    owned();work=OUT/'build/frontend';source=work/'frontend';source.mkdir(parents=True,exist_ok=True)
    for path in (ROOT/'frontend').rglob('*'):
        relative=path.relative_to(ROOT/'frontend')
        if path.is_symlink() or any(p in ('node_modules','.next','.git','dist') or p.startswith('.env') for p in relative.parts):continue
        if path.is_file():
            target=source/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
    recipe=(ROOT/'deploy/docker/Dockerfile.frontend').read_text().replace('RUN if [ "$RUN_CHECKS" = "true" ]; then npm run check && npm test; fi && npm run build','RUN npm run typecheck && node --test tests/public-demo-ui.test.mjs && npm run build')
    recipe+='\nLABEL io.zerotrust.scope="'+PROJECT+'"\n';(work/'Dockerfile').write_text(recipe)
    image='zt-d10/frontend:offline-20261113';node='node@sha256:ec318aabf188af4e5488847eea4b24452650b9917140563e140762526a37f1df'
    args=['docker','build','--pull=false','--tag',image,'--build-arg','NODE_IMAGE='+node,'--build-arg','KEYCLOAK_URL=https://auth.full-function.test:39443','--build-arg','KEYCLOAK_REALM=DoAn','--build-arg','KEYCLOAK_CLIENT_ID=zerotrust-spa','--build-arg','API_BASE_URL=','--build-arg','PORTAL_MODE=standard','--build-arg','SITE_URL=https://portal.full-function.test:39443',str(work)]
    result=run(*args,check=False,timeout=600);(OUT/'frontend-build.log').write_text(result.stdout+result.stderr,encoding='utf-8');need(result.returncode==0,'FRONTEND_BUILD_FAILED')
    save('frontend-artifact.json',{'image':image,'id':run('docker','image','inspect','--format','{{.Id}}',image).stdout.strip(),'node_image':node,'node_version':'24.22.2','npm_version':'11.21.2','tests':'typecheck + public-demo-ui.test.mjs + Next production build; see frontend-build.log'})
    preservation();print('PASS exact Node24.22.2/npm11.21.2 targeted frontend checks and production image',flush=True)
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('prepare','build','start','check','preservation','refresh','proxy','frontend-build'));args=p.parse_args()
    globals()[args.action.replace('-','_')]()
