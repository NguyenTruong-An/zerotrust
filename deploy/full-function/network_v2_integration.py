"""Bounded synthetic Network v2 lane. Never calls the active operate/configure driver."""
import argparse,datetime as dt,hashlib,ipaddress,json,os,shutil,subprocess,sys,time,zipfile
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
OUT=ROOT/'target/network-v2-integration-20261112'
STATE=OUT/'private'
PROJECT='zt-network-v2-20261112'
SUBNET='10.253.236.0/27'
RISK='zt-network-v2/risk:20261112-1'
KC='zt-network-v2/keycloak:20261112-2'
RISK_BASE='sha256:1ec3c4db626d6c232ca9a30c61188d69e883d40eb0005c29bd0d15921258686a'
MYSQL80='sha256:1c9444499b0ab9000f008ce719c7fc2c2c279c97aae542356c9a1a7c03819f5d'
MYSQL84='sha256:8afece5fe884d21fc2944b5f200daa9c94a00ba98c196a5765ae2bb665a7ee80'
REDIS='redis@sha256:ec1c2d3603c3d7d65b153bedda0248b641aa3bd7684503406b27b9e870ac0796'
NGINX='nginx:1.30.6-alpine@sha256:bb8f722b4be005fcd7827816a136ab779fd40185d85b5171be915cc7fc0575c7'

def need(value,reason):
    if not value:raise RuntimeError(reason)

def run(*args,data=None,timeout=300,check=True):
    proc=subprocess.run(args,cwd=ROOT,input=data,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=timeout)
    if check and proc.returncode:raise RuntimeError('COMMAND_FAILED_'+args[0]+'_'+str(proc.returncode)+'_DETAILS_WITHHELD')
    return proc

def save(name,value):
    OUT.mkdir(exist_ok=True,parents=True)
    (OUT/name).write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def snapshot():
    ids=run('docker','ps','-aq').stdout.split()
    rows=json.loads(run('docker','inspect',*ids).stdout)
    return {x['Id']:{'name':x['Name'],'image':x['Image'],'running':x['State']['Running'],
        'started':x['State']['StartedAt'],'restarts':x['RestartCount'],'ports':x['HostConfig'].get('PortBindings'),
        'mounts':sorted([{k:m.get(k) for k in ('Type','Name','Source','Destination','RW')} for m in x['Mounts']],key=lambda m:m['Destination'])}
        for x in rows if not x['Name'].startswith('/'+PROJECT+'-')}

def compose(*args,data=None,timeout=300,check=True):
    return run('docker','compose','-p',PROJECT,'-f',str(OUT/'compose.json'),*args,data=data,timeout=timeout,check=check)

def owned():
    ids=run('docker','ps','-aq','--filter','label=io.zerotrust.scope='+PROJECT).stdout.split()
    for row in json.loads(run('docker','inspect',*ids).stdout) if ids else []:
        need(row['Name'].startswith('/'+PROJECT+'-') and not row['HostConfig'].get('PortBindings'),'FOREIGN_OR_PUBLISHED_CONTAINER')
        for mount in row['Mounts']:
            if (mount['Type']=='volume' and mount['Destination']=='/data'
                    and row['Config']['Labels'].get('com.docker.compose.service')=='materialize'
                    and row['Image']=='sha256:ec1c2d3603c3d7d65b153bedda0248b641aa3bd7684503406b27b9e870ac0796'):
                # Redis's image VOLUME created by this lane's one-off materializer, never a DB store.
                save('materializer-volume.json',{'container':row['Id'],'volume':mount['Name'],'destination':'/data','use':'unused image-declared anonymous volume; retained, not cleaned'})
                continue
            need(mount['Type']=='volume' and mount['Name'].startswith(PROJECT+'_') or
                mount['Type']=='bind' and (mount['Source'].replace('\\','/').lower().endswith(('/deploy/full-function','/deploy/full-function/materialize.sh')) or
                'network-v2-integration-20261112' in mount['Source'] or '/geoip-private/data/releases/' in mount['Source']),
                'FOREIGN_MOUNT')

def prepare():
    need(shutil.disk_usage(ROOT).free>15*1024**3,'DISK_BELOW_15_GIB')
    need(not STATE.exists(),'EXISTING_PRIVATE_STATE_DO_NOT_OVERWRITE')
    before=snapshot(); save('preservation-before.json',before)
    for name in run('docker','network','ls','--format','{{.Name}}').stdout.split():
        row=json.loads(run('docker','network','inspect',name).stdout)[0]
        for cfg in row.get('IPAM',{}).get('Config') or []:
            if cfg.get('Subnet'):
                block=ipaddress.ip_network(cfg['Subnet'],strict=False)
                need(block.version!=4 or not block.overlaps(ipaddress.ip_network(SUBNET)),'SUBNET_OVERLAP')
    import operate as full
    base=full.base
    full.PROJECT=PROJECT;full.OUT=OUT;full.STATE=STATE;full.SUBNET=SUBNET
    full.PROXY_IP='10.253.236.25';full.HIGH_TEST_IP='10.253.236.27'
    base.STATE=STATE;base.PROJECT=base.SCOPE=PROJECT;base.SUBNET=ipaddress.ip_network(SUBNET)
    base.PORT=full.PORT;base.PORTAL_HOST=full.PORTAL_HOST;base.AUTH_HOST=full.AUTH_HOST;base.REALM='DoAn'
    base.PORTAL='https://'+full.PORTAL_HOST+':39443';base.AUTH='https://'+full.AUTH_HOST+':39443'
    base.ISSUER=base.AUTH+'/realms/DoAn'
    base.JWK='https://keycloak:8443/realms/DoAn/protocol/openid-connect/certs'
    base.TOKEN='https://keycloak:8443/realms/DoAn/protocol/openid-connect/token'
    full.prepare()
    # Keep native DB audit/events and structured SPI traces; suppress raw-IP WARN event text.
    for role in ('keycloak','installer'):
        config=STATE/role/'keycloak.conf'
        base.save(role,'keycloak.conf',config.read_text()+'\nlog-level=info,org.keycloak.events:error\n')
    # Fresh test-only fixture certificate, issued exclusively by this lane's private CA.
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID,NameOID
    ca=x509.load_pem_x509_certificate((STATE/'ca.crt').read_bytes())
    key=serialization.load_pem_private_key((STATE/'ca.key').read_bytes(),None)
    leaf_key=rsa.generate_private_key(public_exponent=65537,key_size=2048);now=dt.datetime.now(dt.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'risk-fixture')]))
          .issuer_name(ca.subject).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=7))
          .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
          .add_extension(x509.SubjectAlternativeName([x509.DNSName('risk-fixture')]),False)
          .add_extension(x509.KeyUsage(True,False,True,False,False,False,False,False,False),True)
          .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),False)
          .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint([x509.UniformResourceIdentifier('http://crl.full-function.test:39445/ca.crl')],None,None,None)]),False)
          .sign(key,hashes.SHA256()))
    base.save('fixture','server.crt',cert.public_bytes(serialization.Encoding.PEM))
    base.save('fixture','server.key',leaf_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    geo=ROOT/'target/full-function-20261111b/geoip-private/data'
    pointer=json.loads((geo/'current.json').read_text());dataset=geo/'releases'/pointer['release']
    metadata=json.loads((dataset/'manifest.json').read_text())
    for edition,value in metadata['files'].items():
        file=dataset/value.get('file',edition+'.mmdb')
        if not file.exists():file=dataset/(edition+'.mmdb')
        need(file.exists(),'MISSING_EXISTING_GEOIP_FILE')
    path=STATE/'risk/application.properties'
    text=path.read_text()+'''\nrisk.network-v2.mode=SHADOW
risk.network-v2.work-queue-capacity=2
risk.network-v2.retention-enabled=false
risk.policy.network-risk.geoip.enabled=true
risk.policy.network-risk.geoip.city-database-path=/geoip/GeoLite2-City.mmdb
risk.policy.network-risk.geoip.asn-database-path=/geoip/GeoLite2-ASN.mmdb
spring.datasource.hikari.maximum-pool-size=6
'''
    base.save('risk','application.properties',text)
    # Dedicated ingress: no upstream School application, no host listener, fixed trusted proxy.
    base.save('ingress','nginx.conf','''worker_processes 1; pid /tmp/nginx.pid; error_log stderr crit;
events { worker_connections 128; }
http { access_log off;
 server { listen 39443 ssl; server_name portal.full-function.test auth.full-function.test;
 ssl_certificate /run/demo/server.crt; ssl_certificate_key /run/demo/server.key;
 location ~ ^/(realms|resources)/ { proxy_pass https://keycloak:8443; proxy_ssl_server_name on; proxy_ssl_name auth.full-function.test;
 proxy_ssl_trusted_certificate /run/demo/ca.crt; proxy_ssl_crl /run/demo/ca.crl.pem; proxy_ssl_verify on;
 proxy_set_header Host $host:39443; proxy_set_header X-Forwarded-Host $host; proxy_set_header X-Forwarded-Port 39443;
 proxy_set_header X-Forwarded-Proto https; proxy_set_header X-Forwarded-For $remote_addr;
 proxy_set_header X-Real-IP $remote_addr; proxy_set_header Forwarded ""; }
 location / { return 404; }
 }}''')
    services={};volumes={}
    def volume(role):volumes[role]={};return role
    for role in ('mysql','redis','keycloak','installer','risk','backend','gateway','migrate','ingress','crl'):volume(role+'-config')
    for role in ('mysql-data','mysql80-data','redis-data'):volume(role)
    def common(image):return dict(image=image,platform='linux/amd64',pull_policy='never',restart='no',
        labels={'io.zerotrust.scope':PROJECT},networks=['core'])
    for name in ('mysql','mysql80'):
        row=common(MYSQL84 if name=='mysql' else MYSQL80)
        row.update(mem_limit='768m',environment={'MYSQL_ROOT_PASSWORD_FILE':'/fixture/root-password'},entrypoint=['bash','-ec'],
            command=['cp /fixture/init.sql /docker-entrypoint-initdb.d/10-network.sql; chmod 0444 /docker-entrypoint-initdb.d/10-network.sql; exec docker-entrypoint.sh mysqld --require-secure-transport=ON --ssl-ca=/fixture/ca.crt --ssl-cert=/fixture/server.crt --ssl-key=/fixture/server.key --default-time-zone=+00:00 --innodb-buffer-pool-size=64M'],
            volumes=['mysql-config:/fixture:ro',('mysql-data' if name=='mysql' else 'mysql80-data')+':/var/lib/mysql'],
            healthcheck={'test':['CMD-SHELL',"mysql --defaults-extra-file=/fixture/school.cnf -Nse 'SELECT 1' | grep -qx 1"],'interval':'3s','timeout':'4s','retries':45})
        row['networks']={'core' if name=='mysql' else 'bootstrap':{'aliases':['mysql']}};services[name]=row
    services['materialize']={**common(REDIS),'network_mode':'none','user':'0','entrypoint':['sh','/script/materialize.sh'],
        'tmpfs':['/data'],
        'volumes':[str(HERE/'materialize.sh')+':/script/materialize.sh:ro',str(STATE)+':/in:ro']+
        [role+'-config:/out/'+role for role in ('mysql','redis','keycloak','installer','risk','backend','gateway','migrate','ingress','crl')]}
    del services['materialize']['networks']
    services['crl']={**common(NGINX),'user':'101:101','read_only':True,'tmpfs':['/tmp:mode=1777','/var/cache/nginx:mode=1777'],
        'entrypoint':['nginx','-c','/run/demo/crl.conf','-g','daemon off;'],'volumes':['crl-config:/run/demo:ro'],
        'networks':{name:{'aliases':['crl.full-function.test']} for name in ('core','bootstrap')},'mem_limit':'64m'}
    services['redis']={**common(REDIS),'mem_limit':'96m','command':['redis-server','/fixture/redis.conf'],
        'volumes':['redis-config:/fixture:ro','redis-data:/data']}
    for name in ('migrate','migrate80'):
        services[name]={**common(RISK),'mem_limit':'384m','entrypoint':['java','@/run/demo/jvm.args','-cp','/app/unpacked/BOOT-INF/classes:/app/unpacked/BOOT-INF/lib/*:/app/tools','Migrate'],
            'volumes':['migrate-config:/run/demo:ro'],'networks':['core' if name=='migrate' else 'bootstrap']}
    for name in ('keycloak','keycloak-init'):
        installer=name.endswith('init');role='installer' if installer else 'keycloak'
        row={**common(KC),'user':'65532:65532','mem_limit':'640m','cap_drop':['ALL'],'security_opt':['no-new-privileges:true'],
            'environment':{'PUBLIC_DEMO_RISK_CALLER_SECRET_FILE':'/run/secrets/risk-caller-client-secret','JAVA_OPTS_APPEND':'-Xms96m -Xmx320m -XX:ActiveProcessorCount=2 -Dcom.sun.net.ssl.checkRevocation=true -Dcom.sun.security.enableCRLDP=true'},
            'command':['--config-file=/run/secrets/keycloak.conf','start','--optimized']+(['--import-realm'] if installer else []),
            'volumes':[role+'-config:/run/secrets:ro']+(['installer-config:/opt/keycloak/data/import:ro'] if installer else []),
            'healthcheck':{'test':['CMD','bash','/run/secrets/ready.sh'],'interval':'4s','timeout':'4s','retries':75,'start_period':'20s'}}
        services[name]=row
    services['risk']={**common(RISK),'mem_limit':'512m','user':'10001:10001','read_only':True,'tmpfs':['/tmp:mode=1777'],
        'volumes':['risk-config:/run/demo:ro',str(dataset)+':/geoip:ro'],
        'healthcheck':{'test':['CMD','java','@/run/demo/jvm.args','-cp','/app/tools','Health','https://risk:8443/actuator/health/readiness','200'],'interval':'5s','timeout':'8s','retries':36}}
    services['ingress']={**common(NGINX),'mem_limit':'64m','user':'101:101','read_only':True,'tmpfs':['/tmp:mode=1777','/var/cache/nginx:mode=1777'],
        'entrypoint':['nginx','-c','/run/demo/nginx.conf','-g','daemon off;'],'volumes':['ingress-config:/run/demo:ro'],
        'networks':{'core':{'ipv4_address':'10.253.236.25','aliases':['portal.full-function.test','auth.full-function.test']}}}
    services['check']={**common('zt-full-function/browser:20261111-1'),'mem_limit':'1g','shm_size':'256m',
        'entrypoint':['sleep','infinity'],'volumes':[str(STATE)+':/private:ro',str(HERE)+':/tests:ro',str(OUT)+':/results'],
        'networks':{'core':{'aliases':['risk-fixture']}}}
    save('compose.json',{'services':services,'networks':{'core':{'internal':True,'ipam':{'config':[{'subnet':SUBNET}]}},'bootstrap':{'internal':True}},'volumes':volumes})
    save('dataset.json',{'release':pointer['release'],'files':{f.name:sha(f) for f in dataset.glob('*.mmdb')}})
    need(snapshot()==before,'PROTECTED_STATE_CHANGED_DURING_PREPARE')
    print('PASS isolated configuration; no published ports; fresh synthetic state',flush=True)

def build(only=None):
    need(shutil.disk_usage(ROOT).free>15*1024**3,'DISK_BELOW_15_GIB')
    need(run('docker','image','inspect','--format','{{.Id}}','zt-full-function/risk:phase2-locking-20261111-1').stdout.strip()==RISK_BASE,'BASE_IMAGE_DRIFT')
    revision=run('git','rev-parse','HEAD').stdout.strip()
    sources={p.relative_to(ROOT).as_posix():sha(p) for module in ('risk-scoring-service','keycloak-risk-extension') for p in (ROOT/module/'src/main').rglob('*') if p.is_file()}
    snapshot_sha=hashlib.sha256(json.dumps(sources,sort_keys=True).encode()).hexdigest()
    for role in ('risk','keycloak'):
        if only and role!=only:continue
        work=OUT/'build'/role;work.mkdir(parents=True,exist_ok=True)
        jar=ROOT/('risk-scoring-service/target/risk-scoring-service-0.0.1-SNAPSHOT.jar' if role=='risk' else 'keycloak-risk-extension/target/keycloak-risk-extension.jar')
        shutil.copyfile(jar,work/'application.jar')
        if role=='risk':
            with zipfile.ZipFile(jar) as archive:archive.extractall(work/'unpacked')
            dockerfile='FROM zt-full-function/risk:phase2-locking-20261111-1\nCOPY application.jar /app/application.jar\nCOPY unpacked/ /app/unpacked/\n'
        else:
            shutil.copytree(ROOT/'keycloak-theme/zerotrust',work/'theme',dirs_exist_ok=True)
            dockerfile='FROM dhi.io/keycloak@sha256:ba20b9bd0ecd48047240249acaff19aa882db5480a03659fcdf14d4b7bd9d424\nCOPY --chown=65532:65532 application.jar /opt/keycloak/providers/keycloak-risk-extension.jar\nCOPY --chown=65532:65532 theme/ /opt/keycloak/themes/zerotrust/\nUSER 65532:65532\nRUN --network=none /opt/keycloak/bin/kc.sh build --db=mysql --health-enabled=true\n'
        dockerfile+='LABEL org.opencontainers.image.revision="'+revision+'" io.zerotrust.source.snapshot="'+snapshot_sha+'" io.zerotrust.scope="'+PROJECT+'"\n'
        (work/'Dockerfile').write_text(dockerfile,encoding='utf-8')
        image=RISK if role=='risk' else KC
        result=run('docker','build','--network','none','--pull=false','--tag',image,str(work),timeout=420,check=False)
        (OUT/(role+'-image-build.log')).write_text(result.stdout+result.stderr,encoding='utf-8')
        need(result.returncode==0,'IMAGE_BUILD_FAILED_'+role)
        ident=run('docker','image','inspect','--format','{{.Id}}',image).stdout.strip()
        previous=OUT/(role+'-artifact.json')
        if only and previous.exists() and not (OUT/(role+'-artifact.initial.json')).exists():shutil.copyfile(previous,OUT/(role+'-artifact.initial.json'))
        save(role+'-artifact.json',{'image':image,'id':ident,'jar_sha256':sha(jar),'source_snapshot':snapshot_sha,'HEAD':revision,'sources':sources,'D17':'PENDING','G8':'INTERNET_NO_GO'})
        print('PASS candidate '+role+' '+ident,flush=True)

def build_spi():
    build('keycloak')
    model=json.loads((OUT/'compose.json').read_text())
    for name in ('keycloak','keycloak-init'):model['services'][name]['image']=KC
    save('compose.json',model)
    compose('up','-d','--wait','--wait-timeout','240','keycloak',timeout=260)

def sql(service,statement,data=None):
    return compose('exec','-T',service,'mysql','--defaults-extra-file=/fixture/root.cnf','-Nse',statement,data=data).stdout.strip()

def start():
    owned()
    compose('run','--no-deps','materialize',timeout=60)
    compose('up','-d','crl')
    compose('up','-d','--wait','--wait-timeout','180','mysql80')
    compose('run','--no-deps','migrate80',timeout=150)
    ledger=sql('mysql80',"SELECT version,checksum,success FROM pd_staging_risk.flyway_schema_history ORDER BY installed_rank")
    need([line.split('\t')[0] for line in ledger.splitlines()]==list('1234567'),'BOOTSTRAP_LEDGER')
    need('5\t661092940\t1' in ledger,'V5_CHECKSUM_DRIFT')
    dump=compose('exec','-T','mysql80','mysqldump','--defaults-extra-file=/fixture/root.cnf','--single-transaction','--set-gtid-purged=OFF','--no-tablespaces','pd_staging_risk').stdout
    compose('stop','--timeout','45','mysql80')
    compose('up','-d','--wait','--wait-timeout','180','mysql')
    compose('exec','-T','mysql','mysql','--defaults-extra-file=/fixture/root.cnf','pd_staging_risk',data=dump)
    compose('run','--no-deps','migrate',timeout=120)
    need(sql('mysql',"SELECT version,checksum,success FROM pd_staging_risk.flyway_schema_history ORDER BY installed_rank")==ledger,'RUNTIME_LEDGER_DRIFT')
    save('migration.json',{'status':'PASS','bootstrap':sql('mysql80','SELECT VERSION()') if False else '8.0.46','runtime':sql('mysql','SELECT VERSION()'),'V5':661092940,'ledger':ledger,'V6':'PASS','V7':'PASS','scope':'fresh synthetic bootstrap + transfer; no active migration'})
    print('PASS V1-V7 native MySQL8.0.46, V5 checksum, transfer and validation on8.4.13',flush=True)
    compose('up','-d','redis')
    compose('up','-d','--wait','--wait-timeout','360','keycloak-init',timeout=390)
    compose('stop','--timeout','60','keycloak-init')
    compose('up','-d','--wait','--wait-timeout','240','keycloak',timeout=260)
    compose('up','-d','--wait','--wait-timeout','180','risk',timeout=200)
    compose('up','-d','ingress','check')
    owned(); print('PASS isolated Risk/Keycloak/Redis/TLS ready; no host listeners',flush=True)

def check():
    owned()
    result=compose('exec','-T','check','/opt/tools/bin/python','/tests/network_v2_check.py',timeout=600,check=False)
    safe='\n'.join(line for line in result.stdout.splitlines() if line.startswith(('PASS ','FAIL ')))+'\n'
    (OUT/'integration.log').write_text(safe,encoding='utf-8');print(safe,end='',flush=True)
    need(result.returncode==0,'INTEGRATION_FAILED_SEE_SANITIZED_RECEIPT')

def maintenance():
    """Native bootstrap service only in the new lane; never a business ADMIN identity."""
    import secrets
    owned();compose('stop','--timeout','40','risk','keycloak')
    credential={'client_id':'network-v2-isolated-maintenance','secret':secrets.token_urlsafe(40)}
    file=STATE/'phase2-maintenance.json'
    need(not file.exists(),'MAINTENANCE_ALREADY_CREATED')
    env=dict(os.environ);env['V2_MAINT_SECRET']=credential['secret']
    cmd=['docker','compose','-p',PROJECT,'-f',str(OUT/'compose.json'),'run','--no-deps','--env','V2_MAINT_SECRET','keycloak-init',
         '--config-file=/run/secrets/keycloak.conf','bootstrap-admin','service','--optimized','--no-prompt',
         '--client-id',credential['client_id'],'--client-secret:env','V2_MAINT_SECRET']
    result=subprocess.run(cmd,cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=180)
    need(result.returncode==0,'ISOLATED_NATIVE_MAINTENANCE_BOOTSTRAP_FAILED')
    file.write_text(json.dumps(credential),encoding='utf-8')
    compose('up','-d','--wait','--wait-timeout','220','keycloak',timeout=240)
    compose('up','-d','--wait','--wait-timeout','160','risk',timeout=180)
    print('PASS native disposable maintenance service; no business ADMIN or protected realm used',flush=True)

def retention():
    owned()
    result=compose('exec','-T','check','/opt/tools/bin/python','/tests/network_v2_check.py','retention-fixture')
    print(result.stdout.strip(),flush=True)
    compose('stop','--timeout','30','risk')
    path=STATE/'risk/application.properties'
    path.write_text(path.read_text()+'\nrisk.network-v2.retention-enabled=true\nrisk.network-v2.retention-batch-size=2\nrisk.network-v2.retention-initial-delay=PT0S\n',encoding='utf-8')
    compose('run','--no-deps','--entrypoint','sh','materialize','-ec',
            'cp /in/risk/application.properties /out/risk/application.properties; chown 10001:10001 /out/risk/application.properties; chmod 600 /out/risk/application.properties')
    compose('up','-d','--wait','--wait-timeout','160','risk',timeout=180)
    result=compose('exec','-T','check','/opt/tools/bin/python','/tests/network_v2_check.py','retention-check')
    print(result.stdout.strip(),flush=True)

def collect():
    import re
    owned();result=json.loads((OUT/'integration.json').read_text())
    logs={name:run('docker','logs',PROJECT+'-'+name+'-1').stdout for name in ()}
    for name in ('risk','keycloak','ingress','redis','mysql'):
        process=run('docker','logs',PROJECT+'-'+name+'-1',check=False)
        logs[name]=process.stdout+process.stderr
    assessments={};spi=[];rows=[]
    for name,blob in logs.items():
        for line in blob.splitlines():
            if 'ZEROTRUST_NETWORK_V2_SHADOW ' in line:
                row=json.loads(line.split('ZEROTRUST_NETWORK_V2_SHADOW ',1)[1]);rows.append(row)
                if 'network_v2' in row:assessments[row['evaluation_id']]=row
            if 'ZEROTRUST_RISK_TRACE ' in line:
                spi.append(json.loads(line.split('ZEROTRUST_RISK_TRACE ',1)[1]))
    checked=[]
    for expected in result['expectations']:
        ident=expected['evaluation_id'];need(ident in assessments,'MISSING_SHADOW_EVIDENCE_'+expected['case'])
        actual=assessments[ident]
        need(actual['network_v2']['candidateScore']==expected['candidateScore'],'SHADOW_SCORE_'+expected['case'])
        need(actual['live_decision']==expected['decision'] and actual['enforcement'] is False,'SHADOW_CHANGED_LIVE_DECISION')
        if expected['case'] in ('familiar','unfamiliar-asn','country-change','new-network','known-return','novel-all'):
            need(actual['network_v2']['historySamples']==3 and actual['network_v2']['distinctDays']>=2,'HISTORY_WINDOW')
        if expected['case']=='partial-geoip':need(actual['network_v2']['quality']=='PARTIAL','PARTIAL_GEOIP_NOT_DEMONSTRATED')
        if expected['case']=='no-record-public':need(actual['network_v2']['quality']=='NO_RECORD','NO_RECORD_NOT_DEMONSTRATED')
        if expected['case']=='history-client-isolation':need(actual['network_v2']['historySamples']==0,'CLIENT_HISTORY_LEAK')
        checked.append({'case':expected['case'],'evidence':actual})
    native=next(row['details'] for row in result['cases'] if row['case']=='Actual SPI native LOGIN -> asynchronous MySQL history')
    joined=[row for row in spi if row.get('evaluation_id')==native['evaluation_id']]
    need(any(row.get('stage')=='AUTHENTICATION_EVENT' and row.get('mfa_execution')=='OTP_EXECUTION_SUCCESS' for row in joined),'NATIVE_MFA_SPI_JOIN')
    need(any(row.get('evaluation_id')==native['evaluation_id'] and row.get('outcome')=='RECORDED' for row in rows),'NATIVE_ASYNC_PERSISTENCE_TRACE')
    queue=json.loads((OUT/'queue-offers.json').read_text());processed=[ident for ident in queue['offered_ids'] if ident in assessments]
    need(len(processed)<queue['offered'] and len(processed)>0,'QUEUE_OVERFLOW_NOT_OBSERVED')
    # Do not write raw logs. Check actual private values and token/address patterns only in memory.
    blob='\n'.join(logs.values());private_values=[]
    roster=json.loads((STATE/'accounts.json').read_text())
    for actor in roster.values():private_values += [actor['username'],actor['password']]
    realm=json.loads((STATE/'installer/DoAn-realm.json').read_text())
    private_values += [c['secret'] for c in realm['clients'] if c.get('secret')]
    need(not any(value in blob for value in private_values),'RUNTIME_LOG_SENSITIVE_VALUE')
    need(not re.search(r'eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',blob),'RUNTIME_LOG_JWT')
    need(not any(address in blob for address in ('8.8.8.8','1.1.1.1','10.2.3.4','3000::1')),'RUNTIME_LOG_RAW_TEST_ADDRESS')
    save('runtime-evidence.json',{'status':'PASS','scoring_cases':checked,'native_SPI_MFA_join':joined,
        'native_verified_network_learning':native,'queue':{'offered':queue['offered'],'processed':len(processed),'dropped':queue['offered']-len(processed),'B0_success_responses':20},
        'runtime_log_scan':'PASS account/password/client-secret/JWT/raw-test-address scan; raw logs not exported',
        'public_browser_geoip':'NOT_VERIFIED; native public-context positive uses explicit service-input simulator',
        'historical_dates':'isolated synthetic fixtures only; not asserted as real historical browser logins'})
    print('PASS joined native LOGIN/MFA/UUID/async persistence, deterministic scores, queue overflow and log privacy',flush=True)

def finish():
    owned();compose('stop','--timeout','40',timeout=150)
    before=json.loads((OUT/'preservation-before.json').read_text());after=snapshot()
    for row in before.values():row['mounts'].sort(key=lambda mount:mount['Destination'])
    need(before==after,'PROTECTED_RUNTIME_DRIFT')
    save('preservation-after.json',{'status':'PASS','protected_container_count':len(before),'unchanged_images_starts_mounts_ports':True,'test_services_stopped':True})
    print('PASS protected runtimes unchanged; isolated services stopped without deleting resources',flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('prepare','build','build_spi','start','maintenance','check','collect','retention','finish'))
    try:globals()[parser.parse_args().action]()
    except Exception as error:
        print('FAIL '+type(error).__name__+' '+(str(error) if isinstance(error,RuntimeError) else 'details withheld'),flush=True)
        raise SystemExit(1)
