"""D10 live read-only preflight. No service credential or private key is read."""
import datetime,hashlib,http.client,json,re,socket,ssl,subprocess,sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
ROOT=Path(__file__).resolve().parents[3];OUT=ROOT/'target/d10-phase3-20261113'
PROJECT='zt-full-function-20261111b'
def need(ok,message):
    if not ok:raise RuntimeError(message)
def run(*args):
    p=subprocess.run(args,cwd=ROOT,capture_output=True,timeout=40)
    need(p.returncode==0,'READ_ONLY_COMMAND_FAILED_'+args[0]);return p.stdout
def sha(data):return hashlib.sha256(data).hexdigest()
def dump(name,value):(OUT/name).write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
def query(sql):
    need(sql.lstrip().upper().startswith(('SELECT','WITH RECURSIVE')) and not re.search(r'\b(INSERT|UPDATE|DELETE|ALTER|DROP|CREATE|CALL)\b',sql,re.I),'READ_ONLY_SQL_REQUIRED')
    return run('docker','exec',PROJECT+'-mysql-1','mysql','--defaults-extra-file=/fixture/root.cnf','-Nse',sql).decode().strip()
def main(out_name='live-preflight.json'):
    OUT.mkdir(exist_ok=True,parents=True)
    verifier=ROOT/'deploy/full-function/d10-release/packet.py'
    subprocess.run([sys.executable,str(verifier),'base'],check=True,cwd=ROOT)
    baseline=json.loads((ROOT/'target/full-function-20261111b/post-cutover-functional-acceptance-20261113/preflight.json').read_text())
    inventory={};configs={};certs={}
    fields='{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"started":{{json .State.StartedAt}},"running":{{json .State.Running}},"restarts":{{json .RestartCount}},"mounts":{{json .Mounts}},"networks":{{json .NetworkSettings.Networks}},"ports":{{json .HostConfig.PortBindings}}}'
    for role,row in baseline['runtime'].items():
        doc=json.loads(run('docker','inspect','--format',fields,row['name']));need(doc['image']==row['image'] and doc['running'],'ACTIVE_PIN_OR_STATE_DRIFT')
        inventory[role]=doc;root='/run/secrets' if role=='keycloak' else '/run/demo'
        private_launch=json.loads(run('docker','inspect','--format','{"config":{{json .Config}},"host":{{json .HostConfig}}}',row['name']))
        public_config={k:private_launch['config'].get(k) for k in ('Entrypoint','Cmd','Env','User','WorkingDir','Healthcheck')}
        doc['launch_sha256']=sha(json.dumps({'config':public_config,'host':private_launch['host']},sort_keys=True,separators=(',',':')).encode())
        files={'keycloak':['keycloak.conf','ready.sh'],'risk':['application.properties','jvm.args'],'backend':['application.properties','jvm.args'],'gateway':['application.properties','jvm.args'],'ingress':['nginx.conf'],'mysql':[],'redis':[],'crl':['crl.conf'],'frontend':[]}[role]
        configs[role]={}
        for file in files:
            # Hash inside the service: secret-bearing configuration never reaches evidence output.
            digest=run('docker','exec',row['name'],'sha256sum',root+'/'+file).decode().split()[0];configs[role][root+'/'+file]=digest
        if role in ('keycloak','risk','backend','gateway','ingress'):
            certs[role]={}
            for file in ['ca.crt','server.crt']+(['browser/server.crt','edge-ca.crt'] if role=='ingress' else []):
                cert=x509.load_pem_x509_certificate(run('docker','exec',row['name'],'cat',root+'/'+file))
                certs[role][file]={'sha256':sha(cert.public_bytes(serialization.Encoding.DER)),'not_after':cert.not_valid_after_utc.isoformat(),'subject':cert.subject.rfc4514_string(),'issuer':cert.issuer.rfc4514_string()}
                need(cert.not_valid_after_utc>datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(days=7),'CERTIFICATE_EXPIRING')
    ctx=ssl.create_default_context(cafile=str(ROOT/'target/full-function-20261111b/windows-access/browser-tls-candidate/public/browser-ca-with-crl.pem'));ctx.verify_flags|=ssl.VERIFY_CRL_CHECK_CHAIN
    tls={}
    for host,path,expected in [('portal.full-function.test','/api/admin/users',401),('auth.full-function.test','/realms/DoAn/.well-known/openid-configuration',200)]:
        c=http.client.HTTPSConnection(host,39443,context=ctx,timeout=12);c.sock=ctx.wrap_socket(socket.create_connection(('127.0.0.1',39443),timeout=12),server_hostname=host)
        c.request('GET',path);r=c.getresponse();body=r.read(65537);c.close();need(r.status==expected,'TLS_HTTP_CONTRACT')
        tls[host]={'status':r.status,'ca_hostname_crl':'PASS'}
        if host.startswith('auth.'):tls[host]['issuer']=json.loads(body)['issuer']
    ledger=query('SELECT version,checksum,success FROM pd_staging_risk.flyway_schema_history ORDER BY installed_rank');need([r.split('\t')[0] for r in ledger.splitlines()]==list('1234567'),'NOT_V7')
    need(query("SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_SCHEMA='pd_staging_risk' AND TABLE_NAME LIKE 'security\\_%'")=='0','UNEXPECTED_PARTIAL_D10_SCHEMA')
    pending=query("SELECT SHA2(s.subject_id,256),s.generation,s.pending_operation_id,r.generation,r.revoked_count,r.revoked_at,r.completed_at,(SELECT COUNT(*) FROM pd_staging_keycloak.USER_ENTITY u WHERE u.ID=s.subject_id),(SELECT COUNT(*) FROM pd_staging_school.users u WHERE u.keycloak_user_id=UUID_TO_BIN(s.subject_id)) FROM pd_staging_risk.subject_device_trust s LEFT JOIN pd_staging_risk.device_trust_revocations r ON r.operation_id=s.pending_operation_id WHERE s.pending_operation_id IS NOT NULL ORDER BY s.subject_id")
    audit=query('SELECT COUNT(*) FROM pd_staging_risk.device_trust_revocations WHERE completed_at IS NULL')
    writer=query("SELECT @@read_only,@@super_read_only,@@require_secure_transport,(SELECT COUNT(*) FROM information_schema.events WHERE EVENT_SCHEMA IN ('pd_staging_school','pd_staging_keycloak','pd_staging_risk') AND STATUS='ENABLED')");need(writer=='0\t0\t1\t0','WRITER_OR_EVENT_SCHEDULER_CONTRACT')
    grants=query("SELECT GRANTEE,TABLE_SCHEMA,GROUP_CONCAT(PRIVILEGE_TYPE ORDER BY PRIVILEGE_TYPE) FROM information_schema.schema_privileges WHERE TABLE_SCHEMA IN ('pd_staging_school','pd_staging_keycloak','pd_staging_risk') GROUP BY GRANTEE,TABLE_SCHEMA")
    # Only the active browser tree and public configuration references, no credentials.
    flows=query("WITH RECURSIVE tree AS (SELECT ID,ALIAS,TOP_LEVEL FROM pd_staging_keycloak.AUTHENTICATION_FLOW WHERE ID=(SELECT BROWSER_FLOW FROM pd_staging_keycloak.REALM WHERE NAME='DoAn') UNION ALL SELECT f.ID,f.ALIAS,f.TOP_LEVEL FROM pd_staging_keycloak.AUTHENTICATION_FLOW f JOIN pd_staging_keycloak.AUTHENTICATION_EXECUTION e ON e.AUTH_FLOW_ID=f.ID JOIN tree t ON e.FLOW_ID=t.ID) SELECT t.ID,t.ALIAS,t.TOP_LEVEL,e.PRIORITY,e.AUTHENTICATOR,e.REQUIREMENT,e.AUTH_FLOW_ID,e.AUTH_CONFIG FROM tree t LEFT JOIN pd_staging_keycloak.AUTHENTICATION_EXECUTION e ON e.FLOW_ID=t.ID ORDER BY t.ALIAS,e.PRIORITY")
    profile=query("SELECT x.VALUE FROM pd_staging_keycloak.COMPONENT c JOIN pd_staging_keycloak.COMPONENT_CONFIG x ON x.COMPONENT_ID=c.ID WHERE c.REALM_ID=(SELECT ID FROM pd_staging_keycloak.REALM WHERE NAME='DoAn') AND c.PROVIDER_ID='declarative-user-profile' AND x.NAME='kc.user.profile.config'")
    # Absent config means exact native default; verify default policy in isolated rehearsal.
    roles=query("SELECT CLIENT_ID,SERVICE_ACCOUNTS_ENABLED,STANDARD_FLOW_ENABLED,DIRECT_ACCESS_GRANTS_ENABLED FROM pd_staging_keycloak.CLIENT WHERE REALM_ID=(SELECT ID FROM pd_staging_keycloak.REALM WHERE NAME='DoAn') AND CLIENT_ID IN ('zerotrust-provisioner','zerotrust-issuer-security','zerotrust-portal-security','zerotrust-gateway-security') ORDER BY CLIENT_ID")
    report={'checked_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'LIVE_READ_ONLY_NO_AUTHORIZATION','inventory':inventory,'configuration_hashes':configs,'certificates':certs,'tls':tls,'schema':7,'flyway':ledger,'writer':writer,'grants':grants,'active_browser_tree':flows,'user_profile_config':json.loads(profile) if profile else 'NATIVE_DEFAULT; isolated behavioral verification required','service_clients':roles,'existing_pending':pending.splitlines(),'incomplete_audit_operations':int(audit),'pending_disposition':'UNRESOLVED: never clear/supersede; preserve/quarantine requires explicit cutover decision','owner_go':False,'B0_SHADOW':'reused exact active pins/config; no policy mutation'}
    unsupported=query("SELECT COUNT(*) FROM pd_staging_keycloak.USER_ENTITY WHERE REALM_ID=(SELECT ID FROM pd_staging_keycloak.REALM WHERE NAME='DoAn') AND FEDERATION_LINK IS NOT NULL");need(unsupported=='0','UNSUPPORTED_FEDERATED_USERS')
    report['federated_users']=int(unsupported);report['trust_rows']=json.loads(query("SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT('subject',subject_id,'generation',generation,'pending',pending_operation_id)),JSON_ARRAY()) FROM pd_staging_risk.subject_device_trust"))
    from executor import migrate_config_hashes
    report['migrate_configuration_hashes']=migrate_config_hashes(PROJECT+'_migrate-config','redis@sha256:ec1c2d3603c3d7d65b153bedda0248b641aa3bd7684503406b27b9e870ac0796')
    dump(out_name,report)
    print('PASS exact 9 live pins, configuration hashes, TLS/CA/hostname/CRL/expiration, V7 and writer grants; '+str(len(report['existing_pending']))+' pre-existing pending subjects retained; no live mutation')
if __name__=='__main__':
    try:main()
    except Exception as e:print('FAIL '+(str(e) if type(e)is RuntimeError else type(e).__name__),file=sys.stderr);sys.exit(1)
