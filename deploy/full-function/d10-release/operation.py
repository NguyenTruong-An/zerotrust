"""D10 native operation helpers shared by the FINAL rehearsal and owner-GO executor.

Does not import or invoke Network-v2 rollout tooling. No owner login/signing secret.
"""
import json,os,secrets,subprocess,sys,time,uuid
from pathlib import Path
from executor import Executor,ROOT,canonical,dpapi,inspect,need,run,sha,write
HERE=Path(__file__).resolve().parent
def helper(e,public,results,existing=None):
    if existing:return existing
    # Keep the long-lived acceptance helper distinct from short-lived archive helpers.
    name=e.name('acceptance-helper');args=['docker','run','-d','--name',name,'--network',e.plan['core_network'],'--label','io.zerotrust.d10.run='+e.id,'--label','io.zerotrust.d10.project='+e.project,'--read-only','--tmpfs','/tmp:mode=1777','--shm-size','256m','--memory','1g','--cap-drop','ALL','--security-opt','no-new-privileges:true','--mount','type=bind,source='+str(HERE)+',target=/scripts,readonly','--mount','type=bind,source='+str(public)+',target=/public,readonly','--mount','type=bind,source='+str(results)+',target=/results','--entrypoint','sleep',e.plan['tooling_image'],'infinity']
    run(*args);return name
def rpc(container,values):
    p=subprocess.run(['docker','exec','-i',container,'/opt/tools/bin/python','/scripts/native_admin.py'],input=canonical(values),capture_output=True,timeout=240)
    try:result=json.loads(p.stdout)
    except ValueError:raise RuntimeError('NATIVE_ADMIN_NO_SAFE_RECEIPT')
    need(p.returncode==0 and result.get('status')=='PASS','NATIVE_ADMIN_'+result.get('reason','FAILED'));return result
def ready(container,host,path,expected=200,port=8443):
    code="import ssl,time,urllib.request,urllib.error;c=ssl.create_default_context(cafile='/public/all-ca-with-crl.pem');c.verify_flags|=ssl.VERIFY_CRL_CHECK_CHAIN;end=time.monotonic()+120\nwhile True:\n try:\n  try:s=urllib.request.urlopen('https://"+host+":"+str(port)+path+"',context=c,timeout=5).status\n  except urllib.error.HTTPError as e:s=e.code\n  if s=="+str(expected)+":break\n except Exception:pass\n if time.monotonic()>end:raise RuntimeError('READY_TIMEOUT')\n time.sleep(.5)\nprint('PASS ready')"
    run('docker','exec',container,'/opt/tools/bin/python','-c',code,timeout=140)
def generated_inputs(runid):
    values={name:secrets.token_urlsafe(36) for name in ('zerotrust-issuer-security','zerotrust-portal-security','zerotrust-gateway-security')}
    values.update(run_id=runid,bootstrap_client='d10-maintenance-'+runid,bootstrap_secret=secrets.token_urlsafe(40),source_browser_alias='zerotrust-browser-recovery')
    values['accounts']={name:{'username':'d10-'+runid+'-'+name,'password':secrets.token_urlsafe(32),'otp':secrets.token_hex(16),'role':role,'portal_id':str(uuid.uuid4())} for name,role in [('admin','ADMIN'),('student_a','STUDENT')]}
    values['accounts']['student_a']['student_id']=str(uuid.uuid4());return values
def protect_inputs(path,values,runid):
    # Fresh D10 machine/test inputs only; token responses are NEVER written here.
    path.write_bytes(dpapi(canonical(values),runid.encode()))
def provisioner_secret(e):
    # Existing supported M2M mechanism. Extract ONLY this service secret into process memory.
    script="sed -n 's/^keycloak\\.admin\\.client-secret[[:space:]]*=[[:space:]]*//p' /run/demo/application.properties"
    secret=run('docker','exec',e.old['backend'],'sh','-c',script).decode().strip()
    need(secret and '\n'not in secret and not secret.startswith('${'),'PROVISIONER_SECRET_FILE_CONTRACT');return secret
def designated(e,container,values):
    need(e.j['phase']=='PREPARED','DESIGNATED_BEFORE_MAINTENANCE')
    result=rpc(container,{**values,'action':'designated'});actors=values['accounts']
    for key,native_id in result['new_designated_ids'].items():actors[key]['id']=str(uuid.UUID(native_id))
    e.j['designated_ids']=[a['id'] for a in actors.values()];e.j['designated_native_receipt']=result;write(e.state,e.j)
    # Exactly six NEW School rows. No existing business/identity row is updated or reset.
    class_id=str(uuid.uuid4());subject_id=str(uuid.uuid4());score_id=str(uuid.uuid4());student=actors['student_a'];suffix=e.id
    statements=["START TRANSACTION","INSERT INTO pd_staging_school.student_classes(id,class_code,class_name,department,course_years) VALUES(UUID_TO_BIN('%s'),'D10-%s','D10 Acceptance %s','D10 controlled acceptance','2026-2027')"%(class_id,suffix,suffix),"INSERT INTO pd_staging_school.subjects(id,subject_code,subject_name,credits) VALUES(UUID_TO_BIN('%s'),'D10-%s','D10 Acceptance %s',1)"%(subject_id,suffix,suffix)]
    for actor in actors.values():
        uuid.UUID(actor['id']);uuid.UUID(actor['portal_id']);need(actor['username'].startswith('d10-'+e.id+'-') and all(c.isalnum() or c in '_-' for c in actor['username']),'DESIGNATED_SQL_SCOPE')
        statements.append("INSERT INTO pd_staging_school.users(id,keycloak_user_id,username,email,first_name,last_name,status) VALUES(UUID_TO_BIN('%s'),UUID_TO_BIN('%s'),'%s','%s@acceptance.invalid','D10','Acceptance','ACTIVE')"%(actor['portal_id'],actor['id'],actor['username'],actor['username']))
    statements += ["INSERT INTO pd_staging_school.students(id,user_id,class_id,student_code,date_of_birth,gender) VALUES(UUID_TO_BIN('%s'),UUID_TO_BIN('%s'),UUID_TO_BIN('%s'),'D10-%s','2000-01-01','MALE')"%(student['student_id'],student['portal_id'],class_id,suffix),"INSERT INTO pd_staging_school.scores(id,student_id,subject_id,semester,academic_year) VALUES(UUID_TO_BIN('%s'),UUID_TO_BIN('%s'),UUID_TO_BIN('%s'),1,'2026-2027')"%(score_id,student['student_id'],subject_id),'COMMIT']
    e.sql(';'.join(statements));e.j['designated_school']={'users':[a['portal_id'] for a in actors.values()],'student':student['student_id'],'class':class_id,'subject':subject_id,'score':score_id,'new_rows':6};write(e.state,e.j)
    print('PASS created exactly two new designated native identities and six synthetic School rows; no existing account changed',flush=True)
def native_process(e,container,values,results,retain_legacy=True):
    inputs={'scope':'DESIGNATED_D10_ACCOUNTS' if e.mode=='live' else 'NEW_DISPOSABLE_REHEARSAL','accounts':values['accounts'],'journal':e.state.relative_to(results).as_posix(),'retain_legacy':retain_legacy,'issuer_secret':values['zerotrust-issuer-security'],'provisioner_secret':values['provisioner_secret'],'exercise_native_mutations':True}
    p=subprocess.Popen(['docker','exec','-i',container,'/opt/tools/bin/python','/scripts/native_acceptance.py'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL);p.stdin.write(canonical(inputs));p.stdin.close();return p
def stage_install(e,container,values):
    if e.j['phase']in ('PREPARED','CLOSING'):e.quiesce();print('PASS all bound writers quiesced; protected paths closed',flush=True)
    if e.j['phase']=='QUIESCED':e.checkpoint();print('PASS encrypted consistent checkpoint; no plaintext SQL file',flush=True)
    if e.j['phase']=='CHECKPOINTED':e.maintenance();print('PASS public maintenance closed',flush=True)
    if e.j['phase']=='MAINTENANCE':e.verify_restore();print('PASS independent restore proof',flush=True)
    if e.j['phase']=='RESTORE_VERIFIED':e.install_artifacts(values);print('PASS additive V9 and exact strict artifacts',flush=True)
    if e.j['phase']=='ARTIFACTS_INSTALLED':e.bootstrap(values);print('PASS native issuer/authority startup',flush=True)
    if e.j['phase']=='ISSUER_AUTHORITY_STARTED':result=rpc(container,{**values,'action':'provision'});e.record('NATIVE_PROVISIONED',result);print('PASS dedicated roles, exact flow/priority and same-origin callback',flush=True)
    if e.j['phase']=='NATIVE_PROVISIONED':e.start_api_private()
    if e.j['phase']=='GATES_STARTING_PRIVATE':
        ready(container,'backend','/api/admin/users',401);ready(container,'portal.full-function.test','/api/admin/users',401,39443);ready(container,'risk','/actuator/health')
        evidence=e.j['evidence']['GATES_STARTING_PRIVATE'];evidence['http_readiness']='Backend401, Portal401, Risk200';e.record('GATES_PRIVATE',evidence);print('PASS all gates READY behind private acceptance ingress',flush=True)
def monitor(e,container,process,results):
    handled=set();deadline=time.monotonic()+1200
    while process.poll()is None:
        need(time.monotonic()<deadline,'DESIGNATED_NATIVE_ACCEPTANCE_TIMEOUT')
        path=results/'acceptance-control.json'
        if path.exists():
            item=json.loads(path.read_text())
            if item['id']not in handled:
                need(item['action']in ('restart-backend','stop-risk','start-risk'),'NATIVE_CONTROL_SCOPE')
                if item['action']=='restart-backend':e.stop(e.name('backend'));e.start(e.name('backend'));ready(container,'backend','/api/admin/users',401)
                elif item['action']=='stop-risk':e.stop(e.name('risk'))
                else:e.start(e.name('risk'));ready(container,'risk','/actuator/health')
                write(results/'acceptance-ack.json',{'id':item['id']});handled.add(item['id'])
        time.sleep(.2)
    lines=process.stdout.read().decode(errors='replace').splitlines();safe='\n'.join(s for s in lines if s.startswith(('PASS ','FAIL ')));(results/'rollout-native.log').write_text(safe+'\n');print(safe,flush=True)
    need(process.returncode==0,'DESIGNATED_NATIVE_ACCEPTANCE_FAILED')
def verify_state(e,values,results):
    report=json.loads((results/'rollout-native.json').read_text());need(report['status']=='PASS','NATIVE_NOT_PASS');need(len(report['cases'])>=15,'NATIVE_MATRIX_INCOMPLETE')
    end=time.monotonic()+60
    subjects=[a['id'] for a in values['accounts'].values()]
    while True:
        pending=e.sql("SELECT COUNT(*) FROM pd_staging_risk.security_operations WHERE operation_kind='MFA_RESET' AND stage<>'COMPLETED'")
        if pending=='0':break
        need(time.monotonic()<end,'MFA_RESET_COMPLETION_PENDING');time.sleep(.5)
    for subject in subjects:
        need(e.sql("SELECT COUNT(*) FROM pd_staging_risk.security_operations WHERE subject_id='%s' AND operation_kind='MFA_RESET' AND stage='COMPLETED'"%subject)=='1','MFA_RESET_REPLAY_OR_INCOMPLETE')
        need(e.sql("SELECT COUNT(*) FROM pd_staging_keycloak.CREDENTIAL WHERE USER_ID='%s' AND TYPE IN ('otp','recovery-authn-codes')"%subject)=='0','DESIGNATED_MFA_CREDENTIAL_REMAINS')
    need(e.sql('SELECT COUNT(*) FROM pd_staging_risk.subject_device_trust WHERE pending_operation_id IS NOT NULL')==str(e.plan['pending_count']),'EXISTING_PENDING_NOT_PRESERVED')
    e.assert_trust_preserved()
    # Runtime configuration values and installed artifact bytes, not fixture labels, establish B0/SHADOW.
    text=run('docker','exec',e.name('risk'),'sh','-c',"grep -E '^(risk.policy.model|risk.network-v2.mode|risk.network-v2.retention-enabled)=' /run/demo/application.properties").decode()
    properties=dict(line.split('=',1) for line in text.splitlines());need(properties.get('risk.policy.model')=='BASELINE_B0' and properties.get('risk.network-v2.mode')=='SHADOW' and properties.get('risk.network-v2.retention-enabled')=='false','B0_SHADOW_CONFIGURATION')
    for role in ('risk','keycloak','backend','gateway','frontend'):need(inspect(e.name(role))['Image']==e.plan['candidate_images'][role],'NATIVE_ARTIFACT_DRIFT')
    report.update(reset_completion='both designated operations COMPLETED exactly once; no OTP/recovery remains',existing_pending_preserved=True,B0_SHADOW=True,images=e.plan['candidate_images']);write(results/'rollout-native.json',report)
    return report
def final_rehearsal():
    import rehearse as r
    need(r.LANE in ('final','final2'),'FINAL_DISPOSABLE_LANE_REQUIRED')
    plan=r.make_plan();plan['tooling_image']=run('docker','image','inspect','--format','{{.Id}}','zt-full-function/browser:20261111-1').decode().strip();write(r.OUT/'execution-plan.json',plan)
    e=Executor(plan,'rehearsal');values=generated_inputs(e.id);values['provisioner_secret']=provisioner_secret(e)
    public=r.OUT/'public';(public/'all-ca-with-crl.pem').write_bytes((public/'internal-ca-with-crl.pem').read_bytes());container=r.PROJECT+'-check-1'
    with e.exclusive():
        try:
            e.assert_source();designated(e,container,values);protect_inputs(r.OUT/'new-designated-inputs.dpapi',values,e.id)
            process=native_process(e,container,values,r.OUT,True);deadline=time.monotonic()+150
            while not (r.OUT/'legacy-witness.json').exists():need(process.poll()is None and time.monotonic()<deadline,'LEGACY_WITNESS_NOT_READY');time.sleep(.3)
            need(json.loads((r.OUT/'legacy-witness.json').read_text())['status']=='READY','LEGACY_WITNESS_INVALID')
            stage_install(e,container,values);monitor(e,container,process,r.OUT);report=verify_state(e,values,r.OUT)
            # Real fail-closed hold/repair, without ever starting old V7 writers.
            e.hold('DISPOSABLE_CONTROLLED_FAILURE_REHEARSAL');need(inspect(e.name('maintenance'))['State']['Running'],'MAINTENANCE_LOST')
            need(all(not inspect(e.old[role])['State']['Running'] for role in ('risk','keycloak','backend','gateway','frontend','ingress')),'OLD_V7_WRITER_REVIVED')
            fingerprint=e.configuration_fingerprints();e.record('GATES_PRIVATE',{'all_gate_images':plan['candidate_images'],'configuration_hashes':fingerprint,'repair':'strict candidates retained; no security rollback'})
            disabled=rpc(container,{**values,'action':'disable-designated'});write(r.OUT/'designated-cleanup.json',disabled)
            deadline=time.monotonic()+60
            while e.sql('SELECT COUNT(*) FROM pd_staging_risk.subject_device_trust WHERE pending_operation_id IS NOT NULL')!=str(plan['pending_count']):need(time.monotonic()<deadline,'DESIGNATED_DISABLE_PENDING');time.sleep(.5)
            e.assert_trust_preserved();cleanup=rpc(container,{**values,'action':'cleanup'});write(r.OUT/'temporary-admin-cleanup.json',cleanup)
            receipt={'status':'PASS','plan_sha256':e.hash,'images':plan['candidate_images'],**{key:True for key in ('strict_api','strict_issuer','legacy_denied','mfa_proof','reset_resume','rbac_ownership','tls_roles','B0_SHADOW','pending_preserved','performance')}}
            e.mark_acceptance(receipt);e.open_public()
            proof={'status':'PASS','scope':'fresh disposable synthetic environment; no live data','plan_sha256':e.hash,'images':plan['candidate_images'],'native_cases':len(report['cases']),'legacy_witness':json.loads((r.OUT/'legacy-witness.json').read_text()),'restore':json.loads((e.out/'restore-proof.json').read_text()),'maintenance':'closed across checkpoint/migration/bootstrap/API startup; only strict gate opening after positive acceptance','fail_closed_repair':'simulated hold; old V7 writers never restarted; strict-compatible candidates retained','schema':9,'B0':'BASELINE_B0','network_v2':'SHADOW; retention=false','pending_preserved':2,'owner_go':False,'temporary_admin_removed':cleanup['temporary_master_client_removed'],'published_ports':0}
            write(r.OUT/'REHEARSAL.json',proof);print('PASS FINAL controlled rehearsal: native lifecycle/frontend + encrypted restore + strict-only open + no security rollback; active untouched',flush=True)
        except Exception as error:
            e.hold(type(error).__name__);raise
if __name__=='__main__':
    try:final_rehearsal()
    except Exception as error:print('FAIL '+(str(error) if isinstance(error,RuntimeError) else type(error).__name__),file=sys.stderr);sys.exit(1)
