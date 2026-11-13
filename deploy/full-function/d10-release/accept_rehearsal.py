"""Run ONLY new Phase3 rehearsal checks; Phase2's 469/18 evidence is reused."""
import json,math,subprocess,sys,time
from pathlib import Path
from executor import Executor,ROOT,canonical,inspect,need,run,sha,write
import rehearse as r
def ready(host,path,expected=200,port=8443):
    code="import ssl,time,urllib.request,urllib.error; c=ssl.create_default_context(cafile='/public/internal-ca-with-crl.pem'); c.verify_flags|=ssl.VERIFY_CRL_CHECK_CHAIN; end=time.monotonic()+100\nwhile True:\n try:\n  try: s=urllib.request.urlopen('https://"+host+":"+str(port)+path+"',context=c,timeout=5).status\n  except urllib.error.HTTPError as e:s=e.code\n  if s=="+str(expected)+":break\n except Exception:pass\n if time.monotonic()>end:raise RuntimeError('READY_TIMEOUT')\n time.sleep(.5)\nprint('PASS ready')"
    run('docker','compose','-p',r.PROJECT,'-f',str(r.OUT/'source.compose.json'),'exec','-T','check','/opt/tools/bin/python','-c',code,timeout=120)
def main():
    plan=json.loads((r.OUT/'execution-plan.json').read_text());e=Executor(plan,'rehearsal');need(e.j['phase']=='GATES_PRIVATE','NEED_PRIVATE_GATES')
    ready('backend','/api/admin/users',401);ready('portal.full-function.test','/api/admin/users',401,39443);ready('risk','/actuator/health')
    actors=json.loads((r.PRIVATE/'accounts.json').read_text())
    for name,actor in actors.items():
        rows=e.sql("SELECT BIN_TO_UUID(u.id),COALESCE(BIN_TO_UUID(s.id),'') FROM pd_staging_school.users u LEFT JOIN pd_staging_school.students s ON s.user_id=u.id WHERE u.keycloak_user_id=UUID_TO_BIN('%s')"%actor['id']).splitlines();need(len(rows)==1,'SYNTHETIC_MAPPING');parts=rows[0].split('\t');actor['portal_id']=parts[0];actor['student_id']=parts[1] if len(parts)>1 else None
    public=r.OUT/'public';(public/'all-ca-with-crl.pem').write_bytes((public/'internal-ca-with-crl.pem').read_bytes())
    inputs={'scope':'NEW_DISPOSABLE_REHEARSAL','accounts':actors,'journal':str(Path(plan['output']).relative_to(r.OUT.relative_to(ROOT))/'journal.json').replace('\\','/'),'retain_legacy':False,'issuer_secret':r.inputs(plan)['zerotrust-issuer-security']}
    process=subprocess.Popen(['docker','compose','-p',r.PROJECT,'-f',str(r.OUT/'source.compose.json'),'exec','-T','check','/opt/tools/bin/python','/scripts/native_acceptance.py'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    process.stdin.write(canonical(inputs));process.stdin.close();handled=set();deadline=time.monotonic()+800
    while process.poll()is None:
        need(time.monotonic()<deadline,'NATIVE_ACCEPTANCE_TIMEOUT')
        path=r.OUT/'acceptance-control.json'
        if path.exists():
            item=json.loads(path.read_text())
            if item['id']not in handled:
                need(item['action']in ('restart-backend','stop-risk','start-risk'),'ACCEPTANCE_CONTROL_SCOPE')
                if item['action']=='restart-backend':e.stop(e.name('backend'));e.start(e.name('backend'));ready('backend','/api/admin/users',401)
                elif item['action']=='stop-risk':e.stop(e.name('risk'))
                else:e.start(e.name('risk'));ready('risk','/actuator/health')
                write(r.OUT/'acceptance-ack.json',{'id':item['id']});handled.add(item['id'])
        time.sleep(.2)
    stdout=process.stdout.read().decode(errors='replace');safe='\n'.join(line for line in stdout.splitlines() if line.startswith(('PASS ','FAIL ')));(r.OUT/'rollout-native.log').write_text(safe+'\n');print(safe)
    need(process.returncode==0,'PHASE3_NATIVE_FAILED_SEE_SANITIZED_RECEIPT')
    target=actors['student_a']['id'];deadline=time.monotonic()+60
    while True:
        status=e.sql("SELECT stage FROM pd_staging_risk.security_operations WHERE subject_id='%s' AND operation_kind='MFA_RESET' ORDER BY created_at DESC LIMIT 1"%target)
        if status=='COMPLETED':break
        need(time.monotonic()<deadline,'RESET_NOT_COMPLETED');time.sleep(.5)
    need(e.sql("SELECT COUNT(*) FROM pd_staging_risk.security_operations WHERE subject_id='%s' AND operation_kind='MFA_RESET'"%target)=='1','RESET_REPLAY_CREATED_ANOTHER_OPERATION')
    need(e.sql("SELECT COUNT(*) FROM pd_staging_keycloak.CREDENTIAL WHERE USER_ID='%s' AND TYPE IN ('otp','recovery-authn-codes')"%target)=='0','RESET_CREDENTIALS_REMAIN')
    need(e.sql('SELECT COUNT(*) FROM pd_staging_risk.subject_device_trust WHERE pending_operation_id IS NOT NULL')=='2','LEGACY_PENDING_CHANGED')
    report=json.loads((r.OUT/'rollout-native.json').read_text());report['reset_completion']='COMPLETED; one durable operation; no OTP/recovery credentials';report['pending_count_preserved']=2;write(r.OUT/'rollout-native.json',report)
    print('PASS Phase3 real frontend/native checks, completed idempotent reset and existing pending preservation')
if __name__=='__main__':
    try:main()
    except Exception as e:print('FAIL '+(str(e) if isinstance(e,RuntimeError) else type(e).__name__),file=sys.stderr);sys.exit(1)
