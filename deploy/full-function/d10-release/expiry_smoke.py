"""Only the added expiry case, on one NEW disposable identity; no full suite rerun."""
import json,sys,uuid
from pathlib import Path

def native():
    import os,ssl
    import native_acceptance as n
    from native_admin import Native
    from playwright.sync_api import sync_playwright
    values=json.load(sys.stdin);n.need(values['scope']=='NEW_DISPOSABLE_REHEARSAL','NO_LIVE_EXPIRY_HELPER')
    n.OUT=Path('/results/expiry');n.OUT.mkdir(exist_ok=True);n.INPUT={'scope':'NEW_DISPOSABLE_REHEARSAL'}
    n.TLS=ssl.create_default_context(cafile='/public/all-ca-with-crl.pem');n.TLS.verify_flags|=ssl.VERIFY_CRL_CHECK_CHAIN
    n.HTTP=n.build_opener(n.ProxyHandler({}),n.HTTPSHandler(context=n.TLS),n.NoRedirect())
    home=Path('/tmp/d10-expiry-'+uuid.uuid4().hex);db=home/'.pki/nssdb';db.mkdir(parents=True);os.environ['HOME']=str(home)
    n.subprocess.run(['certutil','-N','-d','sql:'+str(db),'--empty-password'],check=True,capture_output=True)
    n.subprocess.run(['certutil','-A','-d','sql:'+str(db),'-n','D10 public test CA','-t','C,,','-i','/public/browser-root.crt'],check=True,capture_output=True)
    a=Native(values);receipt=a.designated();actor=values['accounts']['admin'];actor['id']=receipt['new_designated_ids']['admin']
    try:
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True,args=['--disable-dev-shm-usage'])
            _,token,claims,count=n.login(browser,actor);n.need(count>0,'NATIVE_OTP_REQUIRED')
            n.api('/api/admin/users',token['access_token']);n.expiry_boundary(token['access_token'],claims);browser.close()
        n.save('rollout-native.json',{'scope':'NEW_DISPOSABLE_REHEARSAL','status':'PASS','cases':n.CASES,'tokens_persisted':False})
    finally:
        # The case waits past TTL300+skew60, so the M2M provisioner token used for creation has expired.
        status,body=a.request('/realms/DoAn/protocol/openid-connect/token','POST',{'grant_type':'client_credentials','client_id':'zerotrust-provisioner','client_secret':values['provisioner_secret']},False,True)
        n.need(status==200 and body.get('access_token'),'DESIGNATED_PROVISIONER_REAUTH');a.token=body['access_token'];a.disable_designated()

def host():
    import subprocess,time
    from executor import Executor,ROOT,canonical,need,run,write
    from operation import generated_inputs,monitor
    out=ROOT/'target/d10-phase3-20261113/rehearsal-final2';e=Executor(json.loads((out/'execution-plan.json').read_text()),'rehearsal')
    values=generated_inputs(uuid.uuid4().hex[:16]);values['accounts']={'admin':values['accounts']['admin']};values['scope']='NEW_DISPOSABLE_REHEARSAL'
    values['provisioner_secret']=run('docker','exec',e.name('backend'),'sh','-c',"sed -n 's/^keycloak\\.admin\\.client-secret[[:space:]]*=[[:space:]]*//p' /run/demo/application.properties").decode().strip()
    need(values['provisioner_secret'],'PROVISIONER_MISSING');container=e.project+'-check-1';results=out/'expiry';results.mkdir(exist_ok=True)
    process=subprocess.Popen(['docker','exec','-i',container,'/opt/tools/bin/python','/scripts/expiry_smoke.py','native'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    process.stdin.write(canonical(values));process.stdin.close();monitor(e,container,process,results)
    need(json.loads((results/'rollout-native.json').read_text())['status']=='PASS','EXPIRY_FAILED')
    print('PASS added native expiry boundary only; one NEW disposable identity disabled; no live mutation')
if __name__=='__main__':
    try:globals()['native' if len(sys.argv)>1 and sys.argv[1]=='native' else 'host']()
    except Exception as error:
        import traceback
        frame=traceback.extract_tb(error.__traceback__)[-1]
        reason=str(error) if isinstance(error,RuntimeError) and str(error).replace('_','').isalnum() else ''
        print('FAIL expiry smoke '+type(error).__name__+'_LINE_'+str(frame.lineno)+(' '+reason if reason else ''),flush=True);sys.exit(1)
