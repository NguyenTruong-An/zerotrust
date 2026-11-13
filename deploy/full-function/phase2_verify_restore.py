"""Read state and authenticate only against the disposable restored network."""
import hashlib
import json
from pathlib import Path
import traceback
from urllib.parse import urlsplit
import verify as v
from phase2_security import browser_setup


def main():
    v.require(v.sql("SELECT checksum,success FROM pd_staging_risk.flyway_schema_history WHERE version='5'")[0]==(661092940,1),'Restored V5 differs')
    _,jwks=v.request(v.ISSUER+'/protocol/openid-connect/certs')
    expected=json.loads((v.PRIVATE/'phase2-restore-public-witness.json').read_text())
    actual={k['kid']:hashlib.sha256(json.dumps(k,sort_keys=True).encode()).hexdigest() for k in jwks['keys']}
    v.require(actual==expected['jwks_by_kid_sha256'],'Restored JWKS/signing keys differ')
    browser_setup()
    with v.sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-proxy-server'])
        ctx=browser.new_context(ignore_https_errors=False);ui=[]
        ctx.on('response',lambda r:ui.append({'path':urlsplit(r.url).path,'status':r.status}) if urlsplit(r.url).path.startswith('/api/') else None)
        page,ctx,t,flow=v.login(browser,v.accounts['student_a'],ctx)
        v.require(flow=='verified OTP','Restored OTP authentication missing')
        # The student UI legitimately hydrates four requests in parallel, matching
        # the unchanged four-slot admission policy. Do not add a fifth probe.
        page.wait_for_load_state('networkidle')
        (v.RESULTS/'browser-api-statuses.json').write_text(json.dumps(ui,indent=2)+'\n')
        v.require(any(x['path']=='/api/students/me/scores' and x['status']==200 for x in ui),'First restored browser grade read did not succeed')
        v.require(not any(x['status']==429 for x in ui),'Normal restored browser hydration was rate-limited')
        v.api('/api/students/me/scores',t['access_token'])
        v.api('/api/admin/users',t['access_token'],expected=403)
        browser.close()
    (v.RESULTS/'restore-acceptance.json').write_text(json.dumps({'status':'PASS','verified':['V5 661092940','JWKS exact','native password/OTP PKCE login','own grades','STUDENT ADMIN403'],'published_ports':0,'D17':'PENDING','G8':'INTERNET_NO_GO'},indent=2)+'\n')
    print('PASS restored exact JWKS/V5, real PKCE+OTP, own grades and STUDENT ADMIN403',flush=True)


if __name__=='__main__':
    try:main()
    except Exception as e:
        detail=(' '+str(e)) if type(e) is RuntimeError else ''
        print('FAIL post-restore '+type(e).__name__+' line='+str(traceback.extract_tb(e.__traceback__)[-1].lineno)+detail+'; secrets withheld',flush=True);raise SystemExit(1)
