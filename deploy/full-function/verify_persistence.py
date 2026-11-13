"""Targeted checks after the host restarts only the new full-function services."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import verify as v


def browser_setup(home):
    (home/'.pki/nssdb').mkdir(parents=True);os.environ['HOME']=str(home)
    for args in (['certutil','-N','--empty-password','-d','sql:'+str(home/'.pki/nssdb')],
                 ['certutil','-A','-d','sql:'+str(home/'.pki/nssdb'),'-n','full-ca','-t','C,,','-i','/private/ca.crt']):
        subprocess.run(args,check=True,capture_output=True)


def main():
    v.passed[:]=json.loads((v.RESULTS/'acceptance.json').read_text())['passed']
    browser_setup(Path('/tmp/zt-persistence-browser'))
    if '--risk-down' in sys.argv:
        with v.sync_playwright() as p:
            browser=p.chromium.launch(headless=True,args=['--no-proxy-server'])
            v.login(browser,v.accounts['student_a'],expect_deny=True)
            browser.close()
        v.record('Actual Risk outage on isolated profile: password login fails closed without issuing a token')
        return
    before=json.loads((v.RESULTS/'persistence-before.json').read_text())
    v.require(v.sql('SELECT COUNT(*) FROM pd_staging_school.students')[0][0]==before['student_count'],'Student count changed on restart')
    v.require(v.sql('SELECT COUNT(*) FROM pd_staging_school.scores')[0][0]==before['score_count'],'Score count changed on restart')
    v.require(hashlib.sha256(repr(v.sql('SELECT * FROM pd_staging_school.scores ORDER BY id')).encode()).hexdigest()==before['score_rows_sha256'],'Score rows changed on restart')
    v.require(v.sql("SELECT checksum FROM pd_staging_risk.flyway_schema_history WHERE version='5'")[0][0]==before['v5']==661092940,'V5 changed')
    _,jwks=v.request(v.ISSUER+'/protocol/openid-connect/certs')
    v.require(hashlib.sha256(json.dumps(jwks,sort_keys=True).encode()).hexdigest()==before['jwks_sha256'],'JWKS changed')
    for alias,actor in v.accounts.items():
        v.require(hashlib.sha256(repr(v.credential_snapshot(actor['id'])).encode()).hexdigest()==before['credentials_sha256'][alias],'Credential changed on restart')
    v.require(v.sql('SELECT generation,pending_operation_id FROM pd_staging_risk.subject_device_trust WHERE subject_id=%s',(before['reset_subject'],))[0]==(before['reset_generation'],None),'Reset trust state changed')
    caller=v.service_token('zerotrust-risk-caller')
    v.require(v.evaluate(before['low_subject'],before['low_device'],caller)['decision']=='ALLOW','LOW trust/history lost')
    v.require(v.evaluate(before['high_subject'],'brand-new-persistence',caller,before['high_ip'])['decision']=='DENY','Redis failure history lost')
    with v.sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-proxy-server'])
        page,ctx,t,flow=v.login(browser,v.accounts['student_b'])
        v.require(flow=='verified OTP','Re-enrolled OTP not usable after restart')
        v.api('/api/students/me/scores',t['access_token'])
        browser.close()
    v.record('Real restart preserves School CRUD rows, V5, JWKS, MFA credentials, reset generation and Redis history; OTP/own grades work afterward')
    (v.RESULTS/'persistence-after.json').write_text(json.dumps({'status':'PASS','verified':list(before),'D17':'PENDING','G8':'INTERNET_NO_GO'},indent=2)+'\n')


if __name__=='__main__':
    try:main()
    except Exception as error:
        detail={'error_type':type(error).__name__}
        if type(error) is RuntimeError:detail['reason']=str(error)
        (v.RESULTS/('outage-failure.json' if '--risk-down' in sys.argv else 'persistence-failure.json')).write_text(json.dumps(detail,indent=2)+'\n')
        print('FAIL persistence/outage '+type(error).__name__+'; sensitive details withheld',flush=True)
        raise SystemExit(1)
