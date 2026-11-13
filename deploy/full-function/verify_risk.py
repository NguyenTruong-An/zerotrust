"""Finish real Risk/browser acceptance from an explicitly high-risk test subnet IP."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import traceback
import uuid

import verify as v

stage='risk preconditions'


def main():
    global stage
    v.passed[:]=json.loads((v.RESULTS/'acceptance.json').read_text())['passed']
    v.require(any('Old Trusted Device replay' in x for x in v.passed),'Real reset/re-enrollment acceptance required')
    high_ip='10.253.245.27'
    probe=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);probe.connect(('mysql',3306))
    v.require(probe.getsockname()[0]==high_ip,'Helper is not on the approved dedicated high-risk test IP');probe.close()
    caller=v.service_token('zerotrust-risk-caller')
    low=str(uuid.uuid4());v.history(low,caller);device='full-function-risk-'+uuid.uuid4().hex
    first=v.evaluate(low,device,caller)
    v.require(first['decision']=='STEP_UP_MFA','Mandatory MFA not applied')
    v.risk('/trusted-devices',{'subjectId':low,'deviceId':device,'trustGeneration':first['trustGeneration']},caller)
    low_result=v.evaluate(low,device,caller)
    medium_result=v.evaluate(low,'brand-new-medium-'+uuid.uuid4().hex,caller,'203.0.113.3')
    v.require(low_result['riskLevel']=='LOW' and low_result['decision']=='ALLOW','LOW API mismatch')
    v.require(medium_result['riskLevel']=='MEDIUM' and medium_result['decision']=='STEP_UP_MFA','MEDIUM API mismatch')
    v.require(40<=medium_result['riskScore']<75,'Numeric MEDIUM threshold fixture mismatch')
    v.record('Real authenticated Risk API LOW/ALLOW and MEDIUM/STEP_UP_MFA with unchanged B0/mandatory MFA')
    home=Path('/tmp/zt-high-browser');(home/'.pki/nssdb').mkdir(parents=True);os.environ['HOME']=str(home)
    for args in (['certutil','-N','--empty-password','-d','sql:'+str(home/'.pki/nssdb')],
                 ['certutil','-A','-d','sql:'+str(home/'.pki/nssdb'),'-n','full-ca','-t','C,,','-i','/private/ca.crt']):
        subprocess.run(args,check=True,capture_output=True)
    with v.sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-proxy-server'])
        admin,ctx,t,_=v.login(browser,v.accounts['admin']);at=t['access_token']
        stage='create disposable HIGH actor through business ADMIN API'
        suffix=uuid.uuid4().hex[:7];password=secrets.token_urlsafe(24)
        student=v.api('/api/admin/students',at,'POST',{'username':'high-'+suffix,'password':password,'email':suffix+'@demo.invalid','firstName':'Synthetic','lastName':'High','studentCode':'HIGH_'+suffix,'dateOfBirth':'2005-01-01','gender':'OTHER','classCode':'DEMO_A'},201)
        raw=v.sql('SELECT u.keycloak_user_id FROM pd_staging_school.users u JOIN pd_staging_school.students s ON s.user_id=u.id WHERE s.id=UNHEX(%s)',(student['id'].replace('-',''),))[0][0]
        high=str(uuid.UUID(bytes=raw));v.history(high,caller,2)
        for _ in range(5):v.risk('/authentication-failures',{'eventId':str(uuid.uuid4()),'subjectId':high,'sourceIp':high_ip},caller)
        # Browser sends a genuine new-device context from this actual source IP.
        result=v.evaluate(high,'brand-new-'+suffix,caller,high_ip)
        v.require(result['riskLevel']=='HIGH' and result['decision']=='DENY','High browser fixture is not actually HIGH')
        stage='real HIGH browser refusal'
        v.login(browser,{'id':high,'username':'high-'+suffix,'password':password,'role':'STUDENT'},expect_deny=True)
        v.record('Real HIGH browser on dedicated high-risk fixture IP: DENY before OTP/enrollment/token; no forwarded-header spoof or threshold change')
        _,jwks=v.request(v.ISSUER+'/protocol/openid-connect/certs')
        target=v.accounts['student_b']['id']
        generation=v.sql('SELECT generation FROM pd_staging_risk.subject_device_trust WHERE subject_id=%s',(target,))[0][0]
        snapshot={'student_count':v.sql('SELECT COUNT(*) FROM pd_staging_school.students')[0][0],
                  'score_count':v.sql('SELECT COUNT(*) FROM pd_staging_school.scores')[0][0],
                  'score_rows_sha256':hashlib.sha256(repr(v.sql('SELECT * FROM pd_staging_school.scores ORDER BY id')).encode()).hexdigest(),
                  'v5':v.sql("SELECT checksum FROM pd_staging_risk.flyway_schema_history WHERE version='5'")[0][0],
                  'jwks_sha256':hashlib.sha256(json.dumps(jwks,sort_keys=True).encode()).hexdigest(),
                  'credentials_sha256':{k:hashlib.sha256(repr(v.credential_snapshot(a['id'])).encode()).hexdigest() for k,a in v.accounts.items()},
                  'reset_generation':generation,'reset_subject':target,'low_subject':low,'low_device':device,
                  'high_subject':high,'high_ip':high_ip,'numeric_results':{'low':low_result['riskScore'],'medium':medium_result['riskScore'],'high':result['riskScore']}}
        (v.RESULTS/'persistence-before.json').write_text(json.dumps(snapshot,indent=2)+'\n')
        browser.close()


if __name__=='__main__':
    try:main()
    except Exception as error:
        failure={'stage':stage,'error_type':type(error).__name__,'line':traceback.extract_tb(error.__traceback__)[-1].lineno}
        if type(error) is RuntimeError:failure['reason']=str(error)
        (v.RESULTS/'risk-failure.json').write_text(json.dumps(failure,indent=2)+'\n')
        print('FAIL stage='+stage+' type='+type(error).__name__+'; sensitive details withheld',flush=True)
        raise SystemExit(1)
