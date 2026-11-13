"""Targeted HTTPS/service/browser checks ONLY on the retained synthetic restore lane."""
import datetime as dt
import hashlib
import ipaddress
import json
import socket
import sys
import time
import traceback
import uuid
import verify as v
import phase2_security as security
from phase2_security import browser_setup


def main():
    global OUTPUT,STAGE
    mode=sys.argv[1];caller=v.service_token('zerotrust-risk-caller')
    output={'mode':mode,'evaluations':[],'browser':[],'public_browser_peer_verified':False}
    OUTPUT=output;STAGE='service'
    def evaluate(label,subject,device,ip):
        response=v.evaluate(subject,device,caller,ip)
        output['evaluations'].append({'case':label,'test_ip':ip,'response':response})
        return response
    if mode!='browser':
        subject=str(uuid.uuid4());device='geoip-'+uuid.uuid4().hex
        v.history(subject,caller)
        first=evaluate('mandatory-new-device',subject,device,'8.8.8.8')
        v.require(first['decision']=='STEP_UP_MFA','New device bypassed mandatory MFA')
        v.risk('/trusted-devices',{'subjectId':subject,'deviceId':device,'trustGeneration':first['trustGeneration']},caller)
        result=evaluate('real-public-country',subject,device,'8.8.8.8')
        if mode=='corrupt':
            v.require(result['riskScore'] is None and result['dataStatus']=='INCOMPLETE' and result['decision']=='STEP_UP_MFA','Corrupt GeoIP became ALLOW')
        else:
            v.require(result['riskScore']==12.5 and result['dataStatus']=='COMPLETE' and result['decision']=='ALLOW','Real country context not applied with fixed D/T/H')
    if mode=='full':
        for label,ip in [('same-policy-public','8.8.4.4'),('real-public-ipv6','2001:4860:4860::8888'),
                         ('country-missing','1.1.1.1'),('no-record','192.0.2.44'),('private','10.2.3.4'),
                         ('loopback','127.0.0.1'),('loopback-v6','::1'),('ula-v6','fd00::1'),('reserved-v6','2001:db8::1'),
                         ('declared-trusted-cidr','198.51.100.22'),('declared-high-cidr','203.0.113.3')]:
            r=evaluate(label,subject,device,ip)
            if label in ('country-missing','no-record','ula-v6','reserved-v6'):
                v.require(r['dataStatus']=='INCOMPLETE' and r['riskScore'] is None and r['decision']=='STEP_UP_MFA','Unknown location treated as safe')
            if label in ('same-policy-public','real-public-ipv6','private','loopback','loopback-v6'):
                v.require(r['riskScore']==12.5,'Default/country Network B0 mismatch')
            if label=='declared-trusted-cidr':v.require(r['riskScore']==0 and r['decision']=='ALLOW','CIDR precedence changed')
            if label=='declared-high-cidr':v.require(r['riskScore']==25 and r['decision']=='STEP_UP_MFA','High-network guardrail changed')
        for ip in ('not-an-ip','::ffff:8.8.8.8',''):
            status,_=v.request('https://risk:8443/internal/v1/risk/evaluations','POST',{'subjectId':subject,
                'authenticationSessionId':str(uuid.uuid4()),'clientId':'zerotrust-spa','ipAddress':ip},caller,nonce=True)
            v.require(status==400,'Invalid/mapped IP bypassed DTO normalization')
        output['invalid_and_mapped_ip_rejected']=True
    if mode in ('full','browser'):
        STAGE='browser';creds={k:hashlib.sha256(repr(v.credential_snapshot(a['id'])).encode()).hexdigest() for k,a in v.accounts.items()}
        browser_setup()
        with v.sync_playwright() as p:
            browser=p.chromium.launch(headless=True,args=['--no-proxy-server'])
            for spoof in ((False,True) if mode=='full' else (True,)):
                if spoof:time.sleep(31-int(time.time())%30)
                start=dt.datetime.now(dt.timezone.utc).isoformat()
                headers={'X-Forwarded-For':'8.8.8.8','X-Real-IP':'8.8.8.8','Forwarded':'for=8.8.8.8;proto=https;host=spoof.invalid'} if spoof else {}
                ctx=browser.new_context(ignore_https_errors=False,extra_http_headers=headers)
                if spoof:
                    # Restrict forged headers to browser auth traffic; exchange the
                    # PKCE code over the normal allowed client contract. Sending
                    # custom headers on the SPA token CORS request tests CORS,
                    # rather than the trusted-peer authentication boundary.
                    attempt=security.start_login(browser,v.accounts['student_a'],ctx)
                    page=attempt['page'];v.require(page.locator('input[name=otp]').count()==1,'Expected actual OTP step')
                    security.finish(attempt);tokens=security.redeem(attempt,'geoip-forged-public-headers')
                else:
                    page,ctx,tokens,flow=v.login(browser,v.accounts['student_a'],ctx)
                    v.require(flow=='verified OTP','GeoIP browser MFA changed')
                    page.wait_for_load_state('networkidle')
                v.api('/api/students/me/scores',tokens['access_token'])
                v.api('/api/admin/users',tokens['access_token'],expected=403)
                actual=socket.gethostbyname(socket.gethostname())
                peer=v.sql("SELECT IP_ADDRESS FROM pd_staging_keycloak.EVENT_ENTITY WHERE USER_ID=%s AND TYPE='LOGIN' ORDER BY EVENT_TIME DESC LIMIT 1",(v.accounts['student_a']['id'],))[0][0]
                v.require(peer==actual and ipaddress.ip_address(peer).is_private and peer!='8.8.8.8','Keycloak peer trust boundary failed')
                output['browser'].append({'case':'forged-public-headers' if spoof else 'normal-https-login','start':start,
                    'end':dt.datetime.now(dt.timezone.utc).isoformat(),'native_event_matches_actual_helper_peer':True,
                    'actual_peer_scope':'PRIVATE_DOCKER_NETWORK','OTP':True,'PKCE':'S256','own_grades':200,'STUDENT_admin':403})
                ctx.close()
            browser.close()
        v.require(all(hashlib.sha256(repr(v.credential_snapshot(a['id'])).encode()).hexdigest()==creds[k] for k,a in v.accounts.items()),'Existing synthetic credentials changed')
        output['existing_credentials_unchanged']=True
    v.require(v.sql("SELECT checksum,success FROM pd_staging_risk.flyway_schema_history WHERE version='5'")[0]==(661092940,1),'V5 changed')
    output['V5']=661092940;output['status']='PASS'
    (v.RESULTS/('service-'+mode+'.json')).write_text(json.dumps(output,indent=2)+'\n')
    print('PASS GeoIP '+mode+' targeted authenticated service'+('/HTTPS browser spoof boundary' if mode in ('full','browser') else '')+' checks',flush=True)


if __name__=='__main__':
    try:main()
    except Exception as e:
        row={'status':'FAIL','type':type(e).__name__,'line':traceback.extract_tb(e.__traceback__)[-1].lineno}
        row['stage']=globals().get('STAGE');row['completed_observations']=globals().get('OUTPUT')
        if type(e) is RuntimeError:row['reason']=str(e)
        (v.RESULTS/('failure-'+sys.argv[1]+'.json')).write_text(json.dumps(row,indent=2)+'\n')
        print('FAIL '+json.dumps(row),flush=True);raise SystemExit(1)
