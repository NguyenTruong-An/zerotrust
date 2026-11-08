"""Run deterministic B0/API assertions over the private staging network."""
import argparse
import datetime as dt
import json
import uuid
from urllib.parse import urlencode

from academic_demo import STATE, TOKEN, compose, require, verify_boundary

CLIENT = 'zerotrust-risk-caller'
BASE = 'https://risk:8443/internal/v1'
DEVICE = 'academic-synthetic-test-device'


def post(url, payload, token=None, nonce=None):
    pairs = [('url',url),('data-binary',payload)]
    if token:
        pairs += [('header','Authorization: Bearer '+token),('header','Content-Type: application/json')]
    if nonce:
        pairs.append(('header','X-ZeroTrust-Risk-Request: '+nonce))
    config = ''.join(f'{name} = {json.dumps(value)}\n' for name,value in pairs)
    result = compose('exec','-T','risk','curl','--silent','--show-error','--max-time','12','--cacert',
                     '/run/demo/ca.crt','--write-out','\n%{http_code}','--config','-',data=config).stdout
    payload, status = result.rsplit('\n',1)
    return int(status),json.loads(payload) if payload else {}


def api(path,payload,token,nonce=None):
    return post(BASE+path,json.dumps(payload),token,nonce)


def evaluate(token,sub,ip,device=DEVICE):
    session=str(uuid.uuid4())
    status, result = api('/risk/evaluations',{'subjectId':sub,'authenticationSessionId':session,
        'clientId':'zerotrust-spa','ipAddress':ip,'userAgent':'Academic Demo B0 test','deviceId':device},
        token,str(uuid.uuid4()))
    require(status==200 and result.get('subjectId')==sub and result.get('authenticationSessionId')==session,
            'Risk API response/binding failed')
    return result


def assert_risk(row,level,decision,label):
    require((row['riskLevel'],row['decision'])==(level,decision),'Unexpected B0 outcome: '+label)
    print(f'PASS {label} {row["riskScore"]} {level} {decision}',flush=True)


def issue(client_id):
    doc=json.loads((STATE/'installer/academic-demo-realm.json').read_text())
    client=next(r for r in doc['clients'] if r['clientId']==client_id)
    status, response = post(TOKEN,urlencode({'grant_type':'client_credentials','client_id':client_id,'client_secret':client['secret']}))
    require(status==200 and response.get('access_token'),'Candidate service client not issued a token')
    return response['access_token']


def seed_history(token,sub,offset=0):
    now=dt.datetime.now(dt.timezone.utc)
    for i in range(1,6):
        occurred=now-dt.timedelta(weeks=i,days=offset)
        status,_=api('/authentication-successes',{'eventId':str(uuid.uuid4()),'subjectId':sub,'clientId':'zerotrust-spa',
                     'authenticatedAt':occurred.isoformat()},token)
        require(status==204,'Unable to seed test history through the private API')


def run():
    code,_ = post(BASE+'/risk/evaluations','{}')
    require(code==401,'Risk accepted unauthenticated caller')
    token=issue(CLIENT)
    low,high,cold=[str(uuid.uuid4()) for _ in range(3)]
    seed_history(token,low)
    seed_history(token,high,offset=2)
    first=evaluate(token,low,'198.51.100.22')
    require(first['riskScore']<40,'Expected low numeric score before MFA guard')
    assert_risk(first,'MEDIUM','STEP_UP_MFA','Mandatory MFA')
    assert_risk(evaluate(token,low,'203.0.113.3'),'MEDIUM','STEP_UP_MFA','numeric MEDIUM')
    status,_=api('/trusted-devices',{'subjectId':low,'deviceId':DEVICE,'trustGeneration':first['trustGeneration']},token)
    require(status==204,'Synthetic trusted-device register failed')
    assert_risk(evaluate(token,low,'198.51.100.22'),'LOW','ALLOW','trusted LOW')
    admin_token=issue('zerotrust-portal-risk-admin')
    revoke=f'/subjects/{low}/trusted-devices/revocations'
    operation={'operationId':str(uuid.uuid4()),'requestedBy':'academic-smoke'}
    require(api(revoke,operation,admin_token)[0]==204 and api(revoke+'/completion',operation,admin_token)[0]==204,
            'Trusted device revoke/complete failed')
    assert_risk(evaluate(token,low,'198.51.100.22'),'MEDIUM','STEP_UP_MFA','revoked device step-up')
    for _ in range(5):
        status,_=api('/authentication-failures',{'eventId':str(uuid.uuid4()),'subjectId':high,'sourceIp':'203.0.113.4'},token)
        require(status==204,'Redis Lua history write failed')
    high_case=evaluate(token,high,'203.0.113.4',None)
    assert_risk(high_case,'HIGH','DENY','numeric HIGH')
    priority=evaluate(token,low,'192.0.2.99')
    require(priority['decision']=='DENY' and priority['riskScore'] is None,'Expected priority DENY before scoring')
    missing=evaluate(token,cold,'198.51.100.22',None)
    require(missing['dataStatus']=='INCOMPLETE' and missing['decision']=='STEP_UP_MFA' and missing['riskScore'] is None,
            'Expected incomplete data challenge')
    print('PASS Priority DENY, Missing Data, authenticated Risk API and Redis Lua history',flush=True)
    compose('restart','redis')
    compose('up','-d','--wait','--wait-timeout','80','redis','risk')
    after=evaluate(token,high,'203.0.113.4',None)
    require(after['decision']=='DENY' and after['riskScore']==high_case['riskScore'],'Redis persisted history did not match after restart')
    print('PASS Redis restart and AOF history persistence',flush=True)


def redis_outage():
    token=issue(CLIENT)
    subject=str(uuid.uuid4())
    seed_history(token,subject)
    require(evaluate(token,subject,'198.51.100.22')['dataStatus']=='COMPLETE','History precondition missing')
    compose('stop','--timeout','20','redis')
    try:
        readiness=compose('exec','-T','risk','curl','--silent','--show-error','--max-time','10','--cacert',
            '/run/demo/ca.crt','-o','/dev/null','-w','%{http_code}','https://risk:8443/actuator/health/readiness').stdout
        require(readiness=='503','Risk readiness did not report unavailable Redis')
        result=evaluate(token,subject,'198.51.100.22')
        require(result['dataStatus']=='INCOMPLETE' and result['decision']=='STEP_UP_MFA' and result['riskScore'] is None,
                'Redis outage did not trigger the incomplete-data MFA contract')
        print('PASS Redis outage readiness 503 and INCOMPLETE/STEP_UP_MFA',flush=True)
    finally:
        compose('up','-d','--wait','--wait-timeout','100','redis','risk')
    require(evaluate(token,subject,'198.51.100.22')['dataStatus']=='COMPLETE','Risk did not recover after Redis outage')
    print('PASS Risk history complete after Redis recovery',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--redis-outage',action='store_true')
    args=parser.parse_args()
    verify_boundary()
    (redis_outage if args.redis_outage else run)()
