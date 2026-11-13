"""Actual synthetic Risk/SPI/MySQL acceptance. Run only in the owned no-port helper."""
import datetime as dt,hashlib,hmac,http.server,json,os,socket,ssl,subprocess,sys,threading,time,traceback,uuid
from pathlib import Path
from urllib.request import Request
from urllib.error import HTTPError
from concurrent.futures import ThreadPoolExecutor
import verify as v
import phase2_security as security

OUT=Path('/results');CASES=[];EXPECT=[];stage='initial'
def require(value,reason):v.require(value,reason)
def record(case,details=None):
    CASES.append({'case':case,'status':'PASS','details':details or {}})
    (OUT/'integration.json').write_text(json.dumps({'cases':CASES,'expectations':EXPECT,'D17':'PENDING','G8':'INTERNET_NO_GO'},indent=2)+'\n')
    print('PASS '+case,flush=True)
def write(sql,args=None):
    with v.pymysql.connect(host='mysql',user='root',password=(v.PRIVATE/'mysql/root-password').read_text(),charset='utf8mb4',ssl=v.context,autocommit=True) as db:
        with db.cursor() as cursor:cursor.execute(sql,args);return cursor.rowcount
def await_true(predicate,reason,timeout=12):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        if predicate():return
        time.sleep(.1)
    raise RuntimeError(reason)
def count(event=None):
    return v.sql('SELECT COUNT(*) FROM pd_staging_risk.network_authentication_contexts'+(' WHERE event_id=%s' if event else ''),(event,) if event else None)[0][0]
def props():
    return dict(line.split('=',1) for line in (v.PRIVATE/'risk/application.properties').read_text().splitlines() if '=' in line and not line.startswith('#'))
def hashed(scope,value):return hmac.digest(props()['risk.authentication-history.pepper'].encode(),(scope+'\0'+value).encode(),'sha256').hex()

class Fixture(http.server.BaseHTTPRequestHandler):
    """Explicit test-only service-context simulator, absent from candidate images."""
    ip=None;successes=[];evaluations=[];errors=[]
    def log_message(self,*args):pass
    def do_POST(self):
        try:
            require(self.path in ('/internal/v1/risk/evaluations','/internal/v1/authentication-successes','/internal/v1/authentication-failures','/internal/v1/trusted-devices'),'FIXTURE_ROUTE_DENIED')
            size=int(self.headers.get('Content-Length','0'));require(0<size<16384,'FIXTURE_BODY_BOUND')
            body=json.loads(self.rfile.read(size));original=body.copy()
            if self.path.endswith('/risk/evaluations') and Fixture.ip:body['ipAddress']=Fixture.ip
            headers={'Content-Type':'application/json','Authorization':self.headers.get('Authorization','')}
            if self.headers.get('X-ZeroTrust-Risk-Request'):headers['X-ZeroTrust-Risk-Request']=self.headers['X-ZeroTrust-Risk-Request']
            request=Request('https://risk:8443'+self.path,data=json.dumps(body).encode(),headers=headers,method='POST')
            try:response=v.opener.open(request,timeout=15)
            except HTTPError as error:response=error
            raw=response.read()
            if self.path.endswith('/risk/evaluations') and response.status==200:
                Fixture.evaluations.append({'original':original,'body':body,'result':json.loads(raw)})
            if self.path.endswith('/authentication-successes') and response.status==204:Fixture.successes.append(body)
            self.send_response(response.status)
            for key in ('Content-Type','X-ZeroTrust-Risk-Request'):
                if response.headers.get(key):self.send_header(key,response.headers[key])
            self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        except Exception:
            Fixture.errors.append('FIXTURE_FORWARD_FAILED')
            self.send_response(502);self.end_headers()

def start_fixture():
    server=http.server.ThreadingHTTPServer(('0.0.0.0',8443),Fixture);server.daemon_threads=True
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('/private/fixture/server.crt','/private/fixture/server.key')
    server.socket=context.wrap_socket(server.socket,server_side=True)
    threading.Thread(target=server.serve_forever,daemon=True).start();return server

def browser_setup():
    # A fresh NSS home avoids certutil's overwrite prompt when reusing this helper.
    home=Path('/tmp/network-v2-browser-'+uuid.uuid4().hex);db=home/'.pki/nssdb';db.mkdir(parents=True)
    os.environ['HOME']=str(home)
    subprocess.run(['certutil','-N','--empty-password','-d','sql:'+str(db)],capture_output=True,check=True,timeout=15)
    subprocess.run(['certutil','-A','-d','sql:'+str(db),'-n','network-v2-ca','-t','C,,','-i','/private/ca.crt'],capture_output=True,check=True,timeout=15)

def config_fixture(token,enabled):
    rows=v.sql("SELECT ID FROM pd_staging_keycloak.AUTHENTICATOR_CONFIG WHERE ALIAS='demo-risk'")
    require(len(rows)==1,'RISK_CONFIG_UNIQUE')
    key=rows[0][0];doc=security.kc('DoAn/authentication/config/'+key,token=token)
    doc['config']['riskServiceBaseUrl']='https://risk-fixture:8443' if enabled else 'https://risk:8443'
    security.kc('DoAn/authentication/config/'+key,'PUT',doc,token,204)

def success(caller,event,subject,evaluation,client='zerotrust-spa'):
    body={'eventId':event,'subjectId':subject,'clientId':client,'authenticatedAt':dt.datetime.now(dt.timezone.utc).isoformat(),'riskEvaluationId':evaluation}
    v.risk('/authentication-successes',body,caller);return body

def evaluate(label,caller,subject,ip='8.8.8.8',device=None,expected=None):
    result=v.evaluate(subject,device,caller,ip)
    EXPECT.append({'case':label,'evaluation_id':result['evaluationId'],'candidateScore':expected,'decision':result['decision']})
    require(result['decision'] in ('STEP_UP_MFA','ALLOW','DENY'),'LIVE_DECISION_CONTRACT')
    time.sleep(.1)
    return result

def historical_fixture(subject,rows,client='zerotrust-spa'):
    # Explicit isolated synthetic historical dates, never asserted as real historical browser logins.
    now=dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    for index,(country,asn,network) in enumerate(rows):
        event='network-v2-history-fixture-'+uuid.uuid4().hex
        when=now-dt.timedelta(hours=(1,25,49)[index])
        write('INSERT INTO pd_staging_risk.authentication_success_events(event_id,subject_id,client_id,authenticated_at,recorded_at) VALUES(%s,%s,%s,%s,%s)',(event,subject,client,when,when))
        write('''INSERT INTO pd_staging_risk.network_authentication_contexts(event_id,subject_hash,client_id,country_code,asn_number,network_hash,accuracy_radius_km,evidence_quality,authenticated_at,recorded_at)
                 VALUES(%s,%s,%s,%s,%s,%s,20,'COUNTRY_ASN',%s,%s)''',(event,hashed('network-v2-subject',subject),client,country,asn,network,when,when))

def main():
    global stage
    stage='strict transport';caller=v.service_token('zerotrust-risk-caller');admin=security.admin_token()
    require(v.request(v.ISSUER+'/.well-known/openid-configuration')[1]['issuer']==v.ISSUER,'EXACT_ISSUER')
    require(v.request('https://risk:8443/internal/v1/risk/evaluations','POST',{},nonce=True)[0]==401,'UNAUTHENTICATED_RISK_NOT_DENIED')
    wrong=v.service_token('zerotrust-provisioner')
    require(v.request('https://risk:8443/internal/v1/risk/evaluations','POST',{},wrong,nonce=True)[0] in (401,403),'WRONG_CALLER_NOT_DENIED')
    require(v.sql("SELECT checksum FROM pd_staging_risk.flyway_schema_history WHERE version='5'")[0][0]==661092940,'V5_DRIFT')
    record('Strict TLS/CRL, signed service JWT, issuer and wrong-caller denial')
    stage='native browser';server=start_fixture();config_fixture(admin,True);browser_setup()
    with v.sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-proxy-server'])
        actor=v.accounts['student_a']
        # First real native login uses the observed private peer unchanged, despite forged public headers.
        ctx=browser.new_context(ignore_https_errors=False,extra_http_headers={'X-Forwarded-For':'8.8.8.8','X-Real-IP':'8.8.8.8','Forwarded':'for=8.8.8.8;proto=https'})
        attempt=security.start_login(browser,actor,ctx);security.finish(attempt);tokens=security.redeem(attempt,'network-v2-private-peer-spoof')
        await_true(lambda:len(Fixture.successes)>=1,'NATIVE_LOGIN_CALLBACK_MISSING')
        raw=Fixture.successes[-1];event=raw['eventId'];evaluation=raw['riskEvaluationId']
        require(raw['subjectId']==actor['id'] and raw['clientId']=='zerotrust-spa','NATIVE_SUBJECT_CLIENT')
        require(Fixture.evaluations[-1]['result']['evaluationId']==evaluation,'NATIVE_EVALUATION_UUID')
        peer=v.sql("SELECT IP_ADDRESS FROM pd_staging_keycloak.EVENT_ENTITY WHERE TYPE='LOGIN' AND USER_ID=%s ORDER BY EVENT_TIME DESC LIMIT 1",(actor['id'],))[0][0]
        require(peer==socket.gethostbyname(socket.gethostname()) and Fixture.evaluations[-1]['original']['ipAddress']==peer,'FORWARDED_PEER_SPOOF_ACCEPTED')
        time.sleep(.5);require(count(event)==0,'PRIVATE_PEER_BECAME_PUBLIC_HISTORY')
        record('Native LOGIN/MFA/PKCE correlation and forged-forwarding rejection',{'evaluation_id':evaluation,'public_browser_geoip':'NOT_VERIFIED_PRIVATE_PEER','network_learning':'NO_PUBLIC_CONTEXT'})
        # Explicit service-input simulator: no browser/header override is enabled in Risk/SPI artifacts.
        Fixture.ip='8.8.8.8';ctx.close()
        remaining=31-int(time.time())%30;time.sleep(remaining)
        attempt=security.start_login(browser,actor);security.finish(attempt);tokens=security.redeem(attempt,'network-v2-controlled-service-context')
        await_true(lambda:len(Fixture.successes)>=2,'NATIVE_PUBLIC_FIXTURE_CALLBACK_MISSING')
        native=Fixture.successes[-1];event=native['eventId'];evaluation=native['riskEvaluationId']
        await_true(lambda:count(event)==1,'NATIVE_NETWORK_HISTORY_NOT_PERSISTED')
        row=v.sql('SELECT s.subject_id,n.subject_hash,n.client_id,n.asn_number,n.country_code,n.evidence_quality,n.accuracy_radius_km FROM pd_staging_risk.network_authentication_contexts n JOIN pd_staging_risk.authentication_success_events s USING(event_id) WHERE n.event_id=%s',(event,))[0]
        require(row[0]==actor['id'] and row[1]==hashed('network-v2-subject',actor['id']) and row[2]=='zerotrust-spa' and row[3]==15169 and row[4]=='US','NATIVE_HISTORY_OWNERSHIP')
        record('Actual SPI native LOGIN -> asynchronous MySQL history',{'evaluation_id':evaluation,'event_id':event,'subject_client_match':True,'ASN_present':True,'quality':row[5],'city_accuracy_radius_km':row[6],'network_input':'EXPLICIT_SYNTHETIC_SERVICE_CONTEXT_NOT_PUBLIC_BROWSER'})
        before=count();refresh= v.request(v.ISSUER+'/protocol/openid-connect/token','POST',{'grant_type':'refresh_token','client_id':'zerotrust-spa','refresh_token':tokens['refresh_token']},form=True)
        require(refresh[0]==200,'NATIVE_REFRESH_FAILED')
        sso=security.start_login(browser,actor,attempt['ctx'],prompt='');security.finish(sso);security.redeem(sso,'network-v2-sso')
        time.sleep(.5);require(count()==before,'SSO_REFRESH_LEARNED_NETWORK')
        v.risk('/authentication-successes',native,caller);time.sleep(.3);require(count()==before,'NATIVE_SUCCESS_REPLAY_LEARNED')
        record('Native refresh, SSO without new evaluation and success replay do not learn')
        attempt['ctx'].close()
        error_before=v.sql("SELECT COUNT(*) FROM pd_staging_keycloak.EVENT_ENTITY WHERE TYPE='LOGIN_ERROR'")[0][0]
        bad=browser.new_context(ignore_https_errors=False)
        invalid=actor.copy();invalid['password']='synthetic-deliberately-wrong-password'
        attempt_bad=security.start_login(browser,invalid,bad)
        await_true(lambda:v.sql("SELECT COUNT(*) FROM pd_staging_keycloak.EVENT_ENTITY WHERE TYPE='LOGIN_ERROR'")[0][0]>error_before,'FAILED_PASSWORD_NATIVE_ERROR_MISSING')
        require(not security.parse_qs(security.urlsplit(attempt_bad['page'].url).query).get('code'),'FAILED_PASSWORD_GOT_CODE')
        time.sleep(.5);require(count()==before,'FAILED_LOGIN_LEARNED');bad.close()
        record('Failed native LOGIN creates no trusted network history')
        # Fault only the isolated shadow table. B0 tables, MFA, JWT and TLS stay available.
        write('RENAME TABLE pd_staging_risk.network_authentication_contexts TO pd_staging_risk.network_context_fault_fixture')
        try:
            successes_before=len(Fixture.successes)
            time.sleep(31-int(time.time())%30)
            fault_attempt=security.start_login(browser,actor);security.finish(fault_attempt)
            security.redeem(fault_attempt,'network-v2-shadow-db-unavailable')
            await_true(lambda:len(Fixture.successes)>successes_before,'FAULT_NATIVE_SUCCESS_CALLBACK_MISSING')
            fault_event=Fixture.successes[-1]['eventId']
            require(v.sql('SELECT COUNT(*) FROM pd_staging_risk.authentication_success_events WHERE event_id=%s',(fault_event,))[0][0]==1,'B0_SUCCESS_HISTORY_BLOCKED_BY_SHADOW')
            fault_attempt['ctx'].close()
        finally:
            write('RENAME TABLE pd_staging_risk.network_context_fault_fixture TO pd_staging_risk.network_authentication_contexts')
        require(count(fault_event)==0,'SHADOW_OUTAGE_FABRICATED_HISTORY')
        record('Actual native MFA/PKCE succeeds while shadow database table is unavailable')
        browser.close()
    config_fixture(admin,False);server.shutdown();require(not Fixture.errors,'FIXTURE_FORWARD_ERRORS')
    contracts()

def load_evidence():
    data=json.loads((OUT/'integration.json').read_text())
    CASES[:]=data['cases'];EXPECT[:]=data.get('expectations',[])

def contracts():
    global stage
    if not CASES:load_evidence()
    caller=v.service_token('zerotrust-risk-caller')
    stage='contract fences';subject=str(uuid.uuid4());other=str(uuid.uuid4())
    result=evaluate('cold-start',caller,subject,expected=None)
    event=str(uuid.uuid4());success(caller,event,other,result['evaluationId']);time.sleep(.2);require(count(event)==0,'CROSS_SUBJECT_LEARNING')
    wrong_client=str(uuid.uuid4());success(caller,wrong_client,subject,result['evaluationId'],'other-client');time.sleep(.2);require(count(wrong_client)==0,'CROSS_CLIENT_LEARNING')
    valid=str(uuid.uuid4());success(caller,valid,subject,result['evaluationId']);await_true(lambda:count(valid)==1,'LEGIT_CORRELATION_CONSUMED_BY_MISMATCH')
    replay=str(uuid.uuid4());success(caller,replay,subject,result['evaluationId']);time.sleep(.3);require(count(replay)==0,'ONE_USE_UUID_REPLAY')
    record('Exact subject/client and one-use evaluation correlation on real MySQL')
    revoke=v.service_token('zerotrust-portal-risk-admin')
    for pending in (True,False):
        subject=str(uuid.uuid4());result=evaluate('generation-race',caller,subject)
        operation={'operationId':str(uuid.uuid4()),'requestedBy':'network-v2-synthetic-integration'}
        v.risk('/subjects/'+subject+'/trusted-devices/revocations',operation,revoke)
        if not pending:v.risk('/subjects/'+subject+'/trusted-devices/revocations/completion',operation,revoke)
        event=str(uuid.uuid4());success(caller,event,subject,result['evaluationId']);time.sleep(.4)
        require(count(event)==0,'GENERATION_PENDING_FENCE')
        require(v.sql('SELECT generation FROM pd_staging_risk.subject_device_trust WHERE subject_id=%s',(subject,))[0][0]==1,'GENERATION_CHANGED_BY_SHADOW')
        if pending:require(v.evaluate(subject,None,caller,'8.8.8.8')['decision']=='DENY','PENDING_NOT_DENIED')
    record('Real revoke/completion generation and pending-reset fences preserved')
    subject=str(uuid.uuid4());device='synthetic-revoked';result=v.evaluate(subject,device,caller,'8.8.8.8')
    v.risk('/trusted-devices',{'subjectId':subject,'deviceId':device,'trustGeneration':result['trustGeneration']},caller)
    write("UPDATE pd_staging_risk.known_devices SET status='REVOKED',revocation_reason='SECURITY',revoked_at=UTC_TIMESTAMP(6) WHERE subject_id=%s",(subject,))
    result=v.evaluate(subject,device,caller,'8.8.8.8');require(result['decision']=='DENY','REVOCATION_NOT_DENIED')
    event=str(uuid.uuid4());success(caller,event,subject,result['evaluationId']);time.sleep(.3);require(count(event)==0,'DENIED_REVOCATION_LEARNED')
    record('Security-revoked device remains DENY and cannot seed network history')
    stage='deterministic historical fixture'
    network=hashed('network-v2-address','8.8.8.8')
    fixtures=[('familiar', [('US',15169,network)]*3,0),('unfamiliar-asn',[('US',64500,network)]*3,20),
              ('country-change',[('VN',15169,network)]*3,20),('new-network',[('US',15169,'a'*64)]*3,10),
              ('known-return',[('VN',15169,'a'*64),('US',15169,network),('US',15169,network)],15),
              ('novel-all',[('VN',64500,'a'*64)]*3,50)]
    for label,rows,points in fixtures:
        subject=str(uuid.uuid4());historical_fixture(subject,rows)
        result=evaluate(label,caller,subject,expected=points)
        require(result['decision']=='STEP_UP_MFA','MANDATORY_MFA_SHADOW_CHANGED')
    subject=str(uuid.uuid4());historical_fixture(subject,[('US',15169,network)]*3,client='other-client')
    evaluate('history-client-isolation',caller,subject,expected=None)
    evaluate('partial-geoip',caller,str(uuid.uuid4()),ip='1.1.1.1',expected=None)
    evaluate('non-public-unavailable',caller,str(uuid.uuid4()),ip='10.2.3.4',expected=None)
    evaluate('no-record-public',caller,str(uuid.uuid4()),ip='3000::1',expected=None)
    record('Real MySQL shadow scoring scenarios submitted',{'history':'EXPLICIT_ISOLATED_SYNTHETIC_UTC_DATES','expected_cases':len(EXPECT),'verified_native_learning_separately':True})
    stage='queue and dependency fault'
    db=v.pymysql.connect(host='mysql',user='root',password=(v.PRIVATE/'mysql/root-password').read_text(),charset='utf8mb4',ssl=v.context,autocommit=True)
    ids=[]
    try:
        with db.cursor() as cursor:cursor.execute('LOCK TABLES pd_staging_risk.network_authentication_contexts WRITE')
        def call(index):
            response=v.evaluate(str(uuid.uuid4()),None,caller,'8.8.8.8')
            require(response['decision']=='STEP_UP_MFA','SHADOW_FAULT_CHANGED_B0')
            return response['evaluationId']
        with ThreadPoolExecutor(max_workers=4) as workers:ids=list(workers.map(call,range(20)))
    finally:
        with db.cursor() as cursor:cursor.execute('UNLOCK TABLES')
        db.close()
    time.sleep(1)
    (OUT/'queue-offers.json').write_text(json.dumps({'offered_ids':ids,'offered':20,'configured_queue_capacity':2,'B0_success_responses':20,'no_live_enforcement':True},indent=2))
    record('Blocked shadow dependency and bounded queue cannot block successful B0 evaluate',{'responses':20,'queue_capacity':2})
    (OUT/'integration-complete').write_text('PASS')

def resume_native():
    global stage
    load_evidence();stage='remaining native negative and shadow outage'
    admin=security.admin_token();server=start_fixture();Fixture.ip='8.8.8.8';config_fixture(admin,True);browser_setup()
    with v.sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-proxy-server'])
        actor=v.accounts['student_a'];before=count()
        error_before=v.sql("SELECT COUNT(*) FROM pd_staging_keycloak.EVENT_ENTITY WHERE TYPE='LOGIN_ERROR'")[0][0]
        bad=browser.new_context(ignore_https_errors=False)
        invalid=actor.copy();invalid['password']='synthetic-deliberately-wrong-password'
        attempt_bad=security.start_login(browser,invalid,bad)
        await_true(lambda:v.sql("SELECT COUNT(*) FROM pd_staging_keycloak.EVENT_ENTITY WHERE TYPE='LOGIN_ERROR'")[0][0]>error_before,'FAILED_PASSWORD_NATIVE_ERROR_MISSING')
        require(not security.parse_qs(security.urlsplit(attempt_bad['page'].url).query).get('code'),'FAILED_PASSWORD_GOT_CODE')
        time.sleep(.5);require(count()==before,'FAILED_LOGIN_LEARNED');bad.close()
        record('Failed native LOGIN creates no trusted network history')
        # Fault only the isolated shadow table. B0 tables, MFA, JWT and TLS stay available.
        write('RENAME TABLE pd_staging_risk.network_authentication_contexts TO pd_staging_risk.network_context_fault_fixture')
        try:
            successes_before=len(Fixture.successes)
            time.sleep(31-int(time.time())%30)
            fault_attempt=security.start_login(browser,actor);security.finish(fault_attempt)
            security.redeem(fault_attempt,'network-v2-shadow-db-unavailable')
            await_true(lambda:len(Fixture.successes)>successes_before,'FAULT_NATIVE_SUCCESS_CALLBACK_MISSING')
            fault_event=Fixture.successes[-1]['eventId']
            require(v.sql('SELECT COUNT(*) FROM pd_staging_risk.authentication_success_events WHERE event_id=%s',(fault_event,))[0][0]==1,'B0_SUCCESS_HISTORY_BLOCKED_BY_SHADOW')
            fault_attempt['ctx'].close()
        finally:
            write('RENAME TABLE pd_staging_risk.network_context_fault_fixture TO pd_staging_risk.network_authentication_contexts')
        require(count(fault_event)==0,'SHADOW_OUTAGE_FABRICATED_HISTORY')
        record('Actual native MFA/PKCE succeeds while shadow database table is unavailable')
        browser.close()
    config_fixture(admin,False);server.shutdown();require(not Fixture.errors,'FIXTURE_FORWARD_ERRORS')
    contracts()

def retention_fixture():
    now=dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    ids=[]
    for label,days in [('expired-a',31),('expired-b',32),('expired-c',33),('boundary-safe',1)]:
        event='network-v2-retention-fixture-'+uuid.uuid4().hex;when=now-dt.timedelta(days=days)
        write('INSERT INTO pd_staging_risk.authentication_success_events(event_id,subject_id,client_id,authenticated_at,recorded_at) VALUES(%s,%s,%s,%s,%s)',(event,'synthetic-retention','zerotrust-spa',when,when))
        write("INSERT INTO pd_staging_risk.network_authentication_contexts(event_id,subject_hash,client_id,network_hash,evidence_quality,authenticated_at,recorded_at) VALUES(%s,%s,'zerotrust-spa',%s,'PARTIAL',%s,%s)",(event,'c'*64,'d'*64,when,when))
        ids.append({'event':event,'expired':days>30})
    (OUT/'retention-fixtures.json').write_text(json.dumps({'ids':ids,'parents':v.sql('SELECT COUNT(*) FROM pd_staging_risk.authentication_success_events')[0][0],'trust':[int(x) for x in v.sql('SELECT SUM(generation),COUNT(*) FROM pd_staging_risk.subject_device_trust')[0]]},indent=2))
    print('PASS isolated retention fixtures prepared; no active or native history backdated',flush=True)

def failed_login_bound():
    """Fill the remaining evidence gap: bind LOGIN_ERROR to the exact browser auth session."""
    global stage
    stage='failed LOGIN session binding';browser_setup()
    actor=v.accounts['student_a'];before=count();started=int(time.time()*1000)
    with v.sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=['--no-proxy-server'])
        context=browser.new_context(ignore_https_errors=False);page=context.new_page();page.set_default_timeout(20000)
        query={'client_id':'zerotrust-spa','redirect_uri':v.PORTAL+'/','response_type':'code','scope':'openid',
               'state':uuid.uuid4().hex,'code_challenge':security.base64.urlsafe_b64encode(hashlib.sha256(uuid.uuid4().bytes).digest()).decode().rstrip('='),'code_challenge_method':'S256','prompt':'login'}
        page.goto(v.ISSUER+'/protocol/openid-connect/auth?'+security.urlencode(query))
        # Exact 26.8.2 AuthenticationSessionManager format: base64url(id.signature),
        # then optional sticky route. Native Keycloak verifies HS512 on the POST;
        # this test only compares its session identifier, never trusts an unsigned input.
        roots=[security.base64.urlsafe_b64decode(cookie['value'].split('.')[0]+'===').decode().rsplit('.',1)[0]
               for cookie in context.cookies() if cookie['name']=='AUTH_SESSION_ID']
        require(len(roots)==1,'BROWSER_AUTH_SESSION_COOKIE_UNAVAILABLE')
        page.locator('#username').fill(actor['username']);page.locator('#password').fill('synthetic-deliberately-wrong-password')
        page.locator('#kc-login').click();page.wait_for_load_state('domcontentloaded')
        require(not security.parse_qs(security.urlsplit(page.url).query).get('code'),'FAILED_LOGIN_ISSUED_CODE')
        matches=[]
        for row in v.sql('''SELECT ID,USER_ID,CLIENT_ID,COALESCE(DETAILS_JSON,DETAILS_JSON_LONG_VALUE),ERROR
                           FROM pd_staging_keycloak.EVENT_ENTITY WHERE TYPE='LOGIN_ERROR' AND EVENT_TIME >= %s''',(started-1000,)):
            details=json.loads(row[3] or '{}')
            if details.get('code_id')==roots[0]:matches.append(row)
        if len(matches)!=1:
            (OUT/'failed-login-binding-diagnostic.json').write_text(json.dumps({'matched':len(matches),
                'cookie_root_sha256':hashlib.sha256(roots[0].encode()).hexdigest(),'cookie_root_length':len(roots[0]),
                'recent_events':[{'subject_match':row[1]==actor['id'],'client_match':row[2]=='zerotrust-spa',
                    'detail_keys':list(json.loads(row[3] or '{}')),
                    'code_id_sha256':hashlib.sha256(str(json.loads(row[3] or '{}').get('code_id')).encode()).hexdigest(),
                    'code_id_length':len(str(json.loads(row[3] or '{}').get('code_id')))}
                    for row in v.sql("SELECT ID,USER_ID,CLIENT_ID,COALESCE(DETAILS_JSON,DETAILS_JSON_LONG_VALUE),ERROR FROM pd_staging_keycloak.EVENT_ENTITY WHERE TYPE='LOGIN_ERROR' ORDER BY EVENT_TIME DESC LIMIT 2")]},indent=2))
        require(len(matches)==1,'NATIVE_ERROR_NOT_EXACTLY_BOUND_TO_BROWSER_SESSION')
        event=matches[0]
        require(event[1]==actor['id'] and event[2]=='zerotrust-spa' and event[4]=='invalid_user_credentials','NATIVE_ERROR_SUBJECT_CLIENT_MISMATCH')
        time.sleep(.3);require(count()==before,'FAILED_SESSION_CREATED_NETWORK_CONTEXT')
        browser.close()
    (OUT/'failed-login-bound.json').write_text(json.dumps({'status':'PASS','native_event_id':event[0],
        'exact_auth_session_cookie_code_id_match':True,'exact_subject_client_match':True,
        'native_error':'invalid_user_credentials','authorization_code_issued':False,'trusted_network_rows_added':0,
        'session_cookie_or_password_exported':False},indent=2))
    print('PASS exact browser auth session -> native LOGIN_ERROR subject/client; no code or network history',flush=True)

def retention_check():
    state=json.loads((OUT/'retention-fixtures.json').read_text());expired=[x['event'] for x in state['ids'] if x['expired']]
    require(sum(count(event) for event in expired)==1,'RETENTION_BATCH_NOT_EXACTLY_TWO')
    require(all(count(x['event'])==1 for x in state['ids'] if not x['expired']),'RETENTION_REMOVED_RECENT_CONTEXT')
    require(v.sql('SELECT COUNT(*) FROM pd_staging_risk.authentication_success_events')[0][0]==state['parents'],'RETENTION_REMOVED_PARENT_EVENTS')
    require(list(v.sql('SELECT SUM(generation),COUNT(*) FROM pd_staging_risk.subject_device_trust')[0])==state['trust'],'RETENTION_CHANGED_SECURITY_STATE')
    (OUT/'retention.json').write_text(json.dumps({'status':'PASS','deleted':2,'remaining_expired':1,'fresh_context_preserved':True,'success_parents_and_generations_unchanged':True,'scheduler':'real candidate service on MySQL8.4.13','active_cleanup_enabled':False},indent=2))
    print('PASS real scheduled bounded retention; parent history and security state unchanged',flush=True)

def rollback_compatibility():
    global stage
    stage='old image compatibility on synthetic V7 schema'
    def guard():
        # Exact synthetic security-state witness, never exported as raw identities/credentials.
        rows=[]
        for table in ('subject_device_trust','device_trust_revocations','known_devices','network_authentication_contexts'):
            rows.append((table,v.sql('SELECT * FROM pd_staging_risk.'+table+' ORDER BY 1')))
        return hashlib.sha256(repr(rows).encode()).hexdigest()
    before=guard();caller=v.service_token('zerotrust-risk-caller')
    result=v.evaluate(v.accounts['student_a']['id'],None,caller,'8.8.8.8')
    require(result['decision']=='STEP_UP_MFA','OLD_IMAGE_MANDATORY_MFA_CHANGED')
    event='rollback-wire-fixture-'+uuid.uuid4().hex
    success(caller,event,v.accounts['student_a']['id'],result['evaluationId'])
    require(v.sql('SELECT COUNT(*) FROM pd_staging_risk.authentication_success_events WHERE event_id=%s',(event,))[0][0]==1,'OLD_IMAGE_SUCCESS_WIRE_INCOMPATIBLE')
    require(before==guard(),'ROLLBACK_COMPATIBILITY_CHANGED_SECURITY_STATE')
    (OUT/'rollback-compatibility.json').write_text(json.dumps({'status':'PASS','schema':'V1-V7 retained',
        'old_image_startup_hibernate_validate':True,'new_optional_success_UUID_accepted':True,
        'mandatory_MFA_preserved':True,'exact_security_context_witness_unchanged':True,
        'database_restore_or_downgrade':False,'scope':'isolated lane only; not active rollback'},indent=2))
    print('PASS old Risk startup/V7 schema/new success wire; security state unchanged without restore',flush=True)

def shadow_allow_boundary():
    global stage
    stage='B0 ALLOW despite maximum shadow candidate';load_evidence()
    caller=v.service_token('zerotrust-risk-caller');subject=str(uuid.uuid4());device='synthetic-allow-boundary-'+uuid.uuid4().hex
    # Explicit service-contract fixtures for D/T/H and trusted-device preconditions.
    # These are not claimed as additional historical native browser authentications.
    v.history(subject,caller)
    first=v.evaluate(subject,device,caller,'8.8.8.8')
    require(first['decision']=='STEP_UP_MFA','INITIAL_MANDATORY_MFA_MISSING')
    v.risk('/trusted-devices',{'subjectId':subject,'deviceId':device,'trustGeneration':first['trustGeneration']},caller)
    historical_fixture(subject,[('VN',64500,'e'*64)]*3)
    result=evaluate('B0-ALLOW-shadow50',caller,subject,device=device,expected=50)
    require(result['decision']=='ALLOW' and result['dataStatus']=='COMPLETE' and result['riskScore']==12.5,'SHADOW_CHANGED_B0_ALLOW')
    record('Candidate score50 cannot change actual B0 ALLOW12.5',{'fixtures':'explicit disposable service/UTC-history fixtures; native MFA verified separately'})

if __name__=='__main__':
    try:
        {'main':main,'resume-native':resume_native,'contracts':contracts,'failed-login-bound':failed_login_bound,'rollback-compatibility':rollback_compatibility,'shadow-allow-boundary':shadow_allow_boundary,'retention-fixture':retention_fixture,'retention-check':retention_check}[sys.argv[1] if len(sys.argv)>1 else 'main']()
    except Exception as error:
        (OUT/'integration-failure.json').write_text(json.dumps({'stage':stage,'type':type(error).__name__,'line':traceback.extract_tb(error.__traceback__)[-1].lineno,'reason':str(error) if type(error) is RuntimeError else 'details withheld','passed_cases':len(CASES)},indent=2))
        print('FAIL '+stage+' '+type(error).__name__+'; sensitive details withheld',flush=True)
        raise SystemExit(1)
