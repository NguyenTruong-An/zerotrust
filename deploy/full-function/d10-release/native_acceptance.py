"""D10 rollout acceptance for NEW/designated test identities only. No tokens leave memory.

One process can retain a legitimate legacy login across maintenance. Browser API evidence
contains method/path/status only; no request headers, HAR, screenshots or token bodies.
"""
import base64,hashlib,hmac,http.client,json,math,os,secrets,socket,ssl,struct,subprocess,sys,time,uuid,traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.request import Request,build_opener,ProxyHandler,HTTPSHandler,HTTPRedirectHandler
from urllib.error import HTTPError
from urllib.parse import urlencode,urlsplit,parse_qs
from playwright.sync_api import sync_playwright
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes
PORTAL='https://portal.full-function.test:39443';ISSUER='https://auth.full-function.test:39443/realms/DoAn'
OUT=Path('/results');CASES=[];LAST={};INPUT={};TLS=None;HTTP=None
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None
def need(ok,reason):
    if not ok:raise RuntimeError(reason)
def save(name,value):
    p=OUT/name;t=p.with_suffix('.tmp');t.write_text(json.dumps(value,indent=2)+'\n');t.replace(p)
def record(case,details=None):CASES.append({'case':case,'status':'PASS','details':details or {}});save('rollout-native.json',{'scope':INPUT['scope'],'cases':CASES,'tokens_persisted':False});print('PASS '+case,flush=True)
def request(url,token=None,method='GET',data=None,form=False):
    headers={'Accept':'application/json'}
    if token:headers['Authorization']='Bearer '+token
    if data is not None:headers['Content-Type']='application/x-www-form-urlencoded' if form else 'application/json';data=(urlencode(data) if form else json.dumps(data)).encode()
    try:r=HTTP.open(Request(url,headers=headers,method=method,data=data),timeout=12)
    except HTTPError as e:r=e
    raw=r.read(262145);need(len(raw)<=262144,'RESPONSE_BOUND')
    try:body=json.loads(raw) if raw else None
    except ValueError:body=None
    return r.status,body
def api(path,token,expected=200,base=PORTAL,method='GET',data=None):
    status,body=request(base+path,token,method,data);need(status==expected,'HTTP_'+str(status)+'_EXPECTED_'+str(expected));return body
def payload(token):return json.loads(base64.urlsafe_b64decode(token.split('.')[1]+'==='))
def verified(token):
    parts=token.split('.');p=payload(token);header=json.loads(base64.urlsafe_b64decode(parts[0]+'==='));status,jwks=request(ISSUER+'/protocol/openid-connect/certs');need(status==200 and header['alg']=='RS256','JWT_SIGNATURE_CONFIG')
    k=next(k for k in jwks['keys'] if k['kid']==header['kid']);integer=lambda x:int.from_bytes(base64.urlsafe_b64decode(x+'==='),'big');rsa.RSAPublicNumbers(integer(k['e']),integer(k['n'])).public_key().verify(base64.urlsafe_b64decode(parts[2]+'==='),(parts[0]+'.'+parts[1]).encode(),padding.PKCS1v15(),hashes.SHA256())
    need(p['iss']==ISSUER and p['exp']>time.time() and p['exp']-p['iat']==300,'JWT_NATIVE_IDENTITY_TTL');return p
def otp(actor):
    while LAST.get(actor['id'])==int(time.time())//30:time.sleep(.1)
    counter=int(time.time())//30;LAST[actor['id']]=counter;digest=hmac.digest(actor['otp'].encode(),struct.pack('>Q',counter),'sha1');offset=digest[-1]&15;return f'{(int.from_bytes(digest[offset:offset+4],"big")&0x7fffffff)%1000000:06d}'
def factors(page,actor):
    page.wait_for_load_state('domcontentloaded')
    if page.locator('#password').count():
        if page.locator('#username').count():page.locator('#username').fill(actor['username'])
        page.locator('#password').fill(actor['password'])
        with page.expect_navigation(wait_until='domcontentloaded'):page.locator('#kc-login').click()
    count=0
    while page.locator('input[name=otp]').count() and count<3:
        page.locator('input[name=otp]').fill(otp(actor))
        with page.expect_navigation(wait_until='domcontentloaded'):page.locator('#kc-login').click()
        count+=1
    return count
def login(browser,actor,context=None,prompt='login',proof=None,exchange=True,native_action=None,new_password=None):
    context=context or browser.new_context(ignore_https_errors=False);page=context.new_page();page.set_default_timeout(20000)
    page.route(PORTAL+'/**',lambda route:route.fulfill(status=200,body='D10 designated callback'))
    verifier=secrets.token_urlsafe(48);challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    q={'client_id':'zerotrust-spa','redirect_uri':PORTAL+'/','response_type':'code','scope':'openid','state':uuid.uuid4().hex,'code_challenge':challenge,'code_challenge_method':'S256'}
    if prompt:q['prompt']=prompt
    if proof:q['claims']=json.dumps({'id_token':{'zt_action_proof':{'value':proof}}})
    if native_action:q['kc_action']=native_action
    page.goto(ISSUER+'/protocol/openid-connect/auth?'+urlencode(q),wait_until='domcontentloaded')
    count=factors(page,actor) if prompt!='none' else 0
    mutated=False
    if new_password is not None and page.locator('#password-new').count():
        page.locator('#password-new').fill(new_password);page.locator('#password-confirm').fill(new_password)
        with page.expect_navigation(wait_until='domcontentloaded'):page.locator('#kc-submit').click()
        actor['password']=new_password;mutated=True
    code=parse_qs(urlsplit(page.url).query).get('code',[None])[0]
    if prompt=='none' and code is None:return context,None,None,count
    if mutated and not exchange:return context,{'code':code,'verifier':verifier},None,count
    need(code is not None,'NATIVE_CODE_MISSING')
    if not exchange:return context,{'code':code,'verifier':verifier},None,count
    status,body=request(ISSUER+'/protocol/openid-connect/token',method='POST',data={'grant_type':'authorization_code','client_id':'zerotrust-spa','redirect_uri':PORTAL+'/','code_verifier':verifier,'code':code},form=True)
    need(status==200 and body.get('access_token'),'NATIVE_TOKEN_EXCHANGE');return context,body,verified(body['access_token']),count
def refresh(token):return request(ISSUER+'/protocol/openid-connect/token',method='POST',data={'grant_type':'refresh_token','client_id':'zerotrust-spa','refresh_token':token},form=True)
def phase():
    file=OUT/INPUT['journal'];return json.loads(file.read_text())['phase'] if file.exists() else 'PREPARED'
def wait_phase(expected,timeout=1200):
    end=time.monotonic()+timeout
    while phase()!=expected:
        need(time.monotonic()<end,'WAIT_PRIVATE_STAGE');time.sleep(.3)
def control(action):
    marker=uuid.uuid4().hex;save('acceptance-control.json',{'id':marker,'action':action});deadline=time.monotonic()+90
    while True:
        p=OUT/'acceptance-ack.json'
        if p.exists() and json.loads(p.read_text()).get('id')==marker:return
        need(time.monotonic()<deadline,'CONTROL_TIMEOUT');time.sleep(.2)
def performance(token):
    latencies=[]
    for _ in range(40):
        t=time.perf_counter();api('/api/admin/users',token);latencies.append(1000*(time.perf_counter()-t))
    ordered=sorted(latencies);p95=ordered[math.ceil(.95*len(ordered))-1];need(p95<=250,'GATEWAY_P95_BUDGET')
    def measured(_):
        t=time.perf_counter();api('/api/admin/users',token,base='https://backend:8443');return 1000*(time.perf_counter()-t)
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures=[];start=time.monotonic()
        for n in range(30):
            while time.monotonic()<start+n*.1:time.sleep(.005)
            futures.append(pool.submit(measured,n))
        loaded=sorted(f.result() for f in futures)
    p99=loaded[math.ceil(.99*len(loaded))-1];need(p99<=500,'BACKEND_P99_BUDGET')
    record('Performance smoke matches proposed fixture budget',{'gateway_samples':40,'gateway_p95_ms':round(p95,2),'backend_requests':30,'backend_concurrency_limit':4,'backend_offered_rps':10,'backend_p99_ms':round(p99,2),'backend_200':30,'authorization_503':0})

def expiry_boundary(token,claims):
    # Original native-signed JWT stays in RAM; never forge exp or alter realm TTL/clock.
    deadline=claims['exp']+61
    while time.time()<=deadline:time.sleep(.5)
    control('stop-risk')
    try:
        api('/api/admin/users',token,401)
        api('/api/admin/users',token,401,'https://backend:8443')
    finally:control('start-risk')
    record('Native JWT beyond TTL300/skew60 is rejected before unavailable authority at both API gates',{'gateway':401,'direct_backend':401,'native_ttl':300,'skew_elapsed':60,'authority_stopped_during_check':True})
def main():
    global INPUT,TLS,HTTP
    INPUT=json.load(sys.stdin);need(INPUT['scope'] in ('NEW_DISPOSABLE_REHEARSAL','DESIGNATED_D10_ACCOUNTS'),'ACCOUNT_SCOPE_REQUIRED')
    TLS=ssl.create_default_context(cafile='/public/all-ca-with-crl.pem');TLS.verify_flags|=ssl.VERIFY_CRL_CHECK_CHAIN;HTTP=build_opener(ProxyHandler({}),HTTPSHandler(context=TLS),NoRedirect())
    home=Path('/tmp/d10-rollout-browser-'+uuid.uuid4().hex);db=home/'.pki/nssdb';db.mkdir(parents=True);os.environ['HOME']=str(home)
    subprocess.run(['certutil','-N','--empty-password','-d','sql:'+str(db)],capture_output=True,check=True)
    subprocess.run(['certutil','-A','-d','sql:'+str(db),'-n','d10-browser-ca','-t','C,,','-i','/public/browser-root.crt'],capture_output=True,check=True)
    admin=INPUT['accounts']['admin'];student=INPUT['accounts']['student_a']
    with sync_playwright() as w:
        browser=w.chromium.launch(headless=True,args=['--disable-dev-shm-usage'])
        if INPUT.get('retain_legacy'):
            # A long-idle legacy Risk can exceed the SPI timeout once (cold pool) and correctly
            # fail closed; retry only the missing-code witness login, never a guard or assertion.
            for attempt in range(3):
                try:context,old,old_claim,factor=login(browser,student);break
                except RuntimeError as error:
                    if str(error)!='NATIVE_CODE_MISSING' or attempt==2:raise
                    time.sleep(10)
            need(factor>0 and 'zt_sec_epoch'not in old_claim,'NOT_LEGACY_NATIVE_WITNESS');api('/api/students/me',old['access_token']);save('legacy-witness.json',{'status':'READY','native_otp':True,'legacy_api_http':200,'expires_at':old_claim['exp'],'token_saved':False})
            wait_phase('GATES_PRIVATE')
            api('/api/students/me',old['access_token'],401);status,body=refresh(old['refresh_token']);need(status>=400 and not(isinstance(body,dict) and body.get('access_token')),'LEGACY_REFRESH_UPGRADED')
            _,code,_,_=login(browser,student,context,prompt='none');need(code is None,'LEGACY_SSO_UPGRADED')
            record('Legacy native JWT/SSO/refresh cannot upgrade across V7 to strict cutover',{'legacy_jwt_still_unexpired':old_claim['exp']>time.time(),'legacy_refresh_http':status,'ssO_code_issued':False})
        else:wait_phase('GATES_PRIVATE')
        admin_context,at,ac,af=login(browser,admin);_,st,sc,sf=login(browser,student);need(af and sf,'NATIVE_MFA_REQUIRED')
        for p,actor,role in [(ac,admin,'ADMIN'),(sc,student,'STUDENT')]:need(p['sub']==actor['id'] and role in p['realm_access']['roles'] and p.get('zt_sec_ver')==1 and p['sid']==p['zt_sec_sid'],'ROLE_SUBJECT_EPOCH')
        for base in (PORTAL,'https://backend:8443'):
            api('/api/admin/users',at['access_token'],base=base);me=api('/api/students/me',st['access_token'],base=base)['data'];scores=api('/api/students/me/scores',st['access_token'],base=base)['data'];content=scores.get('content',[]) if isinstance(scores,dict) else scores
            need(me['userId']==student['portal_id'] and me['id']==student['student_id'] and all(s['studentId']==me['id'] for s in content),'OWNERSHIP')
            api('/api/admin/users',st['access_token'],403,base);api('/api/admin/users',None,401,base)
        record('Native fresh ADMIN/STUDENT MFA and Gateway/direct Backend 200/403/401/ownership')
        _,sso,sso_claim,factor=login(browser,admin,admin_context,prompt='none');need(sso is not None and not factor and sso_claim['sid']==ac['sid'],'STRICT_SSO_REUSE');at=sso;ac=sso_claim
        status,rotated=refresh(st['refresh_token']);need(status==200 and verified(rotated['access_token'])['zt_sec_epoch']==sc['zt_sec_epoch'],'STRICT_REFRESH_ROTATION')
        status,reused=refresh(st['refresh_token']);need(status>=400 and not(isinstance(reused,dict) and reused.get('access_token')),'STRICT_REFRESH_REUSE')
        _,st,sc,_=login(browser,student)
        if INPUT.get('exercise_native_mutations'):
            status,machine=request('https://keycloak:8443/realms/DoAn/protocol/openid-connect/token',method='POST',data={'grant_type':'client_credentials','client_id':'zerotrust-provisioner','client_secret':INPUT['provisioner_secret']},form=True);need(status==200,'MUTATION_MACHINE_AUTH')
            user_url='https://keycloak:8443/admin/realms/DoAn/users/'+student['id']
            previous=st;previous_epoch=sc['zt_sec_epoch']
            need(request(user_url,machine['access_token'],'PUT',{'enabled':False})[0]==204,'DESIGNATED_DISABLE');api('/api/students/me',previous['access_token'],401,'https://backend:8443')
            need(request(user_url,machine['access_token'],'PUT',{'enabled':True})[0]==204,'DESIGNATED_ENABLE');_,st,sc,_=login(browser,student);need(sc['zt_sec_epoch']>previous_epoch,'REENABLE_REVIVED_EPOCH')
            record('Native designated disable/re-enable synchronizes authority and never revives old JWT')
            previous=st;new_password=secrets.token_urlsafe(32)
            need(request(user_url+'/reset-password',machine['access_token'],'PUT',{'type':'password','value':new_password,'temporary':False})[0]==204,'DESIGNATED_PASSWORD_RESET');student['password']=new_password;api('/api/students/me',previous['access_token'],401,'https://backend:8443');_,st,sc,_=login(browser,student)
            record('Native designated admin password reset revokes old JWT; real new-password/OTP login recovers')
            previous=st;_,aia,_,_=login(browser,student,native_action='UPDATE_PASSWORD',new_password=secrets.token_urlsafe(32),exchange=False)
            if aia['code']:
                status,body=request(ISSUER+'/protocol/openid-connect/token',method='POST',data={'grant_type':'authorization_code','client_id':'zerotrust-spa','redirect_uri':PORTAL+'/','code_verifier':aia['verifier'],'code':aia['code']},form=True);need(status>=400 and not(isinstance(body,dict) and body.get('access_token')),'SELF_PASSWORD_STALE_ATTEMPT_ISSUED')
            api('/api/students/me',previous['access_token'],401,'https://backend:8443');_,st,sc,_=login(browser,student)
            record('Native self UPDATE_PASSWORD revokes old attempt/JWT; fresh primary and real OTP recover')
            status,updated=refresh(at['refresh_token']);need(status==200,'ADMIN_REFRESH_AFTER_MUTATIONS');at=updated;ac=verified(at['access_token'])
        record('New strict SSO reuse and native refresh rotation/reuse after reviewed flow cutover')
        # Commit boundary, real designated subject only, via the dedicated issuer service.
        status,machine=request('https://keycloak:8443/realms/DoAn/protocol/openid-connect/token',method='POST',data={'grant_type':'client_credentials','client_id':'zerotrust-issuer-security','client_secret':INPUT['issuer_secret']},form=True);need(status==200,'RACE_MACHINE_AUTH')
        def probe():
            began=time.monotonic();status,_=request('https://backend:8443/api/students/me',st['access_token']);return began,status
        with ThreadPoolExecutor(max_workers=8) as pool:
            before=[pool.submit(probe) for _ in range(16)];racing_refresh=pool.submit(refresh,st['refresh_token'])
            status,_=request('https://risk:8443/internal/v1/security/revocations',machine['access_token'],'POST',{'subjectId':student['id'],'operationId':str(uuid.uuid4()),'actorId':'d10-designated-acceptance','kind':'ACCEPTANCE_REVOCATION','quarantine':False,'disabled':None});need(status==200,'RACE_REVOCATION_COMMIT');committed=time.monotonic()
            after=[pool.submit(probe) for _ in range(16)];observations=[f.result() for f in before+after]
            need(all(s==401 for began,s in observations if began>=committed),'ALLOW_STARTED_AFTER_COMMIT')
            status,body=racing_refresh.result()
            if isinstance(body,dict) and body.get('access_token'):api('/api/students/me',body['access_token'],401,'https://backend:8443')
        api('/api/admin/users',at['access_token'],base='https://backend:8443')
        record('Commit race denies every API begun after authoritative commit; other subject allowed',{'requests':32,'after_commit':sum(t>=committed for t,s in observations),'after_commit_allowed':sum(t>=committed and s==200 for t,s in observations)})
        _,st,sc,_=login(browser,student)
        # No actor action proof: reject before any reset mutation.
        api('/api/admin/users/'+student['portal_id']+'/mfa/reset',at['access_token'],403,method='POST')
        record('Ordinary ADMIN JWT cannot reset MFA before a fresh bound native proof')
        # Account API may reject unknown fields or discard them; either way none may persist.
        status,profile=request('https://keycloak:8443/realms/DoAn/account/',at['access_token'])
        need(status==200,'ACCOUNT_PROFILE_READ_'+str(status))
        attributes=dict(profile.get('attributes') or {});attributes.update({'zt.d10.effect':['forbidden'],'zt_sec_epoch':['999'],'zt_mfa_proof':[str(uuid.uuid4())]});profile['attributes']=attributes
        status,_=request('https://keycloak:8443/realms/DoAn/account/',at['access_token'],'POST',profile)
        need(status in (200,204,400),'RESERVED_ATTRIBUTE_WRITE_STATUS');status,after=request('https://keycloak:8443/realms/DoAn/account/',at['access_token']);need(status==200 and not any(k.startswith(('zt.','zt_')) for k in (after.get('attributes') or {})),'RESERVED_ATTRIBUTE_WRITABLE')
        record('Ordinary user cannot persist reserved receipt/epoch/MFA attributes via native Account API')
        # Actual frozen frontend: challenge -> native reauthentication -> explicit second confirmation.
        ui=browser.new_context(ignore_https_errors=False);page=ui.new_page();page.set_default_timeout(30000);network=[]
        def response(r):
            path=urlsplit(r.url).path
            if path.startswith('/api/'):
                network.append({'method':r.request.method,'path':path,'status':r.status});save('spa-network.json',network)
        page.on('response',response)
        page.goto(PORTAL);page.get_by_role('button',name='Đăng nhập với Keycloak').click();page.wait_for_url('https://auth.full-function.test:39443/**');factors(page,admin);page.wait_for_url(PORTAL+'/**',timeout=40000)
        page.get_by_role('link',name='Tài khoản',exact=True).click();page.get_by_role('button',name='Reset MFA cho '+student['username'],exact=True).click();page.get_by_role('button',name='Xác nhận reset MFA',exact=True).click()
        page.wait_for_url('https://auth.full-function.test:39443/**');need(factors(page,admin)>0,'SPA_FRESH_FACTOR_MISSING');page.wait_for_url(PORTAL+'/**',timeout=40000)
        need(urlsplit(page.url).path=='/admin/users','FRESH_PROOF_MUST_RETURN_DIRECTLY_TO_CONFIRMATION')
        page.get_by_role('button',name='Reset MFA cho '+student['username'],exact=True).click()
        observed=[]
        def lose_reply(route):
            # Supported request-header accessor, NEW designated browser only. Keep the
            # one Bearer in memory and send only this exact POST over verified CA/CRL TLS.
            # This avoids APIRequestContext's separate Node trust store; never ignore TLS.
            authorization=route.request.header_value('authorization')
            need(authorization is not None and authorization.startswith('Bearer '),'DESIGNATED_BROWSER_AUTH_CONTEXT')
            token=authorization[7:];p=verified(token)
            need(p['sub']==admin['id'] and p.get('zt_mfa_target')==student['id'] and p.get('zt_mfa_action')=='MFA_RESET','DESIGNATED_ACTION_CONTEXT')
            status,_=request(PORTAL+'/api/admin/users/'+student['portal_id']+'/mfa/reset',token,'POST');observed.append(status);route.abort('connectionfailed')
        pattern=PORTAL+'/api/admin/users/'+student['portal_id']+'/mfa/reset';page.route(pattern,lose_reply)
        page.get_by_role('button',name='Xác nhận reset MFA',exact=True).click();end=time.monotonic()+30
        while not observed:need(time.monotonic()<end,'SPA_RESET_NOT_SENT');page.wait_for_timeout(100)
        need(observed[0] in (204,503),'SPA_RESET_REJECTED');page.unroute(pattern,lose_reply)
        control('restart-backend');page.get_by_role('button',name='Xác nhận reset MFA',exact=True).click();page.wait_for_timeout(1000)
        # Protocol token remains unexpired; revocation, rather than expiry, must deny it.
        need(sc['exp']>time.time(),'REVOKE_WITNESS_EXPIRED');api('/api/students/me',st['access_token'],401,'https://backend:8443');api('/api/admin/users',at['access_token'],base='https://backend:8443')
        save('spa-network.json',network);record('Frozen SPA challenge/reauth/confirm; lost browser reply + Portal restart + same nonce retry; target revoked and other subject allowed',{'initial_reset_http':observed[0],'tokens_or_headers_saved':False})
        control('stop-risk');api('/api/admin/users',at['access_token'],503,'https://backend:8443');api('/api/admin/users',at['access_token'],503)
        status,body=refresh(at['refresh_token']);need(status>=400 and not(isinstance(body,dict) and body.get('access_token')),'ISSUER_OUTAGE_FAIL_OPEN');control('start-risk');api('/api/students/me',st['access_token'],401,'https://backend:8443')
        record('Runtime authority outage fails closed at both API gates and native refresh; restart preserves revoke')
        _,at,ac,_=login(browser,admin);performance(at['access_token']);expiry_token=at['access_token'];expiry_claims=ac
        status,_=request(ISSUER+'/protocol/openid-connect/logout',method='POST',data={'client_id':'zerotrust-spa','refresh_token':at['refresh_token']},form=True);need(status==204,'STRICT_LOGOUT_STATUS')
        api('/api/admin/users',at['access_token'],401,'https://backend:8443');status,body=refresh(at['refresh_token']);need(status>=400 and not(isinstance(body,dict) and body.get('access_token')),'LOGOUT_REFRESH_UPGRADED')
        record('Native logout synchronizes verified SID and denies unexpired JWT/refresh')
        if INPUT.get('exercise_native_mutations'):
            _,fresh,fresh_claim,_=login(browser,admin)
            challenge=api('/api/admin/users/'+admin['portal_id']+'/mfa/reset/challenge',fresh['access_token'],method='POST')['data']
            _,proof,proof_claim,factor=login(browser,admin,proof=challenge['proofId']);need(factor>0 and proof_claim.get('zt_mfa_target')==admin['id'],'SELF_RESET_FRESH_FACTOR')
            status,_=request(PORTAL+'/api/admin/users/'+admin['portal_id']+'/mfa/reset',proof['access_token'],'POST');need(status in (204,503),'SELF_RESET_RESPONSE')
            control('restart-backend');api('/api/admin/users',proof['access_token'],401,'https://backend:8443')
            record('Native fresh ADMIN self-reset persists and resumes after Portal restart without a valid actor JWT',{'foreground_http':status,'actor_jwt_after_revoke':401})
        expiry_boundary(expiry_token,expiry_claims)
        save('rollout-native.json',{'scope':INPUT['scope'],'status':'PASS','cases':CASES,'tokens_persisted':False});browser.close()
if __name__=='__main__':
    try:main()
    except Exception as e:
        reason=str(e) if type(e)is RuntimeError and all(c.isalnum() or c in '_-/ ' for c in str(e)) else type(e).__name__
        frames=[f for f in traceback.extract_tb(e.__traceback__) if f.filename==__file__]
        if frames:reason+='_LINE_'+str(frames[-1].lineno)
        save('rollout-native.json',{'scope':INPUT.get('scope'),'status':'FAIL','cases':CASES,'reason':reason,'tokens_persisted':False});print('FAIL '+reason,flush=True);sys.exit(1)
