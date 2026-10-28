"""Bounded fresh Demo acceptance. Real OIDC/TOTP/API calls, no fault injection."""
import base64
import datetime as dt
import hashlib
import hmac
import http.client
import http.cookiejar
import json
from html.parser import HTMLParser
from pathlib import Path
import secrets
import socket
import ssl
import struct
import sys
import time
from urllib.parse import urlencode,urljoin,urlsplit,parse_qs
import urllib.request as request
import urllib.error
import uuid
from bootstrap import ROOT,ISSUER,ident

PORTAL='https://localhost:8443'
UA='ZeroTrustDemo/1.0'
cfg=json.loads((ROOT/'credentials.json').read_text())
evidence=ROOT/'evidence';evidence.mkdir(exist_ok=True)
seedfile=ROOT/'otp-seeds.json'
seeds=json.loads(seedfile.read_text()) if seedfile.exists() else {}
counterfile=ROOT/'otp-counters.json'
counters=json.loads(counterfile.read_text()) if counterfile.exists() else {}
budgetfile=evidence/'auth-budget.json'
budget=json.loads(budgetfile.read_text()) if budgetfile.exists() else {'transactions':0,'OTP':0,'limit':12}


def store(path,value):path.write_text(json.dumps(value,indent=2))


class Connection(http.client.HTTPSConnection):
    def connect(self):
        host={8443:'gateway',8444:'keycloak'}[self.port] if self.host=='localhost' else self.host
        sock=socket.create_connection((host,self.port),timeout=15)
        assert self._context.check_hostname and self._context.verify_mode==ssl.CERT_REQUIRED
        self.sock=self._context.wrap_socket(sock,server_hostname=self.host)


class HTTPS(request.HTTPSHandler):
    def https_open(self,req):return self.do_open(Connection,req,context=self._context)


class Redirect(request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None


class Forms(HTMLParser):
    def __init__(self,body):
        super().__init__();self.forms=[];self.current=None;self.feed(body.decode())
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='form':self.current={**a,'inputs':{}};self.forms.append(self.current)
        elif tag=='input' and self.current is not None and a.get('name'):self.current['inputs'][a['name']]=a.get('value','')
    def handle_endtag(self,tag):
        if tag=='form':self.current=None


def totp(seed):
    key=base64.b32decode(seed+'='*((-len(seed))%8));msg=struct.pack('>Q',int(time.time())//30)
    digest=hmac.new(key,msg,hashlib.sha1).digest();offset=digest[-1]&15
    return str((int.from_bytes(digest[offset:offset+4],'big')&0x7fffffff)%1000000).zfill(6)


class Client:
    def __init__(self):
        self.jar=http.cookiejar.CookieJar()
        self.context=ssl.create_default_context(cafile=str(ROOT/'ca.crt'))
        self.opener=request.build_opener(HTTPS(context=self.context),request.HTTPCookieProcessor(self.jar),Redirect(),request.ProxyHandler({}))
        self.tokens={};self.actor=None
    def call(self,method,url,body=None,token=None,form=False):
        p=urlsplit(url);assert p.scheme=='https' and p.hostname in ['localhost','risk','keycloak','gateway','backend']
        data=(urlencode(body).encode() if form else json.dumps(body).encode()) if body is not None else None
        headers={'User-Agent':UA}
        if body is not None:headers['Content-Type']='application/x-www-form-urlencoded' if form else 'application/json'
        if token:headers['Authorization']='Bearer '+token
        req=request.Request(url,data=data,headers=headers,method=method)
        try:
            with self.opener.open(req,timeout=20) as response:return response.status,response.read(),response.headers
        except urllib.error.HTTPError as error:return error.code,error.read(),error.headers
    def follow(self,response,current):
        for _ in range(8):
            if response[0] not in [301,302,303,307,308]:return response,current
            target=urljoin(current,response[2]['Location'])
            if target.startswith(PORTAL+'/'):return response,target
            assert target.startswith('https://localhost:8444/')
            current=target;response=self.call('GET',current)
        raise AssertionError('REDIRECT_LIMIT')
    def api(self,method,path,body=None,expected=200,token=None):
        status,raw,_=self.call(method,PORTAL+path,body,token or self.tokens.get('access_token'))
        assert status==expected, 'API_STATUS_'+path+'_'+str(status)
        return json.loads(raw) if raw else None
    def login(self,actor,deny=False):
        assert budget['transactions']<budget['limit'],'AUTH_BUDGET_EXHAUSTED'
        budget['transactions']+=1;store(budgetfile,budget)
        verifier=secrets.token_urlsafe(48);state=secrets.token_urlsafe(24);nonce=secrets.token_urlsafe(24)
        challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
        current=ISSUER+'/protocol/openid-connect/auth?'+urlencode({'client_id':'zerotrust-spa','redirect_uri':PORTAL+'/',
            'response_type':'code','scope':'openid','state':state,'nonce':nonce,'code_challenge':challenge,'code_challenge_method':'S256','prompt':'login'})
        response,current=self.follow(self.call('GET',current),current)
        forms=Forms(response[1]).forms
        login=next(f for f in forms if 'username' in f['inputs'])
        target=urljoin(current,login['action']);user=cfg['users'][actor]
        response,current=self.follow(self.call('POST',target,{**login['inputs'],'username':user['username'],'password':user['password']},form=True),target)
        forms=Forms(response[1]).forms if response[0]==200 else []
        otp=next((f for f in forms if 'otp' in f['inputs']),None)
        enrollment=next((f for f in forms if 'totpSecret' in f['inputs']),None)
        if deny:
            assert response[0]==403 and not otp and not enrollment and 'code' not in parse_qs(urlsplit(current).query),'HIGH_NOT_DENIED'
            return {'actor':actor,'denied':403,'tokens':False}
        if otp or enrollment:
            form=otp or enrollment
            if enrollment:
                seeds[actor]=base64.b32encode(enrollment['inputs']['totpSecret'].encode()).decode();store(seedfile,seeds)
            assert actor in seeds,'OTP_SEED_MISSING'
            while time.time()%30>24 or int(time.time())//30<=counters.get(actor,-1):time.sleep(.4)
            counters[actor]=int(time.time())//30;store(counterfile,counters)
            budget['OTP']+=1;store(budgetfile,budget)
            target=urljoin(current,form['action']);values={**form['inputs'],('otp' if otp else 'totp'):totp(seeds[actor])}
            if enrollment:values['userLabel']='Demo authenticator'
            response,current=self.follow(self.call('POST',target,values,form=True),target)
        callback=parse_qs(urlsplit(current).query)
        assert callback.get('state')==[state] and callback.get('code'),'NO_OIDC_CALLBACK'
        status,raw,_=self.call('POST',ISSUER+'/protocol/openid-connect/token',{'grant_type':'authorization_code','client_id':'zerotrust-spa',
            'redirect_uri':PORTAL+'/','code':callback['code'][0],'code_verifier':verifier},form=True)
        assert status==200,'CODE_EXCHANGE_FAILED';self.tokens=json.loads(raw);self.actor=actor
        from cryptography.hazmat.primitives.asymmetric import rsa,padding
        from cryptography.hazmat.primitives import hashes
        def decode(text):return base64.urlsafe_b64decode(text+'='*((-len(text))%4))
        h,c,s=self.tokens['id_token'].split('.');header=json.loads(decode(h));claims=json.loads(decode(c))
        status,raw,_=self.call('GET',ISSUER+'/protocol/openid-connect/certs');assert status==200
        jwk=next(k for k in json.loads(raw)['keys'] if k['kid']==header['kid']);assert header['alg']=='RS256'
        rsa.RSAPublicNumbers(int.from_bytes(decode(jwk['e']),'big'),int.from_bytes(decode(jwk['n']),'big')).public_key().verify(decode(s),(h+'.'+c).encode(),padding.PKCS1v15(),hashes.SHA256())
        assert claims['iss']==ISSUER and claims['sub']==user['id'] and claims['nonce']==nonce and claims['exp']>time.time()
        return {'actor':actor,'OTP':bool(otp),'enrollment':bool(enrollment),'tokens':True}
    def logout(self):
        status,_,_=self.call('POST',ISSUER+'/protocol/openid-connect/logout',{'client_id':'zerotrust-spa','refresh_token':self.tokens['refresh_token']},form=True)
        assert status==204,'LOGOUT_FAILED'
        device=[cookie for cookie in self.jar if cookie.name=='ZT_DEVICE_ID']
        self.jar.clear()
        for cookie in device:self.jar.set_cookie(cookie)
        self.tokens={}
    def machine(self):
        status,raw,_=self.call('POST',ISSUER+'/protocol/openid-connect/token',{'grant_type':'client_credentials','client_id':'zerotrust-risk-caller',
                 'client_secret':cfg['clients']['zerotrust-risk-caller']},form=True)
        assert status==200,'MACHINE_AUTH_FAILED'
        return json.loads(raw)['access_token']
    def evaluate(self,actor,ip):
        device=next((cookie.value for cookie in self.jar if cookie.name=='ZT_DEVICE_ID'),None)
        status,body,_=self.call('POST','https://risk:8443/internal/v1/risk/evaluations',{'subjectId':cfg['users'][actor]['id'],
            'authenticationSessionId':str(uuid.uuid4()),'clientId':'zerotrust-spa','ipAddress':ip,'userAgent':UA,'deviceId':device},self.machine())
        assert status==200,'RISK_EVALUATION_FAILED';return json.loads(body)


def fixtures():
    marker=ROOT/'synthetic-history.json'
    if marker.exists():return
    client=Client();token=client.machine();now=dt.datetime.now(dt.timezone.utc)
    for actor in ['student','high']:
        for i in range(5):
            instant=now-dt.timedelta(minutes=5+i) if actor=='student' else now-dt.timedelta(days=1,hours=12,minutes=i)
            status,_,_=client.call('POST','https://risk:8443/internal/v1/authentication-successes',{'eventId':'demo-fixture-'+str(uuid.uuid4()),
                'subjectId':cfg['users'][actor]['id'],'clientId':'zerotrust-spa','authenticatedAt':instant.isoformat()},token)
            assert status==204,'HISTORY_FIXTURE_FAILED'
    # Documented synthetic failure events for the high-source lane, never guessed passwords.
    for _ in range(5):
        status,_,_=client.call('POST','https://risk:8443/internal/v1/authentication-failures',{'eventId':'demo-fixture-'+str(uuid.uuid4()),
            'subjectId':cfg['users']['high']['id'],'sourceIp':'172.30.80.200'},token)
        assert status==204,'FAILURE_FIXTURE_FAILED'
    store(marker,{'synthetic_success_events':10,'synthetic_failure_events':5,'failure_fixture_created_at':time.time(),'via':'authorized Risk events API','high_fixture_expires':'15 minutes (normal Redis TTL)'})


def normal():
    fixtures();client=Client();rows=[]
    for actor in ['student','admin']:
        first=client.login(actor);rows.append(first)
        if first['enrollment']:
            client.logout();second=client.login(actor);assert second['OTP'],'REAL_OTP_REQUIRED';rows.append(second)
        else:assert first['OTP'],'REAL_OTP_REQUIRED'
        if actor=='student':
            for path in ['/api/students/me','/api/students/me/scores','/api/students/me/scores/summary']:client.api('GET',path)
            assert client.api('GET','/api/students/me/scores')['data'],'SCORES_EMPTY'
            client.api('GET','/api/admin/users',expected=403)
            token=client.tokens['access_token'];client.api('GET','/api/students/me',expected=401,token=token[:-3]+('AAA' if token[-3:]!='AAA' else 'BBB'))
            client.logout();low=client.evaluate(actor,'172.30.80.100');assert low['decision']=='ALLOW' and low['riskLevel']=='LOW','LOW_NOT_REACHED'
            third=client.login(actor);assert not third['OTP'] and not third['enrollment'];rows.append({**third,'real_risk':low})
        if actor=='admin':
            for path in ['/api/admin/students','/api/admin/subjects','/api/admin/users']:client.api('GET',path)
            student=ident(cfg,'student_student')
            scores=client.api('GET','/api/admin/students/'+student+'/scores')['data'];assert scores
            item=scores[0];old=item['attendanceScore'];path='/api/admin/scores/'+item['id']
            try:
                changed=client.api('PATCH',path,{'attendanceScore':9.5})['data']
                assert float(changed['attendanceScore'])==9.5
            finally:
                client.api('PATCH',path,{'attendanceScore':old})
            client.api('GET','/api/students/me/scores',expected=403)
            rows.append({'admin_grade_update_restore':'PASS','admin_is_not_student':403})
        client.logout()
    result={'PASS':True,'mode':'real HTTPS OIDC/TOTP and APIs; no browser UI claim','cases':rows,'budget':budget}
    store(evidence/'smoke-normal.json',result);print(json.dumps(result))


def high_decision():
    fixtures();client=Client();marker=ROOT/'synthetic-history.json';fixture=json.loads(marker.read_text())
    if time.time()-fixture.get('failure_fixture_created_at',0)>600:
        token=client.machine()
        for _ in range(5):
            status,_,_=client.call('POST','https://risk:8443/internal/v1/authentication-failures',{'eventId':'demo-fixture-'+str(uuid.uuid4()),
                'subjectId':cfg['users']['high']['id'],'sourceIp':'172.30.80.200'},token)
            assert status==204
        fixture['failure_fixture_created_at']=time.time();store(marker,fixture)
    decision=client.evaluate('high','172.30.80.200')
    assert decision['decision']=='DENY' and decision['riskLevel']=='HIGH' and decision['riskScore']>=75,'NUMERIC_HIGH_NOT_REACHED'
    return client,decision


def high():
    client,decision=high_decision()
    result=client.login('high',deny=True)
    store(evidence/'smoke-high.json',{'PASS':True,'real_risk':decision,'oidc':result,'actual_source':'172.30.80.200','budget':budget})
    print(json.dumps({'PASS':True,'real_risk':decision,'oidc':result,'budget':budget}))


def fresh_proof():
    client=Client();result=client.login('student')
    assert result['enrollment'],'FRESH_USER_MUST_ENROLL'
    for path in ['/api/students/me','/api/students/me/scores','/api/students/me/scores/summary']:client.api('GET',path)
    client.api('GET','/api/admin/users',expected=403)
    client.logout()
    store(evidence/'fresh-install-proof.json',{'PASS':True,'initial_TOTP_enrollment':True,'student_apis':200,'RBAC':403,'budget':budget})
    print('Fresh source-only installation, OIDC subject, official TOTP enrollment and Student APIs PASS')


if __name__=='__main__':
    try:
        assert cfg['owner']=='zerotrust-demo'
        if sys.argv[1]=='normal':normal()
        elif sys.argv[1]=='high':high()
        elif sys.argv[1]=='fresh-proof':fresh_proof()
        elif sys.argv[1]=='fixtures':fixtures()
        elif sys.argv[1]=='high-engine':
            _,decision=high_decision();store(evidence/'fresh-high-engine.json',{'PASS':True,'decision':decision});print('Fresh HIGH engine PASS; no extra browser login')
        else:raise AssertionError('UNKNOWN_VERIFICATION_MODE')
    except Exception as error:
        print('DEMO_ACCEPTANCE_STOPPED: '+(str(error) if isinstance(error,AssertionError) else type(error).__name__),file=sys.stderr)
        sys.exit(1)
