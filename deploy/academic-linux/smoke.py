"""Strict-TLS HTTP and synthetic OIDC smoke for the Linux Academic Demo."""
import argparse
import base64
import hashlib
import hmac
from html.parser import HTMLParser
import http.client
from http.cookiejar import CookieJar
import json
from pathlib import Path
import secrets
import socket
import ssl
import struct
import time
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit
from urllib.request import HTTPSHandler, HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler, Request, build_opener
import uuid

from linux_demo import activate, base, check, compose_contract, load_config, read_lock, sql


class Callback(Exception):
    def __init__(self,url):
        self.url=url


class Redirects(HTTPRedirectHandler):
    def __init__(self, portal, auth):
        self.portal=portal
        self.auth=auth

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target=urlsplit(newurl)
        origin=f'{target.scheme}://{target.netloc}'
        if origin==self.portal:
            raise Callback(newurl)
        check(origin==self.auth,'Unexpected OIDC redirect origin')
        return super().redirect_request(req,fp,code,msg,headers,newurl)


class LoopbackHTTPS(HTTPSHandler):
    def __init__(self, context, port, hosts):
        super().__init__(context=context)
        self.port=port
        self.hosts=hosts

    def https_open(self, request):
        check(request.host.split(':')[0] in self.hosts,'HTTPS request escaped expected hostnames')
        def connection(host, **kwargs):
            conn=http.client.HTTPSConnection(host,**kwargs)
            conn._create_connection=lambda _addr,timeout,source: socket.create_connection(('127.0.0.1',self.port),timeout,source)
            return conn
        return self.do_open(connection,request,context=self._context)


class Forms(HTMLParser):
    def __init__(self,body):
        super().__init__(convert_charrefs=True)
        self.forms=[]
        self.current=None
        self.feed(body.decode('utf-8',errors='replace'))

    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='form':
            self.current=(a.get('action',''),{})
            self.forms.append(self.current)
        if tag=='input' and self.current and a.get('name'):
            self.current[1][a['name']]=a.get('value','')

    def handle_endtag(self,tag):
        if tag=='form':
            self.current=None

    def find(self,field):
        return next((f for f in self.forms if field in f[1]),None)


class Smoke:
    def __init__(self,c):
        self.c=c
        self.state=c['state']
        self.context=ssl.create_default_context(cafile=str(self.state/'ingress/edge-ca.crt'))
        self.auth=c['auth_url']
        self.portal=c['portal_url']
        self.issuer=self.auth+'/realms/'+base.REALM
        self.oidc=self.issuer+'/protocol/openid-connect/'
        self.prefix='pd_'+c['schema_env']+'_'
        self.otp_window={}

    def client(self):
        return build_opener(ProxyHandler({}),LoopbackHTTPS(self.context,self.c['bind_port'],{self.c['auth_host'],self.c['portal_host']}),
                            HTTPCookieProcessor(CookieJar()),Redirects(self.portal,self.auth))

    def request(self,client,url,form=None,token=None,post_json=False):
        data=None
        headers={'User-Agent':'ZeroTrust Academic Demo acceptance'}
        if form is not None:
            data=urlencode(form).encode()
            headers['Content-Type']='application/x-www-form-urlencoded'
        if post_json:
            data=b'{}'
            headers['Content-Type']='application/json'
        if token:
            headers['Authorization']='Bearer '+token
        try:
            with client.open(Request(url,data=data,headers=headers),timeout=16) as r:
                return r.status,r.read(),r.url
        except HTTPError as e:
            with e:
                return e.code,e.read(),e.url

    def infrastructure(self):
        client=self.client()
        try:
            with socket.create_connection(('127.0.0.1',self.c['bind_port']),timeout=8) as sock:
                with self.context.wrap_socket(sock,server_hostname='hostname-mismatch.invalid'):
                    raise RuntimeError('TLS accepted an unrelated hostname')
        except ssl.SSLCertVerificationError:
            pass
        status,data,_=self.request(client,self.issuer+'/.well-known/openid-configuration')
        check(status==200 and json.loads(data)['issuer']==self.issuer,'Discovery issuer mismatch')
        check(self.request(client,self.portal+'/')[0]==200,'Portal HTTPS unavailable')
        for url in (self.auth+'/admin/',self.auth+'/realms/master/.well-known/openid-configuration',
                    self.portal+'/actuator/health',self.portal+'/internal/v1/risk/evaluations',self.portal+'/observatory'):
            check(self.request(client,url)[0]==404,'Private route is exposed')
        raw=base.compose('ps','--format','json').stdout
        health=json.loads(raw) if raw.lstrip().startswith('[') else [json.loads(line) for line in raw.splitlines() if line.strip()]
        check(len([r for r in health if r.get('State')=='running' and r.get('Health')=='healthy'])==8,
              'Expected eight healthy services')
        grants=sql('mysql','SHOW GRANTS FOR CURRENT_USER','school').splitlines()
        check(len(grants)==6 and sum('GRANT SELECT ON' in line for line in grants)==5,'School DB grant scope mismatch')
        check(sql('mysql',f"SELECT checksum,success FROM {self.prefix}risk.flyway_schema_history WHERE version='5'")=='661092940\t1',
              'Flyway V5 ledger mismatch')
        print('PASS 8 healthy services, TLS chain/SAN, Portal HTTPS, OIDC issuer, private routes, School grants and V5',flush=True)

    def post_form(self,client,form,page,changes):
        action,fields=form
        url=urljoin(page,action)
        p=urlsplit(url)
        check(f'{p.scheme}://{p.netloc}'==self.auth and p.path.startswith(f'/realms/{base.REALM}/login-actions/'),
              'Unexpected form origin or path')
        return self.request(client,url,form={**fields,**changes})

    def auth_flow(self,account,variant='normal'):
        client=self.client()
        verifier=secrets.token_urlsafe(48)
        challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        state=secrets.token_urlsafe(24)
        redirect=self.portal+'/'
        params={'client_id':'zerotrust-spa','response_type':'code','redirect_uri':redirect,'scope':'openid',
                'state':state,'code_challenge':challenge,'code_challenge_method':'S256','prompt':'login'}
        status,html,page=self.request(client,self.oidc+'auth?'+urlencode(params))
        form=Forms(html).find('username')
        check(status==200 and form is not None,'Password form missing')
        try:
            status,html,page=self.post_form(client,form,page,{'username':account['username'],'password':account['password']})
            forms=Forms(html)
            if variant=='denied':
                check(forms.find('otp') is None and forms.find('totp') is None,'Risk outage allowed MFA continuation')
                check(urlsplit(page).hostname==self.c['auth_host'] and 'login-actions' in urlsplit(page).path,
                      'Risk outage left authentication flow')
                return 'denied'
            form=forms.find('totp')
            if form and 'totpSecret' in form[1]:
                check(variant!='wrong-otp','Wrong OTP test requires existing synthetic enrollment')
                otp=self.otp(account['id'],form[1]['totpSecret'].encode())
                status,html,page=self.post_form(client,form,page,{'totp':otp,'userLabel':'Academic smoke'})
                form=Forms(html).find('otp')
            else:
                form=forms.find('otp')
            if form:
                sub=str(uuid.UUID(account['id']))
                record=sql('mysql',f"SELECT SECRET_DATA FROM {self.prefix}keycloak.CREDENTIAL WHERE USER_ID='{sub}' AND TYPE='otp' LIMIT 1")
                check(record,'Synthetic OTP not enrolled')
                otp=self.otp(sub,json.loads(record)['value'].encode(),remember=variant!='wrong-otp')
                if variant=='wrong-otp':
                    invalid='000000' if otp!='000000' else '111111'
                    status,html,page=self.post_form(client,form,page,{'otp':invalid})
                    check(Forms(html).find('otp') is not None and urlsplit(page).hostname==self.c['auth_host'],
                          'Wrong OTP did not stay on challenge')
                    return 'wrong-otp'
                self.post_form(client,form,page,{'otp':otp})
        except Callback as callback:
            check(variant not in ('wrong-otp','denied'),'Denied flow returned a Portal callback')
            fields=parse_qs(urlsplit(callback.url).query)
            check(fields.get('state')==[state] and len(fields.get('code',[]))==1,'Invalid authorization callback')
            status,data,_=self.request(client,self.oidc+'token',form={'grant_type':'authorization_code','client_id':'zerotrust-spa',
                'redirect_uri':redirect,'code':fields['code'][0],
                'code_verifier':secrets.token_urlsafe(48) if variant=='wrong-pkce' else verifier})
            if variant=='wrong-pkce':
                check(status==400 and json.loads(data).get('error')=='invalid_grant','Wrong PKCE verifier accepted')
                return 'wrong-pkce'
            check(status==200,'Authorization code exchange failed')
            tokens=json.loads(data)
            return client,tokens
        raise RuntimeError('Authentication flow did not return a callback')

    def otp(self,subject,secret,remember=True):
        while int(time.time())%30>=26 or remember and self.otp_window.get(subject)==int(time.time())//30:
            time.sleep(1)
        window=int(time.time())//30
        if remember:
            self.otp_window[subject]=window
        mac=hmac.digest(secret,struct.pack('>Q',window),'sha1')
        return f'{(struct.unpack_from(">I",mac,mac[-1]&15)[0]&0x7fffffff)%1000000:06d}'

    def accounts(self):
        check(self.c['mode']=='rehearsal','Credential flows require an isolated rehearsal')
        return json.loads((self.state/'accounts.json').read_text())

    def browser_protocol(self):
        accounts=self.accounts()
        client,t=self.auth_flow(accounts['student_b'])
        status,data,_=self.request(client,self.portal+'/api/students/me/scores',token=t['access_token'])
        ids=sql('mysql',f'SELECT HEX(id) FROM {self.prefix}school.subjects ORDER BY subject_code').splitlines()
        check(status==200 and len(ids)==2 and str(uuid.UUID(hex=ids[1])).encode() in data
              and str(uuid.UUID(hex=ids[0])).encode() not in data,'Student score ownership failed')
        check(self.request(client,self.portal+'/api/admin/student-classes',token=t['access_token'])[0]==403,'Student accessed ADMIN')
        try:
            self.request(client,self.oidc+'logout?'+urlencode({'id_token_hint':t['id_token'],'post_logout_redirect_uri':self.portal+'/'}))
        except Callback:
            pass
        status,_,_=self.request(client,self.oidc+'token',form={'grant_type':'refresh_token','client_id':'zerotrust-spa',
                                                             'refresh_token':t['refresh_token']})
        check(status==400,'Refresh still valid after logout')
        client,t=self.auth_flow(accounts['admin'])
        token=t['access_token']
        check(self.request(client,self.portal+'/api/admin/student-classes',token=token)[0]==200
              and self.request(client,self.portal+'/api/admin/student-classes',token=token,post_json=True)[0]==403,
              'ADMIN read/write separation failed')
        conf='header = '+json.dumps('Authorization: Bearer '+token)+'\n'
        direct=base.compose('exec','-T','risk','curl','--silent','--show-error','--cacert','/run/demo/ca.crt',
                            '-o','/dev/null','-w','%{http_code}','--config','-','-H','Content-Type: application/json',
                            '--data','{}','https://backend:8443/api/admin/student-classes',data=conf)
        check(direct.stdout=='403','Direct backend academic write accepted')
        check(self.auth_flow(accounts['student_b'],'wrong-otp')=='wrong-otp','OTP rejection missing')
        check(self.auth_flow(accounts['student_b'],'wrong-pkce')=='wrong-pkce','PKCE rejection missing')
        print('PASS TLS OIDC/PKCE positive and negative, OTP, RBAC, own scores, direct write deny, logout/refresh',flush=True)

    def faults(self):
        accounts=self.accounts()
        import risk_smoke
        risk_smoke.run()
        risk_smoke.redis_outage()
        base.compose('stop','--timeout','30','risk')
        try:
            check(self.auth_flow(accounts['student_b'],'denied')=='denied','Expected fail-closed')
            print('PASS Keycloak fail-closed during Risk outage',flush=True)
        finally:
            base.compose('up','-d','--wait','--wait-timeout','110','risk')

    def recovery(self):
        self.accounts()
        def state():
            _,raw,_=self.request(self.client(),self.oidc+'certs')
            kids=sorted(row['kid'] for row in json.loads(raw)['keys'])
            row=sql('mysql',f"""SELECT
              (SELECT COUNT(*) FROM {self.prefix}keycloak.REALM),
              (SELECT COUNT(*) FROM {self.prefix}keycloak.CREDENTIAL WHERE TYPE='otp'),
              (SELECT COUNT(*) FROM {self.prefix}risk.known_devices),
              (SELECT checksum FROM {self.prefix}risk.flyway_schema_history WHERE version='5' AND success=1)""")
            return kids,row
        before=state()
        check(int(before[1].split()[1])>0 and int(before[1].split()[2])>0,'MFA and Risk test state missing')
        base.compose('stop','--timeout','45','ingress','gateway','frontend','backend','risk','keycloak','redis','mysql')
        base.compose('up','-d','--wait','--wait-timeout','190')
        check(state()==before,'Realm keys, MFA, Risk or V5 state drift after restart')
        dump=base.compose('exec','-T','mysql','mysqldump','--defaults-extra-file=/fixture/root.cnf',
             '--no-data','--set-gtid-purged=OFF','--no-tablespaces','--databases',
             *(self.prefix+x for x in ('school','risk','keycloak'))).stdout
        check(all(f'CREATE DATABASE' in dump and self.prefix+x in dump for x in ('school','risk','keycloak')),
              'Backup schema permissions/inventory missing')
        print('PASS restart persisted JWKS, enrolled MFA, Risk state, V5 and mysqldump schema readiness',flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',required=True,type=Path)
    p.add_argument('--manifest',required=True,type=Path)
    p.add_argument('--exercise',action='store_true',help='Change only isolated synthetic fixtures; include fault and restart lanes')
    a=p.parse_args()
    c=load_config(a.config)
    activate(c)
    compose_contract(c)
    base.verify_boundary()
    read_lock(c,a.manifest)
    s=Smoke(c)
    s.infrastructure()
    if a.exercise:
        s.browser_protocol()
        s.faults()
        s.recovery()


if __name__=='__main__':
    try:
        main()
    except (ValueError,RuntimeError,OSError,Callback,KeyError) as error:
        detail=str(error) if type(error) is RuntimeError else type(error).__name__
        raise SystemExit('Smoke stopped: '+detail) from None
