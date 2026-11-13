"""Native admin operations for the approved D10 maintenance lane. Input secrets in memory only."""
import json,ssl,sys,time,uuid,traceback
from urllib.request import Request,build_opener,HTTPSHandler,ProxyHandler,HTTPRedirectHandler
from urllib.error import HTTPError
from urllib.parse import urlencode,quote
def need(ok,message):
    if not ok:raise RuntimeError(message)
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None
class Native:
    def __init__(self,inputs):
        self.i=inputs;self.base='https://keycloak:8443';self.token=None
        context=ssl.create_default_context(cafile='/public/internal-ca-with-crl.pem');context.verify_flags|=ssl.VERIFY_CRL_CHECK_CHAIN
        self.http=build_opener(ProxyHandler({}),HTTPSHandler(context=context),NoRedirect())
    def request(self,path,method='GET',data=None,auth=True,form=False,expected=None):
        headers={'Accept':'application/json'}
        if auth:headers['Authorization']='Bearer '+self.token
        if data is not None:headers['Content-Type']='application/x-www-form-urlencoded' if form else 'application/json';data=(urlencode(data) if form else json.dumps(data)).encode()
        try:r=self.http.open(Request(self.base+path,data=data,headers=headers,method=method),timeout=10)
        except HTTPError as e:r=e
        raw=r.read(262145);need(len(raw)<=262144,'NATIVE_RESPONSE_BOUND')
        try:body=json.loads(raw) if raw else None
        except ValueError:body=None
        if expected is not None:need(r.status in expected,'NATIVE_HTTP_'+method+'_'+str(r.status)+'_'+path)
        return r.status,body
    def login(self):
        deadline=time.monotonic()+180
        while True:
            try:
                status,body=self.request('/realms/master/protocol/openid-connect/token','POST',{'grant_type':'client_credentials','client_id':self.i['bootstrap_client'],'client_secret':self.i['bootstrap_secret']},False,True)
                if status==200 and body.get('access_token'):self.token=body['access_token'];return
            except Exception:pass
            need(time.monotonic()<deadline,'NATIVE_BOOTSTRAP_AUTH_UNAVAILABLE');time.sleep(1)
    def api(self,path,method='GET',data=None,expected=(200,)):return self.request('/admin/realms/DoAn'+path,method,data,expected=expected)[1]
    def client(self,name):
        rows=self.api('/clients?clientId='+quote(name));need(len(rows)<=1,'NATIVE_CLIENT_AMBIGUOUS');return rows[0] if rows else None
    def role(self,client,name):
        status,body=self.request('/admin/realms/DoAn/clients/'+client+'/roles/'+quote(name))
        if status==404:self.api('/clients/'+client+'/roles','POST',{'name':name},(201,));body=self.api('/clients/'+client+'/roles/'+quote(name))
        else:need(status==200,'ROLE_LOOKUP')
        return body
    def provision_clients(self):
        spa=self.client('zerotrust-spa');need(spa is not None,'SPA_CLIENT_MISSING')
        callback='https://portal.full-function.test:39443/admin/users'
        if callback not in spa.get('redirectUris',[]):
            spa['redirectUris']=[*spa.get('redirectUris',[]),callback];self.api('/clients/'+spa['id'],'PUT',spa,(204,))
        risk=self.client('zerotrust-risk-api');need(risk is not None,'RISK_AUDIENCE_MISSING')
        names=['security:authorize','security:issue','security:reset'];roles={name:self.role(risk['id'],name) for name in names}
        native=self.client('zerotrust-native-security')
        if native is None:
            self.api('/clients','POST',{'clientId':'zerotrust-native-security','enabled':True,'bearerOnly':True,'protocol':'openid-connect','attributes':{'d10.owner':self.i['run_id']}},(201,));native=self.client('zerotrust-native-security')
        else:need(native.get('attributes',{}).get('d10.owner')==self.i['run_id'],'UNOWNED_NATIVE_AUDIENCE')
        native_role=self.role(native['id'],'security:reset-native')
        output={}
        for name,rights in [('zerotrust-gateway-security',['security:authorize']),('zerotrust-portal-security',['security:authorize','security:reset']),('zerotrust-issuer-security',['security:authorize','security:issue'])]:
            audiences=['zerotrust-risk-api']+(['zerotrust-native-security'] if name=='zerotrust-portal-security' else [])
            body={'clientId':name,'enabled':True,'publicClient':False,'secret':self.i[name],'serviceAccountsEnabled':True,'standardFlowEnabled':False,'directAccessGrantsEnabled':False,'implicitFlowEnabled':False,'protocol':'openid-connect','defaultClientScopes':['basic','roles'],'attributes':{'d10.owner':self.i['run_id']},'protocolMappers':[{'name':'d10-aud-'+a,'protocol':'openid-connect','protocolMapper':'oidc-audience-mapper','config':{'included.client.audience':a,'access.token.claim':'true','id.token.claim':'false'}} for a in audiences]}
            current=self.client(name)
            if current is None:self.api('/clients','POST',body,(201,));current=self.client(name)
            else:need(current.get('attributes',{}).get('d10.owner')==self.i['run_id'],'UNOWNED_D10_CLIENT')
            user=self.api('/clients/'+current['id']+'/service-account-user')
            self.api('/users/'+user['id']+'/role-mappings/clients/'+risk['id'],'POST',[roles[r] for r in rights],(204,))
            if name=='zerotrust-portal-security':self.api('/users/'+user['id']+'/role-mappings/clients/'+native['id'],'POST',[native_role],(204,))
            secret=self.api('/clients/'+current['id']+'/client-secret');need(secret.get('value')==self.i[name],'D10_CLIENT_SECRET_MISMATCH')
            assigned=self.api('/users/'+user['id']+'/role-mappings/clients/'+risk['id']);need({r['name'] for r in assigned}==set(rights),'D10_ROLE_SCOPE')
            output[name]={'roles':rights,'audiences':audiences,'standard_flow':False,'direct_grant':False,'service_account':True}
        return output
    def clone_browser(self):
        realm=self.api('');flows=self.api('/authentication/flows');by_id={f['id']:f for f in flows};by_alias={f['alias']:f for f in flows}
        old=by_alias[self.i.get('source_browser_alias',realm['browserFlow'])];alias='d10-browser-'+self.i['run_id']
        replacements={'auth-cookie':'d10-cookie','auth-username-password-form':'d10-password','auth-otp-form':'d10-otp','auth-recovery-authn-code-form':'d10-recovery'};proof=[];counter=[0]
        def flow(identifier):
            if identifier not in by_id:by_id[identifier]=self.api('/authentication/flows/'+identifier)
            return by_id[identifier]
        def rows(name):return [e for e in self.api('/authentication/flows/'+quote(name,safe='')+'/executions') if e.get('level',0)==0]
        if alias in by_alias:
            need(not by_alias[alias].get('builtIn'),'D10_FLOW_BUILTIN_CONFLICT')
            if realm['browserFlow']==alias:
                def validate(source,target):
                    expected=rows(source);actual=rows(target);tail=any(e.get('providerId')=='auth-username-password-form' for e in expected)
                    need(len(actual)==len(expected)+int(tail),'EXISTING_FLOW_INCOMPLETE')
                    for original,new in zip(expected,actual):
                        need(new['requirement']==original['requirement'] and new['priority']==original['priority'] and bool(new.get('authenticationFlow'))==bool(original.get('authenticationFlow')),'EXISTING_FLOW_REQUIREMENT')
                        if original.get('authenticationFlow'):validate(flow(original['flowId'])['alias'],flow(new['flowId'])['alias'])
                        else:
                            need(new.get('providerId')==replacements.get(original['providerId'],original['providerId']),'EXISTING_FLOW_PROVIDER')
                            if original.get('authenticationConfig'):
                                need(self.api('/authentication/config/'+original['authenticationConfig'])['config']==self.api('/authentication/config/'+new['authenticationConfig'])['config'],'EXISTING_FLOW_CONFIG')
                    if tail:need(actual[-1].get('providerId')=='d10-auth-ticket' and actual[-1]['requirement']=='REQUIRED','EXISTING_FLOW_TICKET')
                validate(old['alias'],alias);need(self.api('/users/profile').get('unmanagedAttributePolicy')is None,'EXISTING_PROFILE_POLICY')
                need((realm['accessTokenLifespan'],realm['ssoSessionIdleTimeout'],realm['ssoSessionMaxLifespan'])==(300,1800,28800),'EXISTING_REALM_POLICY_CHANGED')
                return {'source':old['alias'],'candidate':alias,'resume':'positive full tree/config/profile verification; no flow rewrite','ttl_sso':[realm['accessTokenLifespan'],realm['ssoSessionIdleTimeout'],realm['ssoSessionMaxLifespan']]}
            # A partial clone was NEVER selected. Repair only this run's inactive generated tree.
            self.api('/authentication/flows/'+by_alias[alias]['id'],'DELETE',expected=(204,))
        self.api('/authentication/flows','POST',{'alias':alias,'description':'D10 strict clone; B0/MFA order retained','providerId':old['providerId'],'topLevel':True,'builtIn':False},(201,))
        def configure(parent,new,original):
            # Exact26.8.2 updateExecutions also writes primitive priority (omitted =>0).
            # Preserve its explicit value, rather than letting a requirement-only PUT reorder MFA.
            self.api('/authentication/flows/'+quote(parent,safe='')+'/executions','PUT',{'id':new['id'],'requirement':original['requirement'],'priority':original['priority']},(204,))
            config=original.get('authenticationConfig')
            if config:
                c=self.api('/authentication/config/'+config);c.pop('id',None);c['alias']='d10-'+self.i['run_id']+'-'+str(counter[0])+'-'+uuid.uuid4().hex[:6];counter[0]+=1
                self.api('/authentication/executions/'+new['id']+'/config','POST',c,(201,))
        def clone(source,target):
            source_rows=rows(source);has_password=False
            for original in source_rows:
                existing={e['id'] for e in rows(target)}
                if original.get('authenticationFlow'):
                    child=flow(original['flowId']);new_alias='d10-'+self.i['run_id']+'-flow-'+str(counter[0]);counter[0]+=1
                    self.api('/authentication/flows/'+quote(target,safe='')+'/executions/flow','POST',{'alias':new_alias,'type':child['providerId'],'provider':child['providerId'],'description':'D10 preserved '+child['alias']},(201,))
                    new=next(e for e in rows(target) if e['id'] not in existing);configure(target,new,original);clone(child['alias'],new_alias)
                    proof.append({'kind':'subflow','requirement':original['requirement'],'source':child['alias']})
                else:
                    provider=original['providerId'];has_password|=provider=='auth-username-password-form';replacement=replacements.get(provider,provider)
                    self.api('/authentication/flows/'+quote(target,safe='')+'/executions/execution','POST',{'provider':replacement},(201,));new=next(e for e in rows(target) if e['id'] not in existing);configure(target,new,original)
                    proof.append({'source':provider,'candidate':replacement,'requirement':original['requirement']})
            if has_password:
                existing={e['id'] for e in rows(target)};self.api('/authentication/flows/'+quote(target,safe='')+'/executions/execution','POST',{'provider':'d10-auth-ticket','priority':1000},(201,));new=next(e for e in rows(target) if e['id'] not in existing);configure(target,new,{'requirement':'REQUIRED','priority':1000});proof.append({'source':None,'candidate':'d10-auth-ticket','requirement':'REQUIRED','priority':1000})
            expected=[(replacements.get(e.get('providerId'),e.get('providerId')),e['requirement'],bool(e.get('authenticationFlow')),e['priority']) for e in source_rows]
            if has_password:expected.append(('d10-auth-ticket','REQUIRED',False,1000))
            observed=[(e.get('providerId'),e['requirement'],bool(e.get('authenticationFlow')),e['priority']) for e in rows(target)]
            need(observed==expected,'CLONED_FLOW_ORDER_REQUIREMENT_MISMATCH_'+json.dumps({'expected':expected,'actual':observed}))
        clone(old['alias'],alias)
        # Exact26.8.2 has ENABLED/ADMIN_VIEW/ADMIN_EDIT; null means disabled.
        profile=self.api('/users/profile');profile['unmanagedAttributePolicy']=None
        need(all(not a['name'].startswith(('zt.','zt_')) for a in profile.get('attributes',[])),'RESERVED_ATTRIBUTE_MANAGED_BY_USER')
        self.api('/users/profile','PUT',profile,(200,204));self.api('','PUT',{'browserFlow':alias},(204,))
        check=self.api('');need(check['browserFlow']==alias,'BROWSER_FLOW_NOT_BOUND')
        need((check['accessTokenLifespan'],check['ssoSessionIdleTimeout'],check['ssoSessionMaxLifespan'])==(300,1800,28800),'REALM_POLICY_CHANGED')
        return {'source':old['alias'],'candidate':alias,'executions':proof,'user_profile':'unmanaged disabled (native null/default); no reserved managed attributes','ttl_sso':[300,1800,28800]}
    def cleanup(self):
        status,rows=self.request('/admin/realms/master/clients?clientId='+quote(self.i['bootstrap_client']),expected=(200,));need(len(rows)==1,'BOOTSTRAP_CLIENT_NOT_UNIQUE')
        self.request('/admin/realms/master/clients/'+rows[0]['id'],'DELETE',expected=(204,));return {'temporary_master_client_removed':True}
    def designated(self):
        # Existing Portal M2M provisioner, not an owner login or owner signing credential.
        status,body=self.request('/realms/DoAn/protocol/openid-connect/token','POST',{'grant_type':'client_credentials','client_id':'zerotrust-provisioner','client_secret':self.i['provisioner_secret']},False,True)
        need(status==200 and body.get('access_token'),'DESIGNATED_PROVISIONER_AUTH');self.token=body['access_token'];ids={}
        for key,actor in self.i['accounts'].items():
            need(actor['username'].startswith('d10-'+self.i['run_id']+'-') and actor['role']in ('ADMIN','STUDENT'),'DESIGNATED_IDENTITY_SCOPE')
            need(not self.api('/users?username='+quote(actor['username'])+'&exact=true'),'DESIGNATED_USERNAME_ALREADY_EXISTS')
            document={'username':actor['username'],'email':actor['username']+'@acceptance.invalid','emailVerified':True,'firstName':'D10','lastName':'Acceptance','enabled':True,'credentials':[{'type':'password','value':actor['password'],'temporary':False},{'type':'otp','userLabel':'D10 designated acceptance','secretData':json.dumps({'value':actor['otp']}),'credentialData':json.dumps({'subType':'totp','digits':6,'counter':0,'period':30,'algorithm':'HmacSHA1'})}]}
            self.api('/users','POST',document,(201,));users=self.api('/users?username='+quote(actor['username'])+'&exact=true');need(len(users)==1,'DESIGNATED_NATIVE_MAPPING');user=users[0]
            role=self.api('/roles/'+actor['role']);self.api('/users/'+user['id']+'/role-mappings/realm','POST',[role],(204,))
            if actor['role']=='ADMIN':
                account=self.client('account');manage=self.api('/clients/'+account['id']+'/roles/manage-account');self.api('/users/'+user['id']+'/role-mappings/clients/'+account['id'],'POST',[manage],(204,))
            ids[key]=user['id']
        return {'status':'PASS','new_designated_ids':ids,'existing_users_modified':False,'credentials_or_tokens_returned':False}
    def disable_designated(self):
        for actor in self.i['accounts'].values():
            need(actor['username'].startswith('d10-'+self.i['run_id']+'-'),'DESIGNATED_DISABLE_SCOPE')
            current=self.api('/users/'+actor['id']);need(current['username']==actor['username'],'DESIGNATED_DISABLE_MAPPING')
            self.api('/users/'+actor['id'],'PUT',{'enabled':False},(204,));need(self.api('/users/'+actor['id'])['enabled']is False,'DESIGNATED_DISABLE_NOT_CONFIRMED')
        return {'status':'PASS','designated_disabled':len(self.i['accounts']),'existing_users_modified':False}
def main():
    inputs=json.load(sys.stdin);need(inputs.get('run_id') and inputs.get('action') in ('provision','cleanup','designated','disable-designated'),'NATIVE_ACTION_SCOPE');native=Native(inputs)
    if inputs['action']=='designated':print(json.dumps(native.designated()));return
    native.login()
    if inputs['action']=='provision':result={'status':'PASS','clients':native.provision_clients(),'flow':native.clone_browser()}
    elif inputs['action']=='disable-designated':result=native.disable_designated()
    else:result={'status':'PASS',**native.cleanup()}
    print(json.dumps(result))
if __name__=='__main__':
    try:main()
    except Exception as e:
        reason=str(e) if type(e)is RuntimeError else type(e).__name__
        if type(e)is KeyError:reason+='_'+str(e.args[0])
        frame=traceback.extract_tb(e.__traceback__)[-1];print(json.dumps({'status':'FAIL','reason':reason+'_LINE_'+str(frame.lineno)}));sys.exit(1)
