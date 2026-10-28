"""Synthetic Demo fixtures only. Never call for a legacy database or realm."""
import uuid

def ident(cfg, label):
    return str(uuid.uuid5(uuid.UUID(cfg['namespace']),label))


def binary(value):
    return "UNHEX('"+uuid.UUID(value).hex+"')"


def school_seed(cfg):
    rows=['USE demo_school;']
    for code in ['A','B']:
        rows.append(f"INSERT INTO student_classes(id,class_code,class_name,department,course_years) VALUES({binary(ident(cfg,'class'+code))},'DEMO_{code}','Demo Class {code}','Computer Science','2026-2030');")
        rows.append(f"INSERT INTO subjects(id,subject_code,subject_name,credits) VALUES({binary(ident(cfg,'subject'+code))},'DEMO_{code}','Demo Subject {code}',3);")
    for actor,user in cfg['users'].items():
        if user['role'] not in ('ADMIN','STUDENT'):
            continue
        local=ident(cfg,'local_'+actor)
        rows.append(f"INSERT INTO users(id,keycloak_user_id,username,email,first_name,last_name,status) VALUES({binary(local)},{binary(user['id'])},'{user['username']}','{actor}@demo.invalid','Demo','{actor}','ACTIVE');")
        if user['role']=='STUDENT':
            code='B' if actor=='student_b' else 'A'
            rows.append(f"INSERT INTO students(id,user_id,class_id,student_code,date_of_birth,gender) VALUES({binary(ident(cfg,'student_'+actor))},{binary(local)},{binary(ident(cfg,'class'+code))},'DEMO_{actor.upper()}','2005-01-01','OTHER');")
            rows.append(f"INSERT INTO scores(id,student_id,subject_id,semester,academic_year,attendance_score,midterm_score,final_score,total_score,grade) VALUES({binary(ident(cfg,'score_'+actor))},{binary(ident(cfg,'student_'+actor))},{binary(ident(cfg,'subject'+code))},1,'2026-2027',9,8,8.5,8.4,'B+');")
    return '\n'.join(rows)+'\n'


def realm(cfg):
    audiences=lambda audience:[{'name':'audience','protocol':'openid-connect','protocolMapper':'oidc-audience-mapper','consentRequired':False,
        'config':{'included.client.audience':audience,'access.token.claim':'true','id.token.claim':'false'}}]
    clients=[{'clientId':name,'name':name,'enabled':True,'protocol':'openid-connect','bearerOnly':True} for name in ['zerotrust-api','zerotrust-risk-api']]
    clients.append({'clientId':'zerotrust-spa','enabled':True,'protocol':'openid-connect','publicClient':True,'standardFlowEnabled':True,'directAccessGrantsEnabled':False,
        'redirectUris':['https://localhost:8443/','https://localhost:8443/silent-check-sso.html'],'webOrigins':['https://localhost:8443'],
        'attributes':{'pkce.code.challenge.method':'S256','post.logout.redirect.uris':'https://localhost:8443/'},'defaultClientScopes':['basic','profile','email','roles','web-origins'],'protocolMappers':audiences('zerotrust-api')})
    for name,secret in cfg['clients'].items():
        clients.append({'clientId':name,'enabled':True,'protocol':'openid-connect','publicClient':False,'secret':secret,'serviceAccountsEnabled':True,
            'standardFlowEnabled':False,'directAccessGrantsEnabled':False,'protocolMappers':audiences('zerotrust-risk-api')})
    users=[{'id':u['id'],'username':u['username'],'enabled':True,'email':actor+'@demo.invalid','emailVerified':True,'firstName':'Demo','lastName':actor,
            'realmRoles':[u['role']],'requiredActions':['CONFIGURE_TOTP'],'credentials':[{'type':'password','value':u['password'],'temporary':False}]} for actor,u in cfg['users'].items() if u['role'] in ('ADMIN','STUDENT')]
    grants={'zerotrust-risk-caller':{'zerotrust-risk-api':['risk:evaluate','risk:device:write','risk:events:write']},
            'zerotrust-portal-risk-admin':{'zerotrust-risk-api':['risk:device:revoke']},
            'zerotrust-provisioner':{'realm-management':['manage-users','view-users','query-users','view-clients','view-realm']}}
    for client,roles in grants.items():users.append({'username':'service-account-'+client,'enabled':True,'serviceAccountClientId':client,'clientRoles':roles})
    execution=lambda authenticator,requirement,priority,config=None:{'authenticator':authenticator,'requirement':requirement,'priority':priority,'authenticatorFlow':False,**({'authenticatorConfig':config} if config else {})}
    riskconfig={'riskServiceBaseUrl':'https://risk:8443','tokenEndpointUrl':'https://keycloak:8444/realms/zerotrust-demo/protocol/openid-connect/token',
        'serviceClientId':'zerotrust-risk-caller','serviceClientSecret':cfg['clients']['zerotrust-risk-caller'],'failureMode':'DENY','monitoredEventClientId':'zerotrust-spa'}
    return {'realm':'zerotrust-demo','enabled':True,'sslRequired':'all','registrationAllowed':False,'resetPasswordAllowed':False,'rememberMe':False,
        'loginTheme':'zerotrust','browserFlow':'demo-browser','eventsEnabled':True,'eventsExpiration':86400,'eventsListeners':['jboss-logging','zerotrust-risk-events'],
        'roles':{'realm':[{'name':role} for role in ['STUDENT','ADMIN']],'client':{'zerotrust-risk-api':[{'name':role} for role in ['risk:evaluate','risk:device:write','risk:events:write','risk:device:revoke']]}},
        'clients':clients,'users':users,'authenticatorConfig':[{'alias':'demo-risk','config':riskconfig}],
        'authenticationFlows':[{'alias':'demo-browser','providerId':'basic-flow','topLevel':True,'builtIn':False,'authenticationExecutions':[
            execution('auth-cookie','ALTERNATIVE',10),{'flowAlias':'demo-forms','authenticatorFlow':True,'requirement':'ALTERNATIVE','priority':20}]},
            {'alias':'demo-forms','providerId':'basic-flow','topLevel':False,'builtIn':False,'authenticationExecutions':[
                execution('auth-username-password-form','REQUIRED',10),execution('zerotrust-risk-authenticator','REQUIRED',20,'demo-risk'),
                {'flowAlias':'demo-mfa','authenticatorFlow':True,'requirement':'CONDITIONAL','priority':30},execution('zerotrust-device-registration','REQUIRED',40)]},
            {'alias':'demo-mfa','providerId':'basic-flow','topLevel':False,'builtIn':False,'authenticationExecutions':[
                execution('zerotrust-risk-step-up-condition','REQUIRED',10),execution('auth-otp-form','REQUIRED',20)]}]}
