"""Prepare the three synthetic DoAn accounts for controlled teacher access (runs on the VM as root).

Adds UPDATE_PASSWORD + CONFIGURE_TOTP first-login actions through the Portal provisioner client
(Keycloak Admin REST, manage-users scope). Never prints passwords, OTP seeds or tokens.
"""
import json, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from common import config, need

HELPER = r'''
import json,ssl,sys
from urllib.request import Request,build_opener,HTTPSHandler,ProxyHandler
from urllib.parse import urlencode,quote
from urllib.error import HTTPError
v=json.load(sys.stdin);c=ssl.create_default_context(cafile='/public/internal-ca-with-crl.pem');c.verify_flags|=ssl.VERIFY_CRL_CHECK_CHAIN
o=build_opener(ProxyHandler({}),HTTPSHandler(context=c));B='https://keycloak:8443'
def call(path,method='GET',data=None,token=None,form=False):
    h={'Accept':'application/json'}
    if token:h['Authorization']='Bearer '+token
    if data is not None:h['Content-Type']='application/x-www-form-urlencoded' if form else 'application/json';data=(urlencode(data) if form else json.dumps(data)).encode()
    try:r=o.open(Request(B+path,data=data,headers=h,method=method),timeout=15)
    except HTTPError as e:r=e
    raw=r.read();return r.status,(json.loads(raw) if raw else None)
s,b=call('/realms/DoAn/protocol/openid-connect/token','POST',{'grant_type':'client_credentials','client_id':'zerotrust-provisioner','client_secret':v['secret']},form=True)
assert s==200,'PROVISIONER_AUTH';t=b['access_token'];out={}
for name in v['users']:
    s,rows=call('/admin/realms/DoAn/users?exact=true&username='+quote(name),token=t);assert s==200 and len(rows)==1,'USER_'+name
    u=rows[0];actions=sorted(set(u.get('requiredActions',[]))|{'UPDATE_PASSWORD','CONFIGURE_TOTP'})
    s,_=call('/admin/realms/DoAn/users/'+u['id'],'PUT',{'requiredActions':actions,'enabled':True},token=t);assert s==204,'UPDATE_'+name
    s,u=call('/admin/realms/DoAn/users/'+u['id'],token=t);out[name]={'enabled':u['enabled'],'requiredActions':sorted(u['requiredActions'])}
print(json.dumps(out))
'''


def main():
    c = config(HERE / 'gcp.json')
    need(c['mode'] == 'gcp', 'GCP_ONLY')
    state = c['state']
    accounts = json.loads((state / 'accounts.json').read_text())
    users = [accounts[k]['username'] for k in ('admin', 'student_a', 'student_b')]
    secret = next(l.split('=', 1)[1] for l in (state / 'backend/application.properties').read_text().splitlines()
                  if l.startswith('keycloak.admin.client-secret='))
    p = subprocess.run(['docker', 'run', '--rm', '-i', '--network', c['project'] + '_core', '--read-only', '--cap-drop', 'ALL',
                        '--security-opt', 'no-new-privileges:true', '--mount', f"type=bind,source={c['out'] / 'public'},target=/public,readonly",
                        '--entrypoint', '/opt/tools/bin/python', 'zt-full-function/browser:20261111-1', '-c', HELPER],
                       input=json.dumps({'secret': secret, 'users': users}).encode(), capture_output=True, timeout=120)
    need(p.returncode == 0, 'TEACHER_ACCOUNT_UPDATE_FAILED')
    print('PASS', p.stdout.decode().strip())


if __name__ == '__main__':
    main()
