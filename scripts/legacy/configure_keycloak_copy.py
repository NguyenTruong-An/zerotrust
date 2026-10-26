"""Apply only reviewed endpoint/TLS/SPA URI changes to an imported candidate after model comparison."""
import argparse
import json
from pathlib import Path
import ssl
import urllib.request
import urllib.parse

BASE = 'https://keycloak:28444'
PROJECT = 'zerotrust-legacy-integration-20261026'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--state', type=Path, required=True)
    args = parser.parse_args(); state = args.state
    approval = json.loads((state/'approval/owner-approval.private.json').read_text())
    assert approval.get('approved') is True and approval['project'] == PROJECT, 'OWNER_APPROVAL_REQUIRED'
    evidence = json.loads((state/'evidence/keycloak-import-comparison.json').read_text())
    assert evidence['PASS'] is True, 'IMPORT_IDENTITY_COMPARISON_REQUIRED'
    journal = state/'evidence/keycloak-endpoint-changes.private.json'
    assert not journal.exists(), 'ALREADY_CONFIGURED_NO_AUTOMATIC_REPEAT_LOGIN'
    credentials = json.loads((state/'approval/admin-credentials.private.json').read_text())
    context = ssl.create_default_context(cafile=str(state/'public-ca/ca.crt'))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    token = None
    def request(path, method='GET', data=None, form=False):
        headers = {}
        if token: headers['Authorization'] = 'Bearer '+token
        if data is not None:
            data = urllib.parse.urlencode(data).encode() if form else json.dumps(data).encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
        with opener.open(urllib.request.Request(BASE+path, data=data, headers=headers, method=method), timeout=20) as response:
            body=response.read();return json.loads(body) if body else None
    auth=request('/realms/master/protocol/openid-connect/token', 'POST',
                 {'client_id':'admin-cli','grant_type':'password', **credentials}, form=True)
    token=auth['access_token']; changes=[]; prefix='/admin/realms/DoAn'
    # Enumerate exact preserved config IDs from the original export; no flow/role changes.
    realm=json.loads((state/'migration-inputs/keycloak/original-export/DoAn-realm.json').read_text(encoding='utf-8'))
    for config in realm.get('authenticatorConfig',[]):
        if 'riskServiceBaseUrl' not in config.get('config',{}):continue
        before=request(prefix+'/authentication/config/'+config['id'])
        assert before['config'].get('failureMode')=='DENY', 'FAILURE_POLICY_DRIFT'
        after=json.loads(json.dumps(before))
        after['config']['riskServiceBaseUrl']='https://risk:8443'
        after['config']['tokenEndpointUrl']='https://keycloak:28444/realms/DoAn/protocol/openid-connect/token'
        request(prefix+'/authentication/config/'+config['id'], 'PUT', after)
        changes.append({'resource':'authenticator-config','before':before,'after':after})
    clients=request(prefix+'/clients?clientId=zerotrust-spa')
    assert len(clients)==1
    before=request(prefix+'/clients/'+clients[0]['id']);after=json.loads(json.dumps(before))
    assert after['publicClient'] and after['standardFlowEnabled'] and not after['directAccessGrantsEnabled']
    after['redirectUris']=['https://localhost:28443/','https://localhost:28443/silent-check-sso.html']
    after['webOrigins']=['https://localhost:28443']
    after.setdefault('attributes',{})['pkce.code.challenge.method']='S256'
    after['attributes']['post.logout.redirect.uris']='https://localhost:28443/'
    request(prefix+'/clients/'+after['id'], 'PUT', after)
    changes.append({'resource':'SPA-URIs','before':before,'after':after})
    before=request(prefix)
    attributes=dict(before.get('attributes',{}))
    attributes['frontendUrl']='https://localhost:28444'
    request(prefix,'PUT',{'sslRequired':'all','attributes':attributes})
    changes.append({'resource':'realm-TLS-and-canonical-issuer',
                    'before':{'sslRequired':before.get('sslRequired'),'frontendUrl':before.get('attributes',{}).get('frontendUrl')},
                    'after':{'sslRequired':'all','frontendUrl':attributes['frontendUrl']}})
    journal.write_text(json.dumps(changes,indent=2))
    print(json.dumps({'status':'PASS','approved_copy_records_updated':len(changes),
                      'users_created':0,'credential_resets':0,'flow_or_role_changes':0}))


if __name__=='__main__':main()
