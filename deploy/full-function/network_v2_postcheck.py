"""Read-only internal TLS/CRL/OIDC checks. No fake successful-login history or MFA reset."""
import json,ssl
from pathlib import Path
from urllib.request import build_opener,HTTPSHandler,ProxyHandler

def main():
    ctx=ssl.create_default_context(cafile='/private/ca-with-crl.pem');ctx.verify_flags|=ssl.VERIFY_CRL_CHECK_CHAIN
    opener=build_opener(ProxyHandler({}),HTTPSHandler(context=ctx))
    def get(url):
        with opener.open(url,timeout=15) as response:
            if response.status!=200:raise RuntimeError('TLS_HTTP_STATUS')
            return json.load(response)
    health=get('https://risk:8443/actuator/health')
    if health['status']!='UP':raise RuntimeError('RISK_HEALTH')
    issuer='https://auth.full-function.test:39443/realms/DoAn'
    # Direct internal endpoint, preserving the issuer returned by strict hostname configuration.
    discovery=get('https://keycloak:8443/realms/DoAn/.well-known/openid-configuration')
    if discovery['issuer']!=issuer:raise RuntimeError('ISSUER_DRIFT')
    if not get('https://keycloak:8443/realms/DoAn/protocol/openid-connect/certs')['keys']:raise RuntimeError('JWKS_EMPTY')
    return {'status':'PASS','TLS_CRL_hostname':True,'issuer':issuer,'JWKS':True,'risk_health':True,
        'authentication_or_security_state_written':False,'fresh_MFA_ADMIN_STUDENT':'OWNER_POST_CUTOVER_CHECK'}

if __name__=='__main__':
    try:result=main()
    except Exception as error:result={'status':'FAIL','type':type(error).__name__}
    Path('/results/result.json').write_text(json.dumps(result)+'\n')
    print('PASS internal read-only verification' if result['status']=='PASS' else 'FAIL internal read-only verification')
    raise SystemExit(0 if result['status']=='PASS' else 1)
