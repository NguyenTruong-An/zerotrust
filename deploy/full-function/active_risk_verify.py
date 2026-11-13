"""Internal verification for future approved active operations; no browser/MFA reset.

Only an ephemeral Risk-only subject gets five synthetic history events/evaluation.
No Keycloak/Portal accounts, credentials or Trusted Device registrations change.
Run only through an authorized context helper. Tests use disposable mounts.
"""
import datetime as dt
import json
from pathlib import Path
import ssl
import sys
import uuid
from urllib.parse import urlencode
from urllib.request import Request,build_opener,ProxyHandler,HTTPSHandler
from urllib.error import HTTPError


def main():
    private=Path('/private');ctx=ssl.create_default_context(cafile=str(private/'ca-with-crl.pem'))
    ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN
    opener=build_opener(ProxyHandler({}),HTTPSHandler(context=ctx))
    def request(url,data=None,token=None,form=False,expected=200):
        headers={}
        if token:headers['Authorization']='Bearer '+token
        if data is not None:
            headers['Content-Type']='application/x-www-form-urlencoded' if form else 'application/json'
            data=(urlencode(data) if form else json.dumps(data)).encode()
        if url.endswith('/risk/evaluations'):headers['X-ZeroTrust-Risk-Request']=str(uuid.uuid4())
        try:response=opener.open(Request(url,data=data,headers=headers),timeout=20)
        except HTTPError as exc:response=exc
        if response.status!=expected:raise RuntimeError('INTERNAL_SERVICE_STATUS_MISMATCH')
        raw=response.read();return json.loads(raw) if raw else None
    health=request('https://risk:8443/actuator/health')
    if health.get('status')!='UP':raise RuntimeError('RISK_HEALTH_NOT_UP')
    realm=json.loads((private/'installer/DoAn-realm.json').read_text())
    client=next(c for c in realm['clients'] if c['clientId']=='zerotrust-risk-caller')
    token=request('https://keycloak:8443/realms/DoAn/protocol/openid-connect/token',
        {'client_id':client['clientId'],'client_secret':client['secret'],'grant_type':'client_credentials'},form=True)['access_token']
    subject=str(uuid.uuid4());now=dt.datetime.now(dt.timezone.utc)
    for i in range(1,6):
        request('https://risk:8443/internal/v1/authentication-successes',{'eventId':str(uuid.uuid4()),'subjectId':subject,
            'clientId':'zerotrust-spa','authenticatedAt':(now-dt.timedelta(weeks=i)).isoformat()},token,expected=204)
    result=request('https://risk:8443/internal/v1/risk/evaluations',{'subjectId':subject,'authenticationSessionId':str(uuid.uuid4()),
        'clientId':'zerotrust-spa','ipAddress':'8.8.8.8','userAgent':'Approved internal verification fixture',
        'deviceId':'internal-untrusted-'+uuid.uuid4().hex},token)
    if result['riskScore']!=27.5 or result['decision']!='STEP_UP_MFA':raise RuntimeError('INTERNAL_B0_OR_MANDATORY_MFA_MISMATCH')
    return {'status':'PASS','mode':sys.argv[1],'TLS_CRL':True,'service_JWT':True,'score':27.5,'decision':'STEP_UP_MFA',
        'verification_scope':'ephemeral Risk-only history/evaluation; no account/credential/trust registration',
        'public_browser_geoip':'NOT_VERIFIED','browser_MFA':'REUSED_PRIOR_RECEIPTS'}


if __name__=='__main__':
    try:result=main()
    except Exception as exc:
        result={'status':'FAIL','type':type(exc).__name__}
        if type(exc) is RuntimeError:result['code']=str(exc)
    Path('/results/result.json').write_text(json.dumps(result)+'\n')
    print('PASS internal verification' if result['status']=='PASS' else 'FAIL internal verification',flush=True)
    raise SystemExit(0 if result['status']=='PASS' else 1)
