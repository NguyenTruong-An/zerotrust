"""Inspect legacy public PKI read-only; negative CRL checks use only fresh keys."""
import datetime as dt
import json
from pathlib import Path
import subprocess

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
import operate as full


def main():
    now=dt.datetime.now(dt.timezone.utc)
    legacy=(Path(__file__).resolve().parents[3]/'runtime'/'lab')
    observed={}
    for name in ('public-ca/ca.crt','public-ca/ca.crl','gateway/server.crt','keycloak/server.crt'):
        raw=(legacy/name).read_bytes()
        if name.endswith('.crl'):
            item=x509.load_pem_x509_crl(raw) if raw.startswith(b'-----') else x509.load_der_x509_crl(raw)
            end=item.next_update_utc
        else:end=x509.load_pem_x509_certificate(raw).not_valid_after_utc
        observed[name]={'valid_until':end.isoformat(),'expired':end<now}
    (full.OUT/'legacy-tls-readonly.json').write_text(json.dumps(observed,indent=2)+'\n')
    ca=x509.load_pem_x509_certificate((full.STATE/'ca.crt').read_bytes())
    key=serialization.load_pem_private_key((full.STATE/'ca.key').read_bytes(),None)
    leaf=x509.load_pem_x509_certificate((full.STATE/'ingress/server.crt').read_bytes())
    negative=full.OUT/'tls-negative';negative.mkdir(exist_ok=True)
    expired=(x509.CertificateRevocationListBuilder().issuer_name(ca.subject)
             .last_update(now-dt.timedelta(days=3)).next_update(now-dt.timedelta(days=1))
             .sign(key,hashes.SHA256()))
    entry=x509.RevokedCertificateBuilder().serial_number(leaf.serial_number).revocation_date(now-dt.timedelta(minutes=1)).build()
    revoked=(x509.CertificateRevocationListBuilder().issuer_name(ca.subject)
             .last_update(now-dt.timedelta(minutes=5)).next_update(now+dt.timedelta(days=1))
             .add_revoked_certificate(entry).sign(key,hashes.SHA256()))
    for name,value in [('expired.pem',expired),('revoked.pem',revoked)]:
        (negative/name).write_bytes(value.public_bytes(serialization.Encoding.PEM))
    cmd=['docker','run','--rm','--network','none','--cap-drop','ALL',
         '--mount',f'type=bind,source={full.STATE},target=/private,readonly',
         '--mount',f'type=bind,source={negative},target=/negative,readonly',
         '--entrypoint','openssl','zt-pd02-candidate/tools:pd-r11-c401e17','verify',
         '-CAfile','/private/ca.crt','-crl_check_all','-purpose','sslserver']
    results=[]
    for label,crl,host,reason in [
        ('valid TLS chain/SAN and CRL','/private/ca.crl.pem',full.PORTAL_HOST,None),
        ('expired CRL rejected','/negative/expired.pem',full.PORTAL_HOST,'CRL has expired'),
        ('revoked leaf rejected','/negative/revoked.pem',full.PORTAL_HOST,'certificate revoked'),
        ('wrong hostname rejected','/private/ca.crl.pem','wrong.full-function.test','hostname mismatch')]:
        p=subprocess.run([*cmd,'-CRLfile',crl,'-verify_hostname',host,'/private/ingress/server.crt'],capture_output=True,encoding='utf-8',timeout=30)
        assert (p.returncode==0 if reason is None else p.returncode!=0 and reason in p.stdout+p.stderr),label
        results.append(label);print('PASS '+label,flush=True)
    (full.OUT/'tls-results.json').write_text(json.dumps({'passed':results,'legacy_material_modified':False,'Windows_trust_modified':False},indent=2)+'\n')


if __name__=='__main__':main()
