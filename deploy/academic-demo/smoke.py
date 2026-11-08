"""Smoke the actual loopback ingress and Portal browser flow, with synthetic accounts."""
import argparse
import base64
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import time
import traceback
from urllib.parse import parse_qs, urlencode, urlsplit
import uuid

from playwright.sync_api import sync_playwright

from academic_demo import AUTH_HOST, ISSUER, PORT, PORTAL, PORTAL_HOST, REALM, STATE, compose, require, verify_boundary
from cryptography import x509
from cryptography.hazmat.primitives import serialization


def request(host, path, method='GET', token=None, form=None):
    client = http.client.HTTPSConnection(host, PORT, context=ssl.create_default_context(cafile=str(STATE/'ca.crt')), timeout=8)
    client._create_connection = lambda _address, timeout, source: socket.create_connection(('127.0.0.1', PORT), timeout, source)
    headers = {'Authorization': 'Bearer '+token} if token else {}
    try:
        body = urlencode(form) if form else ('{}' if method=='POST' else None)
        if method=='POST':
            headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
        client.request(method, path, body=body, headers=headers)
        response = client.getresponse()
        return response.status, response.read()
    finally:
        client.close()


def mysql(sql, profile='root', check=True):
    return compose('exec','-T','mysql','mysql',f'--defaults-extra-file=/fixture/{profile}.cnf','-Nse',sql,check=check)


def infrastructure():
    status, body = request(AUTH_HOST,f'/realms/{REALM}/.well-known/openid-configuration')
    require(status==200 and json.loads(body)['issuer']==ISSUER,'OIDC discovery issuer mismatch')
    require(request(PORTAL_HOST,'/')[0]==200,'Portal TLS failed')
    require(request(AUTH_HOST,'/admin/')[0]==404 and request(PORTAL_HOST,'/actuator/health')[0]==404,
            'Private management path leaked')
    require(request(PORTAL_HOST,'/observatory')[0]==404, 'Private Observatory path leaked')
    grants=mysql('SHOW GRANTS FOR CURRENT_USER','school').stdout.splitlines()
    require(len(grants)==6 and sum('GRANT SELECT ON' in line for line in grants)==5,'Unexpected School DB grants')
    before=mysql('SELECT COUNT(*) FROM scores','school').stdout
    denial=mysql('DELETE FROM scores WHERE 1=0','school',check=False)
    require(denial.returncode!=0 and '1142' in denial.stderr and mysql('SELECT COUNT(*) FROM scores','school').stdout==before,
            'School SQL write guard did not reject')
    require(mysql("SELECT checksum,success FROM pd_staging_risk.flyway_schema_history WHERE version='5'").stdout.strip()=='661092940\t1',
            'V5 ledger mismatch')
    print('PASS TLS with CA/SAN, OIDC issuer, private route denies, School SELECT-only and Flyway V5',flush=True)


def totp(secret):
    digest = hmac.digest(secret, struct.pack('>Q', int(time.time())//30), 'sha1')
    value = struct.unpack_from('>I', digest, digest[-1]&15)[0]&0x7fffffff
    return f'{value%1000000:06}'


def begin(page, account):
    page.goto(PORTAL,wait_until='domcontentloaded')
    page.get_by_role('button',name='Đăng nhập với Keycloak').click()
    page.wait_for_url(lambda url: urlsplit(url).hostname==AUTH_HOST)
    q=parse_qs(urlsplit(page.url).query)
    require(q.get('code_challenge_method')==['S256'] and 'code_challenge' in q,'Browser did not use PKCE S256')
    page.locator('#username').fill(account['username'])
    page.locator('#password').fill(account['password'])
    page.locator('#kc-login, button[type=submit]').first.click()
    page.wait_for_load_state('domcontentloaded')


def submit(page):
    page.locator('input[type=submit],button[type=submit]').first.click()


def login(browser,account,wrong_otp=False):
    page=browser.new_page()
    page.set_default_timeout(15000)
    tokens=[]
    def response(r):
        if r.status==200 and urlsplit(r.url).path.endswith('/protocol/openid-connect/token'):
            tokens.append(r.json())
    page.on('response',response)
    begin(page,account)
    enrollment=page.locator('input[name=totpSecret]')
    otp=page.locator('input[name=otp]')
    if enrollment.count():
        secret=enrollment.input_value().encode()
        page.locator('input[name=totp]').fill(totp(secret))
        label=page.locator('input[name=userLabel]')
        if label.count():
            label.fill('Academic synthetic')
        submit(page)
        stage='enrollment'
    elif otp.count():
        actor_id=account['id']
        raw=mysql(f"SELECT SECRET_DATA FROM pd_staging_keycloak.CREDENTIAL WHERE USER_ID='{actor_id}' AND TYPE='otp' LIMIT 1").stdout
        secret=json.loads(raw)['value'].encode()
        if wrong_otp:
            correct=totp(secret)
            otp.fill('000000' if correct!='000000' else '111111')
            submit(page)
            otp.wait_for()
            require(urlsplit(page.url).hostname==AUTH_HOST and not tokens,'Wrong OTP produced a token')
            page.close()
            return 'wrong OTP rejected'
        otp.fill(totp(secret))
        submit(page)
        stage='verified OTP'
    else:
        stage='password-only'
    page.get_by_role('button',name='Đăng xuất',exact=True).wait_for(timeout=25000)
    require(tokens and tokens[-1].get('access_token'),'Frontend did not obtain access token')
    return page,tokens[-1],stage


def browser_check(outage=False):
    accounts=json.loads((STATE/'accounts.json').read_text())
    cert=x509.load_pem_x509_certificate((STATE/'ingress/server.crt').read_bytes())
    public_key=cert.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    pin=base64.b64encode(hashlib.sha256(public_key).digest()).decode()
    chrome=Path(os.environ.get('ACADEMIC_CHROME',r'C:\Program Files\Google\Chrome\Application\chrome.exe'))
    with sync_playwright() as p:
        browser=p.chromium.launch(**({'executable_path':str(chrome)} if chrome.is_file() else {}),args=[
            f'--host-resolver-rules=MAP {PORTAL_HOST} 127.0.0.1, MAP {AUTH_HOST} 127.0.0.1',
            '--ignore-certificate-errors-spki-list='+pin,'--no-proxy-server','--disable-background-networking'])
        try:
            if outage:
                page=browser.new_page()
                issued=[]
                page.on('response',lambda response: issued.append(response.status) if '/openid-connect/token' in response.url else None)
                begin(page,accounts['student_b'])
                page.locator('#kc-error-message, #input-error').first.wait_for(timeout=18000)
                require(urlsplit(page.url).hostname==AUTH_HOST and not issued,'Risk outage produced an authentication callback')
                print('PASS browser fail-closed during Risk Service outage',flush=True)
                return
            student,tokens,stage=login(browser,accounts['student_b'])
            token=tokens['access_token']
            status,scores=request(PORTAL_HOST,'/api/students/me/scores',token=token)
            require(status==200,f'Student score read returned HTTP {status}')
            subjects=mysql('SELECT HEX(id) FROM pd_staging_school.subjects ORDER BY subject_code').stdout.splitlines()
            require(len(subjects)==2 and str(uuid.UUID(hex=subjects[1])).encode() in scores
                    and str(uuid.UUID(hex=subjects[0])).encode() not in scores,'Student scope mismatch')
            require(request(PORTAL_HOST,'/api/admin/student-classes',token=token)[0]==403,'Student crossed ADMIN boundary')
            student.get_by_role('button',name='Đăng xuất',exact=True).click()
            student.get_by_role('button',name='Đăng nhập với Keycloak').wait_for(timeout=20000)
            refresh_status,_=request(AUTH_HOST,f'/realms/{REALM}/protocol/openid-connect/token','POST',
                                     form={'grant_type':'refresh_token','client_id':'zerotrust-spa','refresh_token':tokens['refresh_token']})
            require(refresh_status==400,'Refresh after logout unexpectedly accepted')
            print(f'PASS Student PKCE S256 ({stage}), own scores, ADMIN deny, logout and refresh denial',flush=True)
            admin,tokens,stage=login(browser,accounts['admin'])
            token=tokens['access_token']
            require(request(PORTAL_HOST,'/api/admin/student-classes',token=token)[0]==200,'ADMIN academic read failed')
            require(request(PORTAL_HOST,'/api/admin/student-classes','POST',token)[0]==403,'ADMIN academic write accepted')
            header = 'header = '+json.dumps('Authorization: Bearer '+token)+'\n'
            direct=compose('exec','-T','risk','curl','--silent','--show-error','--cacert','/run/demo/ca.crt',
                '-o','/dev/null','-w','%{http_code}','--config','-','-H','Content-Type: application/json',
                '--data','{}','https://backend:8443/api/admin/student-classes',data=header)
            require(direct.stdout=='403','Direct School backend accepted academic write')
            print(f'PASS ADMIN Portal login ({stage}), academic read and direct/backend write deny',flush=True)
            admin.close()
            require(login(browser,accounts['student_b'],wrong_otp=True)=='wrong OTP rejected','Expected fresh browser OTP challenge')
            print('PASS fresh-browser wrong OTP rejection',flush=True)
        finally:
            browser.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--risk-outage',action='store_true')
    args=parser.parse_args()
    verify_boundary()
    infrastructure()
    try:
        if args.risk_outage:
            compose('stop','--timeout','30','risk')
            try:
                browser_check(outage=True)
            finally:
                compose('up','-d','--wait','--wait-timeout','100','risk')
        else:
            browser_check()
    except Exception as error:
        frame = next((frame for frame in reversed(traceback.extract_tb(error.__traceback__)) if Path(frame.filename)==Path(__file__)), None)
        place = f'{frame.name}:{frame.lineno}' if frame else 'browser harness'
        label = str(error) if type(error) is RuntimeError else type(error).__name__
        raise SystemExit(f'Browser smoke failed at {place} ({label}); credentials and URLs redacted') from None
