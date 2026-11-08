"""Exercise the combined synthetic RC in Chromium with an isolated trusted CA."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import traceback
from urllib.parse import urlsplit
import uuid

from rc import HERE, PREFIX, base, check, configure, linux, sql


def passed(name):
    print('PASS '+name,flush=True)


def suite(browser, c):
    spec=importlib.util.spec_from_file_location('browser_flows',linux.LOCAL/'smoke.py')
    b=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(b)
    accounts=json.loads((c['state']/'accounts.json').read_text())
    student,tokens,stage=b.login(browser,accounts['student_b'])
    check(stage=='enrollment','Expected fresh STUDENT TOTP enrollment')
    passed('Chromium strict TLS, STUDENT OIDC Code + PKCE S256 and TOTP enrollment')
    student_last_otp_window=int(time.time())//30
    token=tokens['access_token']
    status,data=b.request(b.PORTAL_HOST,'/api/students/me/scores',token=token)
    subjects=sql('mysql',f'SELECT HEX(id) FROM {PREFIX}school.subjects ORDER BY subject_code').splitlines()
    check(status==200 and len(subjects)==2 and str(uuid.UUID(hex=subjects[1])).encode() in data
          and str(uuid.UUID(hex=subjects[0])).encode() not in data,'STUDENT score ownership failed')
    passed('STUDENT sees own records only')
    check(b.request(b.PORTAL_HOST,'/api/admin/student-classes',token=token)[0]==403,'STUDENT crossed ADMIN boundary')
    passed('STUDENT denied ADMIN API')
    student.get_by_role('button',name='Đăng xuất',exact=True).click()
    student.get_by_role('button',name='Đăng nhập với Keycloak').wait_for(timeout=25000)
    passed('Browser RP logout returns to Portal')
    status,_=b.request(b.AUTH_HOST,f'/realms/{b.REALM}/protocol/openid-connect/token','POST',
        form={'grant_type':'refresh_token','client_id':'zerotrust-spa','refresh_token':tokens['refresh_token']})
    check(status==400,'Refresh accepted after logout')
    passed('Refresh token rejected after RP logout')
    student.context.close()

    admin,tokens,_=b.login(browser,accounts['admin'])
    token=tokens['access_token']
    check(b.request(b.PORTAL_HOST,'/api/admin/student-classes',token=token)[0]==200,'ADMIN read failed')
    passed('ADMIN logs in and reads academic data')
    check(b.request(b.PORTAL_HOST,'/api/admin/student-classes','POST',token)[0]==403,'ADMIN write accepted')
    passed('ADMIN academic write denied')
    admin.context.close()

    check(b.login(browser,accounts['student_b'],wrong_otp=True)=='wrong OTP rejected','Wrong OTP accepted')
    passed('Wrong OTP rejected in a fresh Chromium context')
    while int(time.time())//30<=student_last_otp_window or int(time.time())%30>=25:
        time.sleep(1)
    student,_,stage=b.login(browser,accounts['student_b'])
    check(stage=='verified OTP','Expected successful OTP challenge')
    passed('Correct OTP accepted in a fresh Chromium context')
    cookies=[cookie for cookie in student.context.cookies() if cookie['name']=='ZT_DEVICE_ID']
    check(len(cookies)==1 and cookies[0]['httpOnly'] and cookies[0]['secure'],'Trusted Device secure cookie missing')
    subject=str(uuid.UUID(accounts['student_b']['id']))
    check(int(sql('mysql',f"SELECT COUNT(*) FROM {PREFIX}risk.known_devices WHERE subject_id='{subject}'"))>0,
          'No device registration stored after OTP')
    passed('Trusted Device registered after OTP with secure HttpOnly cookie')
    student.context.close()

    base.compose('stop','--timeout','30','risk')
    try:
        page=browser.new_page()
        issued=[]
        page.on('response',lambda r: issued.append(r.status) if urlsplit(r.url).path.endswith('/openid-connect/token') else None)
        b.begin(page,accounts['student_a'])
        page.locator('#kc-error-message, #input-error').first.wait_for(timeout=18000)
        check(urlsplit(page.url).hostname==b.AUTH_HOST and not issued,'Risk outage issued a login token')
        passed('Browser login fails closed during Risk outage')
        page.context.close()
    finally:
        base.compose('up','-d','--wait','--wait-timeout','110','risk')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',required=True,type=Path)
    p.add_argument('--certutil',required=True,type=Path)
    p.add_argument('--config',default=HERE/'rehearsal.json',type=Path)
    p.add_argument('--project',default='zt-pd-r22')
    a=p.parse_args()
    c,_,_,_=configure(a.config,a.manifest,a.project)
    from playwright.sync_api import sync_playwright
    with tempfile.TemporaryDirectory(prefix='zt-r22-chromium-') as root:
        home=Path(root)
        db=home/'.pki/nssdb'
        db.mkdir(parents=True)
        for args in (('-N','--empty-password'),('-A','-n','Academic Demo test CA','-t','C,,',
                      '-i',str(c['state']/'ingress/edge-ca.crt'))):
            subprocess.run([str(a.certutil),'-d','sql:'+str(db),*args],check=True,capture_output=True)
        env={**os.environ,'HOME':str(home),'XDG_CONFIG_HOME':str(home/'.config')}
        with sync_playwright() as p:
            browser=p.chromium.launch(channel='chromium',env=env,args=[
                f"--host-resolver-rules=MAP {c['portal_host']} 127.0.0.1, MAP {c['auth_host']} 127.0.0.1",
                '--no-proxy-server','--disable-background-networking'])
            try:
                suite(browser,c)
            finally:
                browser.close()


if __name__=='__main__':
    try:
        main()
    except Exception as error:
        frame=next((f for f in reversed(traceback.extract_tb(error.__traceback__)) if f.filename==__file__),None)
        message=str(error) if type(error) is RuntimeError else type(error).__name__
        raise SystemExit(f'Browser stopped at {frame.lineno if frame else "launch"}: {message}') from None
