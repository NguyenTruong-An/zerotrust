"""Targeted DHI compatibility on the new candidate project only, from Windows Chrome.

Uses a temporary Playwright profile/SPKI exception; backend requests verify the new
synthetic CA. This is not public PKI acceptance and does not modify any Chrome profile.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import urlsplit
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT/'target/bounded-remediation-20261110'
PROJECT = 'zt-security-20261110'
ENGINE_ID = 'e87199e0-3944-4e49-a66f-e1adc093d1ae'
sys.path.insert(0, str(ROOT/'deploy/academic-demo'))
import academic_demo as base


def owned(service):
    name = PROJECT+'-'+service+'-1'
    d = json.loads(subprocess.check_output(['docker', 'inspect', name], encoding='utf-8'))[0]
    original = {v['Id'] for v in json.loads((OUT/'existing-containers.json').read_text())}
    base.require(d['Id'] not in original and d['Config']['Labels']['com.docker.compose.project'] == PROJECT,
                 'Foreign container rejected')
    return name


def compose(*args, check=True, **kwargs):
    base.require(args[:3] == ('exec', '-T', 'mysql'), 'Only candidate SQL reads allowed here')
    p = subprocess.run(['docker', 'exec', owned('mysql'), *args[3:]], capture_output=True,
                       encoding='utf-8', timeout=30)
    base.require(not check or p.returncode == 0, 'Candidate SQL command failed')
    return p


def student_scores(b, token, subject_index):
    status, scores = b.request(base.PORTAL_HOST, '/api/students/me/scores', token=token)
    subjects = b.mysql('SELECT HEX(id) FROM pd_staging_school.subjects ORDER BY subject_code').stdout.splitlines()
    own = len(subjects) == 2 and str(UUID(hex=subjects[subject_index])).encode() in scores
    foreign = len(subjects) == 2 and str(UUID(hex=subjects[1-subject_index])).encode() in scores
    base.require(status == 200 and own and not foreign,
                 f'Student score ownership failed (HTTP {status}, fixture subjects={len(subjects)}, own={own}, other={foreign})')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--resume-enrolled', action='store_true')
    mode.add_argument('--confirm-first-login', action='store_true')
    args = parser.parse_args()
    engine = subprocess.check_output(['docker', 'info', '--format', '{{.ID}}'], encoding='utf-8').strip()
    base.require(engine == ENGINE_ID, 'Canonical Docker Engine ID mismatch')
    base.STATE = Path(r'\\wsl.localhost\Ubuntu\tmp\zerotrust-security-20261110')
    base.PORT = 34443
    base.PORTAL_HOST, base.AUTH_HOST = 'portal.pd-r22.test', 'auth.pd-r22.test'
    base.PORTAL = 'https://'+base.PORTAL_HOST+':34443'
    base.ISSUER = 'https://'+base.AUTH_HOST+':34443/realms/academic-demo'
    base.compose = compose
    spec = importlib.util.spec_from_file_location('candidate_browser_flows', ROOT/'deploy/academic-demo/smoke.py')
    b = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(b)
    accounts = json.loads((base.STATE/'accounts.json').read_text())
    cert = x509.load_pem_x509_certificate((base.STATE/'ingress/server.crt').read_bytes())
    spki = base64.b64encode(hashlib.sha256(cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).digest()).decode()
    receipt = OUT/'browser-results.json'
    results = json.loads(receipt.read_text())['passed'] if args.resume_enrolled or args.confirm_first_login else []
    enrollment = 'DHI startup, SPI/theme, OIDC code + PKCE S256 and fresh MFA enrollment'
    base.require(not args.resume_enrolled or results == [enrollment], 'Fresh enrollment receipt required to resume')
    def passed(s):
        results.append(s)
        receipt.write_text(json.dumps({'passed': results}, indent=2))
        print('PASS '+s, flush=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',
            headless=True, args=[f'--host-resolver-rules=MAP {base.PORTAL_HOST} 127.0.0.1, MAP {base.AUTH_HOST} 127.0.0.1',
                                '--ignore-certificate-errors-spki-list='+spki, '--no-proxy-server', '--disable-background-networking'])
        theme = []
        class Pages:
            def new_page(self):
                page = browser.new_page()
                page.on('response', lambda r: theme.append(True) if '/zerotrust/' in urlsplit(r.url).path and r.status == 200 else None)
                return page
        pages = Pages()
        try:
            if args.confirm_first_login:
                page, tokens, stage = b.login(pages, accounts['student_a'])
                base.require(stage == 'enrollment', 'Second student was already enrolled')
                student_scores(b, tokens['access_token'], 0)
                passed('Second STUDENT sees own scores immediately after fresh MFA enrollment')
                page.context.close()
                return
            page, tokens, stage = b.login(pages, accounts['student_b'])
            expected_stage = 'verified OTP' if args.resume_enrolled else 'enrollment'
            base.require(stage == expected_stage, 'Unexpected student MFA stage')
            base.require(theme, 'ZeroTrust theme resource not loaded')
            if not args.resume_enrolled:
                passed(enrollment)
            last_window = int(time.time())//30
            token = tokens['access_token']
            student_scores(b, token, 1)
            base.require(b.request(base.PORTAL_HOST, '/api/admin/student-classes', token=token)[0] == 403,
                         'Student crossed ADMIN boundary')
            passed('Candidate issuer/JWT, STUDENT own scores and ADMIN denial over strict TLS')
            page.get_by_role('button', name='Đăng xuất', exact=True).click()
            page.get_by_role('button', name='Đăng nhập với Keycloak').wait_for(timeout=25000)
            page.context.close()
            admin, admin_tokens, _ = b.login(pages, accounts['admin'])
            token = admin_tokens['access_token']
            path = '/api/admin/student-classes'
            base.require(b.request(base.PORTAL_HOST, path, token=token)[0] == 200, 'ADMIN read failed')
            base.require(b.request(base.PORTAL_HOST, path, method='POST', token=token)[0] == 403, 'ADMIN write allowed')
            admin.context.close()
            passed('ADMIN reads academic data and cannot write')
            base.require(b.login(pages, accounts['student_b'], wrong_otp=True) == 'wrong OTP rejected', 'Wrong OTP accepted')
            passed('Wrong OTP rejected')
            while int(time.time())//30 <= last_window or int(time.time())%30 >= 25:
                time.sleep(0.5)
            page, _, stage = b.login(pages, accounts['student_b'])
            base.require(stage == 'verified OTP', 'Correct OTP failed')
            cookies = [c for c in page.context.cookies() if c['name'] == 'ZT_DEVICE_ID']
            base.require(len(cookies) == 1 and cookies[0]['httpOnly'] and cookies[0]['secure'], 'Device cookie flags failed')
            rows = b.mysql('SELECT COUNT(*) FROM pd_staging_risk.known_devices').stdout.strip()
            base.require(int(rows) > 0, 'Risk did not register trusted device')
            passed('Correct OTP, secure device cookie and Risk device registration')
            page.context.close()
            risk = owned('risk')
            subprocess.run(['docker', 'stop', '--time', '30', risk], check=True, capture_output=True)
            try:
                page = pages.new_page()
                issued = []
                page.on('response', lambda r: issued.append(True) if r.status == 200 and
                        urlsplit(r.url).path.endswith('/openid-connect/token') else None)
                b.begin(page, accounts['student_a'])
                page.locator('#kc-error-message, #input-error').first.wait_for(timeout=18000)
                base.require(urlsplit(page.url).hostname == base.AUTH_HOST and not issued, 'Risk outage issued a token')
                passed('SPI fails closed while candidate Risk service is unavailable')
                page.context.close()
            finally:
                subprocess.run(['docker', 'start', risk], check=True, capture_output=True)
        finally:
            browser.close()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('Candidate browser stopped: '+(str(error) if type(error) is RuntimeError else type(error).__name__)) from None
