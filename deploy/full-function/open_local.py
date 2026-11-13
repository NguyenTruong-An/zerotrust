"""Prepare/launch ONLY the new private Firefox profile, with normal CA validation."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes
import operate as full


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--launch',action='store_true')
    parser.add_argument('--verify',action='store_true')
    args=parser.parse_args()
    full.check((full.STATE/'installed').is_file(),'New full-function profile is not installed')
    profile=full.STATE/'owner-firefox'
    ca=x509.load_pem_x509_certificate((full.STATE/'ca.crt').read_bytes())
    identity={'project':full.PROJECT,'ca_sha256':ca.fingerprint(hashes.SHA256()).hex()}
    marker=profile/'full-function-owner.json'
    if marker.exists():full.check(json.loads(marker.read_text())==identity,'Private browser belongs to another CA/project')
    else:
        full.check(not profile.exists(),'Do not reuse another browser profile')
        profile.mkdir(mode=0o700)
        cmd=['docker','run','--rm','--network','none','--cap-drop','ALL',
             '--mount',f'type=bind,source={profile},target=/profile',
             '--mount',f'type=bind,source={full.STATE/"ca.crt"},target=/ca.crt,readonly',
             '--entrypoint','sh','zt-full-function/browser:20261111-1','-ec',
             'certutil -N --empty-password -d sql:/profile; certutil -A -d sql:/profile -n full-function-ca -t C,, -i /ca.crt']
        full.run(*cmd)
        marker.write_text(json.dumps(identity,indent=2)+'\n')
    prefs={'network.dns.localDomains':','.join((full.PORTAL_HOST,full.AUTH_HOST,'crl.full-function.test')),
           'network.proxy.type':0,'browser.shell.checkDefaultBrowser':False,'browser.startup.homepage_override.mstone':'ignore',
           'datareporting.policy.dataSubmissionEnabled':False,'toolkit.telemetry.enabled':False}
    (profile/'user.js').write_text(''.join('user_pref('+json.dumps(k)+', '+json.dumps(v)+');\n' for k,v in prefs.items()),encoding='utf-8')
    os.environ['PLAYWRIGHT_BROWSERS_PATH']=str(full.OUT/'browser-tools')
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        executable=Path(p.firefox.executable_path)
        full.check(executable.is_file(),'Install the pinned private Firefox tools first')
        if args.verify:
            context=p.firefox.launch_persistent_context(str(profile),headless=True,ignore_https_errors=False,firefox_user_prefs=prefs)
            page=context.new_page()
            response=page.goto('https://'+full.PORTAL_HOST+':39443')
            full.check(response.status==200,'Firefox normal TLS/hostname trust failed')
            auth=page.goto('https://'+full.AUTH_HOST+':39443/realms/DoAn/.well-known/openid-configuration')
            full.check(auth.status==200 and json.loads(auth.text())['issuer']=='https://'+full.AUTH_HOST+':39443/realms/DoAn','Firefox Auth issuer/TLS failed')
            context.close()
            (full.OUT/'owner-browser.json').write_text(json.dumps({'status':'PASS','normal_CA_TLS':True,'hostname_mapping':'private Firefox profile only','TLS_ignore_flags':False,'Windows_root_modified':False},indent=2)+'\n')
            print('PASS private owner Firefox: normal CA/hostname TLS, Portal/Auth DoAn, no TLS exception or system trust change')
        if args.launch:
            subprocess.Popen([str(executable),'-no-remote','-new-instance','-profile',str(profile),'https://'+full.PORTAL_HOST+':39443'],
                             stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            print('Opened only the isolated full-function Firefox profile; no login or secret entered')
    if os.name=='nt':
        launcher=full.OUT/'Open-Full-Function.cmd'
        launcher.write_text('@echo off\r\n"'+sys.executable+'" -B "'+str(Path(__file__).resolve())+'" --launch\r\n',encoding='utf-8',newline='')
        viewer=full.OUT/'Open-Admin-Credentials.cmd'
        viewer.write_text('@echo off\r\necho Opening the private ADMIN window. Please wait...\r\n"'+sys.executable+'" -B "'+str(full.HERE/'show_account.py')+'" --account admin\r\nif errorlevel 1 pause\r\n',encoding='utf-8',newline='')


if __name__=='__main__':main()
