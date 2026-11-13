"""Private MaxMind acquisition, pair staging, diagnostics and atomic release pointer.

Never copies Lab MMDBs, logs credentials/presigned URLs, or alters a running Risk
image. Deployment/restart remains an explicit isolated-controller operation.
"""
import argparse
import base64
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import uuid
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request,build_opener,HTTPSHandler,HTTPRedirectHandler,ProxyHandler
import ssl
import operate as full

PRIVATE=full.OUT/'geoip-private'
DATA=PRIVATE/'data'
EVIDENCE=full.OUT/'phase21a'
EDITIONS=('GeoLite2-City','GeoLite2-ASN')
REDIRECT_HOST='mm-prod-geoip-databases.a2649acb697e2c09b632799562c076f2.r2.cloudflarestorage.com'


def credentials():
    values={}
    raw=(PRIVATE/'GeoIP.conf').read_bytes()
    full.check(len(raw)<=8192,'Unexpected private configuration size')
    encoding='utf-16' if raw[:2] in (b'\xff\xfe',b'\xfe\xff') else 'utf-8-sig'
    names={'accountid':'AccountID','licensekey':'LicenseKey','editionids':'EditionIDs'}
    for line in raw.decode(encoding).splitlines():
        match=re.fullmatch(r'\s*(AccountID|LicenseKey|EditionIDs)(?:\s*[=:]\s*|\s+)(.*?)\s*',line,re.I)
        if match:values[names[match[1].lower()]]=match[2].strip().strip('\"\x27')
    full.check(values.get('AccountID','').isdigit() and bool(values.get('LicenseKey')),'Owner AccountID/LicenseKey not yet supplied in the private file')
    full.check(set(values.get('EditionIDs','').split())==set(EDITIONS),'Only City/ASN editions are in scope')
    return values


class SafeRedirect(HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        target=urlsplit(newurl)
        full.check(target.scheme=='https' and target.hostname in ('download.maxmind.com',REDIRECT_HOST)
                   and not target.username and not target.password and target.port in (None,443),'Unexpected download redirect')
        new=super().redirect_request(req,fp,code,msg,headers,newurl)
        new.remove_header('Authorization')
        return new


def fetch_bytes(edition,suffix,cfg,limit):
    url='https://download.maxmind.com/geoip/databases/'+edition+'/download?suffix='+suffix
    request=Request(url,headers={'User-Agent':'ZeroTrust academic private GeoIP updater'})
    # unredirected headers prevent the account/key reaching the R2 download host.
    request.add_unredirected_header('Authorization','Basic '+base64.b64encode((cfg['AccountID']+':'+cfg['LicenseKey']).encode()).decode())
    context=ssl.create_default_context();context.minimum_version=ssl.TLSVersion.TLSv1_2
    opener=build_opener(ProxyHandler({}),HTTPSHandler(context=context),SafeRedirect())
    try:
        with opener.open(request,timeout=90) as response:
            data=response.read(limit+1)
            full.check(0<len(data)<=limit,'Unexpected download size')
            return data
    except HTTPError as e:raise RuntimeError('Official MaxMind download HTTP '+str(e.code)+'; credentials/URL withheld') from None
    except Exception as e:
        if type(e) is RuntimeError:raise
        raise RuntimeError('Official download failed: '+type(e).__name__+'; URL/credentials withheld') from None


def probe(folder,as_of=None):
    if as_of is not None:as_of=dt.datetime.fromisoformat(as_of).isoformat()
    tools=EVIDENCE/'probe';classes=tools/'classes';libs=tools/'lib'
    if not libs.exists():
        tools.mkdir(parents=True,exist_ok=True);classes.mkdir();libs.mkdir()
        raw=subprocess.run(['docker','cp','zt-full-function-phase2-locking-risk:/app/application.jar','-'],capture_output=True,check=True).stdout
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:data=archive.extractfile(archive.getmembers()[0]).read()
        import zipfile
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for name in archive.namelist():
                if name.startswith('BOOT-INF/lib/') and name.endswith('.jar'):target=libs/Path(name).name
                elif name.startswith('BOOT-INF/classes/') and not name.endswith('/'):
                    target=classes/name.removeprefix('BOOT-INF/classes/');target.parent.mkdir(parents=True,exist_ok=True)
                else:continue
                target.write_bytes(archive.read(name))
    output=EVIDENCE/('probe-'+uuid.uuid4().hex+'.json')
    result=full.run('docker','run','--rm','--network','none','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','1g',
        '--mount',f'type=bind,source={full.HERE},target=/source,readonly',
        '--mount',f'type=bind,source={tools},target=/probe',
        '--mount',f'type=bind,source={folder},target=/geoip,readonly',
        '--mount',f'type=bind,source={EVIDENCE},target=/results',
        '--entrypoint','sh','zt-full-function/browser:20261111-1','-ec',
        'javac -encoding UTF-8 -cp "/probe/classes:/probe/lib/*" -d /probe/classes /source/GeoIpProbe.java && java -Xmx640m -cp "/probe/classes:/probe/lib/*" GeoIpProbe /geoip /results/'+output.name+(' '+as_of if as_of else ''),timeout=180,check=False)
    full.check(result.returncode==0,'Real database validation/probe failed; no activation; sensitive output withheld')
    return json.loads(output.read_text(encoding='utf-8')),output


def fetch():
    cfg=credentials();DATA.mkdir(parents=True,exist_ok=True);EVIDENCE.mkdir(exist_ok=True)
    stage=DATA/('staging-'+uuid.uuid4().hex);stage.mkdir(mode=0o700)
    receipt={'provider':'MaxMind GeoLite2','downloaded_at':dt.datetime.now(dt.timezone.utc).isoformat(),
        'official_source':'https://download.maxmind.com/geoip/databases/','transport':'TLS verified; Basic auth only initial origin; no request-time web service',
        'license':'Owner MaxMind account / GeoLite EULA; datasets not redistributed','files':{}}
    for edition in EDITIONS:
        archive=fetch_bytes(edition,'tar.gz',cfg,200*1024*1024)
        checksum=fetch_bytes(edition,'tar.gz.sha256',cfg,4096).decode('ascii').strip()
        expected=re.search(r'\b[0-9a-fA-F]{64}\b',checksum)
        full.check(expected and hashlib.sha256(archive).hexdigest()==expected[0].lower(),'Official archive checksum mismatch')
        with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as tar:
            matches=[m for m in tar.getmembers() if m.isfile() and Path(m.name).name==edition+'.mmdb']
            full.check(len(matches)==1 and matches[0].size<200*1024*1024,'Unexpected archive MMDB layout')
            data=tar.extractfile(matches[0]).read()
            (stage/(edition+'.mmdb')).write_bytes(data)
            for member in tar.getmembers():
                if member.isfile() and Path(member.name).name.upper() in ('LICENSE.TXT','COPYRIGHT.TXT') and member.size<65536:
                    (stage/(edition+'-'+Path(member.name).name)).write_bytes(tar.extractfile(member).read())
        receipt['files'][edition]={'archive_sha256':expected[0].lower(),'mmdb_sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
        print('PASS official verified HTTPS/checksum acquisition: '+edition,flush=True)
    diagnostics,proof=probe(stage);receipt['metadata']={k:diagnostics[k] for k in ('city','asn')}
    release=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+hashlib.sha256(json.dumps(receipt['files'],sort_keys=True).encode()).hexdigest()[:12]
    receipt['release']=release;receipt['probe_evidence']=proof.name
    (stage/'manifest.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    releases=DATA/'releases';releases.mkdir(exist_ok=True);os.replace(stage,releases/release)
    (EVIDENCE/'acquisition.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    print('PASS staged real pair '+release+'; running profile unchanged',flush=True)


def activate(release):
    full.check(re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}',release),'Invalid release name')
    folder=DATA/'releases'/release
    full.check(folder.resolve().parent==(DATA/'releases').resolve() and not folder.is_symlink(),'Unexpected release path')
    manifest=json.loads((folder/'manifest.json').read_text())
    full.check(manifest.get('release')==release and set(manifest.get('files',{}))==set(EDITIONS),'Incomplete/mismatched dataset manifest')
    for edition,f in manifest['files'].items():
        path=folder/(edition+'.mmdb')
        full.check(not path.is_symlink() and path.is_file() and 0<path.stat().st_size<=200*1024*1024,'Invalid dataset file')
        full.check(hashlib.sha256(path.read_bytes()).hexdigest()==f['mmdb_sha256'],'Staged data drift')
    probe(folder)
    pointer=DATA/'current.json';old=json.loads(pointer.read_text()) if pointer.exists() else None
    new={'release':release,'previous_release':(old.get('previous_release') if old.get('release')==release else old.get('release')) if old else None,'changed_at':dt.datetime.now(dt.timezone.utc).isoformat(),
         'scope':'private data selection only; loaded in-memory Risk readers require controlled isolated restart'}
    temp=DATA/('pointer-'+uuid.uuid4().hex+'.tmp');temp.write_text(json.dumps(new,indent=2)+'\n');os.replace(temp,pointer)
    print('PASS atomic verified pair pointer; no running Risk/image/config changed',flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('check-credentials','fetch','status','activate','rollback'));p.add_argument('--release')
    args=p.parse_args();EVIDENCE.mkdir(exist_ok=True)
    if args.action=='check-credentials':credentials();print('PASS private credentials populated; values withheld')
    elif args.action=='fetch':fetch()
    elif args.action=='activate':activate(args.release or '')
    elif args.action=='rollback':
        old=json.loads((DATA/'current.json').read_text());full.check(old.get('previous_release'),'No previous verified release');activate(old['previous_release'])
    else:
        pointer=json.loads((DATA/'current.json').read_text());diagnostic,_=probe(DATA/'releases'/pointer['release'])
        print(json.dumps({'status':'PASS','release':pointer['release'],'city':diagnostic['city'],'asn':diagnostic['asn'],'raw_credentials_output':False}))


if __name__=='__main__':
    try:main()
    except Exception as e:
        reason=str(e) if type(e) is RuntimeError else type(e).__name__
        print('BLOCKED '+reason,flush=True);raise SystemExit(1)
