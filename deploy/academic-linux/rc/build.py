"""Build each Academic Demo RC application image from canonical source."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from linux_demo import NODE, ROOT, check, image_id, load_config, run

DHI = '44b3665b60304cb4448e3ab9943ab02727ee793c2ec4b954d2de2ee84f28b892'
IMAGES = ('keycloak', 'backend', 'risk', 'gateway', 'frontend')
MODULES = {'backend':'.', 'risk':'risk-scoring-service', 'gateway':'gateway'}
PORT = 34443
PORTAL = f'https://portal.pd-r22.test:{PORT}'
AUTH = f'https://auth.pd-r22.test:{PORT}'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def inputs(service):
    shared = ('.dockerignore','.mvn','mvnw','pom.xml')
    paths = {
        'keycloak':(*shared,'keycloak-risk-extension','keycloak-theme/zerotrust','deploy/academic-linux/rc/Dockerfile.keycloak-dhi'),
        'frontend':('.dockerignore','frontend','deploy/docker/Dockerfile.frontend'),
        'backend':(*shared,'src','deploy/docker/Dockerfile.java','deploy/demo/Health.java'),
        'risk':(*shared,'risk-scoring-service','deploy/docker/Dockerfile.java','deploy/demo/Health.java','deploy/demo/Migrate.java',
                'deploy/legacy/InspectRisk.java','deploy/legacy/MigrateLegacyRisk.java'),
        'gateway':(*shared,'gateway','deploy/docker/Dockerfile.java','deploy/demo/Health.java'),
    }[service]
    files=run('git','ls-files','--cached','--others','--exclude-standard','--',*paths).stdout.splitlines()
    return {name:sha(ROOT/name) for name in sorted(set(files))}


def dhi_context(oci):
    if oci is None:
        return f'docker-image://dhi.io/keycloak@sha256:{DHI}'
    oci=oci.resolve()
    refs=json.loads((oci/'index.json').read_text())['manifests']
    check(len(refs)==1 and refs[0]['digest']=='sha256:'+DHI,'OCI index does not identify the reviewed DHI base')
    blob=oci/'blobs/sha256'
    check(sha(blob/DHI)==DHI,'OCI manifest hash mismatch')
    manifest=json.loads((blob/DHI).read_text())
    for item in [manifest['config'],*manifest['layers']]:
        digest=item['digest'].removeprefix('sha256:')
        check(sha(blob/digest)==digest,'OCI blob hash mismatch')
    tag=refs[0]['annotations']['org.opencontainers.image.ref.name']
    return f'oci-layout://{oci}:{tag}'


def build(service, release, output, oci, config=None):
    ref=f'zt-pd-r22/{service}:{release}'
    receipt=output/(service+'.json')
    check(image_id(ref) is None and not receipt.exists(),'Use a new release ID for a changed build')
    files=inputs(service)
    revision=run('git','rev-parse','HEAD').stdout.strip()
    snapshot=hashlib.sha256(json.dumps(files,sort_keys=True).encode()).hexdigest()
    args={'SOURCE_REVISION':revision,'SOURCE_SNAPSHOT':snapshot}
    extra=[]
    if service=='keycloak':
        recipe=HERE/'Dockerfile.keycloak-dhi'
        extra=['--build-context','dhi_base='+dhi_context(oci)]
    elif service=='frontend':
        recipe=ROOT/'deploy/docker/Dockerfile.frontend'
        args.update(NODE_IMAGE=NODE, KEYCLOAK_URL=config['auth_url'] if config else AUTH, KEYCLOAK_REALM='academic-demo',
            KEYCLOAK_CLIENT_ID='zerotrust-spa', API_BASE_URL='', PORTAL_MODE='public-demo',
            SITE_URL=config['portal_url'] if config else PORTAL, RUN_CHECKS='true')
    else:
        recipe=ROOT/'deploy/docker/Dockerfile.java'
        args.update(MODULE=MODULES[service],RUN_CHECKS='false')
    cmd=['docker','buildx','build','--platform','linux/amd64','--load','--metadata-file',
        str(output/(service+'-buildkit.json')),'-f',str(recipe),'-t',ref,*extra]
    for key,val in args.items():
        cmd.extend(['--build-arg',f'{key}={val}'])
    subprocess.run([*cmd,'.'],cwd=ROOT,check=True)
    check(inputs(service)==files,'Application source changed during build')
    receipt.write_text(json.dumps({'image':ref,'id':image_id(ref),'revision':revision,
        'snapshot':snapshot,'inputs':files,'build_args':args},indent=2)+'\n')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('services',nargs='+',choices=IMAGES)
    p.add_argument('--release',required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--oci',type=Path,help='Optional local OCI layout for the same exact DHI digest')
    p.add_argument('--config',type=Path,help='Build the frontend for the two hostnames in this configuration')
    a=p.parse_args()
    import re
    check(re.fullmatch(r'rc[0-9]+',a.release),'Use an immutable rcN release identifier')
    a.output.mkdir(parents=True,exist_ok=True)
    config=load_config(a.config) if a.config else None
    for name in a.services:
        build(name,a.release,a.output.resolve(),a.oci,config)
