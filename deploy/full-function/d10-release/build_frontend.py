"""Build only the Phase3 callback fix; retain the sealed Phase2 frontend image."""
import json,shutil,subprocess,sys
from pathlib import Path
from executor import ROOT,need,run,sha,write
OUT=ROOT/'target/d10-phase3-20261113';WORK=OUT/'frontend-build'
def main():
    source=WORK/'frontend';source.mkdir(parents=True,exist_ok=True)
    for p in (ROOT/'frontend').rglob('*'):
        rel=p.relative_to(ROOT/'frontend')
        if p.is_symlink() or any(part in ('node_modules','.next','.git','dist') or part.startswith('.env') for part in rel.parts):continue
        if p.is_file():q=source/rel;q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,q)
    recipe=(ROOT/'deploy/docker/Dockerfile.frontend').read_text().replace('RUN if [ "$RUN_CHECKS" = "true" ]; then npm run check && npm test; fi && npm run build','RUN npm run typecheck && node --test tests/public-demo-ui.test.mjs && npm run build')
    recipe+='\nLABEL io.zerotrust.d10.purpose="phase3-callback-fix"\n';(WORK/'Dockerfile').write_text(recipe,newline='\n')
    image='zt-d10/frontend:phase3-20261113';node='node@sha256:ec318aabf188af4e5488847eea4b24452650b9917140563e140762526a37f1df'
    args=['docker','build','--pull=false','--tag',image,'--build-arg','NODE_IMAGE='+node,'--build-arg','KEYCLOAK_URL=https://auth.full-function.test:39443','--build-arg','KEYCLOAK_REALM=DoAn','--build-arg','KEYCLOAK_CLIENT_ID=zerotrust-spa','--build-arg','API_BASE_URL=','--build-arg','PORTAL_MODE=standard','--build-arg','SITE_URL=https://portal.full-function.test:39443',str(WORK)]
    p=subprocess.run(args,cwd=ROOT,capture_output=True,timeout=600);(OUT/'frontend-build.log').write_bytes(p.stdout+p.stderr);need(p.returncode==0,'FRONTEND_TARGETED_BUILD_FAILED')
    write(OUT/'frontend-artifact.json',{'image':image,'id':run('docker','image','inspect','--format','{{.Id}}',image).decode().strip(),'node_image':node,'node':'24.22.2','npm':'11.21.2','tests':'typecheck +12 component tests + production build','reason':'fresh action proof must return directly to /admin/users; exact same-origin redirect added to planned SPA configuration'})
    print('PASS Phase3 frontend targeted checks and production image; old Phase2 image retained')
if __name__=='__main__':
    try:main()
    except Exception as e:print('FAIL '+(str(e) if isinstance(e,RuntimeError) else type(e).__name__),file=sys.stderr);sys.exit(1)
