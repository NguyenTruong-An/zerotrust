"""Build the D-10 frontend (same source/recipe as Phase 3) for the GCP sslip.io hostnames."""
import argparse, json, shutil, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
from common import config, need, sha_file

NODE = 'node@sha256:ec318aabf188af4e5488847eea4b24452650b9917140563e140762526a37f1df'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', type=Path, default=HERE / 'gcp.json')
    c = config(p.parse_args().config)
    out = c['out']; work = out / 'frontend-build'; source = work / 'frontend'
    if work.exists():
        shutil.rmtree(work)
    source.mkdir(parents=True)
    for f in (ROOT / 'frontend').rglob('*'):
        rel = f.relative_to(ROOT / 'frontend')
        if f.is_symlink() or any(part in ('node_modules', '.next', '.git', 'dist') or part.startswith('.env') for part in rel.parts):
            continue
        if f.is_file():
            q = source / rel; q.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(f, q)
    recipe = (ROOT / 'deploy/docker/Dockerfile.frontend').read_text().replace(
        'RUN if [ "$RUN_CHECKS" = "true" ]; then npm run check && npm test; fi && npm run build',
        'RUN npm run typecheck && node --test tests/public-demo-ui.test.mjs && npm run build')
    need('npm run typecheck' in recipe, 'FRONTEND_RECIPE_DRIFT')
    recipe += '\nLABEL io.zerotrust.gcp.purpose="gcp-fast-track-d10"\n'
    (work / 'Dockerfile').write_text(recipe, newline='\n')
    image = c['frontend_image']
    args = ['docker', 'build', '--pull=false', '--tag', image, '--build-arg', 'NODE_IMAGE=' + NODE,
            '--build-arg', 'KEYCLOAK_URL=' + c['auth_url'], '--build-arg', 'KEYCLOAK_REALM=DoAn',
            '--build-arg', 'KEYCLOAK_CLIENT_ID=zerotrust-spa', '--build-arg', 'API_BASE_URL=',
            '--build-arg', 'PORTAL_MODE=standard', '--build-arg', 'SITE_URL=' + c['portal_url'], str(work)]
    r = subprocess.run(args, cwd=ROOT, capture_output=True, timeout=900)
    (out / 'frontend-build.log').write_bytes(r.stdout + r.stderr)
    need(r.returncode == 0, 'FRONTEND_BUILD_FAILED')
    ident = subprocess.run(['docker', 'image', 'inspect', '--format', '{{.Id}}', image], capture_output=True, text=True).stdout.strip()
    (out / 'frontend-artifact.json').write_text(json.dumps({'image': image, 'id': ident, 'node_image': NODE,
        'portal': c['portal_url'], 'auth': c['auth_url'], 'tests': 'typecheck + public-demo-ui tests + production build',
        'source_sha256': {str(k): v for k, v in sorted((p.relative_to(source).as_posix(), sha_file(p)) for p in source.rglob('*') if p.is_file())}}, indent=1) + '\n')
    print('PASS GCP frontend image ' + ident + ' for ' + c['portal_url'])


if __name__ == '__main__':
    main()
