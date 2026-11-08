"""Package only the exact RC images and validated non-secret deployment inputs."""
import argparse
import json
from pathlib import Path
import subprocess
import tarfile

from build import sha
from rc import HERE, ROOT, check, configure


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',required=True,type=Path)
    p.add_argument('--config',default=HERE/'rehearsal.json',type=Path)
    p.add_argument('--project',default='zt-pd-r22')
    p.add_argument('--output',required=True,type=Path)
    a=p.parse_args()
    _,m,_,_=configure(a.config,a.manifest,a.project,allow_production=True)
    out=a.output.resolve()
    out.mkdir(parents=True,exist_ok=False)
    images=out/'app-images.tar'
    subprocess.run(['docker','image','save','--output',str(images),
        *(b['image'] for b in m['builds'].values())],check=True)
    with tarfile.open(images) as archive:
        index=json.load(archive.extractfile('index.json'))
        check({b['id'] for b in m['builds'].values()}<={v['digest'] for v in index['manifests']},
              'Archive image IDs differ from lock')
    extra={p.relative_to(ROOT).as_posix() for p in HERE.iterdir() if p.is_file()
        and p.name in ('README.md','bundle.py','recovery.py','rollback.py','browser.py','measure.py')}
    archive_path=out/'deployment.tar.gz'
    with tarfile.open(archive_path,'x:gz') as archive:
        for name in sorted(set(m['deployment_hashes'])|extra):
            f=ROOT/name
            check(f==f.resolve() and f.is_relative_to(ROOT) and f.is_file(),'Unexpected bundle source')
            archive.add(f,arcname=name,recursive=False)
        archive.add(a.manifest,arcname='release-lock.json',recursive=False)
    registry=out/'registry-images.txt'
    registry.write_text(''.join(ref+'\n' for ref in m['registry']),encoding='ascii')
    (out/'SHA256SUMS').write_text(''.join(f'{sha(f)}  {f.name}\n' for f in (images,archive_path,registry)),encoding='ascii')
    print('PASS bundle image index matches all five app IDs; deployment and four registry inputs hashed.')


if __name__=='__main__':
    main()
