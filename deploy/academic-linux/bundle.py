"""Package exact local app images and the source files in a reviewed Linux release lock."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile

from linux_demo import IMAGE_PINS, ROOT, activate, base, check, compose_contract, load_config, read_lock


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f,'sha256').hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',required=True,type=Path)
    p.add_argument('--manifest',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path)
    args=p.parse_args()
    c=load_config(args.config)
    activate(c)
    compose_contract(c)
    base.verify_boundary()
    manifest=read_lock(c,args.manifest)
    target=args.output.absolute()
    check(target==target.resolve() and not target.exists(),'Bundle output must be a new directory')
    target.mkdir(mode=0o700,parents=True)
    app_images=[ref for ref in manifest['images'] if '@sha256:' not in ref]
    images=target/'app-images.tar'
    subprocess.run(['docker','image','save','--output',str(images),*app_images],cwd=ROOT,check=True)
    with tarfile.open(images) as t:
        index=json.load(t.extractfile('index.json'))
        listed={v['digest'] for v in index['manifests']}
        check({manifest['images'][ref] for ref in app_images}<=listed,'Image archive differs from lock')
    extras=['deploy/academic-linux/'+n for n in ('README.md','smoke.py','backup.py','production.example.json','rehearsal.example.json')]
    deployment=target/'deployment.tar.gz'
    with tarfile.open(deployment,'x:gz') as t:
        for name in sorted(set(manifest['source_hashes'])|set(extras)):
            f=ROOT/name
            check(f==f.resolve() and f.is_relative_to(ROOT) and f.is_file(),'Invalid bundle input')
            t.add(f,arcname=name,recursive=False)
        t.add(args.manifest,arcname='release-lock.json',recursive=False)
    entries={f.name:sha(f) for f in (images,deployment)}
    (target/'SHA256SUMS').write_text(''.join(f'{digest}  {name}\n' for name,digest in entries.items()),encoding='ascii')
    (target/'registry-images.txt').write_text(''.join(ref+'\n' for ref in IMAGE_PINS if '@sha256:' in ref),encoding='ascii')
    print('Transfer bundle written: five exact local images, deployment files and SHA256SUMS.')


if __name__=='__main__':
    try:
        main()
    except (RuntimeError,ValueError,OSError,KeyError,subprocess.SubprocessError) as error:
        detail=str(error) if type(error) is RuntimeError else type(error).__name__
        raise SystemExit('Bundle stopped: '+detail) from None
