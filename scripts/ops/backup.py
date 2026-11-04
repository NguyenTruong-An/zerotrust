"""Cold backup of the existing lab; never restore into or delete a volume."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

import relocate_runtime as layout
import zt


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    rows = zt.collect()
    errors = zt.diagnose(rows)['errors']
    if errors:
        raise RuntimeError('Lab preflight failed')
    running = {s for s, i in rows.items() if i['State']['Running']}
    if running and running != set(zt.SERVICES):
        raise RuntimeError('Start or stop the whole lab before taking a consistent backup')
    root = zt.ROOT.parent / 'backups' / ('lab-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    layout.secure_directory(root)
    manifest = {'created_utc': dt.datetime.now(dt.timezone.utc).isoformat(), 'status': 'incomplete',
                'project': zt.PROJECT, 'files': {}, 'images': {s: i['Image'] for s, i in rows.items()}}
    try:
        if running:
            subprocess.run([sys.executable, str(zt.ROOT / 'scripts/ops/zt.py'), 'stop'], check=True, stdout=subprocess.DEVNULL)
        stopped = zt.collect()
        layout.require_stopped(stopped)
        if any(stopped[s]['Id'] != rows[s]['Id'] for s in rows):
            raise RuntimeError('Container identities changed')
        runtime = layout.source_root(stopped)
        with tarfile.open(root / 'runtime.tar.gz', 'w:gz') as archive:
            archive.add(runtime, arcname='runtime')
        helper = rows['crl']['Image']
        packer = zt.ROOT / 'scripts/legacy/archive_volume.py'
        for service, suffix in zt.DATA_VOLUMES.items():
            volume = f'{zt.PROJECT}_{suffix}'
            command = ['docker', 'run', '--rm', '--network', 'none', '--read-only',
                       '--entrypoint', '/opt/tools/bin/python',
                       '--mount', f'type=volume,src={volume},dst=/source,readonly',
                       '--mount', f'type=bind,src={root},dst=/backup',
                       '--mount', f'type=bind,src={packer},dst=/pack.py,readonly',
                       helper, '/pack.py', 'pack', '/source', f'/backup/{service}.tar.gz']
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
            print(f'Archived {service}', flush=True)
        for path in sorted(root.glob('*.tar.gz')):
            # Read every member to detect compressed-stream truncation/corruption.
            count = 0
            with tarfile.open(path, 'r:gz') as archive:
                for entry in archive:
                    count += 1
                    if entry.isfile():
                        with archive.extractfile(entry) as stream:
                            while stream.read(1024 * 1024):
                                pass
            manifest['files'][path.name] = {'sha256': sha256(path), 'bytes': path.stat().st_size, 'members': count}
        for name in ('compose.lab.yaml',):
            shutil.copy2(zt.ROOT / name, root / name)
        manifest['status'] = 'archive_verified'
        manifest['restore_database_test'] = 'not_performed'
    finally:
        (root / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        if running:
            subprocess.run([sys.executable, str(zt.ROOT / 'scripts/ops/zt.py'), 'start'], check=True)
    print(f'Backup: {root}', flush=True)


if __name__ == '__main__':
    main()
