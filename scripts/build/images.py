"""Build lab images from an immutable source archive; never deploy or push."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import sys

ROOT = Path(__file__).resolve().parents[2]
SERVICES = ('backend', 'risk', 'gateway', 'frontend', 'keycloak', 'crl')
INPUT_ROOTS = {'src', 'frontend', 'gateway', 'risk-scoring-service',
               'keycloak-risk-extension', 'keycloak-theme', 'deploy', 'database', '.mvn'}
INPUT_FILES = {'pom.xml', 'mvnw', 'mvnw.cmd', '.dockerignore', '.node-version',
               'compose.build.yaml', 'scripts/build/images.py'}
EXCLUDED_PARTS = {'target', 'node_modules', '.next', '.git', '__pycache__', '.local-legacy'}


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def eligible(name):
    path = PurePosixPath(name)
    return (not path.is_absolute() and '..' not in path.parts
            and (name in INPUT_FILES or path.parts[0] in INPUT_ROOTS)
            and not any(p in EXCLUDED_PARTS or p.startswith('.env') for p in path.parts)
            and '.private.' not in name
            and path.suffix.lower() not in {'.key', '.p12', '.pfx', '.pyc', '.mmdb'})


def source_files(revision=None):
    if revision:
        entries = git('ls-tree', '-r', '-z', revision).decode('utf-8').split('\0')
        committed = dict(entry.split('\t', 1)[::-1] for entry in entries if entry)
        names = committed
    else:
        names = git('ls-files', '-z', '--cached', '--others', '--exclude-standard').decode('utf-8').split('\0')
    files = {}
    for name in sorted(set(filter(None, names))):
        if not eligible(name):
            continue
        if revision:
            if committed[name].split()[0] not in {'100644', '100755'}:
                raise RuntimeError(f'Committed build input is not a regular file: {name}')
            files[name] = git('cat-file', 'blob', f'{revision}:{name}')
            continue
        path = ROOT / name
        if path.is_symlink() or not path.resolve().is_relative_to(ROOT.resolve()):
            raise RuntimeError(f'Build input points outside source: {name}')
        if path.is_file():
            files[name] = path.read_bytes()
    for name in INPUT_FILES:
        if name not in files:
            raise RuntimeError(f'Required build input missing: {name}')
    return files


def archive_bytes(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(files.items()):
            entry = tarfile.TarInfo(name)
            # Maven compares source mtime with a missing destination's zero mtime.
            # A positive fixed epoch keeps archives deterministic and resources copyable.
            entry.size, entry.mode, entry.mtime = len(data), 0o644, 946684800
            archive.addfile(entry, io.BytesIO(data))
    return stream.getvalue()


def build_arguments(model, service):
    build = model['services'][service]['build']
    filename = build['dockerfile']
    if not filename.startswith('deploy/docker/') or '..' in PurePosixPath(filename).parts:
        raise RuntimeError(f'Unsupported Dockerfile: {filename}')
    args = dict(build.get('args', {}))
    if 'RUN_CHECKS' in args and str(args['RUN_CHECKS']).lower() != 'true':
        raise RuntimeError('Standard builds must run checks')
    args['RUN_CHECKS'] = 'true'
    return filename, args


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--service', choices=SERVICES, action='append', help='Repeat to select multiple services; default all six')
    parser.add_argument('--check', action='store_true', help='Dockerfile checks only, no image output')
    parser.add_argument('--committed', action='store_true', help='Use only the committed HEAD bytes')
    options = parser.parse_args(argv)
    revision = git('rev-parse', 'HEAD').decode().strip()
    dirty = not options.committed and bool(git('status', '--porcelain'))
    files = source_files(revision if options.committed else None)
    content = archive_bytes(files)
    if ((not options.committed and files != source_files())
            or revision != git('rev-parse', 'HEAD').decode().strip()):
        raise RuntimeError('Source changed while taking the snapshot; retry after edits finish')
    digest = hashlib.sha256(content).hexdigest()
    model = json.loads(files['compose.build.yaml'])
    version = f'{revision[:12]}-{digest[:12]}-lab'
    output = ROOT / '.build-artifacts' / version
    output.mkdir(parents=True, exist_ok=True)
    archive_path = output / 'context.tar'
    archive_path.write_bytes(content)
    manifest = {'schema': 1, 'created_utc': datetime.now(timezone.utc).isoformat(),
                'revision': revision, 'working_tree_dirty': dirty, 'source_snapshot_sha256': digest,
                'source_mode': 'committed_head' if options.committed else 'working_tree',
                'source_files': {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
                'environment': 'lab', 'version': version, 'check_only': options.check, 'services': {}}
    manifest_path = output / ('check-manifest.json' if options.check else 'build-manifest.json')
    for service in options.service or SERVICES:
        filename, args = build_arguments(model, service)
        tag = f'zerotrust-build/{service}:{version}'
        args.update(SOURCE_REVISION=revision, SOURCE_SNAPSHOT=digest)
        metadata = output / f'{service}.metadata.json'
        log = output / f'{service}{".check" if options.check else ""}.log'
        command = ['docker', 'buildx', 'build', '--progress', 'plain', '--file', filename]
        if options.check:
            command += ['--check']
        else:
            command += ['--load', '--tag', tag, '--metadata-file', str(metadata),
                        '--label', f'org.opencontainers.image.version={version}',
                        '--label', f'io.zerotrust.source.dirty={str(dirty).lower()}']
        for key, value in sorted(args.items()):
            command += ['--build-arg', f'{key}={value}']
        command.append('-')
        print(f'{"Checking" if options.check else "Building"} {service}: {tag}\nLog: {log}', flush=True)
        with archive_path.open('rb') as source, log.open('wb') as log_file:
            result = subprocess.run(command, stdin=source, stdout=log_file, stderr=subprocess.STDOUT)
        record = {'dockerfile': filename, 'build_args': args, 'status': 'passed' if result.returncode == 0 else 'failed'}
        if result.returncode == 0 and not options.check:
            info = json.loads(subprocess.check_output(['docker', 'image', 'inspect', tag]))[0]
            labels = info['Config'].get('Labels') or {}
            if labels.get('org.opencontainers.image.revision') != revision or labels.get('io.zerotrust.source.snapshot') != digest:
                raise RuntimeError(f'{service}: image provenance labels do not match the snapshot')
            record.update(tag=tag, image_id=info['Id'], repo_digests=info.get('RepoDigests', []))
        manifest['services'][service] = record
        manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        if result.returncode:
            print('\n'.join(log.read_text(encoding='utf-8', errors='replace').splitlines()[-45:]), file=sys.stderr)
            raise RuntimeError(f'{service} failed; see {log}')
        print(f'{service}: PASS', flush=True)
    print(f'Manifest: {manifest_path}', flush=True)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        sys.exit(1)
