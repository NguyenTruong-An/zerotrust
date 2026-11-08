"""Explicit local artifact encryption/decryption using age. No backup collection, scheduling or network.
No child output, key contents, paths or parser causes are logged. Never overwrite an existing artifact.
"""
import os
import re
import stat
import subprocess
import uuid
from pathlib import Path


def _check(valid):
    if not valid:
        raise ValueError("Backup cryptographic operation rejected (values and paths redacted)")


def _run(executable, arguments, output):
    output = Path(output)
    _check(not output.exists() and output.parent.is_dir())
    partial = output.with_name(output.name+".partial-"+uuid.uuid4().hex)
    fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        result = subprocess.run([str(executable), *map(str, arguments)], stdin=subprocess.DEVNULL, stdout=stream,
                                stderr=subprocess.PIPE, timeout=60,
                                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        stream.flush()
        os.fsync(stream.fileno())
    _check(result.returncode == 0)
    # A successful operation publishes without overwriting, even across a concurrent writer race.
    # Partial/quarantine artifacts stay private; cleanup is outside this task's no-delete scope.
    os.link(partial, output)


def encrypt(executable, source, recipients, output):
    try:
        source, recipients, output = map(Path, (source, recipients, output))
        _check(source.is_file() and not source.is_symlink() and output.suffix == ".age")
        _check(recipients.is_file() and not recipients.is_symlink() and recipients.stat().st_size <= 4096)
        values = recipients.read_text(encoding="utf-8").splitlines()
        _check(1 <= len(values) <= 2 and len(set(values)) == len(values))
        _check(all(re.fullmatch(r"age1[0-9a-z]{58}", line) for line in values))
        _check(output.resolve() != source.resolve())
        _run(executable, ["-R", recipients, source], output)
    except Exception:
        raise ValueError("Backup encryption rejected (values and paths redacted)") from None


def decrypt(executable, source, identity, output):
    try:
        source, identity, output = map(Path, (source, identity, output))
        _check(source.is_file() and not source.is_symlink() and identity.is_file() and not identity.is_symlink())
        _check(source.parent.resolve() not in identity.resolve().parents)  # Decryption key outside backup tree.
        if os.name == "posix":
            _check(stat.S_IMODE(identity.stat().st_mode) & 0o077 == 0)
        _check(output.resolve() != source.resolve())
        _run(executable, ["-d", "-i", identity, source], output)
    except Exception:
        raise ValueError("Backup decryption rejected (values and paths redacted)") from None
