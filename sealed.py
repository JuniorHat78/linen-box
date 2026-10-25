"""Authenticated file boxes and strictly inventoried archives."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b'CBX1\r\n'
AAD = b'opaque-worker/archive/v1'
MAX_BYTES = 2 * 1024**3


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''):
            digest.update(block)
    return digest.hexdigest()


def seal(source, destination, key):
    if len(key) != 32 or Path(source).stat().st_size > MAX_BYTES:
        raise ValueError('Invalid box parameters')
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    cipher.authenticate_additional_data(AAD)
    with Path(source).open('rb') as stream, Path(destination).open('xb') as out:
        out.write(MAGIC + nonce)
        for block in iter(lambda: stream.read(1024**2), b''):
            out.write(cipher.update(block))
        out.write(cipher.finalize())
        out.write(cipher.tag)


def unseal(source, destination, key):
    source, destination = Path(source), Path(destination)
    size = source.stat().st_size
    if len(key) != 32 or not len(MAGIC) + 28 <= size <= MAX_BYTES + len(MAGIC) + 28:
        raise ValueError('Invalid box parameters')
    temporary = destination.with_name(destination.name + '.partial')
    try:
        with source.open('rb') as stream, temporary.open('xb') as out:
            if stream.read(len(MAGIC)) != MAGIC:
                raise ValueError('Invalid box header')
            nonce = stream.read(12)
            stream.seek(-16, 2)
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, stream.read(16))).decryptor()
            cipher.authenticate_additional_data(AAD)
            stream.seek(len(MAGIC) + 12)
            remaining = size - len(MAGIC) - 28
            while remaining:
                block = stream.read(min(1024**2, remaining))
                if not block:
                    raise ValueError('Truncated box')
                out.write(cipher.update(block))
                remaining -= len(block)
            out.write(cipher.finalize())
        if destination.exists():
            raise FileExistsError('Refusing replacement')
        temporary.rename(destination)
    finally:
        temporary.unlink(missing_ok=True)


def extract_checked(archive_path, destination):
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    names = set()
    with tarfile.open(archive_path, 'r:gz') as archive:
        members = archive.getmembers()
        if len(members) > 10000 or sum(m.size for m in members) > MAX_BYTES:
            raise ValueError('Archive exceeds limits')
        for member in members:
            relative = PurePosixPath(member.name)
            target = destination.joinpath(*relative.parts)
            if (not member.isfile() or relative.is_absolute() or '..' in relative.parts
                    or '\\' in member.name or ':' in member.name or member.name in names
                    or not target.resolve().is_relative_to(destination)):
                raise ValueError('Unsafe archive member')
            names.add(member.name)
        for member in members:
            target = destination.joinpath(*PurePosixPath(member.name).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source, target.open('xb') as out:
                shutil.copyfileobj(source, out, 1024**2)
    manifest = json.loads((destination / 'bundle.json').read_text())
    if manifest.get('schema') != 1 or set(manifest['files']) | {'bundle.json'} != names:
        raise ValueError('Inventory mismatch')
    for name, digest in manifest['files'].items():
        if sha(destination / name) != digest:
            raise ValueError('File digest mismatch')
    return manifest


def pack_checked(directory, destination, metadata=None):
    directory = Path(directory).resolve()
    files = sorted(p for p in directory.rglob('*') if p.is_file() and p.name != 'bundle.json')
    if any(p.is_symlink() or not p.resolve().is_relative_to(directory) for p in files):
        raise ValueError('Unsafe input file')
    manifest = {'schema': 1, 'files': {p.relative_to(directory).as_posix(): sha(p) for p in files},
                **(metadata or {})}
    (directory / 'bundle.json').write_text(json.dumps(manifest, sort_keys=True), encoding='utf-8')
    with tarfile.open(destination, 'x:gz') as archive:
        for path in [*files, directory / 'bundle.json']:
            archive.add(path, arcname=path.relative_to(directory).as_posix(), recursive=False)
    return manifest
