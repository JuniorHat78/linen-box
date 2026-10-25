"""Execute one shard of a sealed, owner-supplied offline workload.

Only ciphertext, opaque identities and generic execution receipts leave here.
Workload stdout, stderr, exception text, plans and results stay in sealed output.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import traceback
from urllib.request import Request, urlopen

from sealed import MAX_BYTES, extract_checked, pack_checked, seal, sha, unseal
from artifact_io import extract_export


def child_environment(directory):
    # An allowlist avoids passing newly introduced provider secrets by accident.
    names = ('PATH', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'LANG', 'LC_ALL',
             'LD_LIBRARY_PATH', 'SSL_CERT_FILE', 'SSL_CERT_DIR')
    env = {name: os.environ[name] for name in names if name in os.environ}
    private_home = str(Path(directory).resolve())
    env.update(HOME=private_home, USERPROFILE=private_home, TMPDIR=private_home,
               TEMP=private_home, TMP=private_home, PYTHONUNBUFFERED='1',
               OPENBLAS_NUM_THREADS='1', OMP_NUM_THREADS='1', MKL_NUM_THREADS='1')
    return env


def gh(*args):
    process = subprocess.run(['gh', *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=300, check=False)
    if process.returncode:
        raise RuntimeError('Transport failed')
    return process.stdout


def fetch(repo, tag, name, target, expected=None):
    url = f'https://github.com/{repo}/releases/download/{tag}/{name}'
    with urlopen(Request(url, headers={'User-Agent': 'opaque-worker/1'}), timeout=120) as response:
        total = 0
        with Path(target).open('xb') as out:
            while block := response.read(1024**2):
                total += len(block)
                if total > MAX_BYTES + 64:
                    raise ValueError('Transport size limit')
                out.write(block)
    if expected and sha(target) != expected:
        raise ValueError('Transport digest mismatch')


def fetch_artifact(repo, item, target):
    artifact_id = item['artifact_id']
    if type(artifact_id) is not int or artifact_id <= 0:
        raise ValueError('Invalid artifact identity')
    archive = target.with_suffix('.zip')
    with archive.open('xb') as output:
        process = subprocess.run(['gh', 'api', f'repos/{repo}/actions/artifacts/{artifact_id}/zip'],
            stdout=output, stderr=subprocess.PIPE, timeout=300)
    if process.returncode or archive.stat().st_size > MAX_BYTES + 1024**2:
        raise ValueError('Artifact transport failed')
    stem = item['asset'].removesuffix('.box')
    directory = target.with_suffix('.export')
    extract_export(archive, directory, stem, 'full')
    source = directory / item['asset']
    if sha(source) != item['sha256']:
        raise ValueError('Artifact digest differs')
    shutil.copyfile(source, target)


def execute(entry, runtime, output, shard, env, seconds, progress=None, progress_seconds=180):
    command = [sys.executable, '-u', str(entry), '--output', str(output), '--shard', str(shard)]
    with (output / 'execution.log').open('wb') as log:
        process = subprocess.Popen(command, cwd=runtime, env=env, stdout=log, stderr=log,
                                   start_new_session=os.name != 'nt')
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            try:
                return process.wait(timeout=min(progress_seconds if progress else seconds,max(.001,deadline-time.monotonic())))
            except subprocess.TimeoutExpired:
                if progress and time.monotonic()<deadline:
                    try:progress()
                    except Exception:
                        # Diagnostic transport must never expose private errors
                        # in public logs or kill a healthy training process.
                        with (output/'progress-error.txt').open('a',encoding='utf8') as f:f.write(traceback.format_exc())
        if process.poll() is None:
            if os.name == 'nt':
                subprocess.run(['taskkill', '/F', '/T', '/PID', str(process.pid)],
                               stdout=log, stderr=log, timeout=30)
            else:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=30)
            return 124
        return process.returncode


def progress_export(args,root,output,key,identity,input_digest):
    source=output/'progress.json';sequence=0;last=None
    def publish():
        nonlocal sequence,last
        if not source.is_file() or source.is_symlink() or source.stat().st_size>2*1024**2:return
        data=source.read_bytes();digest=hashlib.sha256(data).hexdigest()
        if digest==last:return
        json.loads(data)  # Reject torn or non-JSON progress; producer uses atomic rename.
        sequence+=1;directory=root/f'progress-{sequence:04d}';directory.mkdir()
        (directory/'progress.json').write_bytes(data)
        name=f"progress-{identity['shard']:03d}-{identity['run']}-{identity['attempt']}-{sequence:04d}"
        archive=root/(name+'.tar.gz');box=root/(name+'.box');receipt=root/(name+'.json')
        pack_checked(directory,archive,dict(identity=identity,input_cipher_sha256=input_digest,status='running'))
        seal(archive,box,key)
        receipt.write_text(json.dumps(dict(schema=1,**identity,status='running',sequence=sequence,
            input_cipher_sha256=input_digest,asset=box.name,output_cipher_sha256=sha(box))),encoding='utf8')
        gh('release','upload',args.tag,str(box),str(receipt),'--repo',args.repo)
        last=digest
    return publish


def run(args):
    if (not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repo)
            or not re.fullmatch(r'r[0-9a-f]{24}', args.tag)
            or not 0 <= args.shard < 256):
        raise ValueError('Invalid job identity')
    key = base64.b64decode(os.environ['BOX_KEY'], validate=True)
    if len(key) != 32:
        raise ValueError('Invalid key')
    root = args.out.resolve()
    root.mkdir(parents=True, exist_ok=False)
    output = root / 'output'
    output.mkdir()
    status = 'failed'
    started = time.monotonic()
    identity = {'tag': args.tag, 'shard': args.shard, 'run': os.environ.get('GITHUB_RUN_ID', 'local'),
                'attempt': os.environ.get('GITHUB_RUN_ATTEMPT', '1')}
    input_digest = None
    try:
        fetch(args.repo, args.tag, 'input.box', root / 'input.box')
        input_digest = sha(root / 'input.box')
        unseal(root / 'input.box', root / 'input.tar.gz', key)
        runtime = root / 'runtime'
        bundle = extract_checked(root / 'input.tar.gz', runtime)
        if bundle.get('job_tag') != args.tag or not args.shard < bundle.get('shards', 0):
            raise ValueError('Encrypted workload identity differs')
        inputs = bundle.get('inputs_by_shard', [])
        for index, item in enumerate(inputs[args.shard] if inputs else []):
            if (not re.fullmatch(r'r[0-9a-f]{24}', item['tag'])
                    or not re.fullmatch(r'[A-Za-z0-9_.-]+', item['asset'])
                    or not re.fullmatch(r'[a-z0-9_-]+', item['label'])):
                raise ValueError('Invalid sealed input identity')
            encrypted_input = root / f'attachment-{index}.box'
            if 'artifact_id' in item:
                fetch_artifact(args.repo, item, encrypted_input)
            else:
                fetch(args.repo, item['tag'], item['asset'], encrypted_input, item['sha256'])
            input_archive = root / f'attachment-{index}.tar.gz'
            unseal(encrypted_input, input_archive, key)
            recovered = extract_checked(input_archive, runtime / 'inputs' / item['label'])
            if recovered.get('identity') != item['identity']:
                raise ValueError('Authenticated attached input differs')
        entry = bundle['entry']
        if entry not in bundle['files'] or not entry.endswith('.py'):
            raise ValueError('Missing entry')
        seconds = bundle['timeout_seconds']
        if type(seconds) is not int or not 1 <= seconds <= 18000:
            raise ValueError('Invalid timeout')
        env_home = root / 'home'
        env_home.mkdir()
        progress=None;interval=bundle.get('progress_seconds',180)
        if 'progress_seconds' in bundle:
            if type(interval) is not int or not 60<=interval<=1800 or args.transport not in ('release','both'):
                raise ValueError('Invalid live progress transport')
            progress=progress_export(args,root,output,key,identity,input_digest)
        code = execute(runtime / entry, runtime, output, args.shard,
                       child_environment(env_home), seconds,progress,interval)
        (output / 'worker-private.json').write_text(json.dumps({**identity,
            'input_cipher_sha256': input_digest, 'returncode': code,
            'seconds': time.monotonic() - started, 'cpu_count': os.cpu_count()}), encoding='utf-8')
        status = 'succeeded' if code == 0 else 'failed'
    except Exception:
        (output / 'worker-error.txt').write_text(traceback.format_exc(), encoding='utf-8')
    pack_checked(output, root / 'output.tar.gz', {'identity': identity,
                 'input_cipher_sha256': input_digest, 'status': status})
    name = f"result-{args.shard:03d}-{identity['run']}-{identity['attempt']}"
    encrypted = root / (name + '.box')
    seal(root / 'output.tar.gz', encrypted, key)
    index_metadata = {}
    index_box = None
    if (output / 'index').is_dir():
        pack_checked(output / 'index', root / 'index.tar.gz', {'identity': identity,
                     'input_cipher_sha256': input_digest, 'status': status})
        index_box = root / (name + '-index.box')
        seal(root / 'index.tar.gz', index_box, key)
        index_metadata = {'index_asset': index_box.name, 'index_cipher_sha256': sha(index_box)}
    # Do not overwrite another attempt; collection verifies the sealed identity.
    receipt = root / (name + '.json')
    receipt.write_text(json.dumps({'schema': 1, **identity, 'status': status,
        'input_cipher_sha256': input_digest, 'output_cipher_sha256': sha(encrypted),
        'asset': encrypted.name, **index_metadata}), encoding='utf-8')
    if args.transport in ('artifact','both'):
        # Export an explicit allowlist only. Workload files and logs cannot
        # enter the public artifact unless already authenticated and encrypted.
        for kind, box in (('index', index_box or encrypted), ('full', encrypted)):
            destination = root / ('export-' + kind)
            destination.mkdir()
            shutil.copyfile(box, destination / box.name)
            shutil.copyfile(receipt, destination / receipt.name)
    if args.transport in ('release','both'):
        assets = ([str(index_box)] if index_box else []) + [str(encrypted), str(receipt)]
        gh('release', 'upload', args.tag, *assets, '--repo', args.repo)
    print(json.dumps({'shard': args.shard, 'status': status}), flush=True)
    return 0 if status == 'succeeded' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--shard', type=int, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--transport', choices=('release', 'artifact','both'), default='release')
    args = parser.parse_args()
    try:
        return run(args)
    except Exception:
        # Never expose private exception messages or tracebacks to public logs.
        print('Worker transport failed; inspect the sealed receipt if available.', flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
