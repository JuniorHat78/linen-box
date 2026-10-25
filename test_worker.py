import contextlib
import argparse
import base64
import io
import json
import os
from pathlib import Path
import tarfile
import shutil
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from cryptography.exceptions import InvalidTag
import sealed
import worker
from artifact_io import extract_export


class Contracts(unittest.TestCase):
    def test_live_progress_is_encrypted_and_unchanged_snapshots_are_not_repeated(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);output=root/'output';output.mkdir();key=os.urandom(32)
            (output/'progress.json').write_text(json.dumps({'private':'metric canary'}))
            args=argparse.Namespace(repo='owner/repo',tag='r'+'a'*24)
            identity=dict(tag=args.tag,shard=0,run='123',attempt='1');calls=[]
            publish=worker.progress_export(args,root,output,key,identity,'input-digest')
            with patch.object(worker,'gh',side_effect=lambda *a:calls.append(a)):
                publish();publish()
            self.assertEqual(len(calls),1)
            for item in calls[0][3:5]:
                self.assertNotIn(b'metric canary',Path(item).read_bytes())
            box=root/'progress-000-123-1-0001.box'
            sealed.unseal(box,root/'recovered.tar.gz',key)
            manifest=sealed.extract_checked(root/'recovered.tar.gz',root/'recovered')
            self.assertEqual(manifest['identity'],identity)
            self.assertEqual(json.loads((root/'recovered/progress.json').read_text())['private'],'metric canary')

    def test_progress_callback_preserves_private_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);output=root/'output';output.mkdir()
            script=root/'entry.py';script.write_text('import time; time.sleep(.15)')
            calls=[]
            self.assertEqual(worker.execute(script,root,output,0,worker.child_environment(root),3,
                lambda:calls.append(1),.03),0)
            self.assertTrue(calls)

    def test_roundtrip_and_tampering(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'source'
            source.write_bytes(b'private workload canary\0' * 1000)
            key = os.urandom(32)
            box = root / 'input.box'
            sealed.seal(source, box, key)
            self.assertNotIn(b'private workload canary', box.read_bytes())
            sealed.unseal(box, root / 'recovered', key)
            self.assertEqual(source.read_bytes(), (root / 'recovered').read_bytes())
            data = bytearray(box.read_bytes())
            data[-17] ^= 1
            box.write_bytes(data)
            with self.assertRaises(InvalidTag):
                sealed.unseal(box, root / 'corrupt', key)
            self.assertFalse((root / 'corrupt').exists())
            self.assertFalse((root / 'corrupt.partial').exists())

    def test_wrong_key(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'a').write_bytes(b'payload')
            sealed.seal(root / 'a', root / 'b', os.urandom(32))
            with self.assertRaises(InvalidTag):
                sealed.unseal(root / 'b', root / 'c', os.urandom(32))

    def test_archive_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'src'
            source.mkdir()
            (source / 'entry.py').write_text('pass')
            sealed.pack_checked(source, root / 'a.tar.gz', {'entry': 'entry.py'})
            self.assertEqual(sealed.extract_checked(root / 'a.tar.gz', root / 'dest')['entry'], 'entry.py')
            (source / 'entry.py').write_text('changed')
            with tarfile.open(root / 'bad.tar.gz', 'w:gz') as tar:
                for p in source.iterdir():
                    tar.add(p, arcname=p.name)
            with self.assertRaisesRegex(ValueError, 'digest'):
                sealed.extract_checked(root / 'bad.tar.gz', root / 'bad')

    def test_unsafe_archives(self):
        for name, kind in [('../escape', tarfile.REGTYPE), ('/escape', tarfile.REGTYPE),
                           ('x\\escape', tarfile.REGTYPE), ('C:escape', tarfile.REGTYPE),
                           ('link', tarfile.SYMTYPE), ('hard', tarfile.LNKTYPE)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                with tarfile.open(root / 'bad.tar.gz', 'w:gz') as tar:
                    item = tarfile.TarInfo(name)
                    item.type = kind
                    item.linkname = '../escape'
                    tar.addfile(item, io.BytesIO())
                with self.assertRaisesRegex(ValueError, 'Unsafe'):
                    sealed.extract_checked(root / 'bad.tar.gz', root / 'out')

    def test_environment_contains_no_provider_credentials(self):
        with patch.dict(os.environ, {'BOX_KEY': 'canary', 'GH_TOKEN': 'canary',
                'GITHUB_TOKEN': 'canary', 'UNEXPECTED_SECRET': 'canary', 'PATH': 'bin'}):
            env = worker.child_environment('private-home')
            self.assertNotIn('canary', env.values())
            self.assertEqual(env['PATH'], 'bin')

    def test_private_stdout_and_stderr(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / 'output'
            output.mkdir()
            script = root / 'entry.py'
            script.write_text("import sys; print('private canary'); print('private error', file=sys.stderr); raise ValueError('private exception')")
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                code = worker.execute(script, root, output, 0, worker.child_environment(root), 20)
            self.assertNotEqual(code, 0)
            self.assertEqual(captured.getvalue(), '')
            self.assertIn('private exception', (output / 'execution.log').read_text())

    def test_artifact_exports_only_sealed_bytes_and_receipts(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'payload';source.mkdir()
            (source/'entry.py').write_text("print('private artifact canary')")
            tag='r'+'a'*24;key=os.urandom(32)
            sealed.pack_checked(source,root/'input.tar.gz',
                {'job_tag':tag,'shards':1,'entry':'entry.py','timeout_seconds':20})
            sealed.seal(root/'input.tar.gz',root/'input.box',key)
            def fetch(repo,job,name,target):shutil.copyfile(root/'input.box',target)
            args=argparse.Namespace(repo='owner/repo',tag=tag,shard=0,out=root/'work',transport='artifact')
            with patch.dict(os.environ,{'BOX_KEY':base64.b64encode(key).decode(),
                    'GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1'}),patch.object(worker,'fetch',fetch),\
                    patch.object(worker,'gh',side_effect=AssertionError('No release API calls')):
                self.assertEqual(worker.run(args),0)
            for kind in ('index','full'):
                files=list((args.out/('export-'+kind)).iterdir())
                self.assertEqual(len(files),2)
                for file in files:
                    self.assertRegex(file.name,r'^result-000-123-1(?:-index)?\.(box|json)$')
                    self.assertNotIn(b'private artifact canary',file.read_bytes())
                    self.assertNotIn(base64.b64encode(key),file.read_bytes())

    def test_artifact_inventory(self):
        stem='result-001-123-1'
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for case,names in enumerate(((stem+'.json',stem+'-index.box'),
                    (stem+'.json','../private'),(stem+'.json','execution.log'),
                    (stem+'.json',stem+'.box','extra'),(stem+'.json',stem+'.json'))):
                archive=root/f'{case}.zip'
                with zipfile.ZipFile(archive,'w') as zipped:
                    for name in names:zipped.writestr(name,b'opaque')
                if case==0:
                    receipt=extract_export(archive,root/'good',stem,'index')
                    self.assertEqual(receipt.read_bytes(),b'opaque')
                else:
                    with self.assertRaises(ValueError):
                        extract_export(archive,root/f'bad-{case}',stem,'index')
                    self.assertFalse((root/f'bad-{case}').exists())

    def test_durable_transport_only_uploads_sealed_result_and_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'payload';source.mkdir();tag='r'+'b'*24;key=os.urandom(32)
            (source/'entry.py').write_text("print('private durable canary')")
            sealed.pack_checked(source,root/'input.tar.gz',dict(job_tag=tag,shards=1,entry='entry.py',timeout_seconds=20))
            sealed.seal(root/'input.tar.gz',root/'input.box',key)
            def fetch(repo,job,name,target):shutil.copyfile(root/'input.box',target)
            args=argparse.Namespace(repo='owner/repo',tag=tag,shard=0,out=root/'work',transport='both')
            with patch.dict(os.environ,{'BOX_KEY':base64.b64encode(key).decode(),'GITHUB_RUN_ID':'124','GITHUB_RUN_ATTEMPT':'1'}),\
                 patch.object(worker,'fetch',fetch),patch.object(worker,'gh') as upload:
                self.assertEqual(worker.run(args),0)
            call=upload.call_args.args
            self.assertEqual(call[:3],('release','upload',tag));self.assertEqual(call[-2:],('--repo','owner/repo'))
            for name in call[3:-2]:
                self.assertIn(Path(name).suffix,('.box','.json'))
                self.assertNotIn(b'private durable canary',Path(name).read_bytes())
            self.assertTrue((args.out/'export-full').is_dir())


if __name__ == '__main__':
    unittest.main()
