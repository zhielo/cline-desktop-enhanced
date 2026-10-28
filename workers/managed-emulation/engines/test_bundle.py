"""No emulator or downloaded executable runs in these host parser tests."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import prepare
import selftest
sys.path.insert(0,str(HERE.parent/'image'))
from smoke_boot import validate_engine_log
from build_image import Node, owned_bundle


class BundleTests(unittest.TestCase):
    def fixture(self, root, engine='qiling'):
        (root/'engine').write_text(engine+'\n')
        (root/'fixed.py').write_text('owned bytes, never execute\n')
        value = prepare.manifest(root,engine)
        (root/'bundle.json').write_text(json.dumps(value,sort_keys=True,separators=(',',':')))
        return value

    def test_manifest_hashes_actual_bytes_and_rejects_mutation_or_extra_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);value=self.fixture(root)
            self.assertEqual(value['files']['fixed.py']['sha256'],hashlib.sha256((root/'fixed.py').read_bytes()).hexdigest())
            with patch.object(selftest,'ROOT',root):
                self.assertEqual(selftest.verify_bundle()[0],'qiling')
                (root/'fixed.py').write_text('changed')
                with self.assertRaises(ValueError):selftest.verify_bundle()
                (root/'fixed.py').write_text('owned bytes, never execute\n')
                (root/'extra').write_text('unexpected')
                with self.assertRaises(ValueError):selftest.verify_bundle()

    def test_all_four_profiles_and_duplicate_manifest_fields_fail_closed(self):
        for engine in prepare.ENGINES:
            with self.subTest(engine=engine),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);self.fixture(root,engine)
                with patch.object(selftest,'ROOT',root):
                    self.assertEqual(selftest.verify_bundle()[0],engine)
                    raw=(root/'bundle.json').read_text()
                    (root/'bundle.json').write_text(raw.replace('{','{"schema":1,',1))
                    with self.assertRaises(ValueError):selftest.verify_bundle()

    def test_receipts_require_exact_engine_full_architecture_checks_and_scope(self):
        counts={'qiling':12,'unidbg':10,'rnidbg':5,'speakeasy':4}
        for engine,arches in selftest.ARCHES.items():
            value={'schema':1,'engine':engine,'architectures':arches,'checks':counts[engine],'bundleSha256':'a'*64,'ownedFixtures':'passed','engineReadiness':'not-tested','vmIsolation':'not-attested'}
            def data(v):return ('CLINE_MANAGED_ENGINE_OWNED_V1 '+json.dumps(v)+'\n').encode()
            with self.subTest(engine=engine):
                self.assertEqual(validate_engine_log(data(value),engine),value)
                self.assertEqual(validate_engine_log(data(value),engine,'a'*64),value)
                with self.assertRaises(ValueError):validate_engine_log(data(value),engine,'b'*64)
                for change in [{'schema':True},{'checks':float(counts[engine])},{'checks':counts[engine]-1},{'architectures':[]},{'engineReadiness':'ready'},{'vmIsolation':'attested'},{'bundleSha256':'x'*64},{'extra':True}]:
                    with self.assertRaises(ValueError):validate_engine_log(data({**value,**change}),engine)
                with self.assertRaises(ValueError):validate_engine_log(data(value)+data(value),engine)
                with self.assertRaises(ValueError):validate_engine_log(data(value)+b'CLINE_MANAGED_ENGINE_FAILED_V1\n',engine)
                duplicate=data(value).replace(b'{',b'{"schema":1,',1)
                with self.assertRaises(ValueError):validate_engine_log(duplicate,engine)

    def test_unknown_engine_and_bad_relative_manifest_path_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with self.assertRaises(ValueError):prepare.manifest(root,'unknown')
            value=self.fixture(root);value['files']['../outside']={'kind':'file','size':0,'sha256':'0'*64}
            (root/'bundle.json').write_text(json.dumps(value))
            with patch.object(selftest,'ROOT',root),self.assertRaises(ValueError):selftest.verify_bundle()

    def test_export_cannot_replace_the_fixed_owned_acceptance_source(self):
        engine='qiling';prefix='opt/cline-engine/'
        source=(HERE/'selftest.py').read_bytes()
        runner=(HERE.parents[1]/'emulation/qiling_runner.py').read_bytes()
        value={'schema':1,'engine':engine,'scope':'development-owned-guest-tests-only','files':{
            'selftest.py':{'kind':'file','size':len(source),'sha256':hashlib.sha256(source).hexdigest()},
            'qiling_runner.py':{'kind':'file','size':len(runner),'sha256':hashlib.sha256(runner).hexdigest()}}}
        original={prefix+'bundle.json':Node('file',0o644,json.dumps(value).encode()),prefix+'engine':Node('file',0o644,b'qiling\n'),
            prefix+'selftest.py':Node('file',0o644,source),prefix+'qiling_runner.py':Node('file',0o644,runner),prefix+'env/bin/python':Node('symlink',0o777,b'/usr/local/bin/python3.13')}
        for label,node in original.items():
            relative=label[len(prefix):]
            if relative == 'bundle.json': continue
            value['files'][relative]=({'kind':'file','size':len(node.data),'sha256':hashlib.sha256(node.data).hexdigest()}
                if node.kind == 'file' else {'kind':'symlink','target':node.data.decode()})
        original[prefix+'bundle.json']=Node('file',0o644,json.dumps(value).encode())
        self.assertEqual(set(owned_bundle(original,engine)),set(original))
        extra={**original,prefix+'unsealed':Node('file',0o644,b'extra')}
        with self.assertRaises(ValueError):owned_bundle(extra,engine)
        for label,change in [('engine',{'size':True}),('selftest.py',{'sha256':'0'*64}),('env/bin/python',{'target':'/tmp/unsealed-python'})]:
            damaged=json.loads(json.dumps(value));damaged['files'][label].update(change)
            tree={**original,prefix+'bundle.json':Node('file',0o644,json.dumps(damaged).encode())}
            with self.assertRaises(ValueError):owned_bundle(tree,engine)
        changed={**original,prefix+'selftest.py':Node('file',0o644,b'print("fake success")')}
        value['files']['selftest.py']['sha256']=hashlib.sha256(b'print("fake success")').hexdigest()
        changed[prefix+'bundle.json']=Node('file',0o644,json.dumps(value).encode())
        with self.assertRaises(ValueError):owned_bundle(changed,engine)


    def test_file_size_and_entry_types_are_strict_before_reading(self):
        for entry in [None, [], {'kind':'file','size':True,'sha256':'0'*64},
                      {'kind':'file','size':1.0,'sha256':'0'*64},
                      {'kind':'file','size':-1,'sha256':'0'*64},
                      {'kind':'file','size':64*1024**2+1,'sha256':'0'*64},
                      {'kind':'file','size':0,'sha256':[]},
                      {'kind':'file','size':0,'sha256':'A'*64}]:
            with self.subTest(entry=entry),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);value=self.fixture(root)
                value['files']['fixed.py']=entry
                (root/'bundle.json').write_text(json.dumps(value))
                with patch.object(selftest,'ROOT',root),self.assertRaises(ValueError):selftest.verify_bundle()

    @unittest.skipUnless(hasattr(os,'mkfifo'), 'Linux guest file types')
    def test_special_files_manifest_links_and_oversized_manifests_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.fixture(root)
            with patch.object(selftest,'ROOT',root):
                os.mkfifo(root/'pipe')
                with self.assertRaises(ValueError):selftest.verify_bundle()
                (root/'pipe').unlink()
                saved=(root/'bundle.json').read_bytes()
                (root/'outside').write_bytes(saved)
                (root/'bundle.json').unlink();(root/'bundle.json').symlink_to(root/'outside')
                with self.assertRaises(OSError):selftest.verify_bundle()
                (root/'bundle.json').unlink()
                with (root/'bundle.json').open('wb') as stream: stream.truncate(4*1024**2+1)
                with self.assertRaises(ValueError):selftest.verify_bundle()

    def test_aggregate_budget_is_checked_before_the_next_file_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.fixture(root)
            read=selftest.regular_bytes
            with patch.object(selftest,'ROOT',root),patch.object(selftest,'MAX_BUNDLE_BYTES',5),patch.object(selftest,'regular_bytes',wraps=read) as observed:
                with self.assertRaises(ValueError):selftest.verify_bundle()
                # engine (7 bytes) already exceeds the test budget, before any
                # manifest-listed file is opened for content verification.
                self.assertEqual([call.args[0].name for call in observed.call_args_list],['bundle.json','engine'])

    def test_symlink_target_schema_and_file_link_substitution_are_refused(self):
        for target in [None,[],True,'','x'*1025,'bad\x00target']:
            with self.subTest(target=target),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);self.fixture(root)
                (root/'link').symlink_to('fixed.py')
                (root/'bundle.json').unlink()
                value=prepare.manifest(root,'qiling');value['files']['link']['target']=target
                (root/'bundle.json').write_text(json.dumps(value))
                with patch.object(selftest,'ROOT',root),self.assertRaises(ValueError):selftest.verify_bundle()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.fixture(root)
            (root/'fixed.py').unlink();(root/'fixed.py').symlink_to('engine')
            with patch.object(selftest,'ROOT',root),self.assertRaises(ValueError):selftest.verify_bundle()



if __name__ == '__main__':
    unittest.main()
