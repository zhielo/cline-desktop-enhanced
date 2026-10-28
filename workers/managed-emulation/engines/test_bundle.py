"""No emulator or downloaded executable runs in these host parser tests."""
import hashlib
import importlib.util
import json
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
                for change in [{'checks':counts[engine]-1},{'architectures':[]},{'engineReadiness':'ready'},{'vmIsolation':'attested'},{'bundleSha256':'x'*64},{'extra':True}]:
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


if __name__ == '__main__':
    unittest.main()
