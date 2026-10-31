"""Host data-only tests. Never installs/executes a downloaded distribution."""
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import python_inputs as inputs


class Response(io.BytesIO):
    status = 200

    def __init__(self, data, url):
        super().__init__(data)
        self.url = url

    def geturl(self):
        return self.url


class InputTests(unittest.TestCase):
    def fixture(self, root):
        locks = root/'locks'
        locks.mkdir()
        for name in ['python-inputs.lock.json', 'requirements-build.lock', 'requirements-qiling.lock', 'requirements-speakeasy.lock']:
            (locks/name).write_bytes((inputs.HERE/name).read_bytes())
        requirements = root/'requirements'
        for name in ['emulation/requirements-qiling.txt', 're-analysis/requirements.txt']:
            path = requirements/name
            path.parent.mkdir(exist_ok=True, parents=True)
            path.write_bytes((inputs.HERE.parents[1]/name).read_bytes())
        return requirements, locks

    def test_all_committed_versions_and_single_artifact_hashes_are_exact(self):
        components, profiles = inputs.load()
        self.assertEqual(len(components), 52)
        self.assertEqual(set(profiles), {'build', 'qiling', 'speakeasy'})
        self.assertEqual(profiles['build'], ['setuptools==80.9.0', 'wheel==0.45.1'])
        self.assertEqual(len(profiles['qiling']), 39)
        self.assertEqual(len(profiles['speakeasy']), 15)
        for engine in ['qiling', 'speakeasy']:
            artifacts = inputs.selected_artifacts(components, profiles, engine)
            self.assertEqual(len(artifacts), len(set(profiles[engine] + inputs.BUILD)))
        with self.assertRaises(ValueError):
            inputs.selected_artifacts(components, profiles, 'rnidbg')

    def test_requirement_drift_unpinned_urls_duplicate_versions_and_hash_changes_fail(self):
        for change in ['qiling==1.4.7\n', 'qiling>=1.4.6\n', 'https://untrusted.invalid/a.whl\n', 'qiling==1.4.6\nqiling==1.4.6\n', 'qiling==1.4.6\nqiling==1.4.5\n']:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root, locks = self.fixture(Path(directory))
                (root/'emulation/requirements-qiling.txt').write_text(change)
                with self.assertRaises(ValueError):
                    inputs.load(root, locks)
        with tempfile.TemporaryDirectory() as directory:
            root, locks = self.fixture(Path(directory))
            path = locks/'requirements-qiling.lock'
            path.write_text(path.read_text().replace('--hash=sha256:', '--hash=sha256:0', 1))
            with self.assertRaisesRegex(ValueError, 'differs'):
                inputs.load(root, locks)

    def test_inventory_rejects_extra_missing_duplicate_scope_and_schema_fields(self):
        changes = [lambda v: v.update(schemaVersion=True), lambda v: v.update(profile='any-host'),
                   lambda v: v.update(extra=True), lambda v: v['components'].pop('wheel==0.45.1'),
                   lambda v: v['components'].update({'unreviewed==1.0':{}})]
        for change in changes:
            with tempfile.TemporaryDirectory() as directory:
                root, locks = self.fixture(Path(directory))
                path = locks/'python-inputs.lock.json'
                value = json.loads(path.read_text())
                change(value)
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    inputs.load(root, locks)
        with tempfile.TemporaryDirectory() as directory:
            root, locks = self.fixture(Path(directory))
            path = locks/'python-inputs.lock.json'
            path.write_text(path.read_text().replace('{', '{"schemaVersion":1,', 1))
            with self.assertRaisesRegex(ValueError, 'Duplicate'):
                inputs.load(root, locks)

    def test_origin_redirect_paths_integrity_and_budgets_are_strict(self):
        components, _ = inputs.load()
        good = components['wheel==0.45.1']['install']
        for changes in [{'bytes':True}, {'bytes':0}, {'bytes':inputs.MAX_FILE+1}, {'sha256':'A'*64},
                        {'filename':'../outside.whl'}, {'url':good['url']+'?token=not-allowed'},
                        {'url':good['url'].replace('https:', 'http:')},
                        {'url':good['url'].replace('files.pythonhosted.org', 'files.pythonhosted.org.evil.invalid')},
                        {'url':good['url'].replace('/packages/', '/packages/%2e%2e/')}, {'extra':True}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                inputs.artifact({**good, **changes})

    def owned(self):
        data = b'owned archive-shaped data; never execute\n'
        artifact = {'filename':'owned-1.0-py3-none-any.whl',
                    'url':'https://files.pythonhosted.org/packages/owned/owned-1.0-py3-none-any.whl',
                    'bytes':len(data), 'sha256':hashlib.sha256(data).hexdigest()}
        return data, artifact

    def test_fetch_verifies_actual_bytes_before_exclusive_publication_and_never_reuses(self):
        data, artifact = self.owned()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'new'
            observed = []
            def opener(request, timeout):
                observed.append((request.full_url, timeout))
                return Response(data, artifact['url'])
            with patch.object(inputs, 'selected_artifacts', return_value=[artifact]):
                self.assertEqual(inputs.fetch({}, {}, 'qiling', output, opener), 1)
                self.assertEqual((output/artifact['filename']).read_bytes(), data)
                self.assertEqual(list(output.glob('*.part')), [])
                with self.assertRaises(FileExistsError):
                    inputs.fetch({}, {}, 'qiling', output, opener)
            self.assertEqual(observed, [(artifact['url'], 30)])

    def test_fetch_refuses_wrong_hash_truncation_growth_and_redirect_before_publication(self):
        data, artifact = self.owned()
        for body, target, status in [(data[:-1], artifact['url'], 200), (b'x'*len(data), artifact['url'], 200),
                                     (data+b'x', artifact['url'], 200), (data, 'https://evil.invalid/a', 200),
                                     (data, artifact['url'], 206)]:
            with self.subTest(target=target, status=status), tempfile.TemporaryDirectory() as directory:
                output = Path(directory)/'new'
                def opener(*args, **kwargs):
                    response = Response(body, target)
                    response.status = status
                    return response
                with patch.object(inputs, 'selected_artifacts', return_value=[artifact]), self.assertRaises(ValueError):
                    inputs.fetch({}, {}, 'qiling', output, opener)
                self.assertFalse((output/artifact['filename']).exists())
                self.assertTrue((output/(artifact['filename']+'.part')).exists())

    def test_acquisition_deadline_retains_partial_data_without_publication(self):
        data, artifact = self.owned()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'new'
            with patch.object(inputs, 'selected_artifacts', return_value=[artifact]), \
                 patch.object(inputs.time, 'monotonic', side_effect=[0,0,0,0,121]), \
                 self.assertRaisesRegex(ValueError, 'deadline'):
                inputs.fetch({}, {}, 'qiling', output, lambda *args, **kwargs: Response(data, artifact['url']))
            self.assertFalse((output/artifact['filename']).exists())
            self.assertTrue((output/(artifact['filename']+'.part')).exists())

    def test_default_downloader_refuses_redirects_before_following_any_destination(self):
        handler = inputs.NoRedirect()
        request = inputs.urllib.request.Request('https://files.pythonhosted.org/packages/owned/archive.zip')
        for target in ['https://evil.invalid/archive.zip', 'http://127.0.0.1/internal',
                       'https://files.pythonhosted.org/packages/other/archive.zip']:
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, 'redirect refused'):
                handler.redirect_request(request, None, 302, 'Moved', {}, target)
        with patch.object(inputs.urllib.request, 'build_opener') as build:
            response = object()
            build.return_value.open.return_value = response
            self.assertIs(inputs.open_artifact(request, 30), response)
            self.assertIsInstance(build.call_args.args[0], inputs.NoRedirect)
            build.return_value.open.assert_called_once_with(request, timeout=30)

    def test_duplicate_artifact_filenames_fail_without_creating_output(self):
        _, artifact = self.owned()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'new'
            with patch.object(inputs, 'selected_artifacts', return_value=[artifact, copy.deepcopy(artifact)]), self.assertRaises(ValueError):
                inputs.fetch({}, {}, 'qiling', output)
            self.assertFalse(output.exists())

    def test_builder_uses_local_hashes_and_pinned_build_tools_not_index_build_resolution(self):
        source = (inputs.HERE/'prepare.py').read_text()
        self.assertIn("python_inputs.load(Path('/build'))", source)
        self.assertIn("python_inputs.fetch(components, profiles, engine, archives)", source)
        self.assertEqual(source.count("'--require-hashes'"), 2)
        self.assertEqual(source.count("'--no-cache-dir'"), 2)
        self.assertIn("'--no-build-isolation'", source)
        self.assertIn("'--ignore-installed'", source)
        self.assertIn("'--no-index'", source)
        self.assertIn("'/build/private-python-tools'", source)
        self.assertNotIn("'install', '--no-cache-dir', '-r', requirements", source)


if __name__ == '__main__':
    unittest.main()
