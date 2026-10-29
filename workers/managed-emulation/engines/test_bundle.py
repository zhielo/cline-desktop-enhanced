"""No emulator or downloaded executable runs in these host parser tests."""
import hashlib
import contextlib
import io
import signal
import subprocess
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import prepare
import selftest
sys.path.insert(0,str(HERE.parent/'image'))
from smoke_boot import validate_engine_log
from build_image import Node, owned_bundle, owned_native_evidence


# Public upstream JNA native ABI checksum; not an API credential.
JNA_ABI_CHECKSUM = "147a998f0cbc89681a1ae6c0dd121629"


class NativeEvidenceTests(unittest.TestCase):
    def fixture(self):
        prefix = "opt/cline-engine/"
        tree = {}
        lock = HERE.parents[1]/"emulation/unidbg/dependencies.sha256"
        originals = {Path(label).name: sha for sha, label in
                     (line.split(maxsplit=1) for line in lock.read_text().splitlines())}
        resources = []
        for jar, label in (
            ("jna-5.10.0.jar", "com/sun/jna/linux-x86-64/libjnidispatch.so"),
            ("unidbg-unicorn2-0.9.9.jar", "natives/linux_64/libunicorn.so"),
        ):
            body = b"data-only owned native placeholder"
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as archive:
                archive.writestr(label, body)
            raw = output.getvalue()
            tree[prefix+"dependency/"+jar] = Node("file", 0o644, raw)
            resources.append({"jar": jar, "resource": label,
                              "originalJarSha256": originals[jar],
                              "rebuiltJarSha256": hashlib.sha256(raw).hexdigest(),
                              "nativeSha256": hashlib.sha256(body).hexdigest()})
        value = {
            "schema": 1, "scope": "development-owned-guest-tests-only",
            "sourceInputs": json.loads((HERE/"native-inputs.lock.json").read_bytes()),
            "patchedBridgeSha256": "a"*64, "patchedJnaSha256": "b"*64,
            "jnaNativeAbi": "6.1.2", "jnaNativeApiChecksum": JNA_ABI_CHECKSUM,
            "resources": resources, "emulatorExecutedDuringBuild": False,
            "engineReadiness": "not-tested",
        }
        return tree, value

    def seal(self, tree, value):
        raw = json.dumps(value).encode()
        tree["opt/cline-engine/native-build.json"] = Node("file", 0o644, raw)
        return raw

    def test_retains_exact_bytes_without_execution_or_readiness_promotion(self):
        tree, record = self.fixture()
        raw = self.seal(tree, record)
        self.assertEqual(owned_native_evidence(tree, "unidbg"), raw)
        self.assertIsNone(owned_native_evidence({}, "qiling"))
        with self.assertRaises(ValueError):
            owned_native_evidence(tree, "qiling")
        with self.assertRaises(ValueError):
            owned_native_evidence({}, "unidbg")

    def test_rejects_scope_schema_budget_duplicate_and_linked_records(self):
        for field, value in (
            ("schema", True), ("scope", "production"), ("engineReadiness", "ready"),
            ("emulatorExecutedDuringBuild", 0), ("extra", "unexpected"),
            ("patchedBridgeSha256", "invalid"), ("jnaNativeAbi", "5.1.0"),
            ("jnaNativeApiChecksum", "0"*32),
        ):
            tree, record = self.fixture()
            record[field] = value
            self.seal(tree, record)
            with self.subTest(field=field), self.assertRaises(ValueError):
                owned_native_evidence(tree, "unidbg")
        tree, record = self.fixture()
        raw = self.seal(tree, record)
        for node in (Node("symlink", 0o777, raw), Node("file", 0o644, b" "*65537),
                     Node("file", 0o644, b'{"schema":1,'+raw[1:])):
            tree["opt/cline-engine/native-build.json"] = node
            with self.assertRaises(ValueError):
                owned_native_evidence(tree, "unidbg")

    def test_requires_exact_locked_source_inputs_and_resource_inventory(self):
        for mutate in (
            lambda r: r["sourceInputs"].update(schema=True),
            lambda r: r["sourceInputs"]["files"][0].update(sha256="c"*64),
            lambda r: r["resources"].pop(),
            lambda r: r["resources"].__setitem__(1, r["resources"][0]),
            lambda r: r["resources"][0].update(jar="../other.jar"),
            lambda r: r["resources"][0].update(resource="wrong.so"),
            lambda r: r["resources"][0].update(originalJarSha256="c"*64),
            lambda r: r["resources"][0].update(nativeSha256="c"*64),
            lambda r: r["resources"][0].update(rebuiltJarSha256="c"*64),
        ):
            tree, record = self.fixture()
            mutate(record)
            self.seal(tree, record)
            with self.assertRaises(ValueError):
                owned_native_evidence(tree, "unidbg")

    def test_compares_sealed_native_resource_not_only_the_generated_manifest(self):
        for body, duplicate in ((b"changed native bytes", False), (b"owned", True)):
            tree, record = self.fixture()
            resource = record["resources"][0]
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as archive:
                archive.writestr(resource["resource"], body)
                if duplicate:
                    import warnings
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", UserWarning)
                        archive.writestr(resource["resource"], body)
            raw = output.getvalue()
            resource["rebuiltJarSha256"] = hashlib.sha256(raw).hexdigest()
            tree["opt/cline-engine/dependency/"+resource["jar"]] = Node("file", 0o644, raw)
            self.seal(tree, record)
            with self.assertRaises(ValueError):
                owned_native_evidence(tree, "unidbg")


class BundleTests(unittest.TestCase):
    def fixture(self, root, engine='qiling'):
        (root/'engine').write_text(engine+'\n')
        (root/'fixed.py').write_text('owned bytes, never execute\n')
        value = prepare.manifest(root,engine)
        (root/'bundle.json').write_text(json.dumps(value,sort_keys=True,separators=(',',':')))
        return value

    def test_owned_jni_refusals_require_exact_reason_and_exit_without_result(self):
        for engine in ('unidbg','rnidbg'):
            for arch in selftest.ARCHES[engine]:
                for case in ('denied','budget','missing'):
                    expected = 76 if case == 'denied' else 75 if case == 'budget' else 1 if engine == 'unidbg' else -signal.SIGABRT
                    stderr = (b'java.lang.IllegalArgumentException: Exact static JNI export required'
                              if engine == 'unidbg' else b"thread main panicked: exact JNI export missing") if case == 'missing' else ('CLINE_UNIDBG_GUARD_V1 '+str(expected)).encode() if engine == 'unidbg' else b''
                    with self.subTest(engine=engine,arch=arch,case=case), tempfile.TemporaryDirectory() as directory:
                        path=Path(directory)/'result.json'
                        result=subprocess.CompletedProcess(['owned-fixture'],expected,b'never print stdout',stderr)
                        selftest.validate_jni_refusal(result,path,engine,arch,case)
                        for code, error in [(0,stderr),(-9,stderr),(137,b'OutOfMemoryError'),(expected,b'unrelated initialization error')]:
                            if code == expected and case != 'missing' and engine != 'unidbg': continue
                            bad=subprocess.CompletedProcess(['owned-fixture'],code,b'never print stdout',error)
                            output=io.StringIO()
                            with contextlib.redirect_stderr(output),self.assertRaisesRegex(ValueError,'JNI refusal/budget boundary'):
                                selftest.validate_jni_refusal(bad,path,engine,arch,case)
                            line=output.getvalue()
                            self.assertNotIn('never print stdout',line)
                            data=json.loads(line.split(' ',1)[1])
                            self.assertEqual((data['engine'],data['architecture'],data['case']),(engine,arch,case))
                            self.assertEqual(data['observedExit'],code)
                            self.assertFalse(data['resultExists'])
                        path.write_text('unexpected result')
                        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(ValueError):
                            selftest.validate_jni_refusal(result,path,engine,arch,case)
                        path.unlink(); path.symlink_to(Path(directory)/'missing-target')
                        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(ValueError):
                            selftest.validate_jni_refusal(result,path,engine,arch,case)

    def test_unidbg_native_callback_uses_stop_not_jvm_exit(self):
        source=(HERE.parents[1]/'emulation/unidbg/src/main/java/ClineRunner.java').read_text()
        callback=source.split('public void hook(Backend b,',1)[1].split('},1,0,null);',1)[0]
        self.assertNotIn('System.exit',callback)
        self.assertIn('guard.stop(b,75);return;',callback)
        self.assertIn('guard.stop(b,76);',callback)
        self.assertIn('backend.emu_stop();',source)
        self.assertIn('if(!guard.failed && guard.code.get()!=0)',source)
        self.assertIn('return withCleanup(emulator,()->{',source)
        self.assertIn('try(AutoCloseable owned=resource) {return action.run();}',source)
        self.assertNotIn('finally {emulator.close();}',source)

    def test_every_owned_unidbg_case_enables_jni_checks_without_relaxing_guards(self):
        commands=[]
        def fake_invoke(command):
            commands.append(command)
            self.assertEqual(command[0],str(selftest.ROOT/'jre/bin/java'))
            self.assertEqual(command.count('-Xcheck:jni'),1)
            self.assertIn('-XX:-CreateCoredumpOnCrash',command)
            self.assertIn('-Xmx256m',command)
            fixture,_,arch,_,_,method,_,result,limit=command[-9:]
            self.assertIn(arch,('arm32','arm64'))
            if Path(fixture).name.startswith('denied-'):
                return subprocess.CompletedProcess(command,76,b'',b'CLINE_UNIDBG_GUARD_V1 76')
            if limit == '1':
                return subprocess.CompletedProcess(command,75,b'',b'CLINE_UNIDBG_GUARD_V1 75')
            if method == 'missing':
                return subprocess.CompletedProcess(command,1,b'',b'java.lang.IllegalArgumentException: Exact static JNI export required')
            Path(result).write_text(json.dumps({'initialized':True,'returnValue':134,'backend':'unicorn2','instructionCount':10}))
            return subprocess.CompletedProcess(command,0,b'',b'')
        with patch.object(selftest,'invoke',side_effect=fake_invoke):
            self.assertEqual(selftest.jni_check('unidbg'),10)
        self.assertEqual(len(commands),10)

    def test_checked_jni_warnings_cannot_pass_with_success_or_guard_exits(self):
        for marker in (b'WARNING in native method:',b'WARNING: JNI local refs:',b'FATAL ERROR in native method:'):
            for code in (0,75,76,1,-6):
                for target in ('stdout','stderr'):
                    with self.subTest(marker=marker,code=code,target=target):
                        values={'stdout':b'', 'stderr':b''};values[target]=marker+b'x'*8000
                        output=io.StringIO()
                        result=subprocess.CompletedProcess([],code,values['stdout'],values['stderr'])
                        with contextlib.redirect_stderr(output),self.assertRaisesRegex(ValueError,'invalid native usage'):
                            selftest.validate_owned_checked_jni(result,'arm64','denied')
                        data=json.loads(output.getvalue().split(' ',1)[1])
                        self.assertEqual(data['observedExit'],code)
                        self.assertLessEqual(len(data['stdoutPrefix']),4096)
                        self.assertLessEqual(len(data['stderrPrefix']),4096)
        with contextlib.redirect_stderr(io.StringIO()) as output:
            for code in (0,75,76,1):
                selftest.validate_owned_checked_jni(subprocess.CompletedProcess([],code,b'',b'SLF4J(W): No SLF4J providers were found.'),'arm32','positive')
            self.assertEqual(output.getvalue(),'')
        with self.assertRaisesRegex(ValueError,'Unknown owned checked JNI profile'):
            selftest.validate_owned_checked_jni(subprocess.CompletedProcess([],0,b'',b''),'x86_64','positive')

    def test_owned_jni_diagnostics_are_bounded_and_unknown_profiles_never_pass(self):
        result=subprocess.CompletedProcess(['owned-fixture'],137,b'never print stdout',b'x'*16000)
        output=io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'result.json'
            with contextlib.redirect_stderr(output),self.assertRaises(ValueError):
                selftest.validate_jni_refusal(result,path,'unidbg','arm64','budget')
            data=json.loads(output.getvalue().split(' ',1)[1])
            self.assertEqual(len(data['stderrTail']),4096)
            self.assertEqual(data['stderrBytes'],16000)
            for engine,arch,case in [('unknown','arm64','budget'),('unidbg','x86_64','budget'),('rnidbg','arm64','unknown')]:
                with self.assertRaisesRegex(ValueError,'Unknown owned JNI refusal profile'):
                    selftest.validate_jni_refusal(result,path,engine,arch,case)

    def test_owned_jvm_fatal_evidence_retained_before_private_directory_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            report=b'# SIGSEGV\n# Problematic frame:\n# C  [libunicorn.so+0x123]\n'
            (root/'hotspot-crash.log').write_bytes(report)
            result=subprocess.CompletedProcess(['never printed argv'],-6,b'owned fatal stdout',b'owned diagnostic')
            output=io.StringIO()
            with contextlib.redirect_stderr(output):
                selftest.owned_jvm_failure_evidence(result,root,'arm64','denied')
            data=json.loads(output.getvalue().split(' ',1)[1])
            self.assertEqual((data['architecture'],data['case'],data['observedExit']),('arm64','denied',-6))
            self.assertEqual(data['hotspot'],{'status':'captured','bytes':len(report),'prefix':report.decode()})
            self.assertEqual(data['stdoutPrefix'],'owned fatal stdout')
            self.assertNotIn('never printed argv',output.getvalue())
            # Collecting a report can never make the failed refusal pass.
            with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(ValueError):
                selftest.validate_jni_refusal(result,root/'result.json','unidbg','arm64','denied')

    def test_owned_jvm_crash_report_and_stdout_prefixes_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'hotspot-crash.log'
            result=subprocess.CompletedProcess([],-6,b'y'*10000,b'')
            path.write_bytes(b'x'*20000)
            output=io.StringIO()
            with contextlib.redirect_stderr(output):
                selftest.owned_jvm_failure_evidence(result,root,'arm32','positive')
            data=json.loads(output.getvalue().split(' ',1)[1])
            self.assertEqual(len(data['hotspot']['prefix']),12288)
            self.assertEqual(data['hotspot']['bytes'],20000)
            self.assertEqual(len(data['stdoutPrefix']),4096)
            self.assertEqual(data['stdoutBytes'],10000)
            with path.open('wb') as stream:stream.truncate(1024*1024+1)
            output=io.StringIO()
            with contextlib.redirect_stderr(output):
                selftest.owned_jvm_failure_evidence(result,root,'arm32','positive')
            self.assertEqual(json.loads(output.getvalue().split(' ',1)[1])['hotspot'],{'status':'byte-budget'})

    def test_owned_jvm_crash_evidence_does_not_follow_links_or_open_special_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'hotspot-crash.log'
            (root/'external').write_text('never read linked bytes')
            result=subprocess.CompletedProcess([],-6,b'',b'')
            for kind in ('absent','link','directory','hardlink','fifo'):
                if kind == 'link':path.symlink_to(root/'external')
                elif kind == 'directory':path.mkdir()
                elif kind == 'hardlink':os.link(root/'external',path)
                elif kind == 'fifo':
                    if not hasattr(os,'mkfifo'):continue
                    os.mkfifo(path)
                output=io.StringIO()
                with contextlib.redirect_stderr(output):
                    selftest.owned_jvm_failure_evidence(result,root,'arm64','missing')
                data=json.loads(output.getvalue().split(' ',1)[1])
                self.assertNotEqual(data['hotspot']['status'],'captured')
                self.assertNotIn('never read linked bytes',output.getvalue())
                if kind == 'directory':path.rmdir()
                elif kind != 'absent':path.unlink()

    def test_unexpected_non_signal_jvm_exit_retains_architecture_and_fatal_evidence(self):
        for arch in ('arm32','arm64'):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                (root/'hotspot-crash.log').write_bytes(b'owned non-signal fatal header')
                (root/'result.json').write_text('never include result bytes')
                result=subprocess.CompletedProcess(['never include argv'],1,b'owned JVM stdout',b'owned stderr')
                with contextlib.redirect_stderr(io.StringIO()) as output:
                    selftest.owned_jvm_failure_evidence(result,root,arch,'positive')
                value=json.loads(output.getvalue().split(' ',1)[1])
                self.assertEqual((value['architecture'],value['case'],value['observedExit']),(arch,'positive',1))
                self.assertEqual(value['stdoutPrefix'],'owned JVM stdout')
                self.assertEqual(value['stderrPrefix'],'owned stderr')
                self.assertTrue(value['resultExists'])
                self.assertEqual(value['hotspot']['status'],'captured')
                self.assertNotIn('never include',output.getvalue())

    def test_owned_jvm_crash_capture_never_reads_reports_on_normal_exit(self):
        with patch.object(selftest.os,'open') as opened,contextlib.redirect_stderr(io.StringIO()) as output:
            for case,code in [('positive',0),('fresh',0),('denied',76),('budget',75),('missing',1)]:
                selftest.owned_jvm_failure_evidence(subprocess.CompletedProcess([],code,b'',b''),Path('/never-open'),'arm64',case)
            opened.assert_not_called()
            self.assertEqual(output.getvalue(),'')
        with self.assertRaisesRegex(ValueError,'Unknown owned JVM failure profile'):
            selftest.owned_jvm_failure_evidence(subprocess.CompletedProcess([],-6,b'',b''),Path('/never-open'),'x86_64','denied')

    def test_builder_probe_uses_the_actual_jlinked_jre_without_engine_dependencies(self):
        result=subprocess.CompletedProcess([],0,b'CLINE_MANAGED_OWNED_JVM_PROBE_V1 passed\n',b'')
        with patch.object(selftest,'invoke',return_value=result) as invoke,contextlib.redirect_stdout(io.StringIO()) as output:
            prepare.verify_private_jre()
        command=invoke.call_args.args[0]
        self.assertEqual(command[0],str(prepare.ROOT/'jre/bin/java'))
        self.assertEqual(command[-3:],['-cp',str(prepare.ROOT/'jvm-probe'),'OwnedJvmProbe'])
        self.assertIn('-Xcheck:jni',command)
        self.assertNotIn('dependency',str(command))
        self.assertNotIn('ClineRunner',command)
        self.assertEqual(invoke.call_count,1)
        value=json.loads(output.getvalue().split(' ',1)[1])
        self.assertFalse(value['engineExecuted'])
        self.assertEqual(value['guestExecution'],'not-tested')
        self.assertEqual(value['engineReadiness'],'not-tested')
        self.assertEqual(value['checks'],4)

    def test_builder_probe_rejects_wrong_exit_output_warning_and_fatal_error(self):
        for code,stdout,stderr in [(1,b'',b'owned JVM initialization error'),(0,b'wrong marker',b''),(0,b'CLINE_MANAGED_OWNED_JVM_PROBE_V1 passed\n',b'warning'),(-6,b'x'*10000,b'y'*10000)]:
            with patch.object(selftest,'invoke',return_value=subprocess.CompletedProcess([],code,stdout,stderr)) as invoke,contextlib.redirect_stdout(io.StringIO()) as output,contextlib.redirect_stderr(io.StringIO()) as errors,self.assertRaisesRegex(ValueError,'Private JVM basic operations failed'):
                prepare.verify_private_jre()
            self.assertEqual(invoke.call_count,1)
            self.assertEqual(output.getvalue(),'')
            value=json.loads(errors.getvalue().split(' ',1)[1])
            self.assertEqual(value['observedExit'],code)
            self.assertLessEqual(len(value['stdoutPrefix']),4096)
            self.assertLessEqual(len(value['stderrPrefix']),4096)
            self.assertFalse(value['engineExecuted'])

    def test_builder_probe_budget_failure_cannot_be_retried_or_promoted(self):
        with patch.object(selftest,'invoke',side_effect=ValueError('Owned command deadline')) as invoke,contextlib.redirect_stdout(io.StringIO()) as output,self.assertRaisesRegex(ValueError,'Owned command deadline'):
            prepare.verify_private_jre()
        self.assertEqual(invoke.call_count,1)
        self.assertEqual(output.getvalue(),'')

    def test_post_failure_jvm_probe_has_no_engine_classpath_or_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'jre').mkdir()
            (root/'jre/release').write_text('JAVA_VERSION="17.0.21"\nOS_ARCH="x86_64"\nUNSELECTED="do not log"\n')
            result=subprocess.CompletedProcess([],0,b'CLINE_MANAGED_OWNED_JVM_PROBE_V1 passed\n',b'')
            with patch.object(selftest,'ROOT',root),patch.object(selftest,'invoke',return_value=result) as invoke,contextlib.redirect_stderr(io.StringIO()) as output:
                selftest.owned_jvm_runtime_probe()
            command=invoke.call_args.args[0]
            self.assertEqual(command[-3:],['-cp',str(root/'jvm-probe'),'OwnedJvmProbe'])
            self.assertNotIn('dependency',str(command))
            self.assertNotIn('ClineRunner',command)
            self.assertIn('-Xcheck:jni',command)
            self.assertEqual(invoke.call_count,1)
            value=json.loads(output.getvalue().split(' ',1)[1])
            self.assertTrue(value['exactProbePassed'])
            self.assertTrue(value['engineFailureUnchanged'])
            self.assertFalse(value['engineRetried'])
            self.assertEqual(value['identity']['fields'],{'JAVA_VERSION':'"17.0.21"','OS_ARCH':'"x86_64"'})
            self.assertNotIn('do not log',output.getvalue())

    def test_post_failure_jvm_probe_bounds_output_and_rejects_false_passes(self):
        for code,stdout,stderr in [(1,b'x'*10000,b'y'*10000),(0,b'passed',b''),(0,b'CLINE_MANAGED_OWNED_JVM_PROBE_V1 passed\n',b'warning')]:
            with patch.object(selftest,'regular_bytes',return_value=b'JAVA_VERSION="17"\n'),patch.object(selftest,'invoke',return_value=subprocess.CompletedProcess([],code,stdout,stderr)),contextlib.redirect_stderr(io.StringIO()) as output:
                selftest.owned_jvm_runtime_probe()
            value=json.loads(output.getvalue().split(' ',1)[1])
            self.assertFalse(value['exactProbePassed'])
            self.assertLessEqual(len(value['stdoutPrefix']),4096)
            self.assertLessEqual(len(value['stderrPrefix']),4096)
            self.assertTrue(value['engineFailureUnchanged'])
        with patch.object(selftest,'regular_bytes',side_effect=ValueError('bad identity')),patch.object(selftest,'invoke',side_effect=ValueError('Owned command deadline')),contextlib.redirect_stderr(io.StringIO()) as output:
            selftest.owned_jvm_runtime_probe()
        value=json.loads(output.getvalue().split(' ',1)[1])
        self.assertEqual(value['identity'],{'status':'unavailable'})
        self.assertEqual(value['status'],'unavailable-or-budget')
        self.assertFalse(value['engineRetried'])
        self.assertNotIn('exactProbePassed',value)

    def test_post_failure_jvm_probe_rejects_ambiguous_release_metadata(self):
        for raw in [b'JAVA_VERSION="17"\nJAVA_VERSION="21"',b'IMPLEMENTOR='+b'x'*257,b'JAVA_VERSION=\xff']:
            with patch.object(selftest,'regular_bytes',return_value=raw),patch.object(selftest,'invoke',side_effect=OSError),contextlib.redirect_stderr(io.StringIO()) as output:
                selftest.owned_jvm_runtime_probe()
            self.assertEqual(json.loads(output.getvalue().split(' ',1)[1])['identity'],{'status':'unavailable'})

    def test_post_failure_probe_never_retries_or_accepts_original_jni_failure(self):
        failed=subprocess.CompletedProcess([],1,b'',b'owned failure')
        with patch.object(selftest,'invoke',return_value=failed) as invoke,patch.object(selftest,'owned_jvm_runtime_probe') as probe,contextlib.redirect_stderr(io.StringIO()),self.assertRaisesRegex(ValueError,'Owned JNI execution failed'):
            selftest.jni_check('unidbg')
        self.assertEqual(invoke.call_count,1)
        probe.assert_called_once_with()
        # An expected exit never launches the diagnostic, even when its result
        # is independently malformed. Only fresh failing JVM exits trigger it.
        with patch.object(selftest,'invoke',return_value=subprocess.CompletedProcess([],0,b'',b'')),patch.object(selftest,'owned_jvm_runtime_probe') as probe,contextlib.redirect_stderr(io.StringIO()),self.assertRaises(OSError):
            selftest.jni_check('unidbg')
        probe.assert_not_called()

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
            value={'schema':1,'engine':engine,'architectures':arches,'checks':counts[engine],'bundleSha256':'a'*64,'executionIdentity':'uid-gid-65534/no-supplementary-groups/no-new-privileges','ownedFixtures':'passed','engineReadiness':'not-tested','vmIsolation':'not-attested'}
            def data(v):return ('CLINE_MANAGED_ENGINE_OWNED_V1 '+json.dumps(v)+'\n').encode()
            with self.subTest(engine=engine):
                self.assertEqual(validate_engine_log(data(value),engine),value)
                self.assertEqual(validate_engine_log(data(value),engine,'a'*64),value)
                with self.assertRaises(ValueError):validate_engine_log(data(value),engine,'b'*64)
                for change in [{'schema':True},{'checks':float(counts[engine])},{'checks':counts[engine]-1},{'architectures':[]},{'engineReadiness':'ready'},{'executionIdentity':'root'},{'vmIsolation':'attested'},{'bundleSha256':'x'*64},{'extra':True}]:
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


    @unittest.skipUnless(sys.platform == 'linux', 'Owned Linux guest supervision')
    def test_owned_child_captures_both_pipes_input_and_exit_status(self):
        code="import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data); sys.stderr.write('owned diagnostic'); raise SystemExit(7)"
        result=selftest.invoke([sys.executable,'-B','-I','-c',code],b'owned input')
        self.assertEqual(result.returncode,7)
        self.assertEqual(result.stdout,b'owned input')
        self.assertEqual(result.stderr,b'owned diagnostic')
        with patch.object(selftest.subprocess,'Popen') as launch:
            with self.assertRaises(ValueError):selftest.invoke(['never-launch'],b'x'*4097)
            launch.assert_not_called()

    @unittest.skipUnless(sys.platform == 'linux', 'Owned Linux guest supervision')
    def test_owned_child_enforces_stream_caps_before_collecting_all_output(self):
        for descriptor in [1,2]:
            with self.subTest(descriptor=descriptor),patch.object(selftest,'INVOKE_STDOUT_LIMIT',1024),patch.object(selftest,'INVOKE_STDERR_LIMIT',1024):
                code="import os; os.write("+str(descriptor)+",b'x'*65536)"
                with self.assertRaisesRegex(ValueError,'output budget'):
                    selftest.invoke([sys.executable,'-B','-I','-c',code])

    @unittest.skipUnless(sys.platform == 'linux', 'Owned Linux guest supervision')
    def test_owned_child_deadline_reaps_the_leader(self):
        actual=selftest.subprocess.Popen
        started=[]
        def launch(*args,**kwargs):
            child=actual(*args,**kwargs);started.append(child);return child
        with patch.object(selftest,'INVOKE_SECONDS',0.2),patch.object(selftest.subprocess,'Popen',side_effect=launch):
            with self.assertRaisesRegex(ValueError,'deadline'):
                selftest.invoke([sys.executable,'-B','-I','-c','import time;time.sleep(60)'])
        self.assertEqual(len(started),1)
        self.assertEqual(started[0].returncode,-9)
        with self.assertRaises(ChildProcessError):os.waitpid(started[0].pid,os.WNOHANG)

    @unittest.skipUnless(sys.platform == 'linux', 'Owned Linux guest supervision')
    def test_owned_child_cleanup_stops_descendants_after_leader_exit(self):
        import time
        with tempfile.TemporaryDirectory() as directory:
            pidfile=Path(directory)/'child-pid'
            # The child closes inherited stdout/stderr. EOF therefore must not
            # allow a background descendant to survive a successful leader.
            descendant="import time;time.sleep(60)"
            leader="import subprocess,sys,pathlib; p=subprocess.Popen([sys.executable,'-c',sys.argv[2]],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);pathlib.Path(sys.argv[1]).write_text(str(p.pid))"
            result=selftest.invoke([sys.executable,'-B','-I','-c',leader,str(pidfile),descendant])
            self.assertEqual(result.returncode,0)
            pid=int(pidfile.read_text())
            for _ in range(100):
                status=Path('/proc')/str(pid)/'stat'
                if not status.exists() or status.read_text().split(') ',1)[1].split()[0] == 'Z':break
                time.sleep(0.01)
            else:
                os.kill(pid,9)
                self.fail('Owned background descendant survived group cleanup')



if __name__ == '__main__':
    unittest.main()
