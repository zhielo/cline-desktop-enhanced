"""Parser/build tests and owned fake-JNI C faults; no emulator/JVM/network."""
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile
import native_rebuild as n
from test_jni_memory import MemoryTests  # Included in the existing required CI command.

class NativeTests(unittest.TestCase):
    def test_missing_complete_jdk_headers_fails_before_download(self):
        with tempfile.TemporaryDirectory() as d,patch.object(n,'fetch') as fetched:
            root=Path(d)
            with self.assertRaisesRegex(ValueError,'Complete JDK'):
                n.build(root/'runtime',root/'work',root/'jdk')
            fetched.assert_not_called()

    def test_exact_lock_and_duplicate_schema_refusal(self):
        lock=Path(__file__).with_name('native-inputs.lock.json')
        v=n.load(lock)
        self.assertEqual({e['name'] for e in v['files']},n.NAMES)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'lock.json'
            for change in [{'schema':True},{'files':v['files'][:-1]}, {'files':v['files']+[v['files'][0]]}]:
                p.write_text(json.dumps({**v,**change}))
                with self.assertRaises(ValueError):n.load(p)
            p.write_text(lock.read_text().replace('{','{"schema":1,',1))
            with self.assertRaisesRegex(ValueError,'Duplicate'):n.load(p)

    def test_invalid_source_fields_and_origins(self):
        v=n.load(Path(__file__).with_name('native-inputs.lock.json'))
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'lock.json'
            for e in [{'name':'../escape'},{'bytes':True},{'bytes':9*1024**2},{'sha256':'z'*64},
                      {'url':'https://raw.githubusercontent.com.evil.invalid/a'},
                      {'url':'https://raw.githubusercontent.com/a?redirect=x'}]:
                value=json.loads(json.dumps(v));value['files'][0].update(e);p.write_text(json.dumps(value))
                with self.assertRaises(ValueError):n.load(p)
        with self.assertRaisesRegex(ValueError,'redirect'):
            n.NoRedirect().redirect_request(None,None,302,'',None,'https://invalid.example')

    def test_fetch_rejects_overflow_short_digest_and_existing_destination(self):
        entry={'name':'jna-sources.jar','url':'https://repo.maven.apache.org/fixed','bytes':3,'sha256':n.digest(b'abc')}
        class Response(io.BytesIO):
            status=200
        class Opener:
            def __init__(self,data):self.data=data
            def open(self,*a,**kw):return Response(self.data)
        for data in (b'abcd',b'ab',b'bad'):
            with self.subTest(data=data),tempfile.TemporaryDirectory() as d:
                root=Path(d)/'fresh'
                with patch.object(n,'load',return_value={'files':[entry]}),patch.object(n.urllib.request,'build_opener',return_value=Opener(data)):
                    with self.assertRaises(ValueError):n.fetch(Path('unused'),root)
                self.assertFalse((root/'jna-sources.jar').exists())
                self.assertTrue((root/'jna-sources.jar.partial').exists())
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(FileExistsError):n.fetch(Path(__file__).with_name('native-inputs.lock.json'),Path(d))

    def test_fetch_exact_bytes_then_seal(self):
        entry={'name':'jna-sources.jar','url':'https://repo.maven.apache.org/fixed','bytes':3,'sha256':n.digest(b'abc')}
        response=io.BytesIO(b'abc');response.status=200
        with tempfile.TemporaryDirectory() as d,patch.object(n,'load',return_value={'files':[entry]}),patch.object(n.urllib.request,'build_opener') as opener:
            opener.return_value.open.return_value=response
            root=Path(d)/'fresh';n.fetch(Path('unused'),root)
            self.assertEqual((root/'jna-sources.jar').read_bytes(),b'abc')
            self.assertFalse((root/'jna-sources.jar.partial').exists())

    def test_native_tar_paths_types_duplicates_and_lengths_fail_closed(self):
        for kind in ('parent','link','duplicate','multiple-root','oversized'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as d:
                path=Path(d)/'source.tar.gz'
                with tarfile.open(path,'w:gz') as t:
                    m=tarfile.TarInfo('root/a');m.size=1;t.addfile(m,io.BytesIO(b'a'))
                    x=tarfile.TarInfo({'parent':'root/../escape','multiple-root':'other/b'}.get(kind,'root/b'))
                    if kind=='link':x.type=tarfile.SYMTYPE;x.linkname='/outside'
                    if kind=='duplicate':x.name='root/a'
                    if kind=='oversized':x.size=9*1024**2
                    t.addfile(x,io.BytesIO(b'x'*x.size) if x.size else None)
                with self.assertRaises(ValueError):n.extract_core(path,Path(d)/'out')
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'source.tar.gz'
            with tarfile.open(path,'w:gz') as t:
                m=tarfile.TarInfo('root/a');m.size=1;t.addfile(m,io.BytesIO(b'a'))
            n.extract_core(path,Path(d)/'out');self.assertEqual((Path(d)/'out/a').read_bytes(),b'a')

    def test_jna_release_abi_comes_from_matching_pinned_source_and_java_constants(self):
        source='\n'.join('<property name="'+name+'" value="'+value+'"/>' for name,value in [('jni.major','6'),('jni.minor','1'),('jni.revision','2'),('jni.md5','a'*32)])
        self.assertEqual(n.jna_identity(source),('6.1.2','a'*32))
        for bad in (source+source,source.replace('name="jni.major"','name="other"'),source.replace('a'*32,'unknown')):
            with self.assertRaises(ValueError):n.jna_identity(bad)
        output='public static final java.lang.String VERSION_NATIVE = "6.1.2";'
        n.verify_java_abi(output,'6.1.2')
        for bad in (output+output,'missing',output.replace('6.1.2','5.1.0')):
            with self.assertRaises(ValueError):n.verify_java_abi(bad,'6.1.2')

    def test_exact_jna_patch_preserves_pending_exception(self):
        original='before\n  fileEncoding = get_system_property(env, "file.encoding");\n  if (fileEncoding) {\nafter\n'
        result=n.patch_jna(original)
        self.assertIn('if ((*env)->ExceptionCheck(env)) return "file.encoding";',result)
        with self.assertRaises(ValueError):n.patch_jna(result)

    def test_all_native_callbacks_checked_before_and_after_and_emulation_preserves_error(self):
        source='''  if (err != UC_ERR_OK) {
    const char *msg = "fixed";
    (*env)->ThrowNew(env, clazz, msg);
  }
'''
        source+='  (*env)->CallVoidMethod(env, nh->hook, onCode, (jlong)address, (int)size);\n'*8
        source+='''  jboolean res = (*env)->CallBooleanMethod(env, nh->hook, onMemEvent, 0);
  jni_env_detach(need_detach);
  return res;
  uc_err err = uc_emu_start(eng, (uint64_t)begin, (uint64_t)until, (uint64_t)timeout, (size_t)count);
'''
        for name in ('onBlock','onCode','onBreak','onRead','onWrite','onInterrupt','onMemEvent'):
            source+='  '+name+' = (*env)->GetMethodID(env, cls, "fixed", "()V");\n'
        result=n.patch_bridge(source)
        self.assertEqual(result.count('if ((*env)->ExceptionCheck(env)) uc_emu_stop(eng);'),8)
        self.assertEqual(result.count('jni_env_detach(need_detach); return; }'),8)
        self.assertIn('res = JNI_FALSE;',result)
        self.assertIn('  if ((*env)->ExceptionCheck(env)) return;\n  if (err != UC_ERR_OK)',result)
        self.assertEqual(result.count('return JNI_ERR;'),7)
        with self.assertRaises(ValueError):n.patch_bridge(result)
        with self.assertRaises(ValueError):n.patch_bridge(source.replace('onMemEvent =','unknown ='))

    def test_resource_replacement_preserves_other_entries_and_missing_or_duplicate_never_publishes(self):
        for kind in ('valid','missing','duplicate'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as d:
                root=Path(d);jar=root/'owned.jar';binary=root/'fixed.so';binary.write_bytes(b'compiled-fixed-native')
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore',UserWarning)
                    with zipfile.ZipFile(jar,'w') as z:
                        z.writestr('class/Keep.class',b'exact-class')
                        if kind!='missing':z.writestr('native/fixed.so',b'upstream-native')
                        if kind=='duplicate':z.writestr('native/fixed.so',b'ambiguous-native')
                original=jar.read_bytes()
                if kind=='valid':
                    n.replace_resource(jar,'native/fixed.so',binary)
                    with zipfile.ZipFile(jar) as z:
                        self.assertEqual(set(z.namelist()),{'class/Keep.class','native/fixed.so'})
                        self.assertEqual(z.read('class/Keep.class'),b'exact-class')
                        self.assertEqual(z.read('native/fixed.so'),binary.read_bytes())
                else:
                    with self.assertRaises(ValueError):n.replace_resource(jar,'native/fixed.so',binary)
                    self.assertEqual(jar.read_bytes(),original)

if __name__=='__main__':unittest.main()
