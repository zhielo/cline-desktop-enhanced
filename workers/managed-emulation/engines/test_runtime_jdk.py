"""Owned archive/parser controls only; never execute downloaded Java or network."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import runtime_jdk as j


class RuntimeJdkTests(unittest.TestCase):
    def lock(self):
        return j.load(Path(__file__).with_name('runtime-jdk.lock.json'))

    def test_exact_identity_and_invalid_lock(self):
        value = self.lock()
        self.assertEqual(value['version'], '21.0.13+9')
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'lock'
            for change in ({'schema':True}, {'bytes':True}, {'bytes':0}, {'bytes':257*1024**2},
                           {'version':'17.0.21+9'}, {'root':'../jdk'}, {'sha256':'z'*64},
                           {'url':value['url']+'?other'}, {'extra':1}):
                path.write_text(json.dumps({**value, **change}))
                with self.subTest(change=change), self.assertRaises(ValueError):
                    j.load(path)
            path.write_text(json.dumps(value).replace('{', '{"schema":1,', 1))
            with self.assertRaisesRegex(ValueError, 'Duplicate'):
                j.load(path)

    def test_download_exact_size_hash_no_retry(self):
        data = b'owned archive bytes'
        value = {**self.lock(), 'bytes':len(data), 'sha256':hashlib.sha256(data).hexdigest()}
        class Response(io.BytesIO):
            status = 200
        for payload, status, success in ((data,200,True),(data+b'x',200,False),
                                         (data[:-1],200,False),(b'x'*len(data),200,False),
                                         (data,403,False)):
            with self.subTest(status=status, payload=payload), tempfile.TemporaryDirectory() as d:
                response = Response(payload); response.status = status
                with patch.object(j.urllib.request,'urlopen',return_value=response) as request:
                    path = Path(d)/'archive'
                    if success:
                        j.fetch(value, path)
                        self.assertEqual(path.read_bytes(),data)
                    else:
                        with self.assertRaises(ValueError): j.fetch(value,path)
                    request.assert_called_once_with(value['url'],timeout=60)
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'exists';path.write_bytes(b'never replace')
            with patch.object(j.urllib.request,'urlopen',return_value=Response(data)):
                with self.assertRaises(FileExistsError):j.fetch(value,path)
            self.assertEqual(path.read_bytes(),b'never replace')

    def archive(self, path, entries):
        with tarfile.open(path,'w:gz') as archive:
            for name, kind, data in entries:
                member=tarfile.TarInfo(name);member.mode=0o755
                if kind == 'file':
                    member.size=len(data);archive.addfile(member,io.BytesIO(data))
                else:
                    member.type={'link':tarfile.SYMTYPE,'hard':tarfile.LNKTYPE,'fifo':tarfile.FIFOTYPE,'dir':tarfile.DIRTYPE}[kind]
                    if kind in ('link','hard'):member.linkname=data
                    archive.addfile(member)

    def test_owned_archive_legal_alias_is_bytes_not_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);archive=root/'input'
            self.archive(archive,[('jdk/legal/a/NOTICE','link','../b/NOTICE'),
                                  ('jdk/legal/b/NOTICE','file',b'owned notice'),
                                  ('jdk/bin/java','file',b'not executable test data')])
            j.extract(archive,root/'out','jdk')
            alias=root/'out/legal/a/NOTICE'
            self.assertFalse(alias.is_symlink());self.assertEqual(alias.read_bytes(),b'owned notice')
            self.assertEqual((root/'out/bin/java').stat().st_mode & 0o777,0o755)
            with self.assertRaises(FileExistsError):j.extract(archive,root/'out','jdk')

    def test_archive_refusals(self):
        bad = [[(name,'file',b'x')] for name in ('/jdk/x','jdk/../x','other/x','jdk//x','jdk/./x','jdk\\x')]
        bad += [[('jdk/x','file',b'x'),('jdk/x','file',b'x')], [('jdk/x','fifo','')],
                [('jdk/x','hard','jdk/a')], [('jdk','file',b'x')],
                [('jdk/bin/alias','link','../legal/a')],
                [('jdk/legal/a','link','../../escape')], [('jdk/legal/a','link','/jdk/legal/b')],
                [('jdk/legal/a','link','missing')],
                [('jdk/legal/a','link','b'),('jdk/legal/b','link','c'),('jdk/legal/c','file',b'x')]]
        for entries in bad:
            with self.subTest(entries=entries),tempfile.TemporaryDirectory() as d:
                root=Path(d);self.archive(root/'archive',entries)
                with self.assertRaises(ValueError):j.extract(root/'archive',root/'out','jdk')
                self.assertFalse((root/'escape').exists())

    def test_archive_member_budget_before_read(self):
        member=tarfile.TarInfo('jdk/huge');member.size=256*1024**2+1
        class Archive:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def __iter__(self):return iter([member])
        with tempfile.TemporaryDirectory() as d,patch.object(j.tarfile,'open',return_value=Archive()):
            with self.assertRaisesRegex(ValueError,'type/size'):j.extract(Path(d)/'in',Path(d)/'out','jdk')

    def test_alias_bytes_and_member_count_are_bounded(self):
        member=tarfile.TarInfo('jdk/legal/source');member.size=256*1024**2
        aliases=[]
        for name in ('a','b'):
            item=tarfile.TarInfo('jdk/legal/'+name);item.type=tarfile.SYMTYPE;item.linkname='source';aliases.append(item)
        class Archive:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def __iter__(self):return iter(aliases+[member])
        with tempfile.TemporaryDirectory() as d,patch.object(j.tarfile,'open',return_value=Archive()):
            with self.assertRaisesRegex(ValueError,'alias budget'):j.extract(Path(d)/'in',Path(d)/'out','jdk')
        class Many(Archive):
            def __iter__(self):
                for index in range(4097):yield tarfile.TarInfo('jdk/f'+str(index))
        with tempfile.TemporaryDirectory() as d,patch.object(j.tarfile,'open',return_value=Many()):
            with self.assertRaisesRegex(ValueError,'path/count'):j.extract(Path(d)/'in',Path(d)/'out','jdk')

    def test_full_and_linked_release_identities_are_separate(self):
        full='IMPLEMENTOR="Eclipse Adoptium"\nJAVA_RUNTIME_VERSION="21.0.13+9-LTS"\nOS_ARCH="x86_64"\nOS_NAME="Linux"\nLIBC="gnu"\n'
        modules=' '.join(sorted(j.REQUIRED_MODULES))
        linked='JAVA_VERSION="21.0.13"\nMODULES="'+modules+'"\n'
        with tempfile.TemporaryDirectory() as d:
            home=Path(d);path=home/'release'
            path.write_text(full);j.verify_release(home,'21.0.13+9')
            for text in (full.replace('x86_64','aarch64'),full.replace('gnu','musl'),
                         full.replace('Adoptium','Other'),full.replace('21.0.13','21.0.12'),
                         full+'OS_NAME="Linux"\n',linked):
                path.write_text(text)
                with self.assertRaises(ValueError):j.verify_release(home,'21.0.13+9')
            path.write_text(linked);j.verify_linked_release(home,'21.0.13+9')
            for text in (full,linked.replace('21.0.13','17.0.21'),linked.replace('java.desktop ',''),
                         linked+'JAVA_VERSION="21.0.13"\n',linked.replace(modules,modules+' jdk.compiler'),
                         linked.replace(modules,modules+' java.base'),linked.replace('MODULES="','MODULES=')):
                path.write_text(text)
                with self.assertRaises(ValueError):j.verify_linked_release(home,'21.0.13+9')
            path.unlink();path.symlink_to(home/'missing')
            for check in (j.verify_release,j.verify_linked_release):
                with self.assertRaises(ValueError):check(home,'21.0.13+9')

    def test_obtain_hash_before_extract_and_no_existing_adoption(self):
        with tempfile.TemporaryDirectory() as d:
            directory=Path(d)/'new';calls=[]
            def fetched(*args):calls.append('fetch')
            def extracted(*args):calls.append('extract')
            def verified(*args):calls.append('verify')
            with patch.object(j,'fetch',side_effect=fetched),patch.object(j,'extract',side_effect=extracted),patch.object(j,'verify_release',side_effect=verified):
                home,value=j.obtain(directory)
                self.assertEqual(calls,['fetch','extract','verify']);self.assertEqual(home,directory/'jdk')
                with self.assertRaises(FileExistsError):j.obtain(directory)
                self.assertEqual(len(calls),3)
            with patch.object(j,'fetch',side_effect=ValueError('bad hash')),patch.object(j,'extract') as extracted:
                with self.assertRaisesRegex(ValueError,'bad hash'):j.obtain(Path(d)/'bad')
                extracted.assert_not_called()


if __name__ == '__main__':unittest.main()
