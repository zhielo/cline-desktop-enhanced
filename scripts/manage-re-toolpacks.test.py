import importlib.util, json, os, stat, tarfile, tempfile, unittest, zipfile, io
from pathlib import Path
s=importlib.util.spec_from_file_location('packs',Path(__file__).with_name('manage-re-toolpacks.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Tests(unittest.TestCase):
 def test_portable_paths(self):
  self.assertEqual(m.safe_member('share/rizin/sdb/file'),'share/rizin/sdb/file')
  for p in ['/tmp/out','../out','a/../b','a//b','C:/out','a\\b','a/.','a/CON.txt','a/file.','a/file ','a\0b']:
   with self.assertRaises(ValueError):m.safe_member(p)
 def test_install_approvals_before_writes(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'missing'
   with self.assertRaises(ValueError):m.import_pack(str(p),'rizin-0.9.1-linux-x64','/missing')
   self.assertFalse(p.exists())
 def test_relative_root(self):
  with self.assertRaises(ValueError):m.private_root('relative-pack-root')
 def test_private_root(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'packs';p.mkdir(mode=0o700);self.assertEqual(m.private_root(str(p)),p)
   if os.name!='nt':
    p.chmod(0o777)
    with self.assertRaises(ValueError):m.private_root(str(p))
 def test_root_symlink(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'real';p.mkdir();q=Path(t)/'link'
   try:q.symlink_to(p,target_is_directory=True)
   except OSError:return
   with self.assertRaises(ValueError):m.private_root(str(q))
 def test_registry_schema(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t);self.assertIsNone(m.registry(p)['active']);(p/'active.json').write_text(json.dumps({'schemaVersion':1,'active':{'packId':'caller-engine','receiptSha256':'a'*64},'history':[]}))
   with self.assertRaises(ValueError):m.registry(p)
 def test_atomic_registry(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t);d={'schemaVersion':1,'active':None,'history':[None]};m.publish(p,d);self.assertEqual(m.registry(p),d);self.assertEqual(list(p.glob('.active-*')),[])
 def test_rollback_approval(self):
  with tempfile.TemporaryDirectory() as t:
   with self.assertRaises(ValueError):m.rollback(t)
 def test_rollback_retains_revision(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t);(p/'revisions').mkdir();(p/'revisions/retained').write_bytes(b'owned');m.publish(p,{'schemaVersion':1,'active':None,'history':[None]});self.assertTrue(m.rollback(t,True)['retainedRevisions']);self.assertTrue((p/'revisions/retained').exists())
 def test_foreign_lock_preserved(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t);(p/'.install.lock').write_text('foreign');m.publish(p,{'schemaVersion':1,'active':None,'history':[None]})
   with self.assertRaises((ValueError,FileExistsError)):m.rollback(t,True)
   self.assertEqual((p/'.install.lock').read_text(),'foreign')
 def test_archive_hash_before_extraction(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t);a=p/'bad.tar.xz';a.write_bytes(b'bad');root=p/'packs'
   with self.assertRaises(ValueError):m.import_pack(str(root),'rizin-0.9.1-linux-x64',str(a),True,True)
   self.assertFalse((root/'active.json').exists());self.assertEqual(list(root.glob('.stage-*')),[]);self.assertFalse((root/'.install.lock').exists())
 def test_tar_links_rejected(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t);a=p/'bad.tar.xz';out=p/'out';out.mkdir()
   with tarfile.open(a,'w:xz') as f:
    x=tarfile.TarInfo('link');x.type=tarfile.SYMTYPE;x.linkname='/tmp/out';f.addfile(x)
   with self.assertRaises(ValueError):m.extract_reviewed(a,{'kind':'tar.xz'},out)
 def test_tar_traversal_rejected(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t);a=p/'bad.tar.xz';out=p/'out';out.mkdir()
   with tarfile.open(a,'w:xz') as f:
    x=tarfile.TarInfo('../escape');x.size=1;f.addfile(x,io.BytesIO(b'x'))
   with self.assertRaises(ValueError):m.extract_reviewed(a,{'kind':'tar.xz'},out)
   self.assertFalse((p/'escape').exists())
 def test_zip_links_rejected(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t);a=p/'bad.zip';out=p/'out';out.mkdir()
   with zipfile.ZipFile(a,'w') as z:
    x=zipfile.ZipInfo('link');x.create_system=3;x.external_attr=(stat.S_IFLNK|0o777)<<16;z.writestr(x,'../escape')
   with self.assertRaises(ValueError):m.extract_reviewed(a,{'kind':'zip'},out)
 def test_duplicate_casefold_rejected(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t);a=p/'bad.zip';out=p/'out';out.mkdir()
   with zipfile.ZipFile(a,'w') as z:z.writestr('A',b'a');z.writestr('a',b'b')
   with self.assertRaises(ValueError):m.extract_reviewed(a,{'kind':'zip'},out)
 def test_expansion_budget(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t);a=p/'owned.zip';out=p/'out';out.mkdir()
   with zipfile.ZipFile(a,'w') as z:z.writestr('owned',b'12345')
   old=m.MAX_EXPANDED;m.MAX_EXPANDED=4
   try:
    with self.assertRaises(ValueError):m.extract_reviewed(a,{'kind':'zip'},out)
   finally:m.MAX_EXPANDED=old
 def test_regular_content_hashed(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t);a=p/'owned.zip';out=p/'out';out.mkdir()
   with zipfile.ZipFile(a,'w') as z:z.writestr('bin/owned',b'1234')
   files=m.extract_reviewed(a,{'kind':'zip'},out);self.assertEqual(files[0]['bytes'],4);self.assertEqual(files[0]['sha256'],m.sha(out/'bin/owned'))
 def test_catalog_pins(self):
  self.assertEqual(len(m.CATALOG),2)
  for s in m.CATALOG.values():self.assertTrue(s['url'].startswith('https://github.com/rizinorg/rizin/releases/download/v0.9.1/'));self.assertRegex(s['sha256'],'^[a-f0-9]{64}$');self.assertGreater(s['bytes'],0)
if __name__=='__main__':unittest.main()
