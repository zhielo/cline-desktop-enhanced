import importlib.util, pathlib, sys, unittest
spec=importlib.util.spec_from_file_location('capture_support',pathlib.Path(__file__).with_name('capture_support.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
ELF=b'\x7fELF'+bytes([2,1,1])+bytes(57)
class SupportTest(unittest.TestCase):
 def test_paths_are_package_scoped_and_shell_metacharacters_denied(self):
  for path in ['/data/app/~~owned/com.example.owned-token/lib/arm64/libowned.so','/data/user/0/com.example.owned/files/libowned.so']:self.assertTrue(m.authorized_module_path('com.example.owned',path))
  for path in ['/system/lib/libowned.so','/data/data/com.other/files/libowned.so','/data/data/com.example.owned/../com.other/libowned.so','/data/data/com.example.owned/lib.so;id','/data/app/com.other/lib.so','/data/app/com.example.owned/base.apk!/lib/lib.so']:self.assertFalse(m.authorized_module_path('com.example.owned',path))
 def test_hashes_are_disk_evidence_only_and_duplicate_paths_read_once(self):
  calls=[];rows=[{'module':'/data/data/com.example.owned/lib.so'} for _ in range(2)]
  a,c,l=m.capture_modules(rows,'com.example.owned',lambda path:(calls.append(path) or ELF));self.assertEqual(len(calls),1);self.assertEqual(len(a),1);self.assertEqual(len(c),1);self.assertEqual(l,[]);self.assertEqual(rows[0]['moduleHashBasis'],'captured-disk-file-not-loaded-memory-proof')
 def test_invalid_or_over_budget_modules_remain_unresolved(self):
  for raw,total in [(b'invalid',0),(ELF,m.MAX_TOTAL),(ELF*(m.MAX_MODULE//len(ELF)+1),0)]:
   rows=[{'module':'/data/data/com.example.owned/lib.so'}];a,c,l=m.capture_modules(rows,'com.example.owned',lambda _:raw,total);self.assertEqual(a,[]);self.assertEqual(c,[]);self.assertTrue(l);self.assertNotIn('moduleSha256',rows[0])
 def test_module_count_is_bounded(self):
  rows=[{'module':'/data/data/com.example.owned/lib'+str(i)+'.so'} for i in range(6)];calls=[];m.capture_modules(rows,'com.example.owned',lambda p:(calls.append(p) or ELF));self.assertEqual(len(calls),4)
 def test_process_output_and_deadline_are_bounded(self):
  with self.assertRaises(ValueError):m.bounded_command([sys.executable,'-c',"print('x'*2048)"],1024,2)
  with self.assertRaises(ValueError):m.bounded_command([sys.executable,'-c','import time;time.sleep(10)'],1024,0.1)
  self.assertEqual(m.bounded_command([sys.executable,'-c',"print('owned')"],1024,2),b'owned\n' if sys.platform!='win32' else b'owned\r\n')
 def test_physical_preflight_is_readonly_and_reports_root_without_attestation(self):
  calls=[]
  def reader(argv,**_):
   calls.append(argv[3:]);return {('get-state',):b'device',('get-serialno',):b'owned-device',('shell','getprop','ro.kernel.qemu'):b'0',('exec-out','su','-c','id'):b'uid=0(root) gid=0(root)',('shell','getprop','ro.product.cpu.abi'):b'arm64-v8a'}[tuple(argv[3:])]
  info=m.physical_preflight('/owned/adb','owned-device',reader);self.assertEqual(info['rootProbe'],'uid0-reported');self.assertEqual(info['attestation'],'not-proven');self.assertEqual(len(calls),5);self.assertFalse(any('install' in c or 'reboot' in c or 'wipe' in c for c in calls))
 def test_physical_preflight_rejects_wrong_serial_emulator_and_denied_root(self):
  defaults={('get-state',):b'device',('get-serialno',):b'owned-device',('shell','getprop','ro.kernel.qemu'):b'0',('exec-out','su','-c','id'):b'uid=0(root)',('shell','getprop','ro.product.cpu.abi'):b'arm64-v8a'}
  for key,bad in [(('get-state',),b'unauthorized'),(('get-serialno',),b'other-device'),(('shell','getprop','ro.kernel.qemu'),b'1'),(('exec-out','su','-c','id'),b'uid=2000(shell)'),(('shell','getprop','ro.product.cpu.abi'),b'unknown')]:
   values=dict(defaults);values[key]=bad
   with self.assertRaises(ValueError):m.physical_preflight('/owned/adb','owned-device',lambda argv,**_:values[tuple(argv[3:])])
if __name__=='__main__':unittest.main()
