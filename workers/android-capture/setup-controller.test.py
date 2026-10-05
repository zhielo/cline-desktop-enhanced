import importlib.util, pathlib, tempfile, unittest
from unittest.mock import patch
from types import SimpleNamespace
spec=importlib.util.spec_from_file_location('setup_controller',pathlib.Path(__file__).with_name('setup-controller.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class SetupTest(unittest.TestCase):
 def setUp(self):
  self.root=tempfile.TemporaryDirectory();self.path=pathlib.Path(self.root.name).resolve();self.hook=self.path/'trusted-hook';self.hook.write_text('owned fixture');self.hook.chmod(0o700);self.cert=self.path/'cert.pem';self.cert.write_text('TLS mocked fixture');self.key=self.path/'key.pem';self.key.write_text('TLS mocked fixture');self.env={name:str(self.hook) for name in m.HOOKS};self.env.update(CLINE_ANDROID_ISOLATION_ACK=m.ACK,CLINE_ANDROID_PHYSICAL_POLICY_ACK='dedicated-authorized-device-with-operator-cleanup',CLINE_ANDROID_WORKER_ID='owned-worker',CLINE_ANDROID_DEVICE_SERIAL='emulator-5554')
 def tearDown(self):self.root.cleanup()
 def planned(self):return m.plan(str(self.path/'new-private'),str(self.cert),str(self.key),self.env)
 def test_dry_plan_validates_without_creating_private_files_or_executing_hooks(self):
  with patch.object(m.sys,'platform','linux'),patch.object(m.shutil,'which',return_value='/owned/bun'),patch.object(m.subprocess,'run',return_value=SimpleNamespace(stdout='1.3.14\n')) as run,patch.object(m.ssl,'SSLContext'):
   output,bun=self.planned();self.assertFalse(output.exists());self.assertEqual(bun,'/owned/bun');self.assertEqual(run.call_count,1);self.assertEqual(run.call_args.args[0],['/owned/bun','--version'])
 def test_existing_directories_and_missing_hooks_fail_closed(self):
  with patch.object(m.sys,'platform','linux'):
   (self.path/'new-private').mkdir()
   with self.assertRaises(ValueError):self.planned()
   (self.path/'new-private').rmdir();self.env['CLINE_ANDROID_RESET']='/missing/executable'
   with self.assertRaises(ValueError):self.planned()
 def test_windows_host_and_unacknowledged_isolation_rejected(self):
  with patch.object(m.sys,'platform','win32'):
   with self.assertRaises(ValueError):self.planned()
  with patch.object(m.sys,'platform','linux'):
   self.env.pop('CLINE_ANDROID_ISOLATION_ACK')
   with self.assertRaises(ValueError):self.planned()
 def test_wrong_bun_pin_rejected(self):
  with patch.object(m.sys,'platform','linux'),patch.object(m.shutil,'which',return_value='/owned/bun'),patch.object(m.subprocess,'run',return_value=SimpleNamespace(stdout='1.3.13\n')),patch.object(m.ssl,'SSLContext'):
   with self.assertRaises(ValueError):self.planned()
if __name__=='__main__':unittest.main()
