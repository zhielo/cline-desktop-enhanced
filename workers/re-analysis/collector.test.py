import hashlib, json, os, pathlib, struct, subprocess, sys, tempfile, unittest

def owned_pe():
 data=bytearray(1024);data[:2]=b'MZ';struct.pack_into('<I',data,0x3c,0x80);data[0x80:0x84]=b'PE\0\0'
 struct.pack_into('<HHIIIHH',data,0x84,0x8664,1,0,0,0,240,0x22)
 o=0x98;struct.pack_into('<H',data,o,0x20b);struct.pack_into('<I',data,o+4,0x200);struct.pack_into('<I',data,o+16,0x1000);struct.pack_into('<I',data,o+20,0x1000);struct.pack_into('<Q',data,o+24,0x140000000);struct.pack_into('<II',data,o+32,0x1000,0x200);struct.pack_into('<HH',data,o+40,6,0);struct.pack_into('<HH',data,o+48,6,0);struct.pack_into('<II',data,o+56,0x2000,0x200);struct.pack_into('<HH',data,o+68,3,0x100);struct.pack_into('<QQQQ',data,o+72,0x100000,0x1000,0x100000,0x1000);struct.pack_into('<I',data,o+108,16)
 s=o+240;data[s:s+8]=b'.text\0\0\0';struct.pack_into('<IIII',data,s+8,6,0x1000,0x200,0x200);struct.pack_into('<I',data,s+36,0x60000020);data[0x200:0x206]=bytes.fromhex('b801000000c3')
 return bytes(data)
def owned_api_pe():
 # Owned minimal PE64 imports one benign modeled API. No compiler or target download.
 data=bytearray(owned_pe())+bytearray(512)
 struct.pack_into('<H',data,0x86,2)
 o=0x98;struct.pack_into('<I',data,o+56,0x3000);struct.pack_into('<II',data,o+120,0x2000,40)
 section=o+240+40;data[section:section+8]=b'.idata\0\0';struct.pack_into('<IIII',data,section+8,0x200,0x2000,0x200,0x400);struct.pack_into('<I',data,section+36,0xc0000040)
 struct.pack_into('<IIIII',data,0x400,0x2040,0,0,0x2080,0x2060)
 struct.pack_into('<Q',data,0x440,0x20a0);struct.pack_into('<Q',data,0x460,0x20a0)
 data[0x480:0x48d]=b'kernel32.dll\0';data[0x4a0:0x4af]=b'\0\0GetTickCount\0'
 code=bytes.fromhex('ff155a100000b801000000c3');data[0x200:0x200+len(code)]=code
 struct.pack_into('<I',data,o+240+8,len(code))
 return bytes(data)
class CollectorTests(unittest.TestCase):
 def invoke(self,data,env):
  with tempfile.TemporaryDirectory() as tmp:
   path=pathlib.Path(tmp)/'owned.exe';path.write_bytes(data)
   return subprocess.run([sys.executable,'-I',str(pathlib.Path(__file__).with_name('collector.py'))],input=json.dumps({'artifact':str(path),'artifactSha256':hashlib.sha256(data).hexdigest()}).encode(),capture_output=True,timeout=30,env={**os.environ,**env})
 def test_no_isolation_ack_fails_before_emulation(self):
  run=self.invoke(owned_pe(),{'CLINE_RE_ISOLATED_WORKER':''});self.assertNotEqual(run.returncode,0);self.assertEqual(json.loads(run.stdout)['status'],'failed')
 @unittest.skipUnless(os.environ.get('CLINE_TEST_REAL_SPEAKEASY')=='1','Explicit real-engine owned acceptance')
 def test_real_owned_pe_entry_was_emulated(self):
  run=self.invoke(owned_pe(),{'CLINE_RE_ISOLATED_WORKER':'disposable-network-disabled'})
  self.assertEqual(run.returncode,0,run.stderr.decode());result=json.loads(run.stdout);self.assertEqual(result['status'],'partial');self.assertEqual(result['engineVersion'],'1.5.11');self.assertGreater(result['entrypointCount'],0);self.assertTrue(result['memoryBoundary']['hard'])
 @unittest.skipUnless(os.environ.get('CLINE_TEST_REAL_SPEAKEASY')=='1','Explicit real-engine owned acceptance')
 def test_real_owned_api_call_is_reported_as_model_evidence(self):
  run=self.invoke(owned_api_pe(),{'CLINE_RE_ISOLATED_WORKER':'disposable-network-disabled'})
  self.assertEqual(run.returncode,0,run.stderr.decode());result=json.loads(run.stdout)
  self.assertTrue(any('GetTickCount' in row['api'] for row in result['apiCalls']),result)
  self.assertEqual(result['status'],'partial')
if __name__=='__main__':unittest.main()
