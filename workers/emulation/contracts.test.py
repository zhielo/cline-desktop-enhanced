import base64,copy,hashlib,json,os,struct,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from contracts import PROFILES,PROFILE_SHA256,scenario,validate_elf
from server import Worker,transport
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def elf(arch='arm64',engine='unidbg'):
 b=bytearray(128);b[:7]=b'\x7fELF\x02\x01\x01';struct.pack_into('<HH',b,16,2 if engine=='qiling' else 3,183 if arch=='arm64' else 62);struct.pack_into('<QQ',b,24,0x1000,64);struct.pack_into('<HH',b,54,56,1);struct.pack_into('<IIQQQQQQ',b,64,1,5,0,0x1000,0,128,128,4096);return bytes(b)
class Contracts(unittest.TestCase):
 def test_admission_and_strict_typed_scenarios(self):
  self.assertEqual(validate_elf(elf(),'unidbg','arm64')['mappedBytes'],128)
  for e,a in [('rnidbg','arm32'),('unidbg','x86_64'),('qiling','arm64')]:
   with self.assertRaises(ValueError):validate_elf(elf(),e,a)
  for value in [{'kind':'jni-int32','className':'com/a','methodName':'m','argument':True},{'kind':'initialize','rootfs':'/'},{'kind':'entry','script':'x'}]:
   with self.assertRaises(ValueError):scenario(value,'qiling' if value['kind']=='entry' else 'unidbg')
 def test_missing_and_external_dependencies_rejected(self):
  for mutate in [lambda b:b.__setitem__(5,2),lambda b:struct.pack_into('<I',b,64,3),lambda b:struct.pack_into('<Q',b,104,67108865),lambda b:struct.pack_into('<Q',b,96,129)]:
   b=bytearray(elf());mutate(b)
   with self.assertRaises(ValueError):validate_elf(bytes(b),'unidbg','arm64')
 def test_signed_contract_no_replay_and_per_engine_identity(self):
  with tempfile.TemporaryDirectory() as d:
   key=Ed25519PrivateKey.generate();calls=[]
   def execute(*args):calls.append(1);return {'status':'partial','engine':'unidbg','outcome':'unverified','memoryBoundary':{'hard':True},'limitations':[]}
   w=Worker(d,key,'x'*32,'owned','unidbg','unused',execute=execute,runtime='f'*64)
   data=elf();v={'protocol':'cline-analysis-job/v1','operation':'emulate_profile','nonce':'a'*32,'requestHash':'b'*64,'artifactSha256':hashlib.sha256(data).hexdigest(),'network':'disabled','timeoutMs':1000,'maxOutputBytes':1048576,'artifactBase64':base64.b64encode(data).decode(),'engine':'unidbg','architecture':'arm64','scenario':{'kind':'initialize'},'instructionLimit':10000,'profileSha256':PROFILE_SHA256,'runtimeSha256':'f'*64}
   _,r=w.job(v);self.assertEqual(r['receipt']['status'],'partial');key.public_key().verify(base64.b64decode(r['signature']),transport.encoded(r['receipt']));self.assertEqual(w.job(v)[1],r);self.assertEqual(len(calls),1)
   for change in [{'engine':'rnidbg'},{'profileSha256':'c'*64},{'runtimeSha256':'c'*64},{'instructionLimit':True},{'network':'recorded'},{'scenario':{'kind':'initialize','hook':'x'}},{'script':'x'}]:
    with self.assertRaises(ValueError):w.job(dict(v,**change))
   self.assertEqual(len(calls),1)
 def test_false_completed_outcome_fails_closed(self):
  with tempfile.TemporaryDirectory() as d:
   w=Worker(d,Ed25519PrivateKey.generate(),'x'*32,'owned','qiling','unused',execute=lambda *_:{},runtime='f'*64)
   with self.assertRaises(ValueError):w.validate_observations({'status':'completed'})
   with self.assertRaises(ValueError):w.validate_observations({'status':'partial','engine':'qiling','outcome':'verified','memoryBoundary':{'hard':True}})
if __name__=='__main__':unittest.main()
