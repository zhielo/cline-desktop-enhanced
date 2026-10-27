"""Explicit owned engine acceptance, never an arbitrary downloaded target."""
import base64,hashlib,json,os,sys,tempfile,threading,time,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from server import Worker,transport
from contracts import PROFILE_SHA256
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
ENGINE=os.environ.get('CLINE_TEST_EMULATION_ENGINE')
@unittest.skipUnless(ENGINE in ['qiling','unidbg','rnidbg'],'Explicit real engine required')
class RealAcceptance(unittest.TestCase):
 def test_startup_signed_primitive_scenarios_replay_mismatch_budget_and_fresh_state(self):
  inventory=os.environ['CLINE_EMULATION_INVENTORY'];m=json.loads(Path(inventory).read_text());key=Ed25519PrivateKey.generate()
  with tempfile.TemporaryDirectory() as d:
   w=Worker(d,key,'x'*32,'owned-'+ENGINE,ENGINE,inventory);index=0
   for arch,file in m['fixtures'].items():
    data=Path(file).read_bytes();s={'kind':'entry','expectedExit':7} if ENGINE=='qiling' else {'kind':'jni-int32','className':'com/cline/Owned','methodName':'transform','argument':42,'expectedReturn':134}
    def job(scenario=s,limit=10000):
     nonlocal index
     index+=1;return {'protocol':'cline-analysis-job/v1','operation':'emulate_profile','nonce':f'{index:032x}','requestHash':'b'*64,'artifactSha256':hashlib.sha256(data).hexdigest(),'network':'disabled','timeoutMs':15000,'maxOutputBytes':1048576,'artifactBase64':base64.b64encode(data).decode(),'engine':ENGINE,'architecture':arch,'scenario':scenario,'instructionLimit':limit,'profileSha256':PROFILE_SHA256,'runtimeSha256':w.runtime}
    positive=job();status,body=w.job(positive);self.assertEqual(status,200);r=body['receipt'];self.assertEqual(r['status'],'partial',r);self.assertEqual(r['evidence']['scenarioCheck'],'passed',r);self.assertEqual(r['evidence']['outcome'],'unverified');key.public_key().verify(base64.b64decode(body['signature']),transport.encoded(r));self.assertEqual(w.job(positive)[1],body)
    original=data
    denied=Path(file).with_name('denied-x64' if arch=='x86_64' else 'denied-'+arch+'.so')
    data=denied.read_bytes();r=w.job(job())[1]['receipt'];self.assertEqual(r['evidence'].get('stopReason'),'unsupported-syscall',r);self.assertNotEqual(r['evidence'].get('scenarioCheck'),'passed',r);data=original
    wrong=dict(s,**({'expectedExit':8} if ENGINE=='qiling' else {'expectedReturn':135}));r=w.job(job(wrong))[1]['receipt'];self.assertEqual(r['evidence']['scenarioCheck'],'failed',r)
    r=w.job(job(limit=1))[1]['receipt'];self.assertNotEqual(r['evidence'].get('scenarioCheck'),'passed',r)
    if ENGINE!='qiling':
     r=w.job(job(dict(s,methodName='missing')))[1]['receipt'];self.assertEqual(r['status'],'failed',r)
    r=w.job(job())[1]['receipt'];self.assertEqual(r['evidence']['scenarioCheck'],'passed',r);self.assertEqual(w.processes,{})
    # Cancellation targets the owned process group, not merely the HTTP request.
    pending=job();result=[];thread=threading.Thread(target=lambda:result.append(w.job(pending)));thread.start();deadline=time.monotonic()+8
    while pending['nonce'] not in w.processes and thread.is_alive() and time.monotonic()<deadline:time.sleep(.005)
    if thread.is_alive() and pending['nonce'] in w.processes:
     self.assertEqual(w.cancel(pending['nonce'])[0],200);thread.join(8);self.assertFalse(thread.is_alive());self.assertEqual(result[0][1]['receipt']['status'],'failed');self.assertEqual(w.processes,{})
    else:thread.join();self.fail('Could not observe owned collector to test cancellation')
if __name__=='__main__':unittest.main()
