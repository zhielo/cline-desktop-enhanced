"""Additive engine workers using the existing authenticated no-replay transport."""
import importlib.util,json,os,sys,time,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from contracts import PROFILE_SHA256,PROFILES,scenario,validate_elf
from runtime_inventory import identity
spec=importlib.util.spec_from_file_location('cline_re_transport',ROOT.parent/'re-analysis/server.py');transport=importlib.util.module_from_spec(spec);spec.loader.exec_module(transport)

class Worker(transport.Worker):
 def __init__(self,root,key,token,worker_id,engine,inventory,execute=None,runtime=None):
  if engine not in PROFILES:raise ValueError('Unknown engine')
  self.engine=engine;self.inventory=str(Path(inventory).resolve())
  super().__init__(root,key,token,worker_id,execute=execute,runtime=runtime)
  if execute is None:self.self_test()
 def runtime_identity(self):return identity(self.inventory,self.engine)[0]
 def collector_path(self):return ROOT/'collector.py'
 def collector_environment(self):return {'CLINE_EMULATION_INVENTORY':self.inventory}
 def collector_request(self,value,artifact):return {k:value[k] for k in ['engine','architecture','scenario','instructionLimit','artifactSha256']}|{'artifact':str(artifact)}
 def receipt_extra(self,value):return {k:value[k] for k in ['architecture','scenario','instructionLimit','profileSha256']}
 def validate(self,value):
  extra={'engine','architecture','scenario','instructionLimit','profileSha256','runtimeSha256'}
  if not isinstance(value,dict) or set(value)-extra != {'protocol','nonce','requestHash','artifactSha256','network','operation','timeoutMs','maxOutputBytes','artifactBase64'} or not extra<=set(value):raise ValueError('Exact profile request required')
  if value['engine']!=self.engine or value['profileSha256']!=PROFILE_SHA256 or value['runtimeSha256']!=self.runtime:raise ValueError('Worker/profile/runtime identity mismatch')
  if type(value['instructionLimit']) is not int or not 1<=value['instructionLimit']<=100000:raise ValueError('Instruction budget')
  scenario(value['scenario'],self.engine)
  base={k:v for k,v in value.items() if k not in extra}
  return transport.validate(base,'emulate_profile',lambda data:validate_elf(data,self.engine,value['architecture']))
 def manifest(self):
  if self.verify_runtime and self.runtime_identity()!=self.runtime:raise ValueError('Runtime changed; restart with an explicitly resealed profile')
  now=time.time();iso=lambda t:time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(t))
  return self.signed({'workerId':self.worker_id,'version':PROFILES[self.engine]['id'],'protocol':'cline-analysis-worker/v1','isolation':'remote-vm','ephemeralSnapshots':True,'networkModes':['disabled'],'maxArtifactBytes':transport.MAX_INPUT,'issuedAt':iso(now),'expiresAt':iso(now+120),'operations':['emulate-profile-'+self.engine],'engine':self.engine,'profileSha256':PROFILE_SHA256,'architectures':PROFILES[self.engine]['architectures'],'runtimeSha256':self.runtime,'isolationClaim':'operator-provisioned-not-hardware-attested'},'manifest')
 def validate_observations(self,observations):
  if not isinstance(observations,dict) or observations.get('status') not in ['partial','failed']:raise ValueError('Invalid status')
  if observations['status']=='partial':
   if observations.get('engine')!=self.engine or observations.get('outcome')!='unverified' or observations.get('memoryBoundary',{}).get('hard') is not True:raise ValueError('Missing modeled evidence')
   if observations.get('scenarioCheck') not in [None,'passed','failed']:raise ValueError('Invalid check')
  rows=observations.get('apiCalls',[])
  if not isinstance(rows,list) or len(rows)>200 or any(not isinstance(r,dict) or set(r)!={'api','arguments','return'} or any(not isinstance(v,str) or len(v)>1000 for v in r.values()) for r in rows):raise ValueError('Invalid rows')
  limits=observations.get('limitations',[])
  if not isinstance(limits,list) or len(limits)>50 or any(not isinstance(s,str) or len(s)>1000 for s in limits):raise ValueError('Invalid limitations')
 def self_test(self):
  _,m=identity(self.inventory,self.engine)
  if not isinstance(m.get('fixtures'),dict) or set(m['fixtures'])!=set(PROFILES[self.engine]['architectures']):raise ValueError('Owned startup fixtures must cover every advertised architecture')
  for architecture,artifact in m['fixtures'].items():
   data=Path(artifact).read_bytes()
   if m['files'].get(str(Path(artifact).resolve()))!=hashlib.sha256(data).hexdigest():raise ValueError('Startup fixture is not sealed')
   value={'engine':self.engine,'architecture':architecture,'artifactSha256':hashlib.sha256(data).hexdigest(),'scenario':{'kind':'entry','expectedExit':7} if self.engine=='qiling' else {'kind':'jni-int32','className':'com/cline/Owned','methodName':'transform','argument':42,'expectedReturn':134},'instructionLimit':10000,'timeoutMs':15000,'nonce':'0'*32}
   validate_elf(data,self.engine,architecture);evidence=self.collect(value,data);self.validate_observations(evidence)
   if self.engine=='qiling' and (evidence.get('capturedBytes')!=12 or evidence.get('capturedSha256')!=hashlib.sha256(b'cline-owned\n').hexdigest()):raise ValueError('Owned startup stdout check failed')
   if evidence.get('status')!='partial' or evidence.get('scenarioCheck')!='passed':raise ValueError('Owned startup self-test failed; worker must stay unavailable')

if __name__=='__main__':
 if sys.platform!='linux' or os.environ.get('CLINE_RE_ISOLATED_WORKER')!='disposable-network-disabled':raise SystemExit('Provision a disposable offline Linux VM and TLS first')
 key=transport.load_pem_private_key(Path(os.environ['CLINE_RE_WORKER_KEY_FILE']).read_bytes(),password=None)
 w=Worker(os.environ['CLINE_RE_WORKER_STATE'],key,os.environ['CLINE_RE_WORKER_TOKEN'],os.environ['CLINE_RE_WORKER_ID'],os.environ['CLINE_EMULATION_ENGINE'],os.environ['CLINE_EMULATION_INVENTORY'])
 server=transport.ThreadingHTTPServer(('127.0.0.1',int(os.environ.get('CLINE_RE_WORKER_PORT','8767'))),transport.Handler);server.worker=w;server.serve_forever()
