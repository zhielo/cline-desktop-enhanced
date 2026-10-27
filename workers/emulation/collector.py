"""Fixed per-engine collector; disposable offline Linux VM mandatory."""
import hashlib,json,os,resource,subprocess,sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from contracts import scenario,validate_elf
from runtime_inventory import identity

LIMITATIONS=['Modeled scenario only, not native behavior or a target-safety verdict.','No APK, external ELF dependencies, user scripts, custom JNI stubs, network or persistent guest state.','VM isolation is operator-provisioned; this collector does not establish or attest it.']
def run(value,inventory):
 engine=value['engine'];_hash,m=identity(inventory,engine);artifact=Path(value['artifact']);data=artifact.read_bytes()
 if hashlib.sha256(data).hexdigest()!=value['artifactSha256']:raise ValueError('Artifact changed')
 validate_elf(data,engine,value['architecture']);s=scenario(value['scenario'],engine)
 result={'status':'partial','engine':engine,'architecture':value['architecture'],'limitations':LIMITATIONS,'memoryBoundary':{'hard':True,'processAddressSpaceBytes':8*1024**3},'outcome':'unverified'}
 if engine=='qiling':
  from qiling_runner import run as qrun
  evidence=qrun(artifact,value['instructionLimit'],value['architecture']);result.update(evidence)
  if evidence['stopReason']=='exit' and 'expectedExit' in s:result['scenarioCheck']='passed' if evidence['exitCode']==s['expectedExit'] else 'failed'
 else:
  with tempfile.TemporaryDirectory(prefix='cline-jni-empty-') as root:
   output=Path(root)/'receipt.json';guest=Path(root)/'rootfs';guest.mkdir()
   args=[str(artifact),str(guest)]
   if engine=='unidbg':args.append(value['architecture'])
   args += [s['kind'],s.get('className',''),s.get('methodName',''),str(s.get('argument',0)),str(output),str(value['instructionLimit'])]
   cmd=([m['java'],'--enable-native-access=ALL-UNNAMED','-Xmx256m','-XX:ReservedCodeCacheSize=64m','-XX:CompressedClassSpaceSize=64m','-cp',m['classpath'],'ClineRunner'] if engine=='unidbg' else [m['runner']])+args
   # The parent worker owns the entire process group and hard timeout/cancellation.
   proc=subprocess.run(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,cwd=root,env={'PATH':'/usr/bin:/bin','HOME':root,'LANG':'C.UTF-8'},check=False)
   if proc.returncode in [75,76]:return {'status':'failed','outcome':'unverified','stopReason':'instruction-budget' if proc.returncode==75 else 'unsupported-syscall','limitations':LIMITATIONS+['The isolated adapter was terminated at its fixed instruction/syscall boundary; no guest return accepted.']}
   if proc.returncode or not output.is_file() or output.stat().st_size>4096:raise ValueError('Adapter failed; no success inferred')
   evidence=json.loads(output.read_bytes());expected_backend='unicorn2' if engine=='unidbg' else 'pinned-unicorn-fork'
   if set(evidence)!={'initialized','returnValue','backend','instructionCount'} or evidence['initialized'] is not True or evidence['backend']!=expected_backend or type(evidence['instructionCount']) is not int or not 0<evidence['instructionCount']<=value['instructionLimit']:raise ValueError('Invalid adapter evidence')
   if s['kind']=='jni-int32' and (type(evidence['returnValue']) is not int or not -2147483648<=evidence['returnValue']<=2147483647):raise ValueError('Invalid JNI return')
   result.update(evidence,engineVersion='0.9.9' if engine=='unidbg' else '06251628767c577a0579ee8c2b834ed688393bfd',stopReason='scenario-return',apiCalls=[{'api':'JNI_OnLoad','arguments':'fixed modeled VM','return':'initialized'}])
   if 'expectedReturn' in s:result['scenarioCheck']='passed' if evidence['returnValue']==s['expectedReturn'] else 'failed'
 # Even a matching primitive fixture is not whole-app verification.
 if identity(inventory,engine)[0]!=_hash:raise ValueError('Runtime changed during execution')
 return result
if __name__=='__main__':
 try:
  if sys.platform!='linux' or os.environ.get('CLINE_RE_ISOLATED_WORKER')!='disposable-network-disabled':raise ValueError('Isolated Linux worker required')
  resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_AS,(8*1024**3,8*1024**3));resource.setrlimit(resource.RLIMIT_FSIZE,(64*1024**2,64*1024**2));resource.setrlimit(resource.RLIMIT_NOFILE,(128,128))
  value=json.loads(sys.stdin.buffer.read(24*1024));result=run(value,os.environ['CLINE_EMULATION_INVENTORY'])
 except Exception:result={'status':'failed','outcome':'unverified','limitations':['Collector failed, unsupported target, budget exceeded or interrupted; no successful execution claim.']}
 sys.stdout.write(json.dumps(result,separators=(',',':')))
