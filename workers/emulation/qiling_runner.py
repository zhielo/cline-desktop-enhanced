"""Fixed Qiling profile. Not a host isolation boundary."""
import hashlib,importlib.metadata,tempfile

# Linux syscall numbers are architecture-specific. Never forward other guest calls.
SYSCALLS={'x86_64':{'write':1,'exit':60,'exit_group':231},'arm32':{'write':4,'exit':1,'exit_group':248},'arm64':{'write':64,'exit':93,'exit_group':94}}

def run(artifact,limit,architecture):
 if importlib.metadata.version('qiling')!='1.4.6' or importlib.metadata.version('unicorn')!='2.1.4':raise ValueError('Unreviewed Qiling runtime')
 from qiling import Qiling
 from qiling.const import QL_VERBOSE,QL_ARCH
 calls=SYSCALLS[architecture]
 rows=[];captured=bytearray();reason='instruction-or-engine-stop';count=0;exit_code=None;truncated=False
 with tempfile.TemporaryDirectory(prefix='cline-qiling-empty-') as guest:
  ql=Qiling([str(artifact)],guest,verbose=QL_VERBOSE.OFF,console=False,env={});original=ql.os.load_syscall
  if ql.arch.type!={'x86_64':QL_ARCH.X8664,'arm32':QL_ARCH.ARM,'arm64':QL_ARCH.ARM64}[architecture]:raise ValueError('Qiling architecture differs from admitted ELF')
  def record(name,args,result):
   nonlocal truncated
   if len(rows)<200:rows.append({'api':name,'arguments':args[:1000],'return':str(result)[:200]})
   else:truncated=True
  def write(q,fd,buf,size):
   nonlocal reason,truncated
   if fd not in [1,2]:reason='unsupported-write-fd';record('write',f'fd={fd}','unsupported');q.emu_stop();return -1
   if size>65536-len(captured):reason='output-budget';truncated=True;q.emu_stop();return -1
   data=bytes(q.mem.read(buf,size));captured.extend(data);record('write',f'fd={fd}; bytes={size}; sha256={hashlib.sha256(data).hexdigest()}',size);return size
  def finish(q,code):
   nonlocal reason,exit_code
   reason='exit';exit_code=int(code)&255;record('exit',f'code={exit_code}',0);q.emu_stop();return 0
  ql.os.set_syscall(calls['write'],write);ql.os.set_syscall(calls['exit'],finish);ql.os.set_syscall(calls['exit_group'],finish)
  def dispatch():
   nonlocal reason
   number=ql.os.get_syscall()
   if number not in calls.values():reason='unsupported-syscall';record(f'syscall-{number}','not executed','unsupported');ql.emu_stop();return
   original()
  def step(q,address,size):
   nonlocal count
   count+=1
  ql.os.load_syscall=dispatch;ql.hook_code(step);ql.run(timeout=1000000,count=limit)
 return {'engineVersion':'1.4.6','backend':'unicorn-2.1.4','stopReason':reason,'exitCode':exit_code,'instructionCount':count,'apiCalls':rows,'truncated':truncated,'capturedBytes':len(captured),'capturedSha256':hashlib.sha256(captured).hexdigest()}
