"""Fixed Qiling profile. Not a host isolation boundary."""
import hashlib,importlib.metadata,tempfile

def run(artifact,limit):
 if importlib.metadata.version('qiling')!='1.4.6' or importlib.metadata.version('unicorn')!='2.1.4':raise ValueError('Unreviewed Qiling runtime')
 from qiling import Qiling
 from qiling.const import QL_VERBOSE
 rows=[];captured=bytearray();reason='instruction-or-engine-stop';count=0;exit_code=None;truncated=False
 with tempfile.TemporaryDirectory(prefix='cline-qiling-empty-') as guest:
  ql=Qiling([str(artifact)],guest,verbose=QL_VERBOSE.OFF,console=False,env={});original=ql.os.load_syscall
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
  ql.os.set_syscall(1,write);ql.os.set_syscall(60,finish);ql.os.set_syscall(231,finish)
  def dispatch():
   nonlocal reason
   number=ql.os.get_syscall()
   if number not in [1,60,231]:reason='unsupported-syscall';record(f'syscall-{number}','not executed','unsupported');ql.emu_stop();return
   original()
  def step(q,address,size):
   nonlocal count
   count+=1
  ql.os.load_syscall=dispatch;ql.hook_code(step);ql.run(timeout=1000000,count=limit)
 return {'engineVersion':'1.4.6','backend':'unicorn-2.1.4','stopReason':reason,'exitCode':exit_code,'instructionCount':count,'apiCalls':rows,'truncated':truncated,'capturedBytes':len(captured),'capturedSha256':hashlib.sha256(captured).hexdigest()}
