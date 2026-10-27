"""Strict host-owned profiles; these validations never execute the target."""
import hashlib,json,re,struct
from pathlib import Path
PROFILES_FILE=Path(__file__).with_name('profiles.json')
PROFILES=json.loads(PROFILES_FILE.read_text())['profiles']
PROFILE_SHA256=hashlib.sha256(PROFILES_FILE.read_bytes()).hexdigest()

def validate_elf(data,engine,architecture):
 if engine not in PROFILES or architecture not in PROFILES[engine]['architectures']:raise ValueError('Unsupported engine/architecture')
 if not 64<=len(data)<=16777216 or data[:4]!=b'\x7fELF' or data[5:7]!=b'\x01\x01':raise ValueError('Bounded little-endian ELF required')
 bits=32 if architecture=='arm32' else 64;machine={'arm32':40,'arm64':183,'x86_64':62}[architecture]
 if data[4]!=(1 if bits==32 else 2) or struct.unpack_from('<H',data,18)[0]!=machine:raise ValueError('ELF architecture mismatch')
 kind=struct.unpack_from('<H',data,16)[0]
 if kind!=(2 if engine=='qiling' else 3):raise ValueError('Unsupported ELF type')
 if bits==64:entry,phoff=struct.unpack_from('<QQ',data,24);phsize,phnum=struct.unpack_from('<HH',data,54)
 else:entry,phoff=struct.unpack_from('<II',data,24);phsize,phnum=struct.unpack_from('<HH',data,42)
 if phsize!=(56 if bits==64 else 32) or not 1<=phnum<=64 or phoff+phnum*phsize>len(data):raise ValueError('Invalid program headers')
 total=0;loaded=False;exec_entry=False
 for i in range(phnum):
  at=phoff+i*phsize
  if bits==64:typ,flags,offset,addr,_,filesz,memsz,align=struct.unpack_from('<IIQQQQQQ',data,at)
  else:typ,offset,addr,_,filesz,memsz,flags,align=struct.unpack_from('<IIIIIIII',data,at)
  if typ in ([2,3,7] if engine=='qiling' else [3,7]):raise ValueError('Unsupported interpreter, dynamic or TLS profile')
  if typ==1:
   if filesz>memsz or offset+filesz>len(data) or memsz>67108864:raise ValueError('ELF load range over budget')
   total+=memsz;loaded=True;exec_entry|=bool(flags&1 and addr<=entry<addr+filesz)
  if typ==2 and engine!='qiling':
   step=16 if bits==64 else 8
   if filesz>1048576 or offset+filesz>len(data) or filesz%step:raise ValueError('Invalid dynamic table')
   for d in range(offset,offset+filesz,step):
    tag=struct.unpack_from('<Q' if bits==64 else '<I',data,d)[0]
    if tag==0:break
    if tag==1:raise ValueError('External DT_NEEDED dependencies unsupported by v1 profile')
 if not loaded or total>67108864 or (engine=='qiling' and not exec_entry):raise ValueError('Unsupported mapped image/entry')
 return {'architecture':architecture,'mappedBytes':total,'entry':hex(entry)}

def scenario(value,engine):
 if not isinstance(value,dict):raise ValueError('Scenario object required')
 if engine=='qiling':
  if set(value)-{'kind','expectedExit'} or value.get('kind')!='entry' or ('expectedExit' in value and (type(value['expectedExit']) is not int or not 0<=value['expectedExit']<=255)):raise ValueError('Invalid entry scenario')
 elif value.get('kind')=='initialize':
  if set(value)!={'kind'}:raise ValueError('Initialization takes no options')
 else:
  if set(value)-{'kind','className','methodName','argument','expectedReturn'} or not {'kind','className','methodName','argument'}<=set(value) or value['kind']!='jni-int32':raise ValueError('Invalid JNI scenario')
  if not isinstance(value['className'],str) or len(value['className'])>200 or not re.fullmatch('[A-Za-z][A-Za-z0-9]*(/[A-Za-z][A-Za-z0-9]*)*',value['className']) or not isinstance(value['methodName'],str) or not re.fullmatch('[A-Za-z][A-Za-z0-9]{0,79}',value['methodName']):raise ValueError('Simple exact JNI class/method required')
  for name in ['argument','expectedReturn']:
   if name in value and (type(value[name]) is not int or not -2147483648<=value[name]<=2147483647):raise ValueError('Int32 only')
 return value
