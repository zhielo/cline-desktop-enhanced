#!/usr/bin/env python3
"""Offline reviewed Rizin packs. No downloads, caller commands or target execution."""
import argparse, hashlib, json, os, platform, re, shutil, stat, subprocess, sys, tarfile, tempfile, time, uuid, zipfile
from pathlib import Path

MAX_EXPANDED = 1024 * 1024 * 1024
MAX_MEMBERS = 4096
CATALOG = {
 'rizin-0.9.1-linux-x64': {'platform':'linux','arch':'x86_64','kind':'tar.xz','bytes':137626404,'sha256':'9102249a9f0b6319c5334a2e5cf8d9cc3f2035e1d3def027c41f6a90f647e8cf','entry':'bin/rizin','url':'https://github.com/rizinorg/rizin/releases/download/v0.9.1/rizin-v0.9.1-static-x86_64.tar.xz'},
 'rizin-0.9.1-windows-x64': {'platform':'win32','arch':'x86_64','kind':'zip','bytes':11731171,'sha256':'45ffa004e26653eaee8d262b8e6eeae09402a7d319c1f20a2ba794bd6af1cc28','entry':'rizin-win-installer-clang_cl-64/bin/rizin.exe','url':'https://github.com/rizinorg/rizin/releases/download/v0.9.1/rizin-windows-shared64-v0.9.1.zip'},
}
LICENSES = {'COPYING':'8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903','COPYING.LESSER':'da7eabb7bafdf7d3ae5e9f223aa5bdc1eece45ac569dc21b3b037520b4464768'}

def sha(path):
 h=hashlib.sha256()
 with open(path,'rb') as f:
  for b in iter(lambda:f.read(1048576),b''): h.update(b)
 return h.hexdigest()

def safe_member(name):
 if not isinstance(name,str) or len(name)>1024 or '\\' in name or ':' in name or '\x00' in name or name.startswith('/'):
  raise ValueError('Unsafe archive member')
 parts=name.rstrip('/').split('/')
 if not parts or any(not x or x in ('.','..') or x.endswith((' ','.')) or re.match(r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)',x,re.I) for x in parts):
  raise ValueError('Unsafe archive member')
 return '/'.join(parts)

def private_root(value):
 p=Path(value)
 if not p.is_absolute(): raise ValueError('Absolute host-owned pack root required')
 p.mkdir(mode=0o700,parents=True,exist_ok=True)
 if p.is_symlink() or p.resolve()!=p: raise ValueError('Canonical non-symlink pack root required')
 s=p.stat()
 if os.name!='nt' and (s.st_uid!=os.getuid() or s.st_mode & 0o077): raise ValueError('Private owner-only pack root required')
 return p

def registry(root):
 p=root/'active.json'
 if not p.exists(): return {'schemaVersion':1,'active':None,'history':[]}
 if p.is_symlink() or p.stat().st_size>65536: raise ValueError('Invalid active registry')
 d=json.loads(p.read_text())
 if set(d)!= {'schemaVersion','active','history'} or d['schemaVersion']!=1 or not isinstance(d['history'],list) or len(d['history'])>16: raise ValueError('Invalid active registry')
 for item in [d['active'],*d['history']]:
  if item is not None and (not isinstance(item,dict) or set(item)!={'packId','receiptSha256'} or item['packId'] not in CATALOG or not re.fullmatch('[a-f0-9]{64}',item['receiptSha256'])): raise ValueError('Invalid registry identity')
 return d

def publish(root,d):
 p=root/f'.active-{uuid.uuid4().hex}.tmp'
 try:
  with open(p,'x',encoding='utf8') as f:
   os.chmod(p,0o600);json.dump(d,f,sort_keys=True);f.flush();os.fsync(f.fileno())
  os.replace(p,root/'active.json')
 finally: p.unlink(missing_ok=True)

def current_spec(pack_id):
 spec=CATALOG[pack_id]
 arch=platform.machine().lower();arch='x86_64' if arch in ('amd64','x86_64') else arch
 if sys.platform!=spec['platform'] or arch!=spec['arch']: raise ValueError('Pack does not match host platform/architecture')
 return spec

def verify_revision(root,identity):
 spec=current_spec(identity['packId']);rev=root/'revisions'/identity['packId'];receipt=rev/'receipt.json'
 if (root/'revisions').is_symlink() or (rev/'payload').is_symlink() or rev.resolve()!=rev: raise ValueError('Revision path links forbidden')
 if rev.is_symlink() or receipt.is_symlink() or receipt.stat().st_size>1048576 or sha(receipt)!=identity['receiptSha256']: raise ValueError('Receipt integrity mismatch')
 d=json.loads(receipt.read_text()); files=d.get('files')
 if d.get('packId')!=identity['packId'] or d.get('archiveSha256')!=spec['sha256'] or d.get('entry')!=spec['entry'] or not isinstance(files,list) or len(files)>MAX_MEMBERS: raise ValueError('Invalid pack receipt')
 actual=[]
 for p in (rev/'payload').rglob('*'):
  if p.is_symlink() or not (p.is_dir() or p.is_file()): raise ValueError('Unexpected pack link or special file')
  if p.is_file(): actual.append(p.relative_to(rev/'payload').as_posix())
 expected=[]; total=0
 for item in files:
  name=safe_member(item['path']);expected.append(name);p=rev/'payload'/name;total+=item['bytes']
  if not p.is_file() or p.is_symlink() or p.stat().st_size!=item['bytes'] or sha(p)!=item['sha256']: raise ValueError('Installed pack file integrity mismatch')
 if total>MAX_EXPANDED or sorted(actual)!=sorted(expected) or len(set(expected))!=len(expected): raise ValueError('Installed pack inventory mismatch')
 return rev/'payload'/spec['entry']

def probe(engine,directory):
 # Only the reviewed engine is executed; the owned four-byte input is never executed.
 env={k:v for k,v in os.environ.items() if k.upper() in ('SYSTEMROOT','WINDIR','TEMP','TMP','PATH','LANG','LC_ALL')};env['PATH']=os.defpath
 def run(args):
  out=directory/'probe.out'
  with open(out,'wb') as f:
   p=subprocess.Popen([str(engine),*args],stdout=f,stderr=subprocess.DEVNULL,env=env,cwd=directory,start_new_session=os.name!='nt')
   deadline=time.monotonic()+10
   try:
    while p.poll() is None:
     if time.monotonic()>deadline or out.stat().st_size>65536: raise ValueError('Reviewed tool health budget exceeded')
     time.sleep(.02)
    if p.returncode or out.stat().st_size>65536: raise ValueError('Reviewed tool health failed')
   finally:
    if p.poll() is None:
     if os.name=='nt': subprocess.run([str(Path(os.environ.get('SystemRoot','C:\\Windows'))/'System32/taskkill.exe'),'/pid',str(p.pid),'/t','/f'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
     else:
      try: os.killpg(p.pid,9)
      except ProcessLookupError: pass
     p.wait(timeout=5)
  text=out.read_text();out.unlink();return text
 if not re.search(r'^rizin 0\.9\.1\b',run(['-v']),re.M): raise ValueError('Reviewed tool version mismatch')
 fixture=directory/'owned-bytes.bin';fixture.write_bytes(bytes([1,2,3,4]))
 try:
  if json.loads(run(['-NN','-q','-2','-x','-c','pxj 4',str(fixture)]))!=[1,2,3,4]: raise ValueError('Owned static fixture health mismatch')
 finally: fixture.unlink(missing_ok=True)
 return {'version':'0.9.1','ownedStaticBytes':True,'targetExecuted':False}

def extract_reviewed(archive,spec,payload):
 names=set();total=0;count=0;files=[];deadline=time.monotonic()+180
 def add(name,size,is_dir,source,mode):
  nonlocal total,count
  name=safe_member(name);key=name.casefold();count+=1
  if key in names or count>MAX_MEMBERS or size<0: raise ValueError('Duplicate or oversized archive inventory')
  names.add(key);total+=size
  if total>MAX_EXPANDED: raise ValueError('Archive expansion budget exceeded')
  p=payload/name
  if is_dir: p.mkdir(mode=0o700,parents=True,exist_ok=True);return
  if mode & 0o6000: raise ValueError('Privileged archive mode forbidden')
  p.parent.mkdir(mode=0o700,parents=True,exist_ok=True);h=hashlib.sha256();written=0
  with open(p,'xb') as dest:
   os.chmod(p,0o600)
   for b in iter(lambda:source.read(1048576),b''):
    if time.monotonic()>deadline: raise ValueError('Extraction deadline exceeded')
    written+=len(b)
    if written>size: raise ValueError('Archive member size mismatch')
    h.update(b);dest.write(b)
  if written!=size: raise ValueError('Archive member truncated')
  files.append({'path':name,'bytes':written,'sha256':h.hexdigest()})
 if spec['kind']=='tar.xz':
  with tarfile.open(archive,'r:xz') as t:
   for m in t:
    if not (m.isfile() or m.isdir()): raise ValueError('Archive links and special files forbidden')
    if m.isfile():
     with t.extractfile(m) as source: add(m.name,m.size,False,source,m.mode)
    else: add(m.name,0,True,None,m.mode)
 else:
  with zipfile.ZipFile(archive) as z:
   for m in z.infolist():
    mode=m.external_attr>>16;kind=stat.S_IFMT(mode)
    if m.flag_bits & 1 or (m.create_system==3 and kind not in (0,stat.S_IFREG,stat.S_IFDIR)): raise ValueError('Encrypted or linked ZIP member forbidden')
    if m.is_dir(): add(m.filename,0,True,None,mode)
    else:
     with z.open(m) as source: add(m.filename,m.file_size,False,source,mode)
 return files

def import_pack(root,pack_id,archive,confirm_install=False,confirm_execution=False):
 if not confirm_install or not confirm_execution: raise ValueError('Explicit install and reviewed-tool execution approvals required')
 root=private_root(root);spec=current_spec(pack_id);lock=root/'.install.lock';token=uuid.uuid4().hex
 fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.write(fd,token.encode());os.close(fd)
 stage=None
 try:
  old=registry(root)
  revisions=root/'revisions';revisions.mkdir(mode=0o700,exist_ok=True)
  if revisions.is_symlink(): raise ValueError('Revision directory link forbidden')
  final=revisions/pack_id
  if final.exists(): raise ValueError('Immutable pack revision already exists; use status or rollback')
  stage=Path(tempfile.mkdtemp(prefix='.stage-',dir=root));snapshot=stage/'archive';archive=Path(archive)
  if not archive.is_absolute() or archive.is_symlink(): raise ValueError('Absolute regular archive required')
  fd=os.open(archive,os.O_RDONLY|(getattr(os,'O_NOFOLLOW',0)));h=hashlib.sha256();count=0
  with os.fdopen(fd,'rb') as src,open(snapshot,'xb') as dest:
   before=os.fstat(src.fileno())
   if not stat.S_ISREG(before.st_mode) or before.st_size!=spec['bytes']: raise ValueError('Reviewed archive size mismatch')
   for b in iter(lambda:src.read(1048576),b''):
    count+=len(b)
    if count>spec['bytes']: raise ValueError('Archive grew while copying')
    h.update(b);dest.write(b)
   after=os.fstat(src.fileno())
   if count!=before.st_size or before.st_size!=after.st_size or before.st_mtime_ns!=after.st_mtime_ns or h.hexdigest()!=spec['sha256']: raise ValueError('Reviewed archive hash mismatch')
  payload=stage/'payload';payload.mkdir(mode=0o700);files=extract_reviewed(snapshot,spec,payload);snapshot.unlink()
  license_root=Path(__file__).resolve().parent.parent/'docs/vendor/rizin-0.9.1';notices=payload/'CLINE-UPSTREAM-NOTICES';notices.mkdir(mode=0o700)
  for name,expected in LICENSES.items():
   source=license_root/name
   if sha(source)!=expected: raise ValueError('Bundled upstream notice integrity mismatch')
   shutil.copyfile(source,notices/name);os.chmod(notices/name,0o600);files.append({'path':f'CLINE-UPSTREAM-NOTICES/{name}','bytes':source.stat().st_size,'sha256':expected})
  engine=payload/spec['entry']
  if not engine.is_file() or engine.is_symlink(): raise ValueError('Expected reviewed engine missing')
  if os.name!='nt': os.chmod(engine,0o700)
  health=probe(engine,stage)
  receipt={'schemaVersion':1,'packId':pack_id,'archiveSha256':spec['sha256'],'entry':spec['entry'],'sourceUrl':spec['url'],'health':health,'files':sorted(files,key=lambda x:x['path']),'licenseNotice':'Upstream GPLv3 and LGPLv3 texts retained; component-specific notices control. Not permission to redistribute without compliance.'}
  (stage/'receipt.json').write_text(json.dumps(receipt,sort_keys=True));os.chmod(stage/'receipt.json',0o600)
  identity={'packId':pack_id,'receiptSha256':sha(stage/'receipt.json')};stage.rename(final);stage=None
  verify_revision(root,identity);publish(root,{'schemaVersion':1,'active':identity,'history':([*old['history'],old['active']])[-16:]})
  return {'packId':pack_id,'entry':str(final/'payload'/spec['entry']),'health':health,'archiveSha256':spec['sha256']}
 finally:
  if stage is not None: shutil.rmtree(stage)
  if lock.exists() and not lock.is_symlink() and lock.read_text()==token: lock.unlink()

def rollback(root,confirmed=False):
 if not confirmed: raise ValueError('Explicit activation change approval required')
 root=private_root(root);lock=root/'.install.lock';token=uuid.uuid4().hex
 fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.write(fd,token.encode());os.close(fd)
 try:
  d=registry(root)
  if not d['history']: raise ValueError('No rollback checkpoint')
  previous=d['history'][-1]
  if previous is not None: verify_revision(root,previous)
  publish(root,{'schemaVersion':1,'active':previous,'history':d['history'][:-1]})
  return {'active':previous,'retainedRevisions':True}
 finally:
  if lock.exists() and not lock.is_symlink() and lock.read_text()==token: lock.unlink()

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=['catalog','import','status','rollback']);p.add_argument('--root');p.add_argument('--pack-id',choices=CATALOG);p.add_argument('--archive');p.add_argument('--confirm-install',action='store_true');p.add_argument('--confirm-reviewed-tool-execution',action='store_true');a=p.parse_args()
 if a.operation=='catalog': result=CATALOG
 elif not a.root: raise ValueError('Host-owned root required')
 elif a.operation=='import':
  if not a.pack_id or not a.archive: raise ValueError('Reviewed pack ID and archive required')
  result=import_pack(a.root,a.pack_id,a.archive,a.confirm_install,a.confirm_reviewed_tool_execution)
 elif a.operation=='rollback': result=rollback(a.root,a.confirm_install)
 else:
  root=private_root(a.root);d=registry(root);result={'active':d['active'],'entry':str(verify_revision(root,d['active'])) if d['active'] else None,'integrityChecked':True,'healthIsImportTimeOnly':True}
 print(json.dumps(result,sort_keys=True))
if __name__=='__main__':
 try: main()
 except Exception as e: print(json.dumps({'status':'failed','reason':str(e)}),file=sys.stderr);sys.exit(1)
