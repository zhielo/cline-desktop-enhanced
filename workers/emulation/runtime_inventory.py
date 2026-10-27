"""Operator-only sealing. Signatures identify this inventory, not VM isolation."""
import argparse,hashlib,importlib.metadata,json,os,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent

def digest(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
 return h.hexdigest()
def identity(path,engine):
 raw=Path(path).read_bytes()
 if len(raw)>4*1024*1024:raise ValueError('Inventory budget')
 m=json.loads(raw)
 if m.get('schemaVersion')!=1 or m.get('engine')!=engine or not isinstance(m.get('files'),dict) or not 1<=len(m['files'])<=20000:raise ValueError('Invalid inventory')
 for p,h in m['files'].items():
  if not Path(p).is_absolute() or digest(p)!=h:raise ValueError('Runtime file changed')
 for p in [ROOT/'server.py',ROOT/'collector.py',ROOT/'contracts.py',ROOT/'profiles.json',ROOT/'qiling_runner.py',ROOT/'runtime_inventory.py',ROOT.parent/'re-analysis/server.py']:
  if m['files'].get(str(p))!=digest(p):raise ValueError('Collector/profile not sealed')
 return hashlib.sha256(raw).hexdigest(),m

def seal(engine,python,java_home=None,unidbg_build=None,rnidbg_binary=None,fixtures=None):
 files={}
 def add(p):
  p=Path(p).resolve()
  if p.is_file() and p.suffix!='.pyc':files[str(p)]=digest(p)
 def tree(p):
  for f in sorted(Path(p).rglob('*')):
   if f.is_file() and 'site-packages' not in f.relative_to(p).parts:add(f)
 for f in ROOT.glob('*.py'):add(f)
 add(ROOT/'profiles.json');add(ROOT.parent/'re-analysis/server.py');add(python)
 # Seal interpreter standard library and installed dependencies in this interpreter.
 tree(Path(os.__file__).parent)
 for dist in importlib.metadata.distributions():
  for f in dist.files or []:add(dist.locate_file(f))
 result={'schemaVersion':1,'engine':engine,'python':str(Path(python).resolve()),'files':files,'rootfs':'generated-empty-no-host-mounts','hostIsolation':'operator-provisioned-not-attested'}
 if engine=='qiling':
  if importlib.metadata.version('qiling')!='1.4.6' or importlib.metadata.version('unicorn')!='2.1.4':raise ValueError('Pinned Qiling environment required')
 elif engine=='unidbg':
  java=Path(java_home).resolve();build=Path(unidbg_build).resolve();tree(java)
  for f in (build/'dependency').glob('*.jar'):add(f)
  tree(build/'classes')
  expected=(ROOT/'unidbg/dependencies.sha256').read_text().splitlines()
  if {f.name for f in (build/'dependency').glob('*.jar')}!={Path(row.split(maxsplit=1)[1].lstrip('*')).name for row in expected}:raise ValueError('Unexpected dependency closure')
  for row in expected:
   h,name=row.split(maxsplit=1);name=name.lstrip('*')
   if digest(build/'dependency'/Path(name).name)!=h:raise ValueError('Unidbg dependency mismatch')
  result.update(java=str(java/'bin/java'),classpath=str(build/'classes')+os.pathsep+str(build/'dependency/*'))
 elif engine=='rnidbg':
  add(rnidbg_binary);result['runner']=str(Path(rnidbg_binary).resolve())
 else:raise ValueError('Unknown engine')
 # Startup self-test binaries are operator-generated from owned checked-in fixtures.
 result['fixtures']={}
 for arch in (['x86_64'] if engine=='qiling' else ['arm32','arm64'] if engine=='unidbg' else ['arm64']):
  p=Path(fixtures)/('owned-x64' if arch=='x86_64' else 'owned-'+arch+'.so');add(p);result['fixtures'][arch]=str(p.resolve())
 return result
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('engine',choices=['qiling','unidbg','rnidbg']);p.add_argument('output');p.add_argument('--java-home');p.add_argument('--unidbg-build');p.add_argument('--rnidbg-binary');p.add_argument('--fixtures',required=True);a=p.parse_args()
 value=seal(a.engine,sys.executable,a.java_home,a.unidbg_build,a.rnidbg_binary,a.fixtures)
 Path(a.output).write_text(json.dumps(value,sort_keys=True,separators=(',',':')))
 print('Sealed runtime inventory:',a.engine,len(value['files']),'files')
