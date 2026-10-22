"""Speakeasy collector. Runs only inside an operator-provisioned disposable VM.
No command line, script, hook, mounted host path or network configuration comes
from the model. Native emulator dependencies are NOT a containment boundary.
"""
import hashlib, importlib.metadata, json, os, resource, struct, sys
from pathlib import Path

def collect(request):
    if sys.platform!='linux' or os.environ.get('CLINE_RE_ISOLATED_WORKER')!='disposable-network-disabled':
        raise ValueError('Operator must provision and acknowledge disposable network-disabled Linux isolation')
    resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_FSIZE,(8*1024**2,8*1024**2))
    resource.setrlimit(resource.RLIMIT_CPU,(110,115))
    artifact=Path(request['artifact'])
    with artifact.open('rb') as f:data=f.read(16*1024**2+1)
    if len(data)>16*1024**2 or data[:2]!=b'MZ' or hashlib.sha256(data).hexdigest()!=request['artifactSha256']:
        raise ValueError('Approved bounded PE identity required')
    if len(data)<256:raise ValueError('Truncated PE')
    pe=struct.unpack_from('<I',data,0x3c)[0]
    if pe<64 or pe+24+112>len(data) or data[pe:pe+4]!=b'PE\0\0':raise ValueError('Unsupported PE headers')
    machine=struct.unpack_from('<H',data,pe+4)[0];magic=struct.unpack_from('<H',data,pe+24)[0]
    if (machine,magic) not in [(0x14c,0x10b),(0x8664,0x20b)] or struct.unpack_from('<H',data,pe+24+68)[0] not in [2,3]:raise ValueError('Only x86/x64 user-mode PE images are supported; no drivers')
    import speakeasy
    version=importlib.metadata.version('speakeasy-emulator')
    if version!='1.5.11':raise ValueError('Unreviewed Speakeasy version')
    emulator=speakeasy.Speakeasy()
    module=emulator.load_module(str(artifact))
    # Default entry only: no arbitrary exports, drivers, shellcode or hooks.
    emulator.run_module(module,all_entrypoints=False)
    raw=emulator.get_report()
    if not isinstance(raw,dict):raise ValueError('Invalid emulator report')
    entries=raw.get('entry_points',[])
    if not isinstance(entries,list) or not entries:raise ValueError('No emulated entry-point evidence')
    rows=[];truncated=False
    for entry in entries[:8]:
        if not isinstance(entry,dict):continue
        apis=entry.get('apis',[])
        if not isinstance(apis,list):continue
        for call in apis:
            if len(rows)>=200:truncated=True;break
            if not isinstance(call,dict):continue
            rows.append({'api':str(call.get('api_name','unknown'))[:200],'arguments':str(call.get('args',[]))[:1000],'return':str(call.get('ret_val','unknown'))[:200]})
    if len(entries)>8:truncated=True
    return {'status':'partial','engineVersion':version,'apiCalls':rows,'entrypointCount':len(entries),'truncated':truncated,'memoryBoundary':{'kind':'rlimit-address-space','bytes':2*1024**3,'hard':True},'limitations':['Modeled Windows behavior only; not an observed Windows machine.','Default entry only. Missing APIs, hidden code and unvisited behavior remain unknown.','Emulation is not a sandbox; isolation and disabled networking are operator responsibilities.']}

if __name__=='__main__':
    try:print(json.dumps(collect(json.load(sys.stdin)),separators=(',',':')))
    except Exception:
        print(json.dumps({'status':'failed','limitations':['Collector failed or exceeded a resource limit; no successful behavior claim.']}))
        sys.exit(1)
