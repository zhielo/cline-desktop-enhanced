"""Fixed specialist adapters. No model-supplied programs, queries, hooks or shell.
The OS resource boundary is not a malware sandbox. Speakeasy runs ONLY in the
operator's isolated worker via its fixed collector, never this desktop entry.
"""
import hashlib, importlib.metadata as metadata, json, os, re, subprocess, sys, tempfile
from pathlib import Path

PROTOCOL = 'cline-advanced-analysis/v1'
MAX_INPUT = 1024 * 1024
MAX_OUTPUT = 1024 * 1024
JOBS = []  # Keep Windows Job handles alive until process exit.

class Blocked(Exception): pass

def bounded_int(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('Integer outside supported budget')
    return value

def fields(value, allowed):
    if not isinstance(value, dict) or set(value) - set(allowed):
        raise ValueError('Unknown or invalid specialist options')
    return value

def memory_boundary():
    """Fail closed if an enforceable per-job address/commit limit is unavailable."""
    if sys.platform == 'linux':
        import resource
        # RLIMIT_AS also covers inherited child virtual address spaces, not RSS.
        resource.setrlimit(resource.RLIMIT_AS, (8 * 1024**3, 8 * 1024**3))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024**2, 64 * 1024**2))
        resource.setrlimit(resource.RLIMIT_CPU, (240, 245))
        return {'kind': 'rlimit-address-space', 'bytes': 8 * 1024**3, 'hard': True}
    if sys.platform == 'win32':
        import ctypes
        from ctypes import wintypes
        class BASIC(ctypes.Structure):
            _fields_ = [('processTime',ctypes.c_int64),('jobTime',ctypes.c_int64),('flags',wintypes.DWORD),('minWorkingSet',ctypes.c_size_t),('maxWorkingSet',ctypes.c_size_t),('activeProcesses',wintypes.DWORD),('affinity',ctypes.c_size_t),('priority',wintypes.DWORD),('scheduling',wintypes.DWORD)]
        class IO(ctypes.Structure):
            _fields_ = [(n,ctypes.c_uint64) for n in ['readOps','writeOps','otherOps','readBytes','writeBytes','otherBytes']]
        class EXTENDED(ctypes.Structure):
            _fields_ = [('basic',BASIC),('io',IO),('processMemory',ctypes.c_size_t),('jobMemory',ctypes.c_size_t),('peakProcessMemory',ctypes.c_size_t),('peakJobMemory',ctypes.c_size_t)]
        k = ctypes.WinDLL('kernel32',use_last_error=True)
        k.CreateJobObjectW.argtypes=[ctypes.c_void_p,wintypes.LPCWSTR]; k.CreateJobObjectW.restype=wintypes.HANDLE
        k.GetCurrentProcess.restype=wintypes.HANDLE
        k.SetInformationJobObject.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD]
        k.AssignProcessToJobObject.argtypes=[wintypes.HANDLE,wintypes.HANDLE]
        k.CloseHandle.argtypes=[wintypes.HANDLE]
        handle=k.CreateJobObjectW(None,None)
        limits=EXTENDED(); limits.basic.flags=0x2000|0x200  # kill on close + job memory
        limits.jobMemory=2 * 1024**3
        if not handle or not k.SetInformationJobObject(handle,9,ctypes.byref(limits),ctypes.sizeof(limits)) or not k.AssignProcessToJobObject(handle,k.GetCurrentProcess()):
            if handle:k.CloseHandle(handle)
            raise Blocked('Windows Job memory containment unavailable')
        JOBS.append(handle)
        return {'kind':'windows-job-commit','bytes':2 * 1024**3,'hard':True}
    raise Blocked('Specialist engines require tested Linux or Windows resource enforcement')

def read_input(target, maximum=MAX_INPUT):
    p=Path(target)
    if not p.is_absolute() or not p.is_file(): raise ValueError('Absolute regular input required')
    with p.open('rb') as f: data=f.read(maximum+1)
    if not data or len(data)>maximum: raise ValueError('Specialist input is empty or over budget')
    return data

def symbolic(data, options):
    fields(options, ['symbolic'])
    o=fields(options.get('symbolic'),['entry','find','avoid','register','minimum','maximum','max_steps','max_states'])
    if len(data)>65536: raise ValueError('Selected raw x86_64 bytes only, at most 64 KiB')
    base=0x100000
    entry=bounded_int(o.get('entry',base),base,base+len(data)-1)
    find=bounded_int(o.get('find'),base,base+len(data)-1)
    avoid=o.get('avoid',[])
    if not isinstance(avoid,list) or len(avoid)>16: raise ValueError('At most 16 avoid addresses')
    avoid=[bounded_int(v,base,base+len(data)-1) for v in avoid]
    if find in avoid: raise ValueError('Find address conflicts with avoid')
    reg=o.get('register','rdi')
    if reg not in ['rdi','rsi','rdx','rcx','r8','r9']: raise ValueError('Unsupported symbolic register')
    low=bounded_int(o.get('minimum',0),0,2**32-1); high=bounded_int(o.get('maximum',255),low,2**32-1)
    steps=bounded_int(o.get('max_steps',128),1,1024); states=bounded_int(o.get('max_states',32),1,128)
    import angr, claripy
    project=angr.load_shellcode(data,arch='amd64',load_address=base)
    state=project.factory.blank_state(addr=entry,add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,angr.options.STRICT_PAGE_ACCESS})
    value=claripy.BVS('approved_input',64);setattr(state.regs,reg,value)
    state.solver.add(claripy.UGE(value,low),claripy.ULE(value,high))
    sim=project.factory.simgr(state); found=None; reason='step-budget'; executed=0
    for _ in range(steps):
        # Keep execution inside the supplied code; never load host libraries or hooks.
        sim.move(from_stash='active',to_stash='avoided',filter_func=lambda s: s.addr in avoid)
        sim.move(from_stash='active',to_stash='escaped',filter_func=lambda s: not base<=s.addr<base+len(data))
        match=next((s for s in sim.active if s.addr==find),None)
        if match is not None: found=match;reason='found';break
        if len(sim.active)>states: reason='state-budget';break
        if not sim.active: reason='no-active-states';break
        sim.step(num_inst=1);executed+=1
    result={'outcome':reason,'steps':executed,'activeStates':len(sim.active),'errors':len(sim.errored),'unconstrainedStates':len(sim.unconstrained),'escapedStates':len(sim.stashes.get('escaped',[])),'entry':entry,'find':find,'register':reg,'minimum':low,'maximum':high,'loadAddress':base,'candidate':None,'constraints':[]}
    if found is not None:
        result['candidate']=found.solver.eval(value)
        result['constraints']=[str(c)[:1000] for c in found.solver.constraints[:32]]
    result['assumptions']=['Raw AMD64 region, synthetic base 0x100000; not a PE/ELF loader.','One symbolic 64-bit argument; other registers start zero. No ABI, stack or library model.','Uninitialized memory and path errors can underconstrain or truncate analysis; candidate is model-specific, not verified native behavior.','No-path and exhausted budgets are inconclusive, not proof of unreachability.']
    return result,metadata.version('angr')

def verified_joern():
    root=Path(os.environ.get('CLINE_JOERN_HOME',''))
    expected=os.environ.get('CLINE_JOERN_MANIFEST_SHA256','')
    if not root.is_absolute() or not re.fullmatch('[a-f0-9]{64}',expected): raise Blocked('Configure a reviewed Joern home and pinned manifest SHA256')
    manifest=root/'cline-runtime.json';raw=read_input(str(manifest))
    if hashlib.sha256(raw).hexdigest()!=expected: raise Blocked('Joern runtime manifest identity changed')
    m=fields(json.loads(raw),['version','files'])
    if not isinstance(m.get('version'),str) or not 1<=len(m['version'])<=100 or not isinstance(m.get('files'),dict) or not 1<=len(m['files'])<=20000: raise ValueError('Invalid Joern manifest')
    actual=set()
    for p in root.rglob('*'):
        if p.is_symlink(): raise Blocked('Joern runtime must not contain symlinks')
        if p.is_file() and p!=manifest:actual.add(p.relative_to(root).as_posix())
    if actual!=set(m['files']): raise Blocked('Joern runtime file inventory changed')
    for name,digest in m['files'].items():
        if not isinstance(digest,str) or not re.fullmatch('[a-f0-9]{64}',digest): raise ValueError('Invalid file digest')
        h=hashlib.sha256()
        with (root/name).open('rb') as f:
            for chunk in iter(lambda:f.read(65536),b''):h.update(chunk)
        if h.hexdigest()!=digest:raise Blocked('Joern runtime file identity changed')
    suffix='.bat' if sys.platform=='win32' else ''
    if suffix:raise Blocked('Joern Windows batch launch is not reviewed; use an isolated Linux worker/runtime')
    for name in ['joern','joern-parse','jdk/bin/java']:
        if name not in actual:raise Blocked('Joern needs pinned launchers and a bundled compatible JDK')
    return root,m['version'],expected

# Query choices are host-owned source, never interpolated Scala from the model.
JOERN_SCRIPT='''import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
@main def exec(cpgFile: String, query: String, selector: String, sink: String, limit: Int, out: String) = {
 importCpg(cpgFile)
 val rows = query match {
  case "callers" => cpg.call.filter(_.name == selector).take(limit + 1).map(n => ujson.Obj("name" -> n.name, "code" -> n.code, "line" -> n.lineNumber.getOrElse(-1), "file" -> n.method.filename)).l
  case "references" => cpg.identifier.filter(_.name == selector).take(limit + 1).map(n => ujson.Obj("name" -> n.name, "code" -> n.code, "line" -> n.lineNumber.getOrElse(-1), "file" -> n.method.filename)).l
  case "source-sink" => cpg.call.filter(_.name == sink).argument.reachableByFlows(cpg.call.filter(_.name == selector)).take(limit + 1).map(p => ujson.Obj("path" -> ujson.Arr.from(p.elements.map(n => ujson.Obj("code" -> n.code, "line" -> n.lineNumber.getOrElse(-1)))))).l
  case _ => throw new IllegalArgumentException("Unknown fixed query")
 }
 os.write.over(os.Path(out),ujson.write(ujson.Obj("rows" -> ujson.Arr.from(rows.take(limit)), "truncated" -> (rows.size > limit))))
}'''

def joern(data, options, limit):
    fields(options,['joern']);o=fields(options.get('joern'),['language','query','selector','sink','input_basis'])
    language=o.get('language');query=o.get('query');selector=o.get('selector');sink=o.get('sink','')
    if language not in ['javascript','java'] or query not in ['callers','references','source-sink']:raise ValueError('Unsupported Joern language/query')
    if not isinstance(selector,str) or not re.fullmatch('[A-Za-z_$][A-Za-z0-9_.$]{0,127}',selector):raise ValueError('Exact identifier selector required')
    if query=='source-sink' and (not isinstance(sink,str) or not re.fullmatch('[A-Za-z_$][A-Za-z0-9_.$]{0,127}',sink)):raise ValueError('Exact sink selector required')
    basis=o.get('input_basis','source')
    if basis not in ['source','decompiler-output']:raise ValueError('Invalid source basis')
    data.decode('utf8')
    root,version,identity=verified_joern()
    with tempfile.TemporaryDirectory(prefix='cline-joern-') as tmp:
        work=Path(tmp);src=work/'src';src.mkdir();(src/('Input.java' if language=='java' else 'input.js')).write_bytes(data)
        script=work/'fixed.sc';script.write_text(JOERN_SCRIPT)
        cpg=work/'cpg.bin';out=work/'result.json'
        env={k:v for k,v in os.environ.items() if k in ['PATH','SYSTEMROOT','TMPDIR','TEMP','TMP']}
        env.update(JAVA_HOME=str(root/'jdk'),JAVA_OPTS='-Xmx512m -XX:MaxMetaspaceSize=256m',HOME=tmp)
        for argv in [[str(root/'joern-parse'),str(src),'--language','JAVASCRIPT' if language=='javascript' else 'JAVASRC','--output',str(cpg)],[str(root/'joern'),'--script',str(script),'--param',f'cpgFile={cpg}','--param',f'query={query}','--param',f'selector={selector}','--param',f'sink={sink}','--param',f'limit={limit}','--param',f'out={out}']]:
            # Discard engine diagnostics; only bounded structured evidence is returned.
            with open(os.devnull, 'wb') as log:
                run=subprocess.run(argv,cwd=tmp,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=log,timeout=90)
                if run.returncode:raise Blocked('Pinned Joern parser/query failed; validate this distribution against owned fixtures')
        result=json.loads(read_input(str(out),MAX_OUTPUT//2))
        fields(result,['rows','truncated'])
        if not isinstance(result.get('rows'),list) or len(result['rows'])>limit or type(result.get('truncated')) is not bool:raise ValueError('Invalid Joern evidence')
        return {'query':query,'language':language,'inputBasis':basis,'runtimeSha256':identity,**result,'coverage':'single-source-file; unresolved calls and missing paths remain unknown'},version

def run(request):
    fields(request,['action','target','options','limit'])
    action=request.get('action');options=request.get('options') or {};limit=bounded_int(request.get('limit',100),1,200)
    readiness=action=='specialist_readiness'
    if readiness:
        if request.get('target') is not None:raise ValueError('Owned readiness never accepts a target')
        fields(options,['specialist_readiness']); r=fields(options.get('specialist_readiness'),['engine']); engine=r.get('engine')
        if engine=='angr':
            data=bytes.fromhex('4883ff2a7506b801000000c331c0c3');action='angr_symbolic';options={'symbolic':{'find':0x100006,'avoid':[0x10000c]}}
        elif engine=='joern':
            data=b'function ownedFixture(x) { return x; }\nownedFixture(42);';action='joern_query';options={'joern':{'language':'javascript','query':'callers','selector':'ownedFixture'}}
        else:raise ValueError('Unknown readiness engine')
    else:
        if action not in ['angr_symbolic','joern_query']:raise ValueError('Unsupported specialist action')
        data=read_input(request.get('target',''))
    input_id={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'format':'raw-amd64' if action=='angr_symbolic' else 'source'}
    boundary=memory_boundary()
    evidence,version=symbolic(data,options) if action=='angr_symbolic' else joern(data,options,limit)
    if readiness:
        if action=='angr_symbolic' and evidence.get('candidate')!=42:raise ValueError('Owned symbolic fixture failed')
        if action=='joern_query' and not evidence.get('rows'):raise ValueError('Owned Joern fixture returned no call')
        evidence['ownedFixturePassed']=True
        evidence['scope']='owned-fixture-only; not target compatibility'
    return {'protocol':PROTOCOL,'status':'completed' if readiness else 'partial','engine':'angr' if action=='angr_symbolic' else 'joern','engineVersion':version,'input':input_id,'evidence':{**evidence,'memoryBoundary':boundary},'limitations':['Selected bounded analysis only. No complete source recovery, whole-program flow or behavioral equivalence claim.']}

if __name__=='__main__':
    try:result=run(json.loads(sys.argv[1]))
    except (ImportError,Blocked) as e:result={'protocol':PROTOCOL,'status':'blocked','engine':'specialist','engineVersion':None,'evidence':{'reason':str(e)[:500]},'limitations':[]}
    except Exception as e:result={'protocol':PROTOCOL,'status':'failed','engine':'specialist','engineVersion':None,'evidence':{'reason':type(e).__name__+': '+str(e)[:500]},'limitations':[]}
    encoded=json.dumps(result,separators=(',',':'))
    if len(encoded.encode())>MAX_OUTPUT:encoded=json.dumps({'protocol':PROTOCOL,'status':'failed','engine':'specialist','engineVersion':None,'evidence':{'reason':'Output budget exceeded'},'limitations':[]})
    print(encoded)
