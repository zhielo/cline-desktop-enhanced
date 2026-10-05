"""Fixed, bounded authorized disk-module collection; not loaded-memory attestation."""
import base64, hashlib, re, subprocess, threading
MAX_MODULE=2*1024*1024
MAX_TOTAL=8*1024*1024

def authorized_module_path(package,path):
    if not isinstance(package,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+',package):return False
    if not isinstance(path,str) or len(path)>2048 or not re.fullmatch(r'/[A-Za-z0-9_./+=~-]+\.so',path) or any(part in ('.','..') for part in path.split('/')):return False
    return path.startswith(('/data/user/0/'+package+'/', '/data/data/'+package+'/')) or (path.startswith('/data/app/') and re.search('/'+re.escape(package)+r'(?:-[A-Za-z0-9_+=-]+)?/',path) is not None)

def bounded_command(argv,limit=MAX_MODULE,timeout=8):
    process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    timer=threading.Timer(timeout,lambda:process.kill() if process.poll() is None else None);timer.start()
    try:
        output=bytearray()
        while True:
            part=process.stdout.read(min(65536,limit+1-len(output)))
            if not part:break
            output.extend(part)
            if len(output)>limit:raise ValueError('Native module byte budget exceeded')
        process.wait(timeout=2)
        if process.returncode!=0:raise ValueError('Native module read failed/deadline')
        return bytes(output)
    finally:
        timer.cancel()
        if process.poll() is None:process.kill()
        process.wait(timeout=2);process.stdout.close()

def capture_modules(registrations,package,read,total=0):
    artifacts=[];captures=[];limitations=[];seen={};attempted=set()
    for row in registrations:
        path=row.get('module')
        if not authorized_module_path(package,path):continue
        if path in seen:
            row.update(moduleSha256=seen[path],moduleHashBasis='captured-disk-file-not-loaded-memory-proof');continue
        if path in attempted:continue
        if len(attempted)>=4:
            limitations.append('Native module count limit reached; coverage is partial.');break
        attempted.add(path)
        try:
            raw=read(path)
            if not isinstance(raw,bytes) or len(raw)<64 or len(raw)>MAX_MODULE or total+len(raw)>MAX_TOTAL or raw[:4]!=b'\x7fELF' or raw[4] not in (1,2) or raw[5] not in (1,2) or raw[6]!=1:raise ValueError('Invalid/oversized disk ELF')
            digest=hashlib.sha256(raw).hexdigest();seen[path]=digest
            row.update(moduleSha256=digest,moduleHashBasis='captured-disk-file-not-loaded-memory-proof')
            if not any(a['sha256']==digest for a in artifacts):
                total+=len(raw);artifacts.append({'id':digest,'sha256':digest,'bytes':len(raw),'format':'elf','source':path});captures.append({'sha256':digest,'base64':base64.b64encode(raw).decode()})
        except Exception:limitations.append('An authorized native disk module was unavailable, unsupported or over budget; identity remains unresolved.')
    return artifacts,captures,limitations

def physical_preflight(adb,serial,reader=bounded_command):
    if not isinstance(serial,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',serial):raise ValueError('Explicit physical serial required')
    def probe(args):return reader([adb,'-s',serial,*args],limit=4096,timeout=8).decode('utf-8').strip()
    if probe(['get-state'])!='device':raise ValueError('Physical device is offline or unauthorized')
    if probe(['get-serialno'])!=serial:raise ValueError('Physical serial mismatch')
    if probe(['shell','getprop','ro.kernel.qemu'])=='1':raise ValueError('Physical mode refuses emulator')
    if not re.search(r'(?:^|\s)uid=0(?:\(|\s|$)',probe(['exec-out','su','-c','id'])):raise ValueError('Root probe denied; review KernelSU authorization, no configuration changed')
    abi=probe(['shell','getprop','ro.product.cpu.abi'])
    if abi not in ('arm64-v8a','armeabi-v7a','x86','x86_64'):raise ValueError('Unsupported physical device ABI')
    return {'kind':'physical','deviceSerialSha256':hashlib.sha256(serial.encode()).hexdigest(),'abi':abi,'rootProbe':'uid0-reported','attestation':'not-proven'}
