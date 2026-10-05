"""Fixed collector, executed ONLY on the operator's isolated worker."""
import base64, hashlib, json, os, re, struct, subprocess, sys, threading, time, zlib
from pathlib import Path
import frida
MAX_CAPTURE=8*1024*1024
config=json.load(sys.stdin)
serial=os.environ.get('CLINE_ANDROID_DEVICE_SERIAL','')
if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',serial):raise SystemExit('An explicitly configured Android device ID is required')
adb=os.environ['CLINE_ANDROID_ADB'];analyzer=os.environ['CLINE_ANDROID_APKANALYZER']
def run(argv,timeout=30):return subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=timeout).stdout
actual=run([analyzer,'manifest','application-id',config['artifact']]).decode().strip()
if actual!=config['package']:raise SystemExit('APK package does not match approved package')
run([adb,'-s',serial,'install','-r',config['artifact']])
device=frida.get_device(serial,timeout=10)
artifacts=[];captures=[];registrations=[];events=[];limitations=['Signed worker observations are operator reports, not hardware attestation or complete execution coverage.','Only standard DEX from supported loader hooks is captured; encryption/key recovery, anti-instrumentation bypass and complete ART coverage are not claimed.','Native addresses without a captured module hash remain unresolved; no static binary identity is inferred.'];seen=set();total=0;lock=threading.Lock()
def message(value,data):
    global total
    if value.get('type')!='send':
        if len(limitations)<50:limitations.append('Instrumentation reported an error; coverage is partial.')
        return
    p=value.get('payload',{})
    with lock:
        if p.get('kind')=='registration':
            if len(registrations)<200:registrations.append(p['record'])
            return
        source=str(p.get('source',''))[:2048];timestamp=int(p.get('timestamp',time.time()*1000))
        if p.get('kind')=='dex' and config['captureDex']:
            try:
                raw=base64.b64decode(p['base64'],validate=True)
                if len(raw)<112 or len(raw)>2*1024*1024 or not re.match(rb'dex\n0(?:3[5-9]|40)\x00',raw) or struct.unpack_from('<I',raw,32)[0]!=len(raw) or hashlib.sha1(raw[32:]).digest()!=raw[12:32] or zlib.adler32(raw[12:])&0xffffffff!=struct.unpack_from('<I',raw,8)[0]:raise ValueError('Unsupported/integrity-invalid DEX capture')
                digest=hashlib.sha256(raw).hexdigest()
                if digest not in seen:
                    if total+len(raw)>MAX_CAPTURE:raise ValueError('Aggregate capture limit')
                    seen.add(digest);total+=len(raw);artifacts.append({'id':digest,'sha256':digest,'bytes':len(raw),'format':'dex','source':source});captures.append({'sha256':digest,'base64':base64.b64encode(raw).decode()})
            except Exception:
                if len(limitations)<50:limitations.append('A DEX capture was rejected by integrity/size limits.')
        elif len(events)<200:events.append({'kind':str(p.get('kind','event'))[:80],'source':source,'timestamp':timestamp})
pid=None;session=None
try:
    pid=device.spawn([config['package']]);session=device.attach(pid)
    source=Path(__file__).with_name('agent.js').read_text()
    script=session.create_script(source);script.on('message',message);script.load();script.exports_sync.configure(config['captureDex']);device.resume(pid)
    time.sleep(config['timeoutMs']/1000)
finally:
    if session:
        try:session.detach()
        except Exception:pass
    if pid:
        try:device.kill(pid)
        except Exception:pass
print(json.dumps({'status':'partial','artifacts':artifacts,'captures':captures,'registrations':registrations,'events':events,'limitations':limitations},ensure_ascii=False,separators=(',',':')))
