"""Authenticated signed transport for the fixed Speakeasy collector.
Run ONLY behind operator TLS in a disposable, network-disabled Linux VM.
This service does not create a VM or attest hardware isolation.
"""
import base64, hashlib, hmac, importlib.metadata, json, os, re, signal, sqlite3, subprocess, sys, tempfile, threading, time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
MAX_INPUT=16*1024**2; MAX_BODY=23*1024**2; MAX_RESULT=1024**2

def encoded(value):return json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()
def duplicate_safe(pairs):
    result={}
    for k,v in pairs:
        if k in result:raise ValueError('Duplicate JSON key')
        result[k]=v
    return result

def validate(value):
    allowed={'protocol','nonce','requestHash','artifactSha256','network','operation','timeoutMs','maxOutputBytes','artifactBase64'}
    if not isinstance(value,dict) or set(value)!=allowed:raise ValueError('Invalid job fields')
    if value['protocol']!='cline-analysis-job/v1' or value['operation']!='emulate_windows' or value['network']!='disabled':raise ValueError('Unsupported execution')
    for name,size in [('nonce',32),('requestHash',64),('artifactSha256',64)]:
        if not isinstance(value[name],str) or not re.fullmatch('[a-f0-9]{'+str(size)+'}',value[name]):raise ValueError('Invalid binding')
    if type(value['timeoutMs']) is not int or not 1000<=value['timeoutMs']<=120000 or value['maxOutputBytes']!=MAX_RESULT:raise ValueError('Invalid limits')
    if not isinstance(value['artifactBase64'],str) or len(value['artifactBase64'])>4*((MAX_INPUT+2)//3):raise ValueError('Input budget')
    data=base64.b64decode(value['artifactBase64'],validate=True)
    if not 64<=len(data)<=MAX_INPUT or data[:2]!=b'MZ' or hashlib.sha256(data).hexdigest()!=value['artifactSha256']:raise ValueError('Invalid PE identity')
    return data

def runtime_identity():
    h=hashlib.sha256(Path(__file__).with_name('collector.py').read_bytes())
    h.update(Path(__file__).read_bytes());h.update(Path(__file__).with_name('requirements.txt').read_bytes())
    h.update(sys.version.encode());h.update(hashlib.sha256(Path(sys.executable).read_bytes()).digest())
    for name in ['attrs','capstone','cffi','cryptography','jsonschema','jsonschema-specifications','lznt1','pefile','pycparser','pycryptodome','referencing','rpds-py','setuptools','speakeasy-emulator','unicorn']:
        dist=importlib.metadata.distribution(name);h.update((name+dist.version).encode())
        for file in sorted(dist.files or [],key=str):
            path=Path(dist.locate_file(file))
            if path.is_file() and path.suffix not in ['.pyc']:
                h.update(str(file).encode()+b'\0');h.update(str(path.stat().st_size).encode()+b'\0')
                with path.open('rb') as f:
                    for part in iter(lambda:f.read(65536),b''):h.update(part)
    return h.hexdigest()

class Worker:
    def __init__(self,root,key,token,worker_id,execute=None,runtime=None):
        self.root=Path(root).resolve();self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
        if not isinstance(key,Ed25519PrivateKey) or not isinstance(token,str) or len(token)<32 or not re.fullmatch('[A-Za-z0-9_.-]{1,128}',worker_id):raise ValueError('Invalid identity')
        self.key,self.token,self.worker_id=key,token,worker_id
        self.verify_runtime=execute is None;self.execute=execute or self.collect;self.runtime=runtime or runtime_identity();self.upload_lock=threading.Lock();self.lock=threading.Lock();self.processes={};self.state_lock=threading.Lock();self.cancelled=set()
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS jobs(nonce TEXT PRIMARY KEY,identity TEXT,status TEXT,result BLOB,created REAL)')
            db.execute("UPDATE jobs SET status='interrupted' WHERE status='running'")
    @contextmanager
    def db(self):
        db=sqlite3.connect(self.root/'jobs.sqlite',timeout=5)
        try:
            with db:yield db
        finally:db.close()
    def signed(self,value,key='receipt'):return {key:value,'signature':base64.b64encode(self.key.sign(encoded(value))).decode()}
    def manifest(self):
        iso=lambda n:time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(n));now=time.time()
        return self.signed({'workerId':self.worker_id,'version':'speakeasy-1.5.11-v1','protocol':'cline-analysis-worker/v1','isolation':'remote-vm','ephemeralSnapshots':True,'networkModes':['disabled'],'maxArtifactBytes':MAX_INPUT,'issuedAt':iso(now),'expiresAt':iso(now+120),'operations':['speakeasy-windows-emulation'],'runtimeSha256':self.runtime},'manifest')
    def result(self,nonce):
        with self.db() as db:row=db.execute('SELECT status,result,created FROM jobs WHERE nonce=?',(nonce,)).fetchone()
        if not row:return 404,{'error':'Unknown nonce'}
        if row[0] in ['running','interrupted','expired'] or row[2]<time.time()-3600:return 409,{'error':'Pending, interrupted or expired; never replayed'}
        return 200,json.loads(row[1])
    def cancel(self,nonce):
        with self.db() as db:row=db.execute('SELECT status FROM jobs WHERE nonce=?',(nonce,)).fetchone()
        if not row:return 404,{'error':'Unknown nonce'}
        with self.state_lock:
            if row[0]=='running':
                self.cancelled.add(nonce)
                process=self.processes.get(nonce)
                if process and process.poll() is None:
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
        return 200,self.signed({'protocol':'cline-analysis-cancel/v1','workerId':self.worker_id,'nonce':nonce,'status':'cancellation-requested' if row[0]=='running' else row[0],'replay':'blocked'})
    def job(self,value):
        data=validate(value);nonce=value['nonce'];identity=hashlib.sha256(encoded(value)).hexdigest()
        if not self.lock.acquire(False):return 409,{'error':'Busy; no new execution'}
        try:
            with self.db() as db:
                old=db.execute('SELECT identity FROM jobs WHERE nonce=?',(nonce,)).fetchone()
                if old:
                    if old[0]!=identity:return 409,{'error':'Nonce conflict'}
                    return self.result(nonce)
                db.execute("UPDATE jobs SET status='expired',result=NULL WHERE created<? AND status!='running'",(time.time()-3600,))
                if db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0]>=4096 or db.execute('SELECT COALESCE(SUM(length(result)),0) FROM jobs').fetchone()[0]>32*MAX_RESULT:return 429,{'error':'Retention budget reached; explicit operator maintenance required'}
                db.execute('INSERT INTO jobs VALUES(?,?,?,?,?)',(nonce,identity,'running',None,time.time()))
            try:
                if self.verify_runtime and runtime_identity()!=self.runtime:raise ValueError('Runtime identity changed')
                observations=self.execute(value,data)
                if not isinstance(observations,dict) or observations.get('status') not in ['partial','failed']:raise ValueError('Invalid collector status')
                rows=observations.get('apiCalls',[]);limits=observations.get('limitations',[])
                if not isinstance(rows,list) or len(rows)>200 or any(not isinstance(r,dict) or set(r)!={'api','arguments','return'} or any(not isinstance(v,str) or len(v)>1000 for v in r.values()) for r in rows):raise ValueError('Invalid API rows')
                if not isinstance(limits,list) or len(limits)>50 or any(not isinstance(s,str) or len(s)>1000 for s in limits):raise ValueError('Invalid limitations')
                if observations['status']=='partial' and (observations.get('engineVersion')!='1.5.11' or observations.get('memoryBoundary',{}).get('hard') is not True):raise ValueError('Missing runtime evidence')
            except Exception:
                observations={'status':'failed','limitations':['Worker collector failed or was interrupted; no successful execution claim.']}
            with self.state_lock:
                cancelled=nonce in self.cancelled;self.cancelled.discard(nonce)
            if cancelled:observations={'status':'failed','limitations':['Cancelled; partial output discarded. No automatic replay.']}
            receipt={'protocol':'cline-analysis-job/v1','workerId':self.worker_id,'nonce':nonce,'requestHash':value['requestHash'],'artifactSha256':value['artifactSha256'],'network':'disabled','status':observations['status'],'engine':'speakeasy','runtimeSha256':self.runtime,'evidence':observations,'limitations':observations.get('limitations',[])}
            result=self.signed(receipt)
            if len(encoded(result))>MAX_RESULT:raise ValueError('Receipt budget exceeded')
            with self.db() as db:db.execute('UPDATE jobs SET status=?,result=? WHERE nonce=?',(observations['status'],encoded(result),nonce))
            return 200,result
        finally:self.lock.release()
    def collect(self,value,data):
        with tempfile.TemporaryDirectory(prefix='cline-emulation-') as tmp:
            artifact=Path(tmp)/'approved.bin';artifact.write_bytes(data)
            env={k:v for k,v in os.environ.items() if k in ['PATH','LANG','LC_ALL']};env.update(CLINE_RE_ISOLATED_WORKER='disposable-network-disabled',HOME=tmp)
            process=subprocess.Popen([sys.executable,'-I','-B',str(Path(__file__).with_name('collector.py'))],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,cwd=tmp,env=env,start_new_session=True)
            with self.state_lock:
                self.processes[value['nonce']]=process
                if value['nonce'] in self.cancelled:os.killpg(process.pid,signal.SIGKILL)
            output=bytearray();overflow=threading.Event()
            def drain():
                for chunk in iter(lambda:process.stdout.read(65536),b''):
                    if len(output)+len(chunk)>MAX_RESULT:
                        overflow.set()
                        if process.poll() is None:os.killpg(process.pid,signal.SIGKILL)
                        return
                    output.extend(chunk)
            reader=threading.Thread(target=drain,daemon=True);reader.start()
            try:
                process.stdin.write(encoded({'artifact':str(artifact),'artifactSha256':value['artifactSha256']}));process.stdin.close()
                process.wait(timeout=value['timeoutMs']/1000)
                reader.join(2)
                if process.returncode or overflow.is_set() or reader.is_alive():raise ValueError('Collector exited or output exceeded limits')
                return json.loads(output,object_pairs_hook=duplicate_safe)
            finally:
                if process.poll() is None:os.killpg(process.pid,signal.SIGKILL)
                process.wait(timeout=5);reader.join(2);process.stdout.close()
                with self.state_lock:self.processes.pop(value['nonce'],None)

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def handle_request(self):
        self.connection.settimeout(130)
        auth=self.headers.get_all('Authorization') or []
        if len(auth)!=1 or not hmac.compare_digest(auth[0],'Bearer '+self.server.worker.token):return self.reply(401,{'error':'Unauthorized'})
        path=self.path
        try:
            if self.command=='GET' and path=='/v1/capabilities':return self.reply(200,self.server.worker.manifest())
            match=re.fullmatch('/v1/jobs/([a-f0-9]{32})',path)
            if match and self.command in ['GET','DELETE']:
                status,body=self.server.worker.result(match[1]) if self.command=='GET' else self.server.worker.cancel(match[1]);return self.reply(status,body)
            if self.command!='POST' or path!='/v1/jobs':return self.reply(404,{'error':'Unsupported route'})
            if not self.server.worker.upload_lock.acquire(False):return self.reply(409,{'error':'Upload busy; no new execution'})
            try:
                sizes=self.headers.get_all('Content-Length') or []
                if len(sizes)!=1 or self.headers.get('Transfer-Encoding'):raise ValueError('Unambiguous length required')
                size=int(sizes[0])
                if not 0<size<=MAX_BODY:raise ValueError('Request budget')
                raw=self.rfile.read(size)
                if len(raw)!=size:raise ValueError('Truncated request')
                value=json.loads(raw,object_pairs_hook=duplicate_safe);status,body=self.server.worker.job(value);self.reply(status,body)
            finally:self.server.worker.upload_lock.release()
        except Exception:self.reply(400,{'error':'Invalid or rejected request; no success claimed'})
    def reply(self,status,body):
        raw=encoded(body);self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
    do_GET=handle_request;do_POST=handle_request;do_DELETE=handle_request

if __name__=='__main__':
    if sys.platform!='linux' or os.environ.get('CLINE_RE_ISOLATED_WORKER')!='disposable-network-disabled':raise SystemExit('Provision a disposable network-disabled Linux VM and TLS first')
    key=load_pem_private_key(Path(os.environ['CLINE_RE_WORKER_KEY_FILE']).read_bytes(),password=None)
    worker=Worker(os.environ['CLINE_RE_WORKER_STATE'],key,os.environ['CLINE_RE_WORKER_TOKEN'],os.environ.get('CLINE_RE_WORKER_ID','speakeasy-worker'))
    server=ThreadingHTTPServer(('127.0.0.1',int(os.environ.get('CLINE_RE_WORKER_PORT','8766'))),Handler);server.worker=worker;server.serve_forever()
