"""Operator-provisioned isolated Android worker. Never deploy on the desktop host."""
import base64, hashlib, hmac, json, os, re, signal, sqlite3, ssl, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from contextlib import contextmanager
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
MAX_INPUT=16*1024*1024
MAX_OUTPUT=16*1024*1024
LOCK=threading.Lock()
def encoded(value):return json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
def duplicate_safe(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('Duplicate JSON key')
        result[key]=value
    return result
def validate_job(value):
    fields={'protocol','nonce','requestHash','artifactSha256','network','operation','packageName','captureDex','timeoutMs','artifactBase64'}
    if not isinstance(value,dict) or set(value)!=fields:raise ValueError('Invalid job fields')
    if value['protocol']!='cline-android-capture/v1' or value['operation']!='android_capture' or value['network']!='disabled':raise ValueError('Unsupported operation/network')
    for name,size in [('nonce',32),('requestHash',64),('artifactSha256',64)]:
        if not isinstance(value[name],str) or not re.fullmatch('[a-f0-9]{%d}'%size,value[name]):raise ValueError('Invalid identity')
    if not isinstance(value['packageName'],str) or len(value['packageName'])>200 or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+',value['packageName']):raise ValueError('Invalid package name')
    if type(value['captureDex']) is not bool or type(value['timeoutMs']) is not int or not 1000<=value['timeoutMs']<=120000:raise ValueError('Invalid capture budget')
    if not isinstance(value['artifactBase64'],str) or len(value['artifactBase64'])>22400000:raise ValueError('Upload limit')
    data=base64.b64decode(value['artifactBase64'],validate=True)
    if not data or len(data)>MAX_INPUT or hashlib.sha256(data).hexdigest()!=value['artifactSha256'] or not data.startswith(b'PK'):raise ValueError('APK identity/format mismatch')
    return data
class Worker:
    def __init__(self,root,key,token,worker_id,execute=None):
        self.root=Path(root);self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
        if self.root.is_symlink():raise ValueError('Worker root must not be a symlink')
        if not isinstance(key,Ed25519PrivateKey) or len(token)<32 or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',worker_id):raise ValueError('Invalid operator identity')
        self.key,self.token,self.worker_id=key,token,worker_id;self.execute=execute or self.capture
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS jobs(nonce TEXT PRIMARY KEY,identity TEXT NOT NULL,status TEXT NOT NULL,result BLOB,created REAL NOT NULL)')
            db.execute("UPDATE jobs SET status='interrupted' WHERE status='running'")
    @contextmanager
    def db(self):
        connection=sqlite3.connect(self.root/'jobs.sqlite',timeout=5)
        try:
            with connection:yield connection
        finally:connection.close()

    def signed(self,receipt,captures=None):return {'receipt':receipt,'signature':base64.b64encode(self.key.sign(encoded(receipt))).decode(),'captures':captures or []}
    def manifest(self):
        now=time.time();iso=lambda n:time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(n))
        m={'workerId':self.worker_id,'version':'1','protocol':'cline-analysis-worker/v1','isolation':'remote-vm','ephemeralSnapshots':True,'networkModes':['disabled'],'maxArtifactBytes':MAX_INPUT,'issuedAt':iso(now),'expiresAt':iso(now+120),'operations':['android-runtime-capture']}
        return {'manifest':m,'signature':base64.b64encode(self.key.sign(encoded(m))).decode()}
    def result(self,nonce):
        with self.db() as db:
            row=db.execute('SELECT status,result,created FROM jobs WHERE nonce=?',(nonce,)).fetchone()
            if row and row[2]<time.time()-3600:
                db.execute("UPDATE jobs SET status='expired',result=NULL WHERE nonce=?",(nonce,));row=('expired',None,row[2])
        if not row:return 404,{'error':'Unknown job'}
        if row[0] in ('running','interrupted','expired'):return 409,{'error':'Job pending/interrupted; not replayed. Inspect worker and create a newly approved job if required.'}
        return 200,json.loads(row[1])
    def job(self,value):
        data=validate_job(value);identity=hashlib.sha256(encoded(value)).hexdigest()
        if not LOCK.acquire(blocking=False):return 409,{'error':'Worker busy; no execution started'}
        try:
            with self.db() as db:
                db.execute("UPDATE jobs SET status='expired',result=NULL WHERE created<? AND status!='running'",(time.time()-3600,))
                old=db.execute('SELECT identity FROM jobs WHERE nonce=?',(value['nonce'],)).fetchone()
                if old:
                    if old[0]!=identity:return 409,{'error':'Nonce identity conflict'}
                    db.commit();return self.result(value['nonce'])
                if db.execute("SELECT COUNT(*) FROM jobs WHERE status!='expired'").fetchone()[0]>=50 or db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0]>=4096 or (db.execute('SELECT COALESCE(SUM(length(result)),0) FROM jobs').fetchone()[0])>100*1024*1024:return 429,{'error':'Worker retention budget reached'}
                db.execute('INSERT INTO jobs VALUES(?,?,?,?,?)',(value['nonce'],identity,'running',None,time.time()))
            try:observations=self.execute(value,data)
            except Exception:observations={'status':'failed','artifacts':[],'captures':[],'registrations':[],'events':[],'limitations':['Capture/lifecycle failed; inspect private worker diagnostics. No successful runtime claim.']}
            receipt={'protocol':'cline-android-capture/v1','workerId':self.worker_id,'nonce':value['nonce'],'requestHash':value['requestHash'],'artifactSha256':value['artifactSha256'],'network':'disabled','status':observations['status'],'engine':'android-frida','evidence':{k:observations.get(k,[]) for k in ['artifacts','registrations','events']},'limitations':observations['limitations']}
            result=self.signed(receipt,observations.get('captures',[]));body=encoded(result)
            if len(body)>MAX_OUTPUT:raise ValueError('Worker output budget exceeded')
            with self.db() as db:db.execute('UPDATE jobs SET status=?,result=? WHERE nonce=?',(receipt['status'],body,value['nonce']))
            return 200,result
        finally:LOCK.release()
    def capture(self,value,data):
        hook=lambda name:subprocess.run([required_executable(name)],check=True,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        # Hooks are fixed operator configuration, never job-supplied commands.
        try:
            hook('CLINE_ANDROID_ISOLATION_CHECK');hook('CLINE_ANDROID_RESET');hook('CLINE_ANDROID_ISOLATION_CHECK')
            with tempfile.TemporaryDirectory(dir=self.root,prefix='capture-') as stage:
                path=Path(stage)/'target.apk';path.write_bytes(data);path.chmod(0o600)
                config={'artifact':str(path),'package':value['packageName'],'captureDex':value['captureDex'],'timeoutMs':value['timeoutMs']}
                process=subprocess.Popen([sys.executable,'-I',str(Path(__file__).with_name('capture.py'))],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
                try:
                    output=bounded_collect(process,encoded(config),value['timeoutMs']/1000+60)
                    if process.returncode!=0 or len(output)>MAX_OUTPUT:raise ValueError('Capture process/output budget')
                    return json.loads(output)
                finally:
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    process.wait(timeout=5)
        finally:hook('CLINE_ANDROID_CLEANUP')
def bounded_collect(process,payload,deadline):
    def stop():
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
    timer=threading.Timer(deadline,stop);timer.start()
    try:
        process.stdin.write(payload);process.stdin.close()
        output=bytearray()
        while True:
            part=process.stdout.read(min(65536,MAX_OUTPUT+1-len(output)))
            if not part:break
            output.extend(part)
            if len(output)>MAX_OUTPUT:raise ValueError('Capture process/output budget')
        process.wait(timeout=5)
        if process.returncode!=0:raise ValueError('Capture process deadline/failure')
        return bytes(output)
    finally:
        timer.cancel();stop();process.wait(timeout=5);process.stdout.close()
def required_executable(name):
    path=Path(os.environ.get(name,''))
    if not path.is_absolute() or not path.is_file() or path.is_symlink() or not os.access(path,os.X_OK):raise ValueError('Missing trusted operator executable: '+name)
    return str(path)
def handler(worker):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass # Never log bearer credentials, captured bytes or target strings.
        def response(self,status,body):
            data=encoded(body);self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        def authorized(self):
            values=self.headers.get_all('Authorization',[])
            if len(values)!=1:return False
            return hmac.compare_digest(values[0].encode('utf-8'), ('Bearer '+worker.token).encode('utf-8'))
        def do_GET(self):
            if self.path=='/v1/capabilities':return self.response(200,worker.manifest())
            if not self.authorized():return self.response(401,{'error':'Unauthorized'})
            match=re.fullmatch(r'/v1/jobs/([a-f0-9]{32})',self.path)
            return self.response(*worker.result(match[1])) if match else self.response(404,{'error':'Unknown endpoint'})
        def do_POST(self):
            if not self.authorized():return self.response(401,{'error':'Unauthorized'})
            if self.path!='/v1/jobs':return self.response(404,{'error':'Unknown endpoint'})
            try:
                if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length',[]))!=1:raise ValueError('Explicit single length required')
                length=int(self.headers['Content-Length'])
                if not 0<length<24*1024*1024:raise ValueError('Body limit')
                self.connection.settimeout(30);raw=self.rfile.read(length)
                if len(raw)!=length:raise ValueError('Truncated body')
                value=json.loads(raw,object_pairs_hook=duplicate_safe)
                return self.response(*worker.job(value))
            except (ValueError,KeyError,TypeError):return self.response(400,{'error':'Invalid bounded job; no successful execution claim'})
    return Handler
if __name__=='__main__':
    if not sys.platform.startswith('linux'):raise SystemExit('Use a separately provisioned Linux controller VM; desktop Windows is not a capture host')
    if os.environ.get('CLINE_ANDROID_ISOLATION_ACK')!='operator-enforced-disposable-android-and-denied-egress':raise SystemExit('Configure an isolated disposable Android environment first; this server does not provision or attest a VM')
    import importlib.util
    if importlib.util.find_spec('frida') is None:raise SystemExit('Install the pinned Frida dependency on the isolated worker')
    for name in ['CLINE_ANDROID_ISOLATION_CHECK','CLINE_ANDROID_RESET','CLINE_ANDROID_CLEANUP','CLINE_ANDROID_ADB','CLINE_ANDROID_APKANALYZER']:required_executable(name)
    key=serialization.load_pem_private_key(Path(os.environ['CLINE_ANDROID_SIGNING_KEY']).read_bytes(),password=None)
    worker=Worker(os.environ['CLINE_ANDROID_WORKER_DATA'],key,os.environ['CLINE_ANDROID_WORKER_TOKEN'],os.environ['CLINE_ANDROID_WORKER_ID'])
    server=ThreadingHTTPServer((os.environ.get('CLINE_ANDROID_BIND','127.0.0.1'),int(os.environ.get('CLINE_ANDROID_PORT','8443'))),handler(worker))
    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.minimum_version=ssl.TLSVersion.TLSv1_2;tls.load_cert_chain(os.environ['CLINE_ANDROID_TLS_CERT'],os.environ['CLINE_ANDROID_TLS_KEY']);server.socket=tls.wrap_socket(server.socket,server_side=True);server.serve_forever()
