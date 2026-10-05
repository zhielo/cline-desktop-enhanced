import base64, importlib.util, hashlib, json, tempfile, unittest, threading, http.client, subprocess, sys, sqlite3
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
spec=importlib.util.spec_from_file_location('worker',Path(__file__).with_name('server.py'));w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
class WorkerTest(unittest.TestCase):
 def setUp(self):
  self.root=tempfile.TemporaryDirectory();self.key=Ed25519PrivateKey.generate();self.calls=0
  def capture(request,data):self.calls+=1;return {'status':'partial','artifacts':[],'captures':[],'registrations':[],'events':[],'limitations':['Owned fixture, not real Android capture']}
  self.worker=w.Worker(self.root.name,self.key,'t'*40,'owned-worker',capture);data=b'PK owned fixture';self.job={'protocol':'cline-android-capture/v1','operation':'android_capture','network':'disabled','nonce':'a'*32,'requestHash':'b'*64,'artifactSha256':hashlib.sha256(data).hexdigest(),'packageName':'com.example.owned','captureDex':False,'timeoutMs':1000,'artifactBase64':base64.b64encode(data).decode()}
 def tearDown(self):self.root.cleanup()
 def test_signed_capabilities_and_receipts(self):
  health=self.worker.manifest();self.key.public_key().verify(base64.b64decode(health['signature']),w.encoded(health['manifest']));status,result=self.worker.job(self.job);self.assertEqual(status,200);self.key.public_key().verify(base64.b64decode(result['signature']),w.encoded(result['receipt']));self.assertEqual(result['receipt']['status'],'partial')
 def test_duplicate_job_does_not_reexecute(self):
  self.worker.job(self.job);self.worker.job(self.job);self.assertEqual(self.calls,1);self.assertEqual(self.worker.result('a'*32)[0],200)
 def test_nonce_conflict_and_interrupted_do_not_replay(self):
  self.worker.job(self.job);self.assertEqual(self.worker.job(dict(self.job,requestHash='c'*64))[0],409)
  with self.worker.db() as db:db.execute("UPDATE jobs SET status='running',result=NULL WHERE nonce=?",('a'*32,))
  other=w.Worker(self.root.name,self.key,'t'*40,'owned-worker',lambda *_:self.fail('Replay forbidden'));self.assertEqual(other.job(self.job)[0],409)
 def test_invalid_fields_hash_and_package_fail_before_execution(self):
  for bad in [dict(self.job,packageName='com.x;echo bad'),dict(self.job,artifactSha256='0'*64),dict(self.job,timeoutMs=True),dict(self.job,command='execute')]:
   with self.assertRaises(ValueError):self.worker.job(bad)
  self.assertEqual(self.calls,0)
 def test_duplicate_json_keys_rejected(self):
  with self.assertRaises(ValueError):json.loads('{"nonce":1,"nonce":2}',object_pairs_hook=w.duplicate_safe)
 def test_expired_job_remains_a_tombstone(self):
  self.worker.job(self.job)
  with self.worker.db() as db:db.execute('UPDATE jobs SET created=0 WHERE nonce=?',('a'*32,))
  self.assertEqual(self.worker.job(self.job)[0],409);self.assertEqual(self.calls,1)
 def test_collector_failure_is_signed_failed_not_success(self):
  def fail(*_):raise RuntimeError('private diagnostic')
  self.worker.execute=fail
  status,result=self.worker.job(self.job);self.assertEqual(status,200);self.assertEqual(result['receipt']['status'],'failed');self.assertNotIn('private diagnostic',json.dumps(result));self.key.public_key().verify(base64.b64decode(result['signature']),w.encoded(result['receipt']))
 def test_http_requires_unique_bearer_before_submission(self):
  server=w.ThreadingHTTPServer(('127.0.0.1',0),w.handler(self.worker));thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
  try:
   conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
   conn.request('POST','/v1/jobs',w.encoded(self.job),{'Content-Type':'application/json'});self.assertEqual(conn.getresponse().status,401);conn.close()
   conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5);conn.putrequest('GET','/v1/jobs/'+self.job['nonce']);conn.putheader('Authorization','Bearer '+'t'*40);conn.putheader('Authorization','Bearer '+'t'*40);conn.endheaders();self.assertEqual(conn.getresponse().status,401);conn.close();self.assertEqual(self.calls,0)
   conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5);conn.request('POST','/v1/jobs',w.encoded(self.job),{'Authorization':'Bearer '+'t'*40});response=conn.getresponse();self.assertEqual(response.status,200);response.read();conn.close();self.assertEqual(self.calls,1)
  finally:server.shutdown();server.server_close();thread.join(timeout=5)
 def test_collector_output_and_deadline_are_bounded(self):
  if not sys.platform.startswith('linux'):self.skipTest('Linux process-group controller only')
  original=w.MAX_OUTPUT;w.MAX_OUTPUT=1024
  try:
   for script in ["import sys;sys.stdin.read();sys.stdout.write('x'*2048)","import sys,time;sys.stdin.read();time.sleep(10)"]:
    process=subprocess.Popen([sys.executable,'-c',script],stdin=subprocess.PIPE,stdout=subprocess.PIPE,start_new_session=True)
    with self.assertRaises(ValueError):w.bounded_collect(process,b'{}',0.2)
    self.assertIsNotNone(process.poll())
  finally:w.MAX_OUTPUT=original
 def test_database_connections_close_after_success(self):
  with self.worker.db() as connection:connection.execute('SELECT 1')
  with self.assertRaises(sqlite3.ProgrammingError):connection.execute('SELECT 1')
 def test_database_connections_close_and_rollback_after_failure(self):
  with self.assertRaises(RuntimeError):
   with self.worker.db() as connection:
    connection.execute('INSERT INTO jobs VALUES(?,?,?,?,?)',('d'*32,'fixture','running',None,0));raise RuntimeError('Owned rollback fixture')
  with self.assertRaises(sqlite3.ProgrammingError):connection.execute('SELECT 1')
  with self.worker.db() as check:self.assertEqual(check.execute('SELECT COUNT(*) FROM jobs WHERE nonce=?',('d'*32,)).fetchone()[0],0)
 def test_opt_in_native_capture_validation(self):
  self.assertEqual(self.worker.job(dict(self.job,captureNative=True))[0],200)
  with self.assertRaises(ValueError):w.validate_job(dict(self.job,captureNative=1))
 def test_explicit_purge_is_signed_blocks_replay_and_does_not_claim_disk_erasure(self):
  self.worker.job(self.job);status,result=self.worker.purge(self.job['nonce']);self.assertEqual(status,200);self.key.public_key().verify(base64.b64decode(result['signature']),w.encoded(result['receipt']));self.assertEqual(result['receipt']['physicalErasure'],'not-proven');self.assertEqual(self.worker.job(self.job)[0],409);self.assertEqual(self.calls,1)
  with self.worker.db() as db:self.assertIsNone(db.execute('SELECT result FROM jobs WHERE nonce=?',(self.job['nonce'],)).fetchone()[0]);self.assertEqual(db.execute('PRAGMA secure_delete').fetchone()[0],1)
 def test_retention_sweep_preserves_nonce_tombstones_and_never_executes(self):
  self.worker.job(self.job)
  with self.worker.db() as db:db.execute('UPDATE jobs SET created=0 WHERE nonce=?',(self.job['nonce'],))
  self.assertEqual(self.worker.sweep_retention(),1);self.assertEqual(self.worker.job(self.job)[0],409);self.assertEqual(self.calls,1)
 def test_running_capture_is_not_purged(self):
  self.worker.job(self.job)
  with self.worker.db() as db:db.execute("UPDATE jobs SET status='running' WHERE nonce=?",(self.job['nonce'],))
  self.assertEqual(self.worker.purge(self.job['nonce'])[0],409)
 def test_delete_endpoint_requires_auth_and_boolean_confirmation(self):
  self.worker.job(self.job);server=w.ThreadingHTTPServer(('127.0.0.1',0),w.handler(self.worker));thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
  try:
   for token,body,expected in [('',{'confirmPlaintextRemoval':True},401),('Bearer '+'t'*40,{'confirmPlaintextRemoval':1},400),('Bearer '+'t'*40,{'confirmPlaintextRemoval':True},200)]:
    conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5);conn.request('DELETE','/v1/jobs/'+self.job['nonce'],w.encoded(body),{'Authorization':token});response=conn.getresponse();self.assertEqual(response.status,expected);response.read();conn.close()
  finally:server.shutdown();server.server_close();thread.join(timeout=5)
if __name__=='__main__':unittest.main()
