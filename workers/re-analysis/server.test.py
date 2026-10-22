import base64, hashlib, http.client, importlib.util, json, pathlib, tempfile, threading, unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
p=pathlib.Path(__file__).with_name('server.py');spec=importlib.util.spec_from_file_location('re_worker',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class WorkerTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.key=Ed25519PrivateKey.generate();self.calls=0
  def execute(value,data):
   self.calls+=1
   return {'status':'partial','engineVersion':'1.5.11','apiCalls':[{'api':'owned','arguments':'[]','return':'0'}],'memoryBoundary':{'hard':True},'limitations':['Owned protocol fixture, not real emulation']}
  self.worker=m.Worker(self.tmp.name,self.key,'t'*40,'owned-worker',execute,'f'*64)
  data=b'MZ'+bytes(126)
  self.job={'protocol':'cline-analysis-job/v1','operation':'emulate_windows','nonce':'a'*32,'requestHash':'b'*64,'artifactSha256':hashlib.sha256(data).hexdigest(),'network':'disabled','timeoutMs':1000,'maxOutputBytes':1048576,'artifactBase64':base64.b64encode(data).decode()}
 def tearDown(self):self.tmp.cleanup()
 def test_signed_runtime_capability_and_receipt_binding(self):
  body=self.worker.manifest();self.key.public_key().verify(base64.b64decode(body['signature']),m.encoded(body['manifest']));self.assertEqual(body['manifest']['runtimeSha256'],'f'*64)
  status,body=self.worker.job(self.job);self.assertEqual(status,200);self.key.public_key().verify(base64.b64decode(body['signature']),m.encoded(body['receipt']));self.assertEqual(body['receipt']['artifactSha256'],self.job['artifactSha256'])
 def test_repeat_retrieves_without_reexecution_and_conflict_rejected(self):
  self.worker.job(self.job);self.worker.job(self.job);self.assertEqual(self.calls,1)
  self.assertEqual(self.worker.job(dict(self.job,requestHash='c'*64))[0],409)
 def test_restart_marks_running_interrupted_and_never_replays(self):
  with self.worker.db() as db:db.execute('INSERT INTO jobs VALUES(?,?,?,?,?)',('a'*32,hashlib.sha256(m.encoded(self.job)).hexdigest(),'running',None,0))
  self.worker=m.Worker(self.tmp.name,self.key,'t'*40,'owned-worker',lambda *_:self.fail('Replayed'),'f'*64)
  self.assertEqual(self.worker.job(self.job)[0],409)
 def test_schema_hash_boolean_and_network_fail_closed(self):
  for extra in [{'network':'recorded'},{'timeoutMs':True},{'artifactSha256':'e'*64},{'script':'arbitrary'},{'operation':'shell'}]:
   with self.assertRaises(ValueError):self.worker.job(dict(self.job,**extra))
  self.assertEqual(self.calls,0)
 def test_invalid_success_and_missing_memory_proof_become_failure(self):
  for index,value in enumerate([{'status':'completed'},{'status':'partial','engineVersion':'1.5.11'}]):
   self.worker.execute=lambda *_:value
   _,body=self.worker.job(dict(self.job,nonce=f'{index+1:032x}'));self.assertEqual(body['receipt']['status'],'failed')
 def test_cancellation_and_retention_never_execute(self):
  self.assertEqual(self.worker.cancel('d'*32)[0],404);self.worker.job(self.job)
  self.worker.cancel('a'*32)
  with self.worker.db() as db:db.execute('UPDATE jobs SET created=0')
  self.assertEqual(self.worker.result('a'*32)[0],409);self.assertEqual(self.calls,1)
 def test_no_duplicate_json_keys(self):
  with self.assertRaises(ValueError):json.loads('{"nonce":1,"nonce":2}',object_pairs_hook=m.duplicate_safe)
 def test_busy_worker_rejects_before_launch(self):
  self.worker.lock.acquire()
  try:self.assertEqual(self.worker.job(self.job)[0],409);self.assertEqual(self.calls,0)
  finally:self.worker.lock.release()
 def test_http_requires_single_auth_header_even_for_health(self):
  server=m.ThreadingHTTPServer(('127.0.0.1',0),m.Handler);server.worker=self.worker;thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
  try:
   for headers in [{},{'Authorization':'Bearer '+'t'*40}]:
    conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=3);conn.request('GET','/v1/capabilities',headers=headers);response=conn.getresponse();self.assertEqual(response.status,200 if headers else 401);response.read();conn.close()
  finally:server.shutdown();server.server_close();thread.join()
class RealWorkerAcceptance(unittest.TestCase):
 @unittest.skipUnless(__import__('os').environ.get('CLINE_TEST_REAL_SPEAKEASY')=='1','Explicit owned real-engine service profile')
 def test_real_collector_result_is_signed_and_bound_without_replay(self):
  fixture_spec=importlib.util.spec_from_file_location('owned_pe_fixture',p.with_name('collector.test.py'));fixture=importlib.util.module_from_spec(fixture_spec);fixture_spec.loader.exec_module(fixture)
  data=fixture.owned_api_pe();key=Ed25519PrivateKey.generate()
  with tempfile.TemporaryDirectory() as tmp:
   worker=m.Worker(tmp,key,'t'*40,'owned-real-worker')
   job={'protocol':'cline-analysis-job/v1','operation':'emulate_windows','nonce':'1'*32,'requestHash':'b'*64,'artifactSha256':hashlib.sha256(data).hexdigest(),'network':'disabled','timeoutMs':30000,'maxOutputBytes':1048576,'artifactBase64':base64.b64encode(data).decode()}
   status,body=worker.job(job);self.assertEqual(status,200);receipt=body['receipt'];self.assertEqual(receipt['status'],'partial',receipt)
   key.public_key().verify(base64.b64decode(body['signature']),m.encoded(receipt));self.assertEqual(receipt['artifactSha256'],job['artifactSha256']);self.assertEqual(receipt['runtimeSha256'],worker.runtime)
   self.assertTrue(any('GetTickCount' in r['api'] for r in receipt['evidence']['apiCalls']))
   self.assertEqual(worker.job(job)[1],body)
 @unittest.skipUnless(__import__('os').environ.get('CLINE_TEST_REAL_SPEAKEASY')=='1','Explicit owned real-engine service profile')
 def test_real_collector_cancellation_terminates_and_discards_output(self):
  import time
  fixture_spec=importlib.util.spec_from_file_location('owned_loop_fixture',p.with_name('collector.test.py'));fixture=importlib.util.module_from_spec(fixture_spec);fixture_spec.loader.exec_module(fixture)
  data=bytearray(fixture.owned_pe());data[0x200:0x202]=bytes.fromhex('ebfe');data=bytes(data)
  with tempfile.TemporaryDirectory() as tmp:
   worker=m.Worker(tmp,Ed25519PrivateKey.generate(),'t'*40,'owned-cancel-worker')
   job={'protocol':'cline-analysis-job/v1','operation':'emulate_windows','nonce':'2'*32,'requestHash':'b'*64,'artifactSha256':hashlib.sha256(data).hexdigest(),'network':'disabled','timeoutMs':15000,'maxOutputBytes':1048576,'artifactBase64':base64.b64encode(data).decode()}
   result=[];thread=threading.Thread(target=lambda:result.append(worker.job(job)));thread.start()
   deadline=time.monotonic()+8
   while job['nonce'] not in worker.processes and thread.is_alive() and time.monotonic()<deadline:time.sleep(.02)
   self.assertIn(job['nonce'],worker.processes)
   self.assertEqual(worker.cancel(job['nonce'])[0],200);thread.join(8);self.assertFalse(thread.is_alive())
   self.assertEqual(result[0][1]['receipt']['status'],'failed');self.assertEqual(worker.processes,{})
   self.assertNotIn('apiCalls',result[0][1]['receipt']['evidence']);self.assertEqual(worker.result(job['nonce'])[1],result[0][1])
if __name__=='__main__':unittest.main()
