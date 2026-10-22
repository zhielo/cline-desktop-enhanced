import importlib.util, json, os, pathlib, subprocess, sys, tempfile, unittest
from unittest.mock import patch
PATH=pathlib.Path(__file__).with_name('re-specialist-worker.py')
spec=importlib.util.spec_from_file_location('specialist',PATH);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Contracts(unittest.TestCase):
 def test_unknown_keys_and_boolean_budgets_rejected(self):
  for value in [True,0,1001]:
   with self.assertRaises(ValueError):m.bounded_int(value,1,1000)
  with self.assertRaises(ValueError):m.fields({'script':'arbitrary'},['query'])
 def test_symbolic_rejects_non_selected_regions_and_unknown_options_before_import(self):
  for data,options in [(b'a'*65537,{'symbolic':{'find':0x100000}}),(b'abc',{'symbolic':{'find':0x200000}}),(b'abc',{'symbolic':{'find':0x100000,'register':'rip'}}),(b'abc',{'symbolic':{'find':0x100000,'find_all':True}})]:
   with self.assertRaises(ValueError):m.symbolic(data,options)
 def test_fixed_joern_queries_reject_scala_and_invalid_sources(self):
  for query,selector in [('arbitrary-script','x'),('references','x);sys.exit(0)')]:
   with self.assertRaises(ValueError):m.joern(b'let x=1;',{'joern':{'language':'javascript','query':query,'selector':selector}},10)
 def test_joern_requires_pinned_runtime_not_path_presence(self):
  with patch.dict(os.environ,{},clear=True):
   with self.assertRaises(m.Blocked):m.verified_joern()
 def test_joern_manifest_change_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   pathlib.Path(d,'cline-runtime.json').write_text('{}')
   with patch.dict(os.environ,{'CLINE_JOERN_HOME':d,'CLINE_JOERN_MANIFEST_SHA256':'a'*64}):
    with self.assertRaises(m.Blocked):m.verified_joern()
 def test_readiness_never_accepts_target(self):
  with self.assertRaises(ValueError):m.run({'action':'specialist_readiness','target':'/tmp/target','options':{'specialist_readiness':{'engine':'angr'}}})
 def test_cli_unknown_action_has_structured_failure(self):
  run=subprocess.run([sys.executable,'-I',str(PATH),json.dumps({'action':'shell','target':'/tmp/x'})],capture_output=True,timeout=10)
  self.assertEqual(json.loads(run.stdout)['status'],'failed')
 def test_boundary_fails_closed_on_unsupported_platform(self):
  with patch.object(sys,'platform','unknown'):
   with self.assertRaises(m.Blocked):m.memory_boundary()
class RealAngr(unittest.TestCase):
 @unittest.skipUnless(os.environ.get('CLINE_TEST_REAL_ANGR')=='1','Explicit real-engine acceptance profile')
 def test_owned_path_model_and_readiness(self):
  run=subprocess.run([sys.executable,'-I',str(PATH),json.dumps({'action':'specialist_readiness','options':{'specialist_readiness':{'engine':'angr'}}})],capture_output=True,timeout=90)
  result=json.loads(run.stdout);self.assertEqual(result['status'],'completed',result);self.assertEqual(result['evidence']['candidate'],42);self.assertTrue(result['evidence']['memoryBoundary']['hard'])
 @unittest.skipUnless(os.environ.get('CLINE_TEST_REAL_ANGR')=='1','Explicit real-engine acceptance profile')
 def test_unsatisfied_model_is_inconclusive_not_unreachable(self):
  evidence,_=m.symbolic(bytes.fromhex('4883ff2a7506b801000000c331c0c3'),{'symbolic':{'find':0x100006,'avoid':[0x10000c],'minimum':0,'maximum':10}})
  self.assertIsNone(evidence['candidate']);self.assertNotIn('unreachable',evidence['outcome'])
 @unittest.skipUnless(os.environ.get('CLINE_TEST_REAL_ANGR')=='1','Explicit real-engine acceptance profile')
 def test_loop_respects_step_budget(self):
  evidence,_=m.symbolic(bytes.fromhex('ebfe90'),{'symbolic':{'find':0x100002,'max_steps':3}})
  self.assertEqual(evidence['outcome'],'step-budget');self.assertEqual(evidence['steps'],3)
class RealJoern(unittest.TestCase):
 @unittest.skipUnless(os.environ.get('CLINE_TEST_REAL_JOERN')=='1','Explicit real Joern distribution profile')
 def test_owned_parse_and_fixed_query(self):
  result=m.run({'action':'specialist_readiness','options':{'specialist_readiness':{'engine':'joern'}}})
  self.assertEqual(result['status'],'completed');self.assertTrue(result['evidence']['ownedFixturePassed'])
 @unittest.skipUnless(os.environ.get('CLINE_TEST_REAL_JOERN')=='1','Explicit real Joern distribution profile')
 def test_real_fixed_source_sink_and_java_references(self):
  cases=[(b'function readInput(){return "owned";} function sendOutput(x){return x;} const data=readInput();sendOutput(data);',{'language':'javascript','query':'source-sink','selector':'readInput','sink':'sendOutput'}),(b'class Input { static int ownedFixture(int value) { return value + 1; } }',{'language':'java','query':'references','selector':'value'})]
  for data,options in cases:
   with self.subTest(query=options['query']):
    evidence,version=m.joern(data,{'joern':options},10)
    self.assertTrue(evidence['rows'],evidence);self.assertEqual(version,'4.0.662');self.assertIn('unknown',evidence['coverage'])
if __name__=='__main__':unittest.main()
