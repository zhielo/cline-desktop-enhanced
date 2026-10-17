import unittest,json,types,tempfile
from pathlib import Path
source=Path(__file__).resolve().parents[1]/'src/extensions/tools/executors/advanced-analysis-worker.ts'
w=types.ModuleType('owned_worker');w.__file__=str(source);exec(json.loads(source.read_text().split('export const ADVANCED_ANALYSIS_WORKER =',1)[1].strip().removesuffix(';')),w.__dict__)
class StaticIRTests(unittest.TestCase):
 def run_owned(self,action,data,architecture='x86_64',limit=200):
  with tempfile.TemporaryDirectory() as directory:
   target=Path(directory)/'owned-fragment.bin';target.write_bytes(data)
   return w.main({'action':action,'target':str(target),'limit':limit,'options':{'architecture':architecture,'bytes':len(data),'address':4096}})
 def test_x86_ir(self):
  result=self.run_owned('lift_native_ir',bytes.fromhex('31c0c3'));self.assertEqual(result['engine'],'miasm');self.assertEqual(result['evidence']['instructionCount'],2);self.assertEqual(result['evidence']['decodedBytes'],3);self.assertEqual(result['evidence']['address'],4096)
 def test_real_expression_pass(self):
  result=self.run_owned('deobfuscation_pass',bytes.fromhex('31c0c3'));self.assertTrue(result['evidence']['simplificationChanged']);self.assertIn('RAX = 0x0',result['evidence']['irAfter'][0]['assignments']);self.assertEqual(result['evidence']['equivalence'],'not-independently-proven')
 def test_arm64_ir(self):
  result=self.run_owned('lift_native_ir',bytes.fromhex('c0035fd6'),'arm64');self.assertEqual(result['status'],'completed');self.assertEqual(result['evidence']['decodedBytes'],4)
 def test_instruction_cap(self):
  result=self.run_owned('lift_native_ir',bytes.fromhex('90909090c3'),limit=2);self.assertEqual(result['status'],'partial');self.assertEqual(result['evidence']['instructionCount'],2)
 def test_unknown_architecture(self):
  with self.assertRaises(ValueError):self.run_owned('lift_native_ir',b'owned','unknown')
class DualDecoderTests(unittest.TestCase):
 def run_owned(self,data,architecture='x86_64',limit=200,**changes):
  with tempfile.TemporaryDirectory() as directory:
   target=Path(directory)/'owned.bin';target.write_bytes(data)
   options={'architecture':architecture,'offset':0,'address':4096,'bytes':len(data)}; options.update(changes)
   return w.main({'action':'native_crosscheck','target':str(target),'limit':limit,'options':options})
 def test_x86_two_actual_engines(self):
  result=self.run_owned(bytes.fromhex('31c090c3'))
  self.assertEqual(result['status'],'completed'); self.assertTrue(result['evidence']['boundaryAgreement'])
  self.assertEqual([d['engine'] for d in result['evidence']['decoders']],['capstone','miasm'])
  self.assertTrue(all(d['version'] for d in result['evidence']['decoders']))
  self.assertEqual(result['evidence']['rangeSha256'],w.digest(bytes.fromhex('31c090c3')))
  self.assertIsNone(result['evidence']['winner']); self.assertFalse(result['evidence']['observedExecution'])
 def test_arm64_both_decode(self):
  result=self.run_owned(bytes.fromhex('1f2003d5c0035fd6'),'arm64')
  self.assertEqual(result['status'],'completed'); self.assertTrue(result['evidence']['boundaryAgreement'])
 def test_ret_does_not_end_linear_range(self):
  result=self.run_owned(bytes.fromhex('c390c3'))
  self.assertEqual(result['evidence']['decoders'][1]['instructions'],3)
 def test_range_origin_not_whole_input(self):
  result=self.run_owned(bytes.fromhex('cccc90c3cc'),offset=2,bytes=2,address=8192)
  self.assertEqual(result['evidence']['comparisons'][0]['address'],8192)
  self.assertEqual(result['evidence']['rangeSha256'],w.digest(bytes.fromhex('90c3')))
  self.assertEqual(result['evidence']['requestedBytes'],2)
 def test_budget_never_agrees_on_prefix_only(self):
  result=self.run_owned(bytes.fromhex('9090c3'),limit=1)
  self.assertEqual(result['status'],'partial'); self.assertFalse(result['evidence']['boundaryAgreement'])
  self.assertTrue(all(d['decodedBytes']==1 for d in result['evidence']['decoders']))
 def test_bad_truncated_instruction_is_partial(self):
  result=self.run_owned(bytes.fromhex('900f'))
  self.assertEqual(result['status'],'partial'); self.assertFalse(result['evidence']['boundaryAgreement'])
 def test_explicit_selection_required(self):
  for changes in [{'offset':None},{'address':None},{'architecture':'unknown'},{'bytes':0},{'bytes':65537},{'address':9007199254740991},{'offset':True}]:
   with self.subTest(changes=changes):
    with self.assertRaises(ValueError): self.run_owned(b'\x90',**changes)
 def test_missing_engine_is_blocked_not_single_engine_fallback(self):
  original=w.required
  try:
   def require(name):
    if name=='miasm': raise w.Blocked('Missing optional engine: miasm')
    return original(name)
   w.required=require
   with self.assertRaises(w.Blocked): self.run_owned(b'\x90')
  finally: w.required=original
if __name__=='__main__':unittest.main(verbosity=2)
