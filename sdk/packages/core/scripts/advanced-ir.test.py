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
if __name__=='__main__':unittest.main(verbosity=2)
