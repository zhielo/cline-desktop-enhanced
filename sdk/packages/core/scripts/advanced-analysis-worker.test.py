import unittest,json,tempfile,struct,hashlib,zlib,zipfile,sys,types
from pathlib import Path
source=Path(__file__).resolve().parents[1]/'src/extensions/tools/executors/advanced-analysis-worker.ts'
code=json.loads(source.read_text().split('export const ADVANCED_ANALYSIS_WORKER =',1)[1].strip().removesuffix(';'))
w=types.ModuleType('worker');w.__file__=str(source);exec(compile(code,'owned-fixed-worker','exec'),w.__dict__)
class WorkerTests(unittest.TestCase):
 def setUp(self): self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
 def tearDown(self): self.temp.cleanup()
 def file(self,name,data): p=self.root/name;p.write_bytes(data);return str(p)
 def action(self,action,data,**kw): return w.main({'action':action,'target':self.file('fixture',data),**kw})
 def dex(self):
  data=bytearray(240);data[:8]=b'dex\n035\0';struct.pack_into('<20I',data,32,240,112,0x12345678,0,0,164,1,148,1,144,0,0,0,0,0,0,1,112,88,152);struct.pack_into('<8I',data,112,0,1,0xffffffff,0,0xffffffff,0,0,0);struct.pack_into('<I',data,144,0);struct.pack_into('<I',data,148,152);data[152:163]=b'\x09LFixture;\x00';struct.pack_into('<I',data,164,6)
  for i,(kind,size,offset) in enumerate([(0,1,0),(6,1,112),(2,1,144),(1,1,148),(0x2002,1,152),(0x1000,1,164)]):struct.pack_into('<HHII',data,168+i*12,kind,0,size,offset)
  data[12:32]=hashlib.sha1(data[32:]).digest();struct.pack_into('<I',data,8,zlib.adler32(data[12:])&0xffffffff);return bytes(data)
 def test_toolchain(self): self.assertFalse(w.main({'action':'toolchain'})['evidence']['engines'][0]['executionVerified'])
 def test_triage(self): self.assertEqual(self.action('triage',b'owned')['input']['sha256'],w.digest(b'owned'))
 @unittest.skipUnless(sys.platform.startswith('linux'),'ELF executable fixture is Linux-only')
 def test_lief(self): self.assertIn(w.main({'action':'native_inventory','target':sys.executable})['status'],['completed','partial'])
 def test_not_elf(self):
  with self.assertRaises(ValueError):self.action('native_inventory',b'bad')
 def test_capstone(self): self.assertEqual([i['mnemonic'] for i in self.action('native_disassemble',bytes.fromhex('9090c3'),options={'architecture':'x86_64','bytes':3})['evidence']['instructions']],['nop','nop','ret'])
 def test_range(self):
  with self.assertRaises(ValueError):self.action('native_disassemble',b'x',options={'architecture':'x86_64','bytes':30})
 def test_z3_proof(self): self.assertEqual(self.action('compare_expressions',json.dumps({'expression':{'op':'xor','args':[{'var':'x'},{'var':'x'}]},'compare':0}).encode())['evidence']['equivalence'],'unsat')
 def test_counterexample(self): self.assertNotEqual(self.action('compare_expressions',b'{"bits":8,"expression":{"var":"x"},"compare":0}')['evidence']['counterexample']['x'],0)
 def test_triton(self): self.assertEqual(self.action('triton_expression',b'{"expression":{"op":"xor","args":[{"var":"x"},{"var":"x"}]}}')['evidence']['simplified'],'(_ bv0 32)')
 def test_string_not_code(self):
  with self.assertRaises(ValueError):self.action('simplify_expression',b'{"expression":"import os"}')
 def test_depth(self):
  value={'var':'x'}
  for _ in range(34):value={'op':'not','args':[value]}
  with self.assertRaises(ValueError):self.action('simplify_expression',json.dumps({'expression':value}).encode())
 def test_dex(self): self.assertEqual(self.action('dex_index',self.dex())['evidence']['classes'],['LFixture;'])
 def test_apk(self):
  path=self.root/'owned.apk'
  with zipfile.ZipFile(path,'w') as archive:archive.writestr('classes.dex',self.dex());archive.writestr('lib/arm64-v8a/libfixture.so',b'\x7fELF')
  self.assertEqual(len(w.main({'action':'apk_inventory','target':str(path)})['evidence']['dex']),1)
 def test_traversal(self):
  path=self.root/'bad.apk'
  with zipfile.ZipFile(path,'w') as archive:archive.writestr('../bad',b'x')
  with self.assertRaises(ValueError):w.main({'action':'apk_inventory','target':str(path)})
 def test_transform(self): self.assertEqual(self.action('transform_blob',b'68656c6c6f',options={'steps':['hex']})['evidence']['chain'][0]['outputSha256'],w.digest(b'hello'))
 def test_expansion(self):
  old=w.MAX_BYTES
  try:
   w.MAX_BYTES=1024
   with self.assertRaises(ValueError):self.action('transform_blob',zlib.compress(b'x'*2048),options={'steps':['zlib']})
  finally:w.MAX_BYTES=old
 def test_qbindiff(self):
  from binexport import binexport2_pb2 as pb
  def export(name,address):
   data=pb.BinExport2();data.meta_information.executable_name=name;data.meta_information.architecture_name='x86-64';data.meta_information.executable_id=name;data.mnemonic.add().name='ret';ins=data.instruction.add();ins.address=address;ins.raw_bytes=b'\xc3';ins.mnemonic_index=0;span=data.basic_block.add().instruction_index.add();span.begin_index=0;span.end_index=1;graph=data.flow_graph.add();graph.basic_block_index.append(0);graph.entry_basic_block_index=0;vertex=data.call_graph.vertex.add();vertex.address=address;vertex.mangled_name='fixture';vertex.type=pb.BinExport2.CallGraph.Vertex.NORMAL;return self.file(name+'.BinExport',data.SerializeToString())
  result=w.main({'action':'match_native_functions','target':export('a',4096),'compare_target':export('b',8192)});self.assertEqual(result['evidence']['matchCount'],1)
 def test_runtime_blocked(self):
  with self.assertRaises(w.Blocked):self.action('trace_native_region',b'\x7fELF')
if __name__=='__main__':unittest.main(verbosity=2)
