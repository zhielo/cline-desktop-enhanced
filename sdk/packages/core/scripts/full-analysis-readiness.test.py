"""Real fixed owned execution fixtures; no target code, licenses or devices."""
import argparse,json,types
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('--pack',choices=['full','angr'],required=True);options=parser.parse_args()
source=Path(__file__).resolve().parents[1]/'src/extensions/tools/executors/advanced-analysis-worker.ts'
code=json.loads(source.read_text().split('export const ADVANCED_ANALYSIS_WORKER =',1)[1].strip().removesuffix(';'))
w=types.ModuleType('owned_worker');w.__file__=str(source);exec(compile(code,'owned-worker','exec'),w.__dict__)
if options.pack=='full':
 result=w.main({'action':'full_readiness'}); print(json.dumps(result))
 assert result['status']=='completed', result
 checks=result['evidence']['checks'];assert {c['engine'] for c in checks}=={'lief','capstone','z3','triton','qbindiff','androguard','miasm','unicorn','qbdi','cryptography'}
 assert all(c['executionVerified'] for c in checks)
 try:w.emulate_block(bytes.fromhex('0f05c3'),{'architecture':'x86_64','bytes':3},20)
 except ValueError:pass
 else:raise AssertionError('Emulated syscall was not blocked')
 try:w.emulate_block(bytes(4097),{'architecture':'x86_64','bytes':4097},20)
 except ValueError:pass
 else:raise AssertionError('Oversized emulation was not blocked')
else:
 result=w.main({'action':'angr_readiness'});print(json.dumps(result));assert result['status']=='completed';assert result['engine']=='angr';assert result['evidence']['hostExecution'] is False
print('Owned '+options.pack+' execution acceptance passed')
