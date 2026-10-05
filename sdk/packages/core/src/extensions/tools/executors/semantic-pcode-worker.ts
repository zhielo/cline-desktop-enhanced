/** Data-only p-code expressions. Never executes the analyzed native target. */
export const SEMANTIC_PCODE_WORKER = String.raw`
import sys, json, hashlib, importlib.metadata

def main():
    request = json.loads(sys.argv[1])
    path = request.get('target')
    with open(path, 'rb') as source:
        raw = source.read(1048577)
    if len(raw) > 1048576:
        raise ValueError('P-code input byte budget exceeded')
    document = json.loads(raw)
    if document.get('schemaVersion') != 1 or document.get('producer') != 'ghidra-high-pcode':
        raise ValueError('Expected validated Ghidra native program document')
    import z3
    selector = ((request.get('options') or {}).get('native') or {}).get('functionName')
    proof_limit = max(1, min(int(request.get('limit', 32)), 32))
    evidence = {'model':'ghidra-pcode-dag-overapproximation/v1','proofs':[], 'branches':[], 'unmodeled':[], 'cutpoints':[], 'truncated':False}
    operations_total = 0
    for function in document['functions']:
        if selector and function['name'] != selector:
            continue
        operations = function['pcode']
        operations_total += len(operations)
        if operations_total > 4096:
            raise ValueError('P-code operation budget exceeded')
        definitions = {op['output']['id']:op for op in operations if op.get('output')}
        cache, active = {}, set()
        unknowns = set()
        def fresh(node, why):
            key = function['entry'] + ':' + node['id']
            unknowns.add(why)
            return z3.BitVec('v_' + key.encode().hex(), node['bytes'] * 8)
        def boolean(value, width):
            return z3.If(value, z3.BitVecVal(1,width), z3.BitVecVal(0,width))
        def expression(node, depth=0):
            width = node['bytes'] * 8
            if node['constant']:
                return z3.BitVecVal(int(node['offsetHex'],16),width)
            key = node['id']
            if key in cache:
                value, assumptions = cache[key]
                unknowns.update(assumptions)
                return value
            if key in active or depth >= 64:
                if len(evidence['cutpoints']) < 100:
                    evidence['cutpoints'].append({'function':function['entry'],'value':key,'reason':'cycle-or-depth-bound'})
                return fresh(node,'cycle-or-depth-bound')
            op = definitions.get(key)
            if op is None:
                return fresh(node,'external-or-omitted-definition')
            active.add(key)
            try:
                args = [expression(v,depth+1) for v in op['inputs']]
                name = op['opcode']
                value = None
                same = len(args) == 2 and args[0].size() == args[1].size()
                if name == 'COPY' and len(args)==1 and args[0].size()==width: value=args[0]
                elif name in ('INT_ZEXT','INT_SEXT') and len(args)==1 and args[0].size()<=width:
                    value=(z3.ZeroExt if name=='INT_ZEXT' else z3.SignExt)(width-args[0].size(),args[0])
                elif name in ('INT_2COMP','INT_NEGATE') and len(args)==1 and args[0].size()==width:
                    value=-args[0] if name=='INT_2COMP' else ~args[0]
                elif same and args[0].size()==width and name in ('INT_ADD','INT_SUB','INT_MULT','INT_XOR','INT_AND','INT_OR'):
                    a,b=args
                    value={'INT_ADD':lambda:a+b,'INT_SUB':lambda:a-b,'INT_MULT':lambda:a*b,'INT_XOR':lambda:a^b,'INT_AND':lambda:a&b,'INT_OR':lambda:a|b}[name]()
                elif len(args)==2 and args[0].size()==width and args[1].size()<=width and name in ('INT_LEFT','INT_RIGHT','INT_SRIGHT'):
                    shift=z3.ZeroExt(width-args[1].size(),args[1]);a=args[0]
                    value=a<<shift if name=='INT_LEFT' else z3.LShR(a,shift) if name=='INT_RIGHT' else a>>shift
                elif same and name in ('INT_EQUAL','INT_NOTEQUAL','INT_LESS','INT_LESSEQUAL','INT_SLESS','INT_SLESSEQUAL'):
                    a,b=args
                    condition={'INT_EQUAL':lambda:a==b,'INT_NOTEQUAL':lambda:a!=b,'INT_LESS':lambda:z3.ULT(a,b),'INT_LESSEQUAL':lambda:z3.ULE(a,b),'INT_SLESS':lambda:a<b,'INT_SLESSEQUAL':lambda:a<=b}[name]()
                    value=boolean(condition,width)
                elif name=='BOOL_NEGATE' and len(args)==1: value=boolean(args[0]==0,width)
                elif len(args)==2 and name in ('BOOL_AND','BOOL_OR','BOOL_XOR'):
                    a,b=args[0]!=0,args[1]!=0
                    value=boolean(z3.And(a,b) if name=='BOOL_AND' else z3.Or(a,b) if name=='BOOL_OR' else z3.Xor(a,b),width)
                elif name=='PIECE' and len(args)==2 and args[0].size()+args[1].size()==width: value=z3.Concat(*args)
                elif name=='SUBPIECE' and len(args)==2 and op['inputs'][1]['constant']:
                    low=int(op['inputs'][1]['offsetHex'],16)*8
                    if low+width<=args[0].size(): value=z3.Extract(low+width-1,low,args[0])
                if value is None:
                    if len(evidence['unmodeled'])<100: evidence['unmodeled'].append({'function':function['entry'],'operation':op['id'],'opcode':name})
                    value=fresh(node,'unmodeled-opcode')
                cache[key]=(value,set(unknowns))
                return value
            finally:
                active.remove(key)
        for op in operations:
            if op.get('output'):
                if len(evidence['proofs'])>=proof_limit: evidence['truncated']=True; break
                unknowns.clear()
                original=expression(op['output']); simplified=z3.simplify(original)
                solver=z3.Solver();solver.set(timeout=250);solver.add(original!=simplified)
                verdict=solver.check()
                record={'function':function['entry'],'operation':op['id'],'address':op['address'],'output':op['output']['id'],'original':str(original)[:2048],'simplified':str(simplified)[:2048],'expressionTextTruncated':len(str(original))>2048 or len(str(simplified))>2048,'equivalence':'model-equivalent' if verdict==z3.unsat else 'not-proven','assumptions':sorted(unknowns)}
                if z3.is_bv_value(simplified) and verdict==z3.unsat:record['constantHex']=hex(simplified.as_long())
                evidence['proofs'].append(record)
            if op['opcode']=='CBRANCH' and len(op['inputs'])==2 and len(evidence['branches'])<32:
                condition=expression(op['inputs'][1]); solver=z3.Solver();solver.set(timeout=250)
                solver.add(condition!=0);nonzero=solver.check();solver.reset();solver.set(timeout=250);solver.add(condition==0);zero=solver.check()
                direction='never-taken' if nonzero==z3.unsat else 'always-taken' if zero==z3.unsat else 'unresolved'
                evidence['branches'].append({'function':function['entry'],'operation':op['id'],'address':op['address'],'block':op['block'],'direction':direction,'scope':'pcode-overapproximation-not-native-proof'})
        if len(evidence['proofs'])>=proof_limit:break
    result={'protocol':'cline-advanced-analysis/v1','status':'partial','engine':'z3-pcode','engineVersion':importlib.metadata.version('z3-solver'),'input':{'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'format':'ghidra-high-pcode'},'evidence':evidence,'limitations':['Equivalence is scoped to the supplied p-code expression model, not native or whole-program equivalence.','Memory, calls, phi nodes, unsupported operations and loop/depth cutpoints are unconstrained inputs. No path feasibility or alias recovery is claimed.','Decompiler evidence is untrusted input; no target runs, no branch is patched and no CFG is rewritten.']}
    text=json.dumps(result,separators=(',',':'))
    if len(text.encode())>1048576:raise ValueError('Semantic evidence output budget exceeded')
    print(text)
try:
    main()
except ImportError:
    print(json.dumps({'protocol':'cline-advanced-analysis/v1','status':'blocked','engine':'z3-pcode','engineVersion':None,'evidence':{'reason':'Reviewed z3-solver installation required'},'limitations':[]}))
except Exception:
    print(json.dumps({'protocol':'cline-advanced-analysis/v1','status':'failed','engine':'z3-pcode','engineVersion':None,'evidence':{'reason':'Invalid input or semantic engine failure'},'limitations':[]}))
`;
