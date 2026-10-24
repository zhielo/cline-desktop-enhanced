import { dirname } from "node:path";
import { idaProgressPrelude } from "./ida-job-diagnostics";
export type FunctionSelector = { symbol?: string; address?: string };
export const TARGETED_GHIDRA_SCRIPT = `// Fixed single-function adapter; never executes target code.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Iterator;
import java.util.HashSet;
import java.math.BigInteger;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.Address;
import com.google.gson.*;
public class ClineDecompileSelected extends GhidraScript {
 private int constantVisits=0;
 private int flowVisits=0;
 private void flow(Varnode n,int depth,HashSet<Varnode> seen,JsonArray sources,JsonArray frontiers) {
  if(flowVisits>=256||depth>8||sources.size()>=32||frontiers.size()>=16){if(frontiers.size()<16)frontiers.add("budget");return;}
  flowVisits++;
  if(n==null){frontiers.add("missing-varnode");return;}
  if(seen.contains(n)){frontiers.add("cycle-or-phi");return;}
  seen.add(n);
  JsonObject source=new JsonObject();
  if(n.isConstant()){if(n.getSize()>8){frontiers.add("wide-constant");return;}source.addProperty("kind","constant");source.addProperty("valueHex","0x"+Long.toUnsignedString(n.getOffset(),16));source.addProperty("bytes",n.getSize());sources.add(source);return;}
  if(n.getHigh() instanceof HighParam){source.addProperty("kind","parameter");source.addProperty("parameterIndex",((HighParam)n.getHigh()).getSlot());sources.add(source);return;}
  PcodeOp op=n.getDef();if(op==null){frontiers.add("unresolved-input");return;}
  if(op.getOpcode()==PcodeOp.CALL||op.getOpcode()==PcodeOp.CALLIND){source.addProperty("kind","call-return");source.addProperty("fromAddressHex","0x"+Long.toUnsignedString(op.getSeqnum().getTarget().getOffset(),16));sources.add(source);return;}
  int code=op.getOpcode();
  if(code==PcodeOp.COPY||code==PcodeOp.CAST||code==PcodeOp.INT_ADD||code==PcodeOp.INT_SUB||code==PcodeOp.INT_MULT||code==PcodeOp.INT_XOR||code==PcodeOp.INT_AND||code==PcodeOp.INT_OR||code==PcodeOp.INT_ZEXT||code==PcodeOp.INT_SEXT||code==PcodeOp.PIECE||code==PcodeOp.SUBPIECE||code==PcodeOp.PTRADD||code==PcodeOp.PTRSUB||code==PcodeOp.MULTIEQUAL) {
   if(op.getNumInputs()>16){frontiers.add("input-budget");return;}
   if(code==PcodeOp.MULTIEQUAL)frontiers.add("phi-alternatives-not-path-sensitive");
   for(int i=0;i<op.getNumInputs();i++)flow(op.getInput(i),depth+1,new HashSet<Varnode>(seen),sources,frontiers);
  } else frontiers.add(code==PcodeOp.LOAD?"memory-load":op.getMnemonic());
 }
 private JsonObject valueFlow(Varnode n) {
  JsonObject report=new JsonObject();JsonArray sources=new JsonArray(),frontiers=new JsonArray();flowVisits=0;
  flow(n,0,new HashSet<Varnode>(),sources,frontiers);
  report.add("sources",sources);report.add("frontiers",frontiers);report.addProperty("visited",flowVisits);
  report.addProperty("coverage","bounded-selected-function-def-use-dependencies-not-value-equivalence");
  return report;
 }
 private BigInteger constant(Varnode n,int depth,HashSet<Varnode> seen) {
  if(++constantVisits>256||n==null||depth>6||n.getSize()<1||n.getSize()>8||seen.contains(n))return null;
  if(n.isConstant())return new BigInteger(Long.toUnsignedString(n.getOffset()));
  seen.add(n);PcodeOp op=n.getDef();if(op==null)return null;
  BigInteger mask=BigInteger.ONE.shiftLeft(n.getSize()*8).subtract(BigInteger.ONE);
  if(op.getOpcode()==PcodeOp.COPY||op.getOpcode()==PcodeOp.CAST){BigInteger v=constant(op.getInput(0),depth+1,seen);return v==null?null:v.and(mask);}
  if(op.getOpcode()==PcodeOp.INT_ADD||op.getOpcode()==PcodeOp.INT_SUB||op.getOpcode()==PcodeOp.PTRADD) {
   BigInteger a=constant(op.getInput(0),depth+1,new HashSet<Varnode>(seen)),b=constant(op.getInput(1),depth+1,new HashSet<Varnode>(seen));if(a==null||b==null)return null;
   if(op.getOpcode()==PcodeOp.PTRADD){BigInteger scale=constant(op.getInput(2),depth+1,new HashSet<Varnode>(seen));if(scale==null)return null;b=b.multiply(scale);}
   return (op.getOpcode()==PcodeOp.INT_SUB?a.subtract(b):a.add(b)).and(mask);
  }
  if(op.getOpcode()==PcodeOp.MULTIEQUAL&&op.getNumInputs()<=16){BigInteger same=null;for(int i=0;i<op.getNumInputs();i++){BigInteger v=constant(op.getInput(i),depth+1,new HashSet<Varnode>(seen));if(v==null||(same!=null&&!same.equals(v)))return null;same=v;}return same;}
  return null; // LOAD, unresolved registers/phi values and external state remain unknown.
 }
 protected void run() throws Exception {
  String[] args=getScriptArgs();
  if(args.length!=3) throw new IllegalArgumentException("Expected output, selector kind, encoded value");
  String value=new String(Base64.getDecoder().decode(args[2]),StandardCharsets.UTF_8);
  Function selected=null;
  if(args[1].equals("address")) {
   selected=currentProgram.getFunctionManager().getFunctionAt(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value.replaceFirst("^0x","")));
  } else if(args[1].equals("symbol")) {
   FunctionIterator functions=currentProgram.getFunctionManager().getFunctions(true); int scanned=0;
   while(functions.hasNext()) {
    if(++scanned>100000 || monitor.isCancelled()) throw new IllegalStateException("Function selection budget/cancellation");
    Function function=functions.next();
    if(function.getName().equals(value)) {if(selected!=null) throw new IllegalStateException("Ambiguous exact function name; use entry address"); selected=function;}
   }
  } else throw new IllegalArgumentException("Unknown selector kind");
  if(selected==null) throw new IllegalStateException("Exact function not found; no containing/nearby function inferred");
  DecompInterface decompiler=new DecompInterface();
  try {
   if(!decompiler.openProgram(currentProgram)) throw new IllegalStateException("Decompiler initialization failed");
   DecompileResults result=decompiler.decompileFunction(selected,60,monitor);
   if(!result.decompileCompleted() || result.getDecompiledFunction()==null) throw new IllegalStateException("Selected decompilation failed");
   String code=result.getDecompiledFunction().getC();
   if(code.length()>1000000) throw new IllegalStateException("Selected pseudocode output budget exceeded");
   try(PrintWriter writer=new PrintWriter(args[0],"UTF-8")) {writer.println("/* selected function @ "+selected.getEntryPoint()+"; not a semantic equivalence proof */");writer.println(code);}
   if(result.getHighFunction()==null)throw new IllegalStateException("High p-code unavailable");
   JsonObject evidence=new JsonObject();evidence.addProperty("schemaVersion",1);evidence.addProperty("addressHex","0x"+Long.toUnsignedString(selected.getEntryPoint().getOffset(),16));
   evidence.addProperty("name",selected.getName());evidence.addProperty("signature",selected.getSignature().getPrototypeString());
   evidence.addProperty("pseudocode",code);evidence.addProperty("architecture",currentProgram.getLanguageID().getIdAsString());
   JsonObject image=new JsonObject();image.addProperty("preferredBaseHex","0x"+Long.toUnsignedString(currentProgram.getImageBase().getOffset(),16));image.addProperty("addressSpace","ghidra-program-virtual");evidence.add("image",image);
   JsonArray calls=new JsonArray(),returns=new JsonArray();int visited=0;boolean truncated=false;
   Iterator<PcodeOpAST> operations=result.getHighFunction().getPcodeOps();
   while(operations.hasNext()) {if(++visited>50000||monitor.isCancelled())throw new IllegalStateException("P-code budget/cancellation");PcodeOpAST op=operations.next();
    if(op.getOpcode()==PcodeOp.RETURN) {
     if(returns.size()>=64){truncated=true;continue;}
     JsonObject ret=new JsonObject();ret.addProperty("fromAddressHex","0x"+Long.toUnsignedString(op.getSeqnum().getTarget().getOffset(),16));
     if(op.getNumInputs()>1)ret.add("flow",valueFlow(op.getInput(1)));else ret.addProperty("voidOrUnavailable",true);
     returns.add(ret);continue;
    }
    if(op.getOpcode()!=PcodeOp.CALL&&op.getOpcode()!=PcodeOp.CALLIND)continue;
    if(calls.size()>=128){truncated=true;continue;}
    JsonObject call=new JsonObject();call.addProperty("fromAddressHex","0x"+Long.toUnsignedString(op.getSeqnum().getTarget().getOffset(),16));
    call.addProperty("kind",op.getOpcode()==PcodeOp.CALL?"direct":"indirect");
    constantVisits=0;
    BigInteger target=op.getOpcode()==PcodeOp.CALL&&op.getInput(0).isAddress()?new BigInteger(Long.toUnsignedString(op.getInput(0).getOffset())):constant(op.getInput(0),0,new HashSet<Varnode>());
    if(target!=null){call.addProperty("targetAddressHex","0x"+target.toString(16));call.addProperty("resolution","bounded-high-pcode-constant-candidate");}
    else call.addProperty("resolution","unknown-memory-register-or-ambiguous-phi");
    JsonArray arguments=new JsonArray();
    for(int i=1;i<op.getNumInputs()&&i<=16;i++){JsonObject argument=valueFlow(op.getInput(i));argument.addProperty("index",i-1);arguments.add(argument);}
    call.add("argumentFlows",arguments);call.addProperty("argumentsTruncated",op.getNumInputs()>17);
    calls.add(call);
   }
   evidence.add("callees",calls);evidence.add("returnFlows",returns);evidence.addProperty("relationsTruncated",truncated);evidence.addProperty("coverage","selected-function-decompiler-and-bounded-high-pcode-not-runtime");
   try(PrintWriter writer=new PrintWriter(args[0]+".native.json","UTF-8")){writer.println(evidence.toString());}
  } finally {decompiler.dispose();}
 }
}
`;
export function targetedIdaScript(
	outputPath: string,
	selector: FunctionSelector,
) {
	return `# Fixed single-function adapter; requires authorized IDA/Hex-Rays installation.
import json, traceback, ida_auto, ida_funcs, ida_hexrays, ida_loader, ida_ida, ida_nalt, idautils, idc
${idaProgressPrelude(dirname(outputPath))}
OUTPUT_PATH = ${JSON.stringify(outputPath)}
SELECTOR = ${JSON.stringify(selector)}
def main():
    cline_phase("input-loaded")
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays unavailable for the loaded processor; configure the licensed matching decompiler in Setup Center")
    cline_phase("decompiler-initialized")
    cline_phase("auto-analysis-waiting")
    cline_check_stop()
    if not ida_auto.auto_wait(): raise RuntimeError("IDA auto-analysis cancelled or incomplete")
    cline_check_stop()
    cline_phase("analysis-complete")
    matches=[]
    if SELECTOR.get("address"):
        address=int(SELECTOR["address"],16)
        function=ida_funcs.get_func(address)
        if function is not None and function.start_ea==address: matches=[address]
    else:
        for count,address in enumerate(idautils.Functions()):
            if count>=100000: raise RuntimeError("Function selection budget exceeded")
            if idc.get_func_name(address)==SELECTOR["symbol"]: matches.append(address)
            if len(matches)>1: raise RuntimeError("Ambiguous exact function name; use entry address")
    if len(matches)!=1: raise RuntimeError("Exact function not found; no containing/nearby function inferred")
    cline_phase("decompilation-started")
    pseudocode=ida_hexrays.decompile(matches[0])
    if pseudocode is None: raise RuntimeError("Selected decompilation failed")
    text=str(pseudocode)
    if len(text)>1000000: raise RuntimeError("Selected pseudocode output budget exceeded")
    with open(OUTPUT_PATH,"w",encoding="utf-8") as output: output.write("/* selected function @ 0x%x; not a semantic equivalence proof */\\n" % matches[0]+text)
    class Calls(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self.items=[]
            self.visited=0
            self.truncated=False
        def visit_expr(self, expr):
            self.visited+=1
            if self.visited>100000:
                self.truncated=True
                return 1
            if expr.op!=ida_hexrays.cot_call: return 0
            if len(self.items)>=128:
                self.truncated=True
                return 1
            site=expr.ea
            known_site=site!=idc.BADADDR
            call={"fromAddressHex":hex(site if known_site else matches[0]),"siteResolution":"ctree-ea" if known_site else "function-entry-fallback","kind":"indirect","resolution":"unknown-expression-target"}
            if expr.x.op==ida_hexrays.cot_obj and expr.x.obj_ea!=idc.BADADDR:
                call.update({"kind":"direct","targetAddressHex":hex(expr.x.obj_ea),"resolution":"hex-rays-object-candidate"})
            self.items.append(call)
            return 0
    calls=Calls()
    calls.apply_to(pseudocode.body,None)
    evidence={"schemaVersion":1,"addressHex":hex(matches[0]),"name":idc.get_func_name(matches[0])[:4096],"signature":(idc.get_type(matches[0]) or "")[:16384],"pseudocode":text,"architecture":ida_ida.inf_get_procname()[:256],"image":{"preferredBaseHex":hex(ida_nalt.get_imagebase()),"addressSpace":"ida-database-virtual"},"callees":calls.items,"relationsTruncated":calls.truncated,"coverage":"selected-function-decompiler-and-bounded-ctree-not-runtime"}
    with open(OUTPUT_PATH+".native.json","w",encoding="utf-8") as output: json.dump(evidence,output,ensure_ascii=True)
    cline_phase("output-written")
    cline_phase("database-saving")
    if not ida_loader.save_database(idc.get_idb_path(), ida_loader.DBFL_COMP): raise RuntimeError("IDA database save failed")
    cline_phase("database-saved")
exit_code=0
try: main()
except Exception:
    exit_code=1
    cline_phase("script-failed")
    with open(OUTPUT_PATH+".error.txt","w",encoding="utf-8") as error: error.write(traceback.format_exc()[:4000])
finally:
    cline_phase("script-exiting")
    idc.qexit(exit_code)
`;
}
