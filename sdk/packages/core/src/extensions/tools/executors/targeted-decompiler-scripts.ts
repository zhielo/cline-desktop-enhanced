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
public class ClineDecompileSelected extends GhidraScript {
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
  } finally {decompiler.dispose();}
 }
}
`;
export function targetedIdaScript(
	outputPath: string,
	selector: FunctionSelector,
) {
	return `# Fixed single-function adapter; requires authorized IDA/Hex-Rays installation.
import traceback, ida_auto, ida_funcs, ida_hexrays, idautils, idc
${idaProgressPrelude(dirname(outputPath))}
OUTPUT_PATH = ${JSON.stringify(outputPath)}
SELECTOR = ${JSON.stringify(selector)}
def main():
    cline_phase("input-loaded")
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays unavailable for the loaded processor; configure the licensed matching decompiler in Setup Center")
    cline_phase("decompiler-initialized")
    cline_phase("auto-analysis-waiting")
    if not ida_auto.auto_wait(): raise RuntimeError("IDA auto-analysis cancelled or incomplete")
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
    cline_phase("output-written")
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
