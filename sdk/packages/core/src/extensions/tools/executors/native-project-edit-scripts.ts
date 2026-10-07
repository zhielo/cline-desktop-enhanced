/** Candidate-only fixed adapters; host publishes only after independent reopen verification. */
export const NATIVE_GHIDRA_EDIT_SCRIPT = `
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.*;
import ghidra.app.cmd.function.*;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.cparser.C.CParserUtils;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
public class ClineNativeEdit extends GhidraScript {
 private JsonObject state(Function f) {JsonObject s=new JsonObject();s.addProperty("name",f.getName());s.addProperty("comment",f.getComment()==null?"":f.getComment());s.addProperty("prototype",f.getPrototypeString(true,true));return s;}
 protected void run() throws Exception {
  String[] args=getScriptArgs();if(args.length!=2)throw new IllegalArgumentException("Expected fixed request and receipt paths");
  JsonObject r=JsonParser.parseString(new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8)).getAsJsonObject();
  String mode=r.get("mode").getAsString(),kind=r.get("kind").getAsString(),value=new String(Base64.getDecoder().decode(r.get("value64").getAsString()),StandardCharsets.UTF_8);
  Function f=null;
  if(kind.equals("address"))f=currentProgram.getFunctionManager().getFunctionAt(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value.replaceFirst("^0x","")));
  else if(kind.equals("symbol")){FunctionIterator it=currentProgram.getFunctionManager().getFunctions(true);int n=0;while(it.hasNext()){if(++n>100000||monitor.isCancelled())throw new IllegalStateException("Selection budget/cancellation");Function x=it.next();if(x.getName().equals(value)){if(f!=null)throw new IllegalStateException("Ambiguous exact function name");f=x;}}}
  else throw new IllegalArgumentException("Invalid selector");
  if(f==null)throw new IllegalStateException("Exact entry not found; no nearby inference");
  JsonObject before=state(f),result=new JsonObject();result.addProperty("requestId",r.get("requestId").getAsString());result.addProperty("requestHash",r.get("requestHash").getAsString());result.addProperty("entry",f.getEntryPoint().toString());result.add("before",before);
  if(mode.equals("verify")){if(!before.equals(r.getAsJsonObject("expected")))throw new IllegalStateException("Persisted candidate state mismatch");result.addProperty("status","verified");result.add("after",before);}
  else if(mode.equals("preview")){result.addProperty("status","preview");result.add("after",before);}
  else if(mode.equals("candidate")) {
   if(!before.equals(r.getAsJsonObject("expected")))throw new IllegalStateException("Function before-state changed");
   int tx=currentProgram.startTransaction("Cline reviewed candidate edit");boolean commit=false;
   try {
    JsonObject changes=r.getAsJsonObject("changes");String oldName=f.getName();
    if(changes.has("prototype")) {
     FunctionDefinitionDataType signature=CParserUtils.parseSignature((DataTypeManagerService)null,currentProgram,changes.get("prototype").getAsString(),false);
     if(signature==null)throw new IllegalStateException("Function prototype parser rejected declaration");
     ApplyFunctionSignatureCmd cmd=new ApplyFunctionSignatureCmd(f.getEntryPoint(),signature,SourceType.USER_DEFINED,false,FunctionRenameOption.RENAME_IF_DEFAULT);
     if(!cmd.applyTo(currentProgram,monitor))throw new IllegalStateException("Function type application failed");
     if(!f.getReturnType().isEquivalent(signature.getReturnType())||f.hasVarArgs()!=signature.hasVarArgs()||f.getParameters().length!=signature.getArguments().length)throw new IllegalStateException("Function type read-back mismatch");
     for(int i=0;i<f.getParameters().length;i++)if(!f.getParameters()[i].getDataType().isEquivalent(signature.getArguments()[i].getDataType()))throw new IllegalStateException("Parameter type read-back mismatch");
    }
    f.setName(changes.has("name")?changes.get("name").getAsString():oldName,SourceType.USER_DEFINED);
    if(changes.has("comment"))f.setComment(changes.get("comment").getAsString());
    JsonObject after=state(f);
    if(changes.has("name")&&!after.get("name").getAsString().equals(changes.get("name").getAsString()))throw new IllegalStateException("Name read-back mismatch");
    if(changes.has("comment")&&!after.get("comment").getAsString().equals(changes.get("comment").getAsString()))throw new IllegalStateException("Comment read-back mismatch");
    if(monitor.isCancelled())throw new IllegalStateException("Edit cancelled");result.add("after",after);result.addProperty("status","candidate-ready");commit=true;
   } finally {currentProgram.endTransaction(tx,commit);}
  } else throw new IllegalArgumentException("Invalid fixed mode");
  Files.write(Paths.get(args[1]),result.toString().getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
 }
}
`;
export function nativeIdaEditScript(
	requestPath: string,
	receiptPath: string,
	databasePath: string,
) {
	return `# Isolated IDA candidate only. No native undo/transaction guarantee is claimed.
import json, base64, ida_auto, ida_funcs, ida_typeinf, ida_loader, ida_name, idautils, idc
REQUEST=${JSON.stringify(requestPath)}
RECEIPT=${JSON.stringify(receiptPath)}
DATABASE=${JSON.stringify(databasePath)}
def state(ea): return dict(name=idc.get_func_name(ea),comment=idc.get_func_cmt(ea,0) or "",prototype=idc.get_type(ea) or "")
def main():
    ida_auto.auto_wait()
    with open(REQUEST,encoding="utf-8") as source:r=json.load(source)
    value=base64.b64decode(r["value64"],validate=True).decode("utf-8");matches=[]
    if r["kind"]=="address":
        ea=int(value,16);f=ida_funcs.get_func(ea)
        if f is not None and f.start_ea==ea: matches=[ea]
    elif r["kind"]=="symbol":
        for count,ea in enumerate(idautils.Functions()):
            if count>=100000:raise RuntimeError("Selection budget exceeded")
            if idc.get_func_name(ea)==value:matches.append(ea)
            if len(matches)>1:raise RuntimeError("Ambiguous exact function name")
    else:raise RuntimeError("Invalid selector")
    if len(matches)!=1:raise RuntimeError("Exact entry not found; no nearby inference")
    ea=matches[0];before=state(ea);mode=r["mode"]
    result=dict(requestId=r["requestId"],requestHash=r["requestHash"],entry="0x%x"%ea,before=before,after=before)
    if mode=="verify":
        if before!=r["expected"]:raise RuntimeError("Persisted candidate state mismatch")
        result["status"]="verified"
    elif mode=="preview":result["status"]="preview"
    elif mode=="candidate":
        if before!=r["expected"]:raise RuntimeError("Function before-state changed")
        changes=r["changes"]
        if "prototype" in changes:
            tif=ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif,None,changes["prototype"],ida_typeinf.PT_SIL) or not tif.is_func():raise RuntimeError("Function prototype parser rejected declaration")
            if not ida_typeinf.apply_tinfo(ea,tif,ida_typeinf.TINFO_DEFINITE):raise RuntimeError("Function type application failed")
            actual=ida_typeinf.tinfo_t()
            if not ida_typeinf.get_tinfo(actual,ea) or not actual.equals_to(tif):raise RuntimeError("Function type read-back mismatch")
        if "name" in changes and not ida_name.set_name(ea,changes["name"],ida_name.SN_CHECK):raise RuntimeError("Name application failed")
        if "comment" in changes and not idc.set_func_cmt(ea,changes["comment"],0):raise RuntimeError("Comment application failed")
        after=state(ea)
        for key in ["name","comment"]:
            if key in changes and after[key]!=changes[key]:raise RuntimeError("Field read-back mismatch")
        if not ida_loader.save_database(DATABASE,0):raise RuntimeError("Candidate database save failed")
        result.update(status="candidate-ready",after=after)
    else:raise RuntimeError("Invalid fixed mode")
    with open(RECEIPT,"x",encoding="utf-8") as output:json.dump(result,output)
code=0
try:main()
except Exception:code=1
finally:idc.qexit(code)
`;
}
