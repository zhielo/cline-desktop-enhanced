/** Fixed read-only mailbox adapters. No eval, user script, database edit or target execution. */
export const MANAGED_GHIDRA_SCRIPT = `
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import com.google.gson.*;
public class ClineManagedSelected extends GhidraScript {
 private Path root; private String nonce;
 private void publish(String name, JsonObject value) throws Exception {
  Path stage=root.resolve(name+".stage");
  Files.write(stage,value.toString().getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
  Files.move(stage,root.resolve(name),StandardCopyOption.ATOMIC_MOVE);
 }
 protected void run() throws Exception {
  String[] args=getScriptArgs(); if(args.length!=2) throw new IllegalArgumentException("Expected private mailbox and nonce");
  root=Paths.get(args[0]); nonce=args[1]; long begun=System.currentTimeMillis(),last=begun;
  DecompInterface decompiler=new DecompInterface();
  try {
   if(!decompiler.openProgram(currentProgram)) throw new IllegalStateException("Decompiler initialization failed");
   JsonObject ready=new JsonObject();ready.addProperty("protocol",1);ready.addProperty("nonce",nonce);publish("ready.json",ready);
   while(!monitor.isCancelled() && System.currentTimeMillis()-begun<900000 && System.currentTimeMillis()-last<90000) {
    Path request=root.resolve("request.json");if(!Files.exists(request)){Thread.sleep(100);continue;}
    if(Files.isSymbolicLink(request)||Files.size(request)>32768) throw new IllegalStateException("Unsafe mailbox request");
    JsonObject r=JsonParser.parseString(new String(Files.readAllBytes(request),StandardCharsets.UTF_8)).getAsJsonObject();Files.delete(request);
    if(!nonce.equals(r.get("nonce").getAsString())) throw new IllegalStateException("Mailbox nonce mismatch");
    String id=r.get("id").getAsString();if(!id.matches("[a-f0-9-]{36}"))throw new IllegalArgumentException("Invalid request ID");
    JsonObject result=new JsonObject();result.addProperty("protocol",1);result.addProperty("nonce",nonce);result.addProperty("id",id);last=System.currentTimeMillis();
    try {
     String kind=r.get("kind").getAsString(),value=new String(Base64.getDecoder().decode(r.get("value64").getAsString()),StandardCharsets.UTF_8);
     Function selected=null;
     if(kind.equals("address"))selected=currentProgram.getFunctionManager().getFunctionAt(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value.replaceFirst("^0x","")));
     else if(kind.equals("symbol")) {FunctionIterator f=currentProgram.getFunctionManager().getFunctions(true);int count=0;
      while(f.hasNext()){if(++count>100000||monitor.isCancelled())throw new IllegalStateException("Function selection budget/cancellation");Function x=f.next();if(x.getName().equals(value)){if(selected!=null)throw new IllegalStateException("Ambiguous exact function name");selected=x;}}
     } else throw new IllegalArgumentException("Unknown fixed action");
     if(selected==null)throw new IllegalStateException("Exact function not found; no containing/nearby inference");
     DecompileResults d=decompiler.decompileFunction(selected,45,monitor);
     if(!d.decompileCompleted()||d.getDecompiledFunction()==null)throw new IllegalStateException("Selected decompilation failed");
     String code=d.getDecompiledFunction().getC();if(code.length()>100000)throw new IllegalStateException("Pseudocode output budget exceeded");
     result.addProperty("status","completed");result.addProperty("entry",selected.getEntryPoint().toString());result.addProperty("code",code);
    }catch(Exception error){result.addProperty("status","failed");String message=String.valueOf(error.getMessage());result.addProperty("error",message.substring(0,Math.min(1000,message.length())));}
    publish(id+".json",result);
   }
  }finally{decompiler.dispose();}
 }
}
`;
export function managedIdaScript(root: string, nonce: string) {
	return `# Fixed read-only worker; requires licensed IDA and Hex-Rays. No target execution.
import os, time, json, base64, ida_auto, ida_funcs, ida_hexrays, idautils, idc
ROOT=${JSON.stringify(root)}
NONCE=${JSON.stringify(nonce)}
def publish(name,value):
    path=os.path.join(ROOT,name)
    with open(path+".stage","x",encoding="utf-8") as output: json.dump(value,output)
    os.replace(path+".stage",path)
def main():
    if not ida_hexrays.init_hexrays_plugin(): raise RuntimeError("Hex-Rays unavailable for loaded processor; configure its licensed decompiler")
    if not ida_auto.auto_wait(): raise RuntimeError("IDA auto-analysis cancelled or incomplete")
    publish("ready.json",dict(protocol=1,nonce=NONCE))
    begun=last=time.monotonic()
    while time.monotonic()-begun<900 and time.monotonic()-last<90:
        request=os.path.join(ROOT,"request.json")
        if not os.path.exists(request): time.sleep(.1); continue
        if os.path.islink(request) or os.path.getsize(request)>32768: raise RuntimeError("Unsafe mailbox request")
        with open(request,encoding="utf-8") as source: r=json.load(source)
        os.unlink(request)
        if r.get("nonce")!=NONCE: raise RuntimeError("Mailbox nonce mismatch")
        ident=r.get("id","")
        if len(ident)!=36 or any(c not in "abcdef0123456789-" for c in ident): raise RuntimeError("Invalid request ID")
        result=dict(protocol=1,nonce=NONCE,id=ident);last=time.monotonic()
        try:
            value=base64.b64decode(r["value64"],validate=True).decode("utf-8")
            matches=[]
            if r["kind"]=="address":
                address=int(value,16);f=ida_funcs.get_func(address)
                if f is not None and f.start_ea==address: matches=[address]
            elif r["kind"]=="symbol":
                for count,address in enumerate(idautils.Functions()):
                    if count>=100000: raise RuntimeError("Function selection budget exceeded")
                    if idc.get_func_name(address)==value: matches.append(address)
                    if len(matches)>1: raise RuntimeError("Ambiguous exact function name")
            else: raise RuntimeError("Unknown fixed action")
            if len(matches)!=1: raise RuntimeError("Exact function not found; no containing/nearby inference")
            code=ida_hexrays.decompile(matches[0])
            if code is None: raise RuntimeError("Selected decompilation failed")
            text=str(code)
            if len(text)>100000: raise RuntimeError("Pseudocode output budget exceeded")
            result.update(status="completed",entry="0x%x"%matches[0],code=text)
        except Exception as error: result.update(status="failed",error=str(error)[:1000])
        publish(ident+".json",result)
try: main()
finally: idc.qexit(0)
`;
}
