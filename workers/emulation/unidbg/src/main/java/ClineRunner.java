import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.backend.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicInteger;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.dvm.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

/** Fixed primitive JNI harness. No supplied Java source, hooks or classpath. */
public final class ClineRunner {
 interface Action { int run() throws Exception; }
 /** Keep the original failure; cleanup cannot turn a guard into an accepted exit. */
 static int withCleanup(AutoCloseable resource,Action action) throws Exception {
  try(AutoCloseable owned=resource) {return action.run();}
 }
 static final class GuardStopped extends RuntimeException {
  private static final long serialVersionUID=1L;
 }
 static final class Guard {
  final AtomicInteger code=new AtomicInteger();
  volatile boolean failed;
  void stop(Backend backend,int reason) {
   try {
    // Upstream Backend documents stopping from a hook. Do not tear down the
    // JVM/backend from an active native callback with System.exit.
    backend.emu_stop();
    code.compareAndSet(0,reason);
   } catch(RuntimeException error) {
    failed=true;
    throw error;
   }
  }
  void check() {
   if(failed)throw new IllegalStateException("Backend guard stop failed");
   if(code.get()!=0)throw new GuardStopped();
  }
 }
 public static void main(String[] a) throws Exception {
  int status=execute(a);
  if(status!=0) {
   // Resource cleanup succeeded after native frames unwound.
   System.err.println("CLINE_UNIDBG_GUARD_V1 "+status);
   System.exit(status);
  }
 }
 static int execute(String[] a) throws Exception {
  if(a.length!=9)throw new IllegalArgumentException("Fixed arguments required");
  AndroidEmulator emulator=(a[2].equals("arm64")?AndroidEmulatorBuilder.for64Bit():AndroidEmulatorBuilder.for32Bit())
    .setProcessName("cline.approved.native").setRootDir(new File(a[1]))
    .addBackendFactory(new Unicorn2Factory(false)).build();
  final Guard guard=new Guard();
  return withCleanup(emulator,()->{
  try {
   if(!emulator.getBackend().getClass().getName().equals("com.github.unidbg.arm.backend.Unicorn2Backend"))throw new IllegalStateException("Unicorn2 backend required; no fallback");
   final AtomicLong steps=new AtomicLong(); final long limit=Long.parseLong(a[8]);
   emulator.getBackend().hook_add_new(new CodeHook() {
    public void onAttach(UnHook h) {} public void detach() {}
    public void hook(Backend b,long address,int size,Object user) {
     if(guard.code.get()!=0){guard.stop(b,guard.code.get());return;}
     if(steps.incrementAndGet()>limit){guard.stop(b,75);return;}
     byte[] x=b.mem_read(address,size); int w=0;for(int i=0;i<Math.min(4,x.length);i++)w|=(x[i]&255)<<(8*i);
     boolean syscall=a[2].equals("arm64")?(w&0xffe0001f)==0xd4000001&&((w>>>5)&0xffff)==0:
       size==2?(w&0xffff)==0xdf00:(w&0x0fffffff)==0x0f000000;
     if(syscall){guard.stop(b,76);}
    }
   },1,0,null);
   VM vm=emulator.createDalvikVM();vm.setVerbose(false);
   // No AndroidResolver, APK classes, custom Java return stubs, IO resolver or host mounts.
   DalvikModule dm=vm.loadLibrary(new File(a[0]),true);guard.check();
   if(dm.getModule().findSymbolByName("JNI_OnLoad",false)==null)throw new IllegalArgumentException("JNI_OnLoad required by this profile");
   dm.callJNI_OnLoad(emulator);guard.check();
   String value="null";
   if(a[3].equals("jni-int32")) {
    String symbol="Java_"+a[4].replace('/','_')+"_"+a[5];
    if(dm.getModule().findSymbolByName(symbol,false)==null)throw new IllegalArgumentException("Exact static JNI export required");
    DvmClass cls=vm.resolveClass(a[4]);
    value=Integer.toString(cls.callStaticJniMethodInt(emulator,a[5]+"(I)I",Integer.parseInt(a[6])));guard.check();
   } else if(!a[3].equals("initialize"))throw new IllegalArgumentException("Unsupported scenario");
   guard.check();
   Files.write(Paths.get(a[7]),("{\"initialized\":true,\"returnValue\":"+value+",\"backend\":\"unicorn2\",\"instructionCount\":"+steps.get()+"}").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
   return 0;
  } catch(RuntimeException error) {
   // Backend stop may interrupt the loader/JNI bridge before its normal return.
   // Only an observed successful stop can produce the dedicated guard exit.
   if(!guard.failed && guard.code.get()!=0)return guard.code.get();
   throw error;
  }
  });
 }
}
