import com.github.unidbg.arm.backend.Backend;
import java.lang.reflect.Proxy;
import java.util.concurrent.atomic.AtomicInteger;

/** Pure fake-backend unit test: never loads an emulator, native backend or target. */
public final class ClineGuardTest {
 static Backend backend(final AtomicInteger calls, final boolean fail) {
  return (Backend)Proxy.newProxyInstance(Backend.class.getClassLoader(),new Class<?>[]{Backend.class},(proxy,method,args)->{
   if(!method.getName().equals("emu_stop"))throw new AssertionError("Unexpected backend operation");
   calls.incrementAndGet();
   if(fail)throw new IllegalStateException("Owned stop failure");
   return null;
  });
 }
 static void require(boolean value) {if(!value)throw new AssertionError("Owned guard assertion");}
 public static void main(String[] args) throws Exception {
  for(int reason:new int[]{75,76}) {
   AtomicInteger calls=new AtomicInteger();ClineRunner.Guard guard=new ClineRunner.Guard();
   guard.check();guard.stop(backend(calls,false),reason);
   require(calls.get()==1 && guard.code.get()==reason && !guard.failed);
   try {guard.check();throw new AssertionError("Stopped guard admitted forward work");}
   catch(ClineRunner.GuardStopped expected) {}
   guard.stop(backend(calls,false),reason==75?76:75);
   require(calls.get()==2 && guard.code.get()==reason);
  }
  AtomicInteger calls=new AtomicInteger();ClineRunner.Guard guard=new ClineRunner.Guard();
  try {guard.stop(backend(calls,true),76);throw new AssertionError("Failed stop admitted");}
  catch(IllegalStateException expected) {}
  require(calls.get()==1 && guard.code.get()==0 && guard.failed);
  try {guard.check();throw new AssertionError("Failed guard admitted forward work");}
  catch(IllegalStateException expected) {}
  guard=new ClineRunner.Guard();guard.stop(backend(calls,false),75);
  try {guard.stop(backend(calls,true),75);throw new AssertionError("Repeated failed stop admitted");}
  catch(IllegalStateException expected) {}
  require(guard.failed);
  for(int result:new int[]{0,75,76}) {
   AtomicInteger closed=new AtomicInteger();
   require(ClineRunner.withCleanup(()->{closed.incrementAndGet();},()->result)==result);
   require(closed.get()==1);
   Exception cleanup=new Exception("Owned cleanup failure");
   try {
    ClineRunner.withCleanup(()->{throw cleanup;},()->result);
    throw new AssertionError("Cleanup failure became an accepted guard exit");
   } catch(Exception error) {require(error==cleanup);}
  }
  for(Throwable primary:new Throwable[]{
    new IllegalArgumentException("Owned original failure"),
    new NoClassDefFoundError("owned/original/Failure")}) {
   Exception cleanup=new Exception("Owned cleanup failure");
   AtomicInteger closed=new AtomicInteger();
   try {
    ClineRunner.withCleanup(()->{closed.incrementAndGet();throw cleanup;},()->{
     if(primary instanceof Error)throw (Error)primary;
     throw (RuntimeException)primary;
    });
    throw new AssertionError("Original failure disappeared");
   } catch(Throwable actual) {
    require(actual==primary && closed.get()==1);
    require(actual.getSuppressed().length==1 && actual.getSuppressed()[0]==cleanup);
   }
  }
  System.out.println("Owned fake-backend stop guards passed; no emulator or readiness established.");
 }
}
