// Fixed, controller-owned Windows lowbox launcher. Target output is never parsed as a receipt.
// AppContainer is a kernel access-control boundary, not a VM or hardware attestation.
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Web.Script.Serialization;
class JavaScriptIsolation {
 [StructLayout(LayoutKind.Sequential)] struct SI { public uint cb; public IntPtr reserved,desktop,title; public uint x,y,xs,ys,xc,yc,fill,flags; public ushort show,reserved2; public IntPtr reservedPtr,input,output,error; }
 [StructLayout(LayoutKind.Sequential)] struct SIX { public SI si; public IntPtr attributes; }
 [StructLayout(LayoutKind.Sequential)] struct PI { public IntPtr process,thread; public uint pid,tid; }
 [StructLayout(LayoutKind.Sequential)] struct SA { public int length; public IntPtr descriptor; public int inherit; }
 [StructLayout(LayoutKind.Sequential)] struct SC { public IntPtr sid,capabilities; public uint count,reserved; }
 [StructLayout(LayoutKind.Sequential)] struct BASIC { public long processTime,jobTime; public uint flags; public UIntPtr minWorking,maxWorking; public uint active; public UIntPtr affinity; public uint priority,scheduling; }
 [StructLayout(LayoutKind.Sequential)] struct IO { public ulong rOps,wOps,oOps,rBytes,wBytes,oBytes; }
 [StructLayout(LayoutKind.Sequential)] struct LIMIT { public BASIC basic; public IO io; public UIntPtr processMemory,jobMemory,peakProcess,peakJob; }
 [DllImport("userenv.dll",CharSet=CharSet.Unicode)] static extern int CreateAppContainerProfile(string name,string display,string description,IntPtr capabilities,uint count,out IntPtr sid);
 [DllImport("userenv.dll",CharSet=CharSet.Unicode)] static extern int DeleteAppContainerProfile(string name);
 [DllImport("advapi32.dll")] static extern IntPtr FreeSid(IntPtr sid);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr buffer,int size,out int required);
 [DllImport("advapi32.dll")] static extern bool EqualSid(IntPtr a,IntPtr b);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr descriptor,out uint size);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool SetFileSecurity(string path,uint information,IntPtr descriptor);
 [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,int flags,ref IntPtr size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,IntPtr size,IntPtr previous,IntPtr returned);
 [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string application,StringBuilder command,IntPtr processAttributes,IntPtr threadAttributes,bool inherit,uint flags,IntPtr environment,string directory,ref SIX startup,out PI process);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes,string name);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,ref LIMIT information,uint size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint time);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,out long creation,out long exit,out long kernel,out long user);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool CreatePipe(out IntPtr read,out IntPtr write,ref SA attributes,uint size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetHandleInformation(IntPtr handle,uint mask,uint flags);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadFile(IntPtr file,byte[] buffer,uint size,out uint read,IntPtr overlap);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFile(string file,uint access,uint share,ref SA attributes,uint creation,uint flags,IntPtr template);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 static void Check(bool ok) { if(!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
 static void Close(ref IntPtr p) { if(p!=IntPtr.Zero && p!=new IntPtr(-1)) CloseHandle(p); p=IntPtr.Zero; }
 static void Grant(string root,string scratch,SecurityIdentifier sid) {
  var security=new DirectorySecurity(); security.SetAccessRuleProtection(true,false);
  var me=WindowsIdentity.GetCurrent().User;
  security.AddAccessRule(new FileSystemAccessRule(me,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
  security.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.ReadAndExecute,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
  Directory.SetAccessControl(root,security);
  var rw=Directory.GetAccessControl(scratch); rw.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.Modify,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow)); Directory.SetAccessControl(scratch,rw);
  IntPtr label; uint size; Check(ConvertStringSecurityDescriptorToSecurityDescriptor("S:(ML;OICI;NW;;;LW)",1,out label,out size));
  try { Check(SetFileSecurity(scratch,0x10,label)); } finally { LocalFree(label); }
 }
 static IntPtr TokenInfo(IntPtr token,int kind) {
  int required; GetTokenInformation(token,kind,IntPtr.Zero,0,out required);
  if(required<4 || required>65536) throw new Exception("Token information budget");
  IntPtr p=Marshal.AllocHGlobal(required); try { Check(GetTokenInformation(token,kind,p,required,out required)); return p; } catch { Marshal.FreeHGlobal(p); throw; }
 }
 static void Verify(IntPtr process,IntPtr sid) {
  IntPtr token; Check(OpenProcessToken(process,8,out token));
  try {
   IntPtr low=TokenInfo(token,29), identity=TokenInfo(token,31), caps=TokenInfo(token,30);
   try { if(Marshal.ReadInt32(low)!=1 || !EqualSid(Marshal.ReadIntPtr(identity),sid) || Marshal.ReadInt32(caps)!=0) throw new Exception("Child is not the exact zero-capability AppContainer"); }
   finally {Marshal.FreeHGlobal(low);Marshal.FreeHGlobal(identity);Marshal.FreeHGlobal(caps);}
  } finally { CloseHandle(token); }
 }
 static string Quote(string s) { if(s.IndexOf('"')>=0 || s.IndexOf('\0')>=0) throw new Exception("Invalid fixed path"); return "\""+s+"\""; }
 sealed class Capture {
  public readonly MemoryStream bytes=new MemoryStream(); public volatile bool overflow; public string error; public Thread thread;
  public Capture(IntPtr pipe,IntPtr job) {thread=new Thread(()=> {try {byte[] buffer=new byte[4096]; uint n; while(ReadFile(pipe,buffer,4096,out n,IntPtr.Zero)&&n>0) {if(bytes.Length+n>65536) {overflow=true;TerminateJobObject(job,124);break;} bytes.Write(buffer,0,(int)n);}}catch(Exception e){error=e.GetType().Name;} });thread.IsBackground=true; thread.Start();}
 }

 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadProcessMemory(IntPtr process,IntPtr address,byte[] bytes,UIntPtr size,out UIntPtr read);
 static string Sha(byte[] bytes) {using(var hash=System.Security.Cryptography.SHA256.Create())return BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-","").ToLowerInvariant();}
 static byte[] Image(string path) {var info=new FileInfo(path);if(!info.Exists||info.Length<64||info.Length>512L*1024*1024)throw new Exception("Native image byte budget");return File.ReadAllBytes(path);}
 static Dictionary<string,object> ModuleObservation(string[] args) {
  if(args.Length!=6)throw new Exception("Expected exact PID, birth ticks, artifact hash/path and runtime address");
  uint pid=uint.Parse(args[1]);long ticks=long.Parse(args[2]);string hash=args[3],path=Path.GetFullPath(args[4]);
  if(!System.Text.RegularExpressions.Regex.IsMatch(hash,"^[a-f0-9]{64}$")||!System.Text.RegularExpressions.Regex.IsMatch(args[5],"^0x[a-fA-F0-9]{1,16}$"))throw new Exception("Invalid native identity/address");
  ulong address=Convert.ToUInt64(args[5].Substring(2),16);
  using(var process=System.Diagnostics.Process.GetProcessById((int)pid)) {
   if(process.StartTime.ToUniversalTime().Ticks!=ticks)throw new Exception("Native process birth changed");
   System.Diagnostics.ProcessModule selected=null;
   foreach(System.Diagnostics.ProcessModule module in process.Modules) {
    ulong start=unchecked((ulong)module.BaseAddress.ToInt64());
    if(string.Equals(Path.GetFullPath(module.FileName),path,StringComparison.OrdinalIgnoreCase)&&address>=start&&address-start<(ulong)module.ModuleMemorySize) {
     if(selected!=null)throw new Exception("Ambiguous loaded module");selected=module;
    }
   }
   if(selected==null)throw new Exception("Runtime address is not in the exact approved loaded module");
   byte[] file=Image(path);if(Sha(file)!=hash)throw new Exception("Mapped artifact changed since approval");
   int pe=BitConverter.ToInt32(file,60);if(pe<64||pe>file.Length-264||BitConverter.ToUInt32(file,pe)!=0x4550)throw new Exception("Invalid bounded PE");
   int machine=BitConverter.ToUInt16(file,pe+4),sections=BitConverter.ToUInt16(file,pe+6),optional=BitConverter.ToUInt16(file,pe+20),opt=pe+24;
   if(sections>96||optional<64||opt+optional+sections*40>file.Length)throw new Exception("Native PE header budget");
   string architecture=machine==0x8664?"x86_64":machine==0x14c?"x86":machine==0xaa64?"arm64":"unknown";
   if(architecture=="unknown")throw new Exception("Unsupported mapped PE architecture");
   ulong imageBase=unchecked((ulong)selected.BaseAddress.ToInt64()),rva=address-imageBase;long fileOffset=-1;
   uint headerBytes=BitConverter.ToUInt32(file,opt+60);
   if(rva<headerBytes && rva+32<=headerBytes)fileOffset=(long)rva;
   for(int i=0;i<sections;i++) {int section=opt+optional+i*40;uint virtualAddress=BitConverter.ToUInt32(file,section+12),rawSize=BitConverter.ToUInt32(file,section+16),raw=BitConverter.ToUInt32(file,section+20);
    if(rva>=virtualAddress && rva-virtualAddress+32<=rawSize) {if(fileOffset>=0)throw new Exception("Ambiguous PE RVA mapping");fileOffset=(long)raw+(long)(rva-virtualAddress);}
   }
   if(fileOffset<0||fileOffset+32>file.Length)throw new Exception("Selected native range is not uniquely file-backed");
   byte[] memory=new byte[32];IntPtr handle=OpenProcess(0x1010,false,pid);if(handle==IntPtr.Zero)throw new Win32Exception();
   try {UIntPtr read;Check(ReadProcessMemory(handle,new IntPtr(unchecked((long)address)),memory,new UIntPtr(32),out read));if(read.ToUInt64()!=32)throw new Exception("Partial native memory read");}finally{CloseHandle(handle);}
   byte[] disk=new byte[32];Array.Copy(file,fileOffset,disk,0,32);
   // Revalidate exact birth, module instance and current backing bytes after the observation.
   process.Refresh();if(process.StartTime.ToUniversalTime().Ticks!=ticks)throw new Exception("Native birth changed during observation");
   bool same=false;foreach(System.Diagnostics.ProcessModule module in process.Modules)if(module.BaseAddress==selected.BaseAddress && module.ModuleMemorySize==selected.ModuleMemorySize && string.Equals(Path.GetFullPath(module.FileName),path,StringComparison.OrdinalIgnoreCase))same=true;
   if(!same||Sha(Image(path))!=hash)throw new Exception("Native module changed during observation");
   return new Dictionary<string,object>{{"profile","cline-native-module/1"},{"artifactSha256",hash},{"pid",pid},{"processToken","win32:"+ticks.ToString(System.Globalization.CultureInfo.InvariantCulture)},{"architecture",architecture},{"runtimeImageBase","0x"+imageBase.ToString("x")},{"runtimeAddress","0x"+address.ToString("x")},{"rva","0x"+rva.ToString("x")},{"observedBytes",32},{"memorySha256",Sha(memory)},{"fileRangeSha256",Sha(disk)},{"byteMatch",Sha(memory)==Sha(disk)},{"scope","host-read-process-memory-exact-birth-and-module-32-byte-range"}};
  }
 }
 static int Main(string[] args) {
  if(args.Length>0 && args[0]=="--module") {
   try {Console.WriteLine(new JavaScriptSerializer().Serialize(ModuleObservation(args)));return 0;}
   catch(Exception e){Console.WriteLine(new JavaScriptSerializer().Serialize(new Dictionary<string,object>{{"error",e.GetType().Name+": "+e.Message}}));return 1;}
  }
  IntPtr sid=IntPtr.Zero,job=IntPtr.Zero,attributes=IntPtr.Zero,security=IntPtr.Zero,handles=IntPtr.Zero,env=IntPtr.Zero;
  IntPtr outRead=IntPtr.Zero,outWrite=IntPtr.Zero,errRead=IntPtr.Zero,errWrite=IntPtr.Zero,input=IntPtr.Zero;
  if(args.Length==2 && args[0]=="--cleanup" && System.Text.RegularExpressions.Regex.IsMatch(args[1],"^cline-js-[a-f0-9]{32}$")) {
   int removed=DeleteAppContainerProfile(args[1]);return removed==0||removed==unchecked((int)0x80070002)||removed==unchecked((int)0x80070003)?0:1;
  }
  PI child=new PI(); string name=args.Length==4?args[3]:""; bool profile=false,attributesInitialized=false;
  Dictionary<string,object> receipt=null; int code=1;string staging=null;
  try {
   if(args.Length!=4||!System.Text.RegularExpressions.Regex.IsMatch(name,"^cline-js-[a-f0-9]{32}$")) throw new Exception("Expected staging root, timeout, mode, controller profile");
   string root=Path.GetFullPath(args[0]); int timeout=int.Parse(args[1]);
   if(timeout<1000||timeout>30000||args[2]!="run") throw new Exception("Invalid fixed run policy");
   if(!System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(root),"^cline-js-isolated-[a-zA-Z0-9_-]{6,32}$") || !string.Equals(Path.GetDirectoryName(root).TrimEnd('\\'),Path.GetTempPath().TrimEnd('\\'),StringComparison.OrdinalIgnoreCase) || (File.GetAttributes(root)&FileAttributes.ReparsePoint)!=0)throw new Exception("Controller-owned private temporary staging required");
   string runtime=Path.Combine(root,"runtime.exe"),target=Path.Combine(root,"target.cjs"),scratch=Path.Combine(root,"scratch");
   if(!File.Exists(runtime)||!File.Exists(target)||!Directory.Exists(scratch)) throw new Exception("Incomplete private staging");
   foreach(string path in Directory.GetFileSystemEntries(root)) if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0) throw new Exception("Reparse staging entry");
   staging=root;
   int hr=CreateAppContainerProfile(name,name,"Ephemeral Cline JS standalone scenario",IntPtr.Zero,0,out sid);
   if(hr!=0) Marshal.ThrowExceptionForHR(hr); profile=true;
   var identity=new SecurityIdentifier(sid); Grant(root,scratch,identity);
   job=CreateJobObject(IntPtr.Zero,null); if(job==IntPtr.Zero) throw new Win32Exception();
   LIMIT limits=new LIMIT(); limits.basic.flags=0x2000|0x8|0x200; limits.basic.active=4; limits.jobMemory=new UIntPtr(256*1024*1024);
   Check(SetInformationJobObject(job,9,ref limits,(uint)Marshal.SizeOf(typeof(LIMIT))));
   SA sa=new SA(); sa.length=Marshal.SizeOf(typeof(SA)); sa.inherit=1;
   Check(CreatePipe(out outRead,out outWrite,ref sa,0)); Check(SetHandleInformation(outRead,1,0));
   Check(CreatePipe(out errRead,out errWrite,ref sa,0)); Check(SetHandleInformation(errRead,1,0));
   input=CreateFile("NUL",0x80000000,3,ref sa,3,0,IntPtr.Zero); if(input==new IntPtr(-1)) throw new Win32Exception();
   IntPtr size=IntPtr.Zero; InitializeProcThreadAttributeList(IntPtr.Zero,2,0,ref size);
   attributes=Marshal.AllocHGlobal(size); Check(InitializeProcThreadAttributeList(attributes,2,0,ref size));attributesInitialized=true;
   SC sc=new SC();sc.sid=sid; security=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SC)));Marshal.StructureToPtr(sc,security,false);
   Check(UpdateProcThreadAttribute(attributes,0,new IntPtr(0x20009),security,new IntPtr(Marshal.SizeOf(typeof(SC))),IntPtr.Zero,IntPtr.Zero));
   handles=Marshal.AllocHGlobal(3*IntPtr.Size); Marshal.WriteIntPtr(handles,0,input);Marshal.WriteIntPtr(handles,IntPtr.Size,outWrite);Marshal.WriteIntPtr(handles,2*IntPtr.Size,errWrite);
   Check(UpdateProcThreadAttribute(attributes,0,new IntPtr(0x20002),handles,new IntPtr(3*IntPtr.Size),IntPtr.Zero,IntPtr.Zero));
   // Exact minimal environment; never inherit API keys, PATH, NODE_OPTIONS, HOME or application settings.
   env=Marshal.StringToHGlobalUni("SystemRoot="+Environment.GetFolderPath(Environment.SpecialFolder.Windows)+"\0TEMP="+scratch+"\0TMP="+scratch+"\0\0");
   SIX startup=new SIX();startup.si.cb=(uint)Marshal.SizeOf(typeof(SIX));startup.si.flags=0x100;startup.si.input=input;startup.si.output=outWrite;startup.si.error=errWrite;startup.attributes=attributes;
   Check(CreateProcess(runtime,new StringBuilder(Quote(runtime)+" "+Quote(target)),IntPtr.Zero,IntPtr.Zero,true,0x80000|0x4|0x400|0x08000000,env,scratch,ref startup,out child));
   // No target instruction can run before exact lowbox token + job assignment verification.
   Verify(child.process,sid); Check(AssignProcessToJobObject(job,child.process));
   long creation,exit,kernel,user; Check(GetProcessTimes(child.process,out creation,out exit,out kernel,out user));
   Close(ref outWrite); Close(ref errWrite); Close(ref input);
   Capture stdout=new Capture(outRead,job),stderr=new Capture(errRead,job);
   if(ResumeThread(child.thread)==0xffffffff) throw new Win32Exception();
   uint wait=WaitForSingleObject(child.process,(uint)timeout); bool timedOut=wait==258;
   if(wait!=0 && !timedOut) throw new Exception("Unknown child wait outcome");
   if(timedOut) Check(TerminateJobObject(job,124));
   Check(TerminateJobObject(job,124)); // terminate all remaining descendants even after root exit
   if(WaitForSingleObject(child.process,5000)!=0) throw new Exception("Child termination unconfirmed");
   if(!stdout.thread.Join(5000)||!stderr.thread.Join(5000)) throw new Exception("Output drain unconfirmed");
   uint exitCode;Check(GetExitCodeProcess(child.process,out exitCode));
   if(stdout.error!=null||stderr.error!=null) throw new Exception("Capture failed");
   receipt=new Dictionary<string,object>{{"profile","cline-js-appcontainer/1"},{"isolation","appcontainer"},{"sid",identity.Value},{"capabilityCount",0},{"verifiedBeforeResume",true},{"pid",child.pid},{"creationFileTime",creation.ToString(System.Globalization.CultureInfo.InvariantCulture)},{"exitCode",exitCode},{"timedOut",timedOut},{"overflow",stdout.overflow||stderr.overflow},{"stdoutBase64",Convert.ToBase64String(stdout.bytes.ToArray())},{"stderrBase64",Convert.ToBase64String(stderr.bytes.ToArray())}};
   code=0;
  } catch(Exception e) {receipt=new Dictionary<string,object>{{"error",e.GetType().Name+": "+e.Message}};code=1;}
  finally {
   if(child.process!=IntPtr.Zero) TerminateProcess(child.process,124);
   Close(ref job); Close(ref child.thread);Close(ref child.process);Close(ref outRead);Close(ref outWrite);Close(ref errRead);Close(ref errWrite);Close(ref input);
   if(attributesInitialized) DeleteProcThreadAttributeList(attributes);
   foreach(IntPtr p in new[]{attributes,security,handles,env}) if(p!=IntPtr.Zero)Marshal.FreeHGlobal(p);
   if(profile && DeleteAppContainerProfile(name)!=0) {receipt=new Dictionary<string,object>{{"error","AppContainer profile cleanup failed"}};code=1;}
   if(sid!=IntPtr.Zero) FreeSid(sid);
   // Host owns bounded cleanup even when the desktop controller has exited/crashed.
   if(staging!=null){bool removed=false;for(int attempt=0;attempt<10;attempt++){try{foreach(string fixedName in new[]{"target.cjs","runtime.exe"}){string file=Path.Combine(staging,fixedName);if(File.Exists(file))File.SetAttributes(file,File.GetAttributes(file)&~FileAttributes.ReadOnly);}Directory.Delete(staging,true);removed=true;break;}catch(DirectoryNotFoundException){removed=true;break;}catch{Thread.Sleep(100);}}
    if(!removed){receipt=new Dictionary<string,object>{{"error","Private staging cleanup unconfirmed"}};code=1;}}
  }
  Console.WriteLine(new JavaScriptSerializer().Serialize(receipt)); return code;
 }
}
