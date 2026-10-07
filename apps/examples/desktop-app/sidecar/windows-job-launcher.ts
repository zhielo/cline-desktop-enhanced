import { join } from "node:path";

/** Fixed suspended-launch supervisor. Job assignment succeeds before target code resumes. */
const SOURCE = String.raw`
using System; using System.Text; using System.Runtime.InteropServices;
public static class ClineOwnedJob {
 [StructLayout(LayoutKind.Sequential)] struct Basic {public long ptime,jtime;public uint flags;public UIntPtr min,max;public uint processes;public UIntPtr affinity;public uint priority,scheduling;}
 [StructLayout(LayoutKind.Sequential)] struct IO {public ulong a,b,c,d,e,f;}
 [StructLayout(LayoutKind.Sequential)] struct Limits {public Basic basic;public IO io;public UIntPtr processMemory,jobMemory,peakProcess,peakJob;}
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Startup {public int cb;public string reserved,desktop,title;public uint x,y,xsize,ysize,xchars,ychars,fill,flags;public ushort show,reservedBytes;public IntPtr reservedPointer,input,output,error;}
 [StructLayout(LayoutKind.Sequential)] struct Info {public IntPtr process,thread;public uint pid,tid;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr CreateJobObject(IntPtr a,string name);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool SetInformationJobObject(IntPtr job,int type,IntPtr info,uint length);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool CreateProcess(string app,StringBuilder command,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string cwd,ref Startup startup,out Info info);
 [DllImport("kernel32.dll")]static extern uint ResumeThread(IntPtr thread);
 [DllImport("kernel32.dll")]static extern uint WaitForSingleObject(IntPtr handle,uint ms);
 [DllImport("kernel32.dll")]static extern bool GetExitCodeProcess(IntPtr process,out uint code);
 [DllImport("kernel32.dll")]static extern bool TerminateProcess(IntPtr process,uint code);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr handle);
 [DllImport("kernel32.dll")]static extern IntPtr GetStdHandle(int n);
 static Exception Error(string stage){return new InvalidOperationException(stage+" failed (Win32 "+Marshal.GetLastWin32Error()+")");}
 static string Quote(string s){var b=new StringBuilder("\"");int slash=0;foreach(char c in s){if(c=='\\'){slash++;continue;}if(c=='"'){b.Append('\\',slash*2+1);b.Append(c);}else{b.Append('\\',slash);b.Append(c);}slash=0;}b.Append('\\',slash*2);b.Append('"');return b.ToString();}
 public static int Run(string exe,string[] args,string cwd,int memoryMiB,int processCount){
  IntPtr job=IntPtr.Zero,ptr=IntPtr.Zero;Info info=new Info();bool resumed=false;
  try{
   job=CreateJobObject(IntPtr.Zero,null);if(job==IntPtr.Zero)throw Error("CreateJobObject");
   var limits=new Limits();limits.basic.flags=0x2000|0x8|0x200;limits.basic.processes=(uint)processCount;limits.jobMemory=(UIntPtr)((ulong)memoryMiB*1024*1024);
   int size=Marshal.SizeOf(typeof(Limits));ptr=Marshal.AllocHGlobal(size);Marshal.StructureToPtr(limits,ptr,false);if(!SetInformationJobObject(job,9,ptr,(uint)size))throw Error("SetInformationJobObject");
   var startup=new Startup();startup.cb=Marshal.SizeOf(typeof(Startup));startup.flags=0x100;startup.input=GetStdHandle(-10);startup.output=GetStdHandle(-11);startup.error=GetStdHandle(-12);
   var command=new StringBuilder(Quote(exe));foreach(string arg in args)command.Append(" "+Quote(arg));
   if(!CreateProcess(exe,command,IntPtr.Zero,IntPtr.Zero,true,4,IntPtr.Zero,cwd,ref startup,out info))throw Error("CreateProcess suspended");
   if(!AssignProcessToJobObject(job,info.process))throw Error("AssignProcessToJobObject");
   if(ResumeThread(info.thread)==0xffffffff)throw Error("ResumeThread");resumed=true;
   if(WaitForSingleObject(info.process,0xffffffff)!=0)throw Error("WaitForSingleObject");uint code;if(!GetExitCodeProcess(info.process,out code))throw Error("GetExitCodeProcess");return unchecked((int)code);
  }finally{if(!resumed&&info.process!=IntPtr.Zero)TerminateProcess(info.process,125);if(info.thread!=IntPtr.Zero)CloseHandle(info.thread);if(info.process!=IntPtr.Zero)CloseHandle(info.process);if(ptr!=IntPtr.Zero)Marshal.FreeHGlobal(ptr);if(job!=IntPtr.Zero)CloseHandle(job);}
 }
}`;
export function windowsJobInvocation(
	executable: string,
	args: string[],
	cwd: string,
	memoryMiB: number,
	maxProcesses: number,
) {
	if (process.platform !== "win32")
		throw new Error(
			"Windows Job Objects are unavailable on this platform; no silent hard-limit fallback",
		);
	if (
		!Number.isInteger(memoryMiB) ||
		memoryMiB < 128 ||
		memoryMiB > 4096 ||
		!Number.isInteger(maxProcesses) ||
		maxProcesses < 1 ||
		maxProcesses > 32
	)
		throw new Error("Native job limit outside policy");
	const payload = Buffer.from(
			JSON.stringify({ executable, args, cwd, memoryMiB, maxProcesses }),
		).toString("base64"),
		source = Buffer.from(SOURCE).toString("base64");
	const script = `$ErrorActionPreference='Stop';try {$d=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${payload}'))|ConvertFrom-Json;Add-Type -TypeDefinition ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${source}')));exit ([ClineOwnedJob]::Run([string]$d.executable,[string[]]$d.args,[string]$d.cwd,[int]$d.memoryMiB,[int]$d.maxProcesses))}catch{[Console]::Error.WriteLine('Native job supervisor failed: '+$_.Exception.Message);exit 125}`;
	return {
		executable: join(
			process.env.SystemRoot ?? "C:\\Windows",
			"System32",
			"WindowsPowerShell",
			"v1.0",
			"powershell.exe",
		),
		args: ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
		containment: "windows-job-object-suspended-launch",
		limits: { memoryMiB, maxProcesses },
	};
}
export const WINDOWS_JOB_SOURCE = SOURCE;
