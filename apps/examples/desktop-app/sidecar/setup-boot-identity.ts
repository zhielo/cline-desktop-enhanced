import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { promisify } from "node:util";
const execute = promisify(execFile);
import { join } from "node:path";

export type SetupBootIdentity = {
	schemaVersion: 1;
	platform: "linux" | "win32";
	hostId: string;
	bootId: string;
};
const guid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
export function validSetupBootIdentity(
	value: unknown,
): value is SetupBootIdentity {
	if (!value || typeof value !== "object") return false;
	const v = value as SetupBootIdentity;
	return (
		v.schemaVersion === 1 &&
		["linux", "win32"].includes(v.platform) &&
		typeof v.hostId === "string" &&
		/^[a-f0-9]{64}$/.test(v.hostId) &&
		typeof v.bootId === "string" &&
		guid.test(v.bootId) &&
		v.bootId !== "00000000-0000-0000-0000-000000000000"
	);
}
// Fixed read-only OS query. No client arguments, wall-clock estimates, PID tests,
// elevation, registry writes, distribution changes or executable discovery via PATH.
const windowsBootQuery = String.raw`
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ClineSetupBoot {
 [DllImport("ntdll.dll")] private static extern int NtQuerySystemInformation(int kind, IntPtr data, int size, out int length);
 public static string Read() {
  IntPtr data = Marshal.AllocHGlobal(32);
  try {
   int length;
   int status = NtQuerySystemInformation(90, data, 32, out length);
   if (status != 0 || length < 16 || length > 32) throw new InvalidOperationException("Boot identity unavailable");
   return ((Guid)Marshal.PtrToStructure(data, typeof(Guid))).ToString("D");
  } finally { Marshal.FreeHGlobal(data); }
 }
}
'@
$registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
try {
 $key = $registry.OpenSubKey('SOFTWARE\Microsoft\Cryptography')
 if ($null -eq $key) { throw 'Host identity unavailable' }
 try { $hostIdentity = [string]$key.GetValue('MachineGuid') } finally { $key.Dispose() }
} finally { $registry.Dispose() }
@{ host = $hostIdentity; boot = [ClineSetupBoot]::Read() } | ConvertTo-Json -Compress
`;
async function boundedSystemFile(path: string) {
	const stat = await lstat(path);
	if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 4096)
		throw new Error("Invalid OS identity file");
	return (await readFile(path, "utf8")).trim().toLowerCase();
}
/** Unavailable OS evidence disables recovery, never installation or existing tools. */
export async function readSetupBootIdentity(): Promise<SetupBootIdentity | null> {
	try {
		let host: string, boot: string;
		if (process.platform === "linux") {
			host = await boundedSystemFile("/etc/machine-id");
			boot = await boundedSystemFile("/proc/sys/kernel/random/boot_id");
		} else if (process.platform === "win32") {
			const systemRoot = process.env.SystemRoot;
			if (!systemRoot || !/^[a-z]:[\\/]/i.test(systemRoot)) return null;
			const { stdout: raw } = await execute(
				join(
					systemRoot,
					"System32",
					"WindowsPowerShell",
					"v1.0",
					"powershell.exe",
				),
				[
					"-NoLogo",
					"-NoProfile",
					"-NonInteractive",
					"-Command",
					windowsBootQuery,
				],
				{
					timeout: 5000,
					maxBuffer: 16384,
					windowsHide: true,
					encoding: "utf8",
				},
			);
			const result = JSON.parse(raw.replace(/^\uFEFF/, ""));
			host = String(result.host).trim().toLowerCase();
			boot = String(result.boot).trim().toLowerCase();
		} else return null;
		if (
			!/^[a-f0-9-]{32,36}$/.test(host) ||
			/^0+$/.test(host.replaceAll("-", ""))
		)
			return null;
		const result = {
			schemaVersion: 1 as const,
			platform: process.platform as "linux" | "win32",
			hostId: createHash("sha256")
				.update(`${process.platform}:${host}`)
				.digest("hex"),
			bootId: boot,
		};
		return validSetupBootIdentity(result) ? result : null;
	} catch {
		return null;
	} // No parser/OS errors or machine identifiers reach the UI.
}
