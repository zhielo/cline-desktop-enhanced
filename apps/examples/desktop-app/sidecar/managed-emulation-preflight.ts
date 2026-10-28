import { execFile } from "node:child_process";
import { win32 } from "node:path";
import { promisify } from "node:util";
import { z } from "zod";

const execute = promisify(execFile);
const flag = z.boolean().nullable();
const bytes = z
	.number()
	.int()
	.nonnegative()
	.max(Number.MAX_SAFE_INTEGER)
	.nullable();
const observation = z.object({
	build: z.string().regex(/^\d{4,6}$/),
	edition: z.string().max(64).nullable(),
	productType: z.number().int().min(1).max(3),
	cpuArchitectures: z.array(z.number().int().min(0).max(255)).min(1).max(64),
	hypervisorPresent: flag,
	hyperVEnabled: flag,
	managementEnabled: flag,
	managementModule: flag,
	vmms: z.enum(["running", "stopped", "absent", "unknown"]),
	servicingRebootPending: flag,
	totalMemoryBytes: bytes,
	freeMemoryBytes: bytes,
	freeStorageBytes: bytes,
});

export type ManagedEmulationHostCheck = {
	id: string;
	label: string;
	state: "observed" | "missing" | "unknown";
};
export type ManagedEmulationPreflight = {
	schemaVersion: 1;
	checkedAt: string;
	platform: "win32" | "unsupported";
	osBuild: string | null;
	query: "observed" | "unavailable" | "not-run";
	hostPrerequisites: "observed" | "missing" | "unknown" | "unsupported";
	checks: ManagedEmulationHostCheck[];
	capacity: {
		totalMemoryGiB: number | null;
		freeMemoryGiB: number | null;
		freeStorageGiB: number | null;
	};
	managedInstallation: "not-implemented";
	containment: "not-tested";
	engineReadiness: "not-tested";
};

/** Fixed read-only query: no elevation, VM/WSL invocation, Hyper-V import, downloads or writes.
 * Only scalar capability/capacity observations leave this process. No names,
 * identifiers, paths, distribution lists, credentials or raw OS diagnostics.
 */
const windowsQuery = String.raw`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules')
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$computer = Get-CimInstance -ClassName Win32_ComputerSystem
$cpus = @(Get-CimInstance -ClassName Win32_Processor)
function FeatureEnabled([string]$name) {
 try {
  $value = Get-CimInstance -ClassName Win32_OptionalFeature -Filter ("Name='" + $name + "'")
  if ($null -eq $value -or $value.InstallState -notin @(1,2,3)) { return $null }
  return [bool]($value.InstallState -eq 1)
 } catch { return $null }
}
$edition = $null
try { $edition = [string](Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID) } catch {}
$vmms = 'unknown'
try {
 $service = Get-Service -Name vmms -ErrorAction SilentlyContinue
 if ($null -eq $service) { $vmms = 'absent' }
 elseif ($service.Status -eq 'Running') { $vmms = 'running' }
 else { $vmms = 'stopped' }
} catch {}
$module = $null
try { $module = [bool](Get-Module -ListAvailable -Name Hyper-V | Select-Object -First 1) } catch {}
$reboot = $null
try {
 $reboot = [bool]((Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'))
} catch {}
$freeStorage = $null
try {
 $volume = [IO.Path]::GetPathRoot($env:LOCALAPPDATA).TrimEnd('\')
 if ($volume -match '^[A-Za-z]:$') {
  $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='" + $volume + "'")
  if ($null -ne $disk -and $disk.DriveType -eq 3) { $freeStorage = [double]$disk.FreeSpace }
 }
} catch {}
@{
 build = [string]$os.BuildNumber
 edition = $edition
 productType = [int]$os.ProductType
 cpuArchitectures = @($cpus | ForEach-Object { [int]$_.Architecture })
 hypervisorPresent = $computer.HypervisorPresent
 hyperVEnabled = FeatureEnabled 'Microsoft-Hyper-V-All'
 managementEnabled = FeatureEnabled 'Microsoft-Hyper-V-Management-PowerShell'
 managementModule = $module
 vmms = $vmms
 servicingRebootPending = $reboot
 totalMemoryBytes = if ($null -eq $computer.TotalPhysicalMemory) { $null } else { [double]$computer.TotalPhysicalMemory }
 freeMemoryBytes = if ($null -eq $os.FreePhysicalMemory) { $null } else { [double]$os.FreePhysicalMemory * 1024 }
 freeStorageBytes = $freeStorage
} | ConvertTo-Json -Depth 4 -Compress
`;

/** Prerequisites are observations, never VM isolation or engine readiness proof. */
export function projectManagedEmulationPreflight(
	value: unknown,
	platform: string,
	architecture: string,
): ManagedEmulationPreflight {
	const parsed = observation.safeParse(value);
	const v = platform === "win32" && parsed.success ? parsed.data : null;
	const checks: ManagedEmulationHostCheck[] = [];
	const add = (id: string, label: string, result: boolean | null) =>
		checks.push({
			id,
			label,
			state: result === null ? "unknown" : result ? "observed" : "missing",
		});
	const supportedEdition =
		v?.edition === null || !v
			? null
			: [
					"Professional",
					"ProfessionalN",
					"Enterprise",
					"EnterpriseN",
					"EnterpriseS",
					"EnterpriseSN",
				].includes(v.edition);
	add(
		"windows-client",
		"Windows client build 19041 or later",
		v ? v.productType === 1 && Number(v.build) >= 19041 : null,
	);
	add("edition", "Reviewed Pro or Enterprise edition family", supportedEdition);
	add(
		"architecture",
		"x86-64 host and processor",
		v
			? architecture === "x64" && v.cpuArchitectures.every((a) => a === 9)
			: null,
	);
	add("hyper-v", "Hyper-V feature enabled", v?.hyperVEnabled ?? null);
	add(
		"management-feature",
		"Hyper-V PowerShell feature enabled",
		v?.managementEnabled ?? null,
	);
	add(
		"management-module",
		"Hyper-V management module present (not imported)",
		v?.managementModule ?? null,
	);
	add(
		"hypervisor",
		"Hypervisor reported present (not isolation attestation)",
		v?.hypervisorPresent ?? null,
	);
	add(
		"vmms",
		"VM management service running (not started by this check)",
		!v || v.vmms === "unknown" ? null : v.vmms === "running",
	);
	add(
		"servicing-reboot",
		"No queried servicing reboot marker",
		v?.servicingRebootPending === null || !v ? null : !v.servicingRebootPending,
	);
	const gib = (n: number | null | undefined) =>
		n == null ? null : Math.floor((n / 1024 ** 3) * 10) / 10;
	return {
		schemaVersion: 1,
		checkedAt: new Date().toISOString(),
		platform: platform === "win32" ? "win32" : "unsupported",
		osBuild: v?.build ?? null,
		query: platform !== "win32" ? "not-run" : v ? "observed" : "unavailable",
		hostPrerequisites:
			platform !== "win32" ||
			(v &&
				(v.productType !== 1 ||
					Number(v.build) < 19041 ||
					architecture !== "x64" ||
					supportedEdition === false ||
					v.cpuArchitectures.some((a) => a !== 9)))
				? "unsupported"
				: checks.some((c) => c.state === "missing")
					? "missing"
					: checks.some((c) => c.state === "unknown")
						? "unknown"
						: "observed",
		checks,
		capacity: {
			totalMemoryGiB: gib(v?.totalMemoryBytes),
			freeMemoryGiB: gib(v?.freeMemoryBytes),
			freeStorageGiB: gib(v?.freeStorageBytes),
		},
		managedInstallation: "not-implemented",
		containment: "not-tested",
		engineReadiness: "not-tested",
	};
}

let inFlight: Promise<ManagedEmulationPreflight> | undefined;
/** Explicit trusted command only. Single-flight, no persistent or readiness cache. */
export function readManagedEmulationPreflight(): Promise<ManagedEmulationPreflight> {
	if (inFlight) return inFlight;
	inFlight = (async () => {
		let raw: unknown = null;
		if (process.platform === "win32") {
			try {
				const root = process.env.SystemRoot;
				if (!root || !/^[A-Za-z]:[\\/]/.test(root) || root.includes("\0"))
					throw new Error("System path unavailable");
				const result = await execute(
					win32.join(
						root,
						"System32",
						"WindowsPowerShell",
						"v1.0",
						"powershell.exe",
					),
					[
						"-NoLogo",
						"-NoProfile",
						"-NonInteractive",
						"-EncodedCommand",
						Buffer.from(windowsQuery, "utf16le").toString("base64"),
					],
					{
						timeout: 15_000,
						maxBuffer: 16_384,
						windowsHide: true,
						encoding: "utf8",
					},
				);
				raw = JSON.parse(result.stdout.replace(/^\uFEFF/, ""));
			} catch {
				/* Unavailable, never raw OS diagnostics or a readiness grant. */
			}
		}
		return projectManagedEmulationPreflight(
			raw,
			process.platform,
			process.arch,
		);
	})().finally(() => {
		inFlight = undefined;
	});
	return inFlight;
}
