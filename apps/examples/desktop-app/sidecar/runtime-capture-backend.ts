import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { realpathSync, statSync, watch } from "node:fs";
import { open, readdir, readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";
import {
	probeProcessStartTokenAsync,
	resolveWindowsProcessStartCommand,
} from "@cline/core";

export type ProcessRow = { pid: number; parentPid: number; birth: string };
const MAX_SCAN = 4096;
const SOURCE_LIMIT = 1024 * 1024;
function check(signal: AbortSignal) {
	signal.throwIfAborted();
}
export async function assertCaptureFile(
	target: string,
	expected: string,
	signal: AbortSignal,
) {
	check(signal);
	// Same native canonical resolver as immutable artifact/task bindings (Windows 8.3 aliases included).
	const canonical = realpathSync.native(target);
	if (resolve(canonical) !== resolve(target))
		throw new Error("Capture target path changed");
	const file = await open(target, "r");
	try {
		const before = await file.stat();
		if (!before.isFile() || before.size > SOURCE_LIMIT)
			throw new Error("Capture requires a regular file no larger than 1 MiB");
		const buffer = Buffer.alloc(SOURCE_LIMIT + 1);
		const { bytesRead } = await file.read(buffer, 0, buffer.length, 0);
		const bytes = buffer.subarray(0, bytesRead);
		const after = await file.stat();
		const pathStat = await stat(target);
		if (
			bytes.length > SOURCE_LIMIT ||
			before.dev !== after.dev ||
			before.ino !== after.ino ||
			before.size !== after.size ||
			before.mtimeMs !== after.mtimeMs ||
			before.ctimeMs !== after.ctimeMs ||
			after.dev !== pathStat.dev ||
			after.ino !== pathStat.ino ||
			createHash("sha256").update(bytes).digest("hex") !== expected
		)
			throw new Error("Capture file changed after approval");
		check(signal);
		return after;
	} finally {
		await file.close();
	}
}
export async function assertCaptureProcess(
	pid: number,
	token: string,
	signal: AbortSignal,
) {
	check(signal);
	const identity = await probeProcessStartTokenAsync(pid);
	check(signal);
	if (identity.status !== "found" || identity.token !== token)
		throw new Error(
			"Selected process exited, changed identity or identity is unavailable",
		);
}
export function parseLinuxTreeRow(
	pid: number,
	text: string,
): ProcessRow | undefined {
	const end = text.lastIndexOf(")");
	if (end < 0 || text.slice(0, text.indexOf(" ")) !== String(pid)) return;
	const fields = text
		.slice(end + 1)
		.trim()
		.split(/\s+/);
	if (["Z", "X", "x"].includes(fields[0] ?? "")) return;
	if (!/^\d+$/.test(fields[1] ?? "") || !/^\d+$/.test(fields[19] ?? "")) return;
	const parentPid = Number(fields[1]);
	if (!Number.isSafeInteger(parentPid)) return;
	return { pid, parentPid, birth: fields[19]! };
}
export function selectProcessTree(
	rows: ProcessRow[],
	pid: number,
	maxProcesses: number,
) {
	if (
		!Number.isSafeInteger(maxProcesses) ||
		maxProcesses < 1 ||
		maxProcesses > 128
	)
		throw new Error("Invalid process output budget");
	const map = new Map<number, ProcessRow>();
	for (const row of rows) {
		if (
			!Number.isSafeInteger(row.pid) ||
			row.pid < 1 ||
			!Number.isSafeInteger(row.parentPid) ||
			row.parentPid < 0 ||
			!/^\d{1,20}$/.test(row.birth) ||
			map.has(row.pid)
		)
			throw new Error("Ambiguous process identity snapshot");
		map.set(row.pid, row);
	}
	const root = map.get(pid);
	if (!root) throw new Error("Selected process absent from snapshot");
	const selected = [root],
		seen = new Set([pid]);
	let truncated = false;
	for (let i = 0; i < selected.length; i++)
		for (const row of rows) {
			if (row.parentPid !== selected[i]?.pid || seen.has(row.pid)) continue;
			// A new parent incarnation cannot be the parent of an older process.
			if (BigInt(row.birth) < BigInt(selected[i]?.birth)) continue;
			seen.add(row.pid);
			if (selected.length === maxProcesses) {
				truncated = true;
				continue;
			}
			selected.push(row);
		}
	return { processes: selected, truncated };
}
async function windowsRows(signal: AbortSignal): Promise<ProcessRow[]> {
	const command = resolveWindowsProcessStartCommand(
		process.pid,
		process.env,
		(p) => {
			try {
				return statSync(p).isFile();
			} catch {
				return false;
			}
		},
	);
	if (!command)
		throw new Error("Trusted Windows metadata interpreter unavailable");
	// Fixed host-owned script. No model source, command line, target name or path is interpolated.
	const script =
		"$ErrorActionPreference='Stop';$module=Join-Path $PSHOME 'Modules/CimCmdlets/CimCmdlets.psd1';if(-not(Test-Path -LiteralPath $module)){$module=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/Modules/CimCmdlets/CimCmdlets.psd1'};Import-Module -Name $module -ErrorAction Stop;$rows=@(Get-CimInstance -ClassName Win32_Process -Property ProcessId,ParentProcessId,CreationDate | Select-Object -First 4097);if($rows.Count -gt 4096){throw 'Process scan budget exceeded'};$out=@($rows | ForEach-Object {if($null -ne $_.CreationDate){@{pid=[long]$_.ProcessId;parentPid=[long]$_.ParentProcessId;birth=$_.CreationDate.ToUniversalTime().Ticks.ToString([Globalization.CultureInfo]::InvariantCulture)}}});ConvertTo-Json -InputObject $out -Compress";
	const output = await new Promise<string>((yes, no) =>
		execFile(
			command.file,
			["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
			{ windowsHide: true, timeout: 10000, maxBuffer: 1024 * 1024, signal },
			(error, stdout) =>
				error
					? no(
							new Error(
								"Windows process metadata capture failed or exceeded its budget",
							),
						)
					: yes(stdout),
		),
	);
	const raw: unknown = JSON.parse(output.replace(/^\uFEFF/, ""));
	if (!Array.isArray(raw) || raw.length > MAX_SCAN)
		throw new Error("Invalid process snapshot");
	return raw
		.filter((r) => r.pid !== 0)
		.map((r) => ({ pid: r.pid, parentPid: r.parentPid, birth: r.birth }));
}
export async function captureProcessTree(
	pid: number,
	token: string,
	maxProcesses: number,
	signal: AbortSignal,
) {
	await assertCaptureProcess(pid, token, signal);
	let rows: ProcessRow[] = [];
	let unreadable = 0;
	if (process.platform === "linux") {
		const ids = (await readdir("/proc")).filter((x) => /^\d+$/.test(x));
		if (ids.length > MAX_SCAN) throw new Error("Process scan budget exceeded");
		for (let offset = 0; offset < ids.length; offset += 16) {
			check(signal);
			const batch = await Promise.all(
				ids.slice(offset, offset + 16).map(async (id) => {
					try {
						return parseLinuxTreeRow(
							Number(id),
							await readFile(`/proc/${id}/stat`, "utf8"),
						);
					} catch {
						return undefined;
					}
				}),
			);
			for (const row of batch)
				if (row) rows.push(row);
				else unreadable++;
		}
	} else if (process.platform === "win32") rows = await windowsRows(signal);
	else throw new Error("Process-tree capture supports Linux and Windows only");
	const selected = selectProcessTree(rows, pid, maxProcesses);
	const rootBirth = selected.processes[0]?.birth;
	const rootMatches =
		process.platform === "win32"
			? BigInt(rootBirth) / BigInt(10) ===
				BigInt(token.slice("win32:".length)) / BigInt(10)
			: token.slice(token.lastIndexOf(":") + 1) === rootBirth;
	if (!rootMatches) throw new Error("Snapshot root birth identity mismatch");
	await assertCaptureProcess(pid, token, signal);
	return {
		schemaVersion: 1,
		status: "partial",
		provider:
			process.platform === "win32"
				? "windows-cim-process-metadata"
				: "linux-proc-process-metadata",
		root: { pid, processToken: token },
		...selected,
		unreadableRows: unreadable,
		observedAt: new Date().toISOString(),
		limitations: [
			"Non-atomic ancestry metadata, not execution or causal tracing. Descendants may exit or reparent during capture; only the selected root identity is independently rechecked.",
			"No command lines, names, paths, environment, memory or process control. Artifact basis does not establish that the process executed that artifact.",
			"Missing/inaccessible processes and process-table budget limits prevent completeness claims.",
		],
	};
}
export async function captureFileActivity(
	target: string,
	expected: string,
	durationMs: number,
	maxEvents: number,
	signal: AbortSignal,
	ready?: () => void,
) {
	if (
		!Number.isSafeInteger(durationMs) ||
		durationMs < 200 ||
		durationMs > 5000 ||
		!Number.isSafeInteger(maxEvents) ||
		maxEvents < 1 ||
		maxEvents > 128
	)
		throw new Error("Invalid file capture budget");
	const initial = await assertCaptureFile(target, expected, signal);
	return new Promise((yes, no) => {
		const events: { event: "change" | "rename"; at: string }[] = [];
		let watcher: ReturnType<typeof watch> | undefined,
			timer: ReturnType<typeof setTimeout> | undefined,
			done = false;
		const cleanup = () => {
			if (timer) clearTimeout(timer);
			watcher?.close();
			signal.removeEventListener("abort", abort);
		};
		const finish = (reason: string, error?: unknown) => {
			if (done) return;
			done = true;
			cleanup();
			if (error) {
				no(error);
				return;
			}
			yes({
				schemaVersion: 1,
				status: "partial",
				provider: "node-fs-watch-exact-file",
				targetHashAtStart: expected,
				events,
				stopReason: reason,
				budget: { durationMs, maxEvents },
				limitations: [
					"Exact-file OS notifications only; not process-attributed file access or syscall tracing.",
					"Events may be coalesced or missed; no events does not prove absence of reads/writes. No contents, sibling names or recursive paths are captured.",
					"Rename or inode replacement ends observation; an observation may be incomplete even when its deadline expires.",
				],
			});
		};
		const abort = () =>
			finish("cancelled", signal.reason ?? new Error("Capture cancelled"));
		signal.addEventListener("abort", abort, { once: true });
		if (signal.aborted) {
			abort();
			return;
		}
		try {
			watcher = watch(target, { persistent: false }, (event) => {
				if (done) return;
				events.push({ event, at: new Date().toISOString() });
				if (event === "rename") finish("rename-or-replacement");
				else if (events.length >= maxEvents) finish("event-budget");
			});
			watcher.on("error", () =>
				finish("watch-error", new Error("File notification capture failed")),
			);
			timer = setTimeout(() => finish("deadline"), durationMs);
			// Registration must still refer to the exact reviewed file, not a replaced path.
			void stat(target)
				.then(async (current) => {
					if (done) return;
					if (
						current.dev !== initial.dev ||
						current.ino !== initial.ino ||
						current.size !== initial.size ||
						current.mtimeMs !== initial.mtimeMs ||
						current.ctimeMs !== initial.ctimeMs
					)
						throw new Error("Capture file changed during watcher registration");
					await assertCaptureFile(target, expected, signal);
					if (!done) ready?.();
				})
				.catch((error) => finish("registration-failed", error));
		} catch (error) {
			finish("watch-failed", error);
		}
	});
}
