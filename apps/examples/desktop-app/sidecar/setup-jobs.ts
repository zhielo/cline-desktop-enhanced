import { prepareProcessEnvironment, redactSensitiveText } from "@cline/core";
import { createHash, randomUUID } from "node:crypto";
import {
	lstatSync,
	mkdirSync,
	readFileSync,
	renameSync,
	writeFileSync,
	unlinkSync,
	readdirSync,
} from "node:fs";
import { join } from "node:path";
import {
	readSetupBootIdentity,
	validSetupBootIdentity,
	type SetupBootIdentity,
} from "./setup-boot-identity";
import { resolveClineDataDir } from "@cline/shared/storage";

export type SetupJob = {
	id: string;
	command: string;
	identity: string;
	hostPid: number;
	status: "running" | "completed" | "failed" | "interrupted";
	phase: string;
	startedAt: string;
	updatedAt: string;
	endedAt?: string;
	error?: string;
	bootIdentity?: SetupBootIdentity;
	recoveryScope?: "native-host-only/v1";
	recoveredAfterReboot?: {
		fromBootId: string;
		toBootId: string;
		checkedAt: string;
	};
};
const running = new Map<
	string,
	{ job: SetupJob; completion: Promise<unknown> }
>();
// Reboot proves only native host processes stopped, not saved VM guests, remote
// workers or device operations. Keep this source-owned allowlist narrow.
const nativeRecoveryCommands = new Set([
	"setup_center_install_full",
	"setup_center_test_full",
	"setup_center_rollback_core",
	"setup_center_test_ghidra",
	"setup_center_test_ida",
]);
let admissionBootIdentity: Promise<SetupBootIdentity | null> | undefined;
const root = () => join(resolveClineDataDir(), "setup-center");
function persist(job: SetupJob) {
	mkdirSync(root(), { recursive: true, mode: 0o700 });
	if (lstatSync(root()).isSymbolicLink())
		throw new Error("Linked setup directory forbidden");
	const record = join(root(), `job-${job.id}.json`);
	const recordStage = `${record}.${randomUUID()}.tmp`;
	writeFileSync(recordStage, JSON.stringify(job), { flag: "wx", mode: 0o600 });
	renameSync(recordStage, record);
	const file = join(root(), "latest-job.json");
	const stage = `${file}.${randomUUID()}.tmp`;
	writeFileSync(stage, JSON.stringify(job), { flag: "wx", mode: 0o600 });
	renameSync(stage, file);
}
/** Read-only persisted host state. Never replay installation after reconnect/restart. */
export function getSetupJob(id?: string): SetupJob | null {
	const active = [...running.values()].find((v) => !id || v.job.id === id);
	if (active) return { ...active.job };
	if (id && !/^[a-f0-9-]{36}$/.test(id))
		throw new Error("Invalid setup job identity");
	const file = join(root(), id ? `job-${id}.json` : "latest-job.json");
	let info: ReturnType<typeof lstatSync>;
	try {
		info = lstatSync(file);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
		throw error;
	}
	if (!info.isFile() || info.isSymbolicLink() || info.size > 8192)
		throw new Error("Invalid setup job record");
	const job = JSON.parse(readFileSync(file, "utf8")) as SetupJob;
	if (
		!/^[a-f0-9-]{36}$/.test(job.id) ||
		!/^setup_center_[a-z_]+$/.test(job.command) ||
		!["running", "completed", "failed", "interrupted"].includes(job.status) ||
		!Number.isFinite(Date.parse(job.startedAt))
	)
		throw new Error("Invalid setup job state");
	if (id && id !== job.id) return null;
	// A receipt surviving restart is not evidence that the previous workers exited.
	return job.status === "running"
		? {
				...job,
				status: "interrupted",
				phase:
					"Different or restarted host; previous setup termination is unconfirmed. No operation was replayed.",
			}
		: job;
}
export function assertSetupIdle() {
	if (recoveryLockPresent())
		throw new Error(
			"Setup recovery is in progress or its termination is unconfirmed",
		);
	try {
		lstatSync(join(root(), "setup-admission.json"));
		throw new Error(
			"Setup admission lease is held; previous setup termination must be confirmed",
		);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
	}
	const job = getSetupJob();
	if (job && ["running", "interrupted"].includes(job.status))
		throw new Error(
			`Setup job ${job.id} is ${job.status}; inspect its state before starting another setup change`,
		);
}
/** Admission is synchronous; identical concurrent requests join the exact same job. */
export function startSetupJob(
	command: string,
	args: Record<string, unknown>,
	operation: (phase: (value: string) => void) => Promise<unknown>,
) {
	const { background: _background, ...identityArgs } = args;
	const identity = createHash("sha256")
		.update(JSON.stringify({ command, args: identityArgs }))
		.digest("hex");
	const current = [...running.values()][0];
	if (current) {
		if (current.job.identity !== identity)
			throw new Error(
				"A different setup operation is already running; no duplicate or competing installation was started",
			);
		return { job: { ...current.job }, completion: current.completion };
	}
	assertSetupIdle();
	const job: SetupJob = {
		id: randomUUID(),
		command,
		identity,
		hostPid: process.pid,
		status: "running",
		phase: "Accepted; preparing setup",
		startedAt: new Date().toISOString(),
		updatedAt: new Date().toISOString(),
	};
	mkdirSync(root(), { recursive: true, mode: 0o700 });
	if (lstatSync(root()).isSymbolicLink())
		throw new Error("Linked setup directory forbidden");
	if (nativeRecoveryCommands.has(command))
		job.recoveryScope = "native-host-only/v1";
	const admission = join(root(), "setup-admission.json");
	writeFileSync(
		admission,
		JSON.stringify({
			id: job.id,
			hostPid: process.pid,
			bootIdentity: job.bootIdentity,
			recoveryScope: job.recoveryScope,
		}),
		{ flag: "wx", mode: 0o600 },
	);
	try {
		persist(job);
	} catch (error) {
		unlinkSync(admission);
		throw error;
	} // Admission persistence failure never starts work.
	const phase = (value: string) => {
		job.phase = value.slice(0, 240);
		job.updatedAt = new Date().toISOString();
		persist(job);
	};
	const completion = Promise.resolve()
		.then(async () => {
			// Hold admission while the bounded OS query runs asynchronously; chat/status
			// remain responsive and no worker can start before identity persistence.
			if (job.recoveryScope) {
				const boot = await (admissionBootIdentity ??= readSetupBootIdentity());
				if (boot) {
					const info = lstatSync(admission);
					if (
						!info.isFile() ||
						info.isSymbolicLink() ||
						info.size > 8192 ||
						JSON.parse(readFileSync(admission, "utf8")).id !== job.id
					)
						throw new Error(
							"Setup admission changed before execution; no worker started",
						);
					job.bootIdentity = boot;
					const stage = `${admission}.${randomUUID()}.tmp`;
					writeFileSync(
						stage,
						JSON.stringify({
							id: job.id,
							hostPid: process.pid,
							bootIdentity: boot,
							recoveryScope: job.recoveryScope,
						}),
						{ flag: "wx", mode: 0o600 },
					);
					renameSync(stage, admission);
					persist(job);
				}
			}
			return await operation(phase);
		})
		.then(
			(result) => {
				const value = result as
					| { result?: { outputDrainTimedOut?: boolean } }
					| undefined;
				if (value?.result?.outputDrainTimedOut) {
					job.status = "interrupted";
					job.phase =
						"Setup subprocess termination unconfirmed; admission retained. No work was replayed.";
					return result;
				}
				job.status = "completed";
				job.phase =
					"Setup operation completed; capability readiness remains execution-receipt based";
				return result;
			},
			(error) => {
				job.status =
					(error as { terminationUnconfirmed?: boolean })
						?.terminationUnconfirmed === true
						? "interrupted"
						: "failed";
				job.phase =
					job.status === "interrupted"
						? "Setup subprocess termination unconfirmed; admission retained. No work was replayed."
						: "Setup operation failed; inspect diagnostics";
				// Redact known environment values and credential syntax before bounding persisted failure text.
				job.error = redactSensitiveText(
					error instanceof Error ? error.message : String(error),
					prepareProcessEnvironment().secretValues,
				).slice(-2000);
				throw error;
			},
		)
		.finally(() => {
			job.endedAt = job.updatedAt = new Date().toISOString();
			try {
				persist(job);
				if (job.status === "interrupted") return;
				const info = lstatSync(admission);
				if (
					!info.isFile() ||
					info.isSymbolicLink() ||
					info.size > 8192 ||
					JSON.parse(readFileSync(admission, "utf8")).id !== job.id
				)
					throw new Error("Setup admission identity changed; lease retained");
				unlinkSync(admission);
				// Keep the newest bounded set of terminal summaries, never active work or runtime/project files.
				const files = readdirSync(root())
					.filter((name) => /^job-[a-f0-9-]{36}\.json$/.test(name))
					.map((name) => ({
						name,
						mtime: lstatSync(join(root(), name)).mtimeMs,
					}))
					.sort((a, b) => b.mtime - a.mtime);
				for (const file of files.slice(32)) {
					const info = lstatSync(join(root(), file.name));
					if (info.isFile() && !info.isSymbolicLink() && info.size <= 8192) {
						const value = JSON.parse(
							readFileSync(join(root(), file.name), "utf8"),
						);
						if (["completed", "failed"].includes(value.status))
							unlinkSync(join(root(), file.name));
					}
				}
			} finally {
				running.delete(job.id);
			}
		});
	completion.catch(() => {}); // Background work remains observed after a request/view disconnects.
	running.set(job.id, { job, completion });
	return { job: { ...job }, completion };
}

function recoveryLockPresent() {
	try {
		lstatSync(join(root(), "setup-recovery.json"));
		return true;
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
		throw error;
	}
}
function recoveryState(current: SetupBootIdentity | null) {
	if (running.size)
		throw new Error("An operation is active in this host; recovery refused");
	const admission = join(root(), "setup-admission.json");
	const info = lstatSync(admission);
	if (!info.isFile() || info.isSymbolicLink() || info.size > 8192)
		throw new Error("Invalid setup admission record");
	const bytes = readFileSync(admission, "utf8");
	const lease = JSON.parse(bytes) as {
		id?: string;
		bootIdentity?: SetupBootIdentity;
		recoveryScope?: "native-host-only/v1";
	};
	if (!lease.id || !/^[a-f0-9-]{36}$/.test(lease.id))
		throw new Error("Invalid setup admission identity");
	const job = getSetupJob(lease.id);
	const latest = getSetupJob();
	if (
		!job ||
		latest?.id !== job.id ||
		!["interrupted", "failed"].includes(job.status)
	)
		throw new Error(
			"Setup records do not identify the same interrupted operation",
		);
	if (
		!validSetupBootIdentity(current) ||
		!validSetupBootIdentity(lease.bootIdentity) ||
		!validSetupBootIdentity(job.bootIdentity)
	)
		throw new Error(
			"OS boot identity unavailable or legacy admission; recovery remains blocked",
		);
	if (
		!nativeRecoveryCommands.has(job.command) ||
		job.recoveryScope !== "native-host-only/v1" ||
		lease.recoveryScope !== job.recoveryScope
	)
		throw new Error(
			"Native-host-only recovery evidence missing; VM, remote worker and device operations cannot be recovered by a host reboot",
		);
	const previous = lease.bootIdentity;
	if (JSON.stringify(previous) !== JSON.stringify(job.bootIdentity))
		throw new Error("Setup boot records disagree");
	if (
		current.platform !== previous.platform ||
		current.hostId !== previous.hostId
	)
		throw new Error("Different host identity; recovery refused");
	if (current.bootId === previous.bootId)
		throw new Error(
			"Same OS boot; previous worker termination is unconfirmed. Restarting the app or a missing PID is not sufficient",
		);
	return { admission, bytes, job, current, previous };
}
/** Explicit inspection only. Settings/status polling never probes the OS. */
export async function inspectSetupRecovery() {
	try {
		if (recoveryLockPresent())
			throw new Error(
				"Setup recovery lock is held; automatic lock removal is forbidden",
			);
		const state = recoveryState(await readSetupBootIdentity());
		return {
			canRecover: true,
			jobId: state.job.id,
			reason:
				"Same host, different OS boot verified. The interrupted job can be closed without replaying work.",
		};
	} catch (error) {
		const code = (error as NodeJS.ErrnoException).code;
		return {
			canRecover: false,
			reason:
				code === "ENOENT"
					? "No retained admission to recover"
					: error instanceof Error
						? error.message
						: "Recovery evidence unavailable",
		};
	}
}
/** Reboot-only recovery; legacy/same-boot/foreign-host leases remain blocked. */
export async function recoverSetupAfterReboot(expectedJobId: string) {
	if (!/^[a-f0-9-]{36}$/.test(expectedJobId))
		throw new Error("Exact setup job identity required");
	mkdirSync(root(), { recursive: true, mode: 0o700 });
	if (lstatSync(root()).isSymbolicLink())
		throw new Error("Linked setup directory forbidden");
	const lock = join(root(), "setup-recovery.json");
	const owner = randomUUID();
	writeFileSync(lock, JSON.stringify({ owner }), { flag: "wx", mode: 0o600 });
	try {
		const state = recoveryState(await readSetupBootIdentity());
		if (state.job.id !== expectedJobId)
			throw new Error("Setup job changed; inspect recovery again");
		const now = new Date().toISOString();
		const job: SetupJob = {
			...state.job,
			status: "failed",
			phase:
				"Interrupted setup closed after verified OS reboot. No work was replayed; inspect installed components before retrying.",
			endedAt: now,
			updatedAt: now,
			recoveredAfterReboot: {
				fromBootId: state.previous.bootId,
				toBootId: state.current.bootId,
				checkedAt: now,
			},
		};
		persist(job); // Keep the lease if durable recovery evidence cannot be saved.
		const info = lstatSync(state.admission);
		if (
			!info.isFile() ||
			info.isSymbolicLink() ||
			readFileSync(state.admission, "utf8") !== state.bytes
		)
			throw new Error("Setup admission changed; lease retained");
		unlinkSync(state.admission);
		return {
			job,
			replayed: false as const,
			readinessEstablished: false as const,
		};
	} finally {
		const info = lstatSync(lock);
		if (
			info.isFile() &&
			!info.isSymbolicLink() &&
			info.size <= 8192 &&
			JSON.parse(readFileSync(lock, "utf8")).owner === owner
		)
			unlinkSync(lock);
	}
}
