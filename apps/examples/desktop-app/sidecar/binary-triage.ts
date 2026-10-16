import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import {
	copyFile,
	lstat,
	mkdir,
	mkdtemp,
	readdir,
	realpath,
	rm,
} from "node:fs/promises";
import { dirname, isAbsolute, join, relative, sep } from "node:path";
import { readFileStrippingUtf8Bom } from "@cline/shared/node";
import { resolveClineDataDir } from "@cline/shared/storage";
import { z } from "zod";
import lock from "../../../../scripts/binary-triage-tools.lock.json";
import { sanitizeEvidence } from "./analysis-workflow";
import {
	type AnalysisWorkflowStore,
	confinedArtifact,
	type WorkflowScope,
} from "./analysis-workflow-store";
import {
	TRIAGE_LIMITATIONS,
	type TriageCapability,
	type TriageInput,
	TriageRequest,
	triageEngine,
} from "./binary-triage-contracts";
import { BINARY_TRIAGE_WORKER } from "./binary-triage-worker";

const Manifest = z
	.object({
		schemaVersion: z.literal(1),
		files: z.record(z.string().regex(/^[a-f0-9]{64}$/)),
	})
	.strict();
const Result = z
	.object({
		engine: z.enum(["radare2", "yara", "capa", "floss"]),
		version: z.string().max(100),
		bindingVersion: z.string().max(100).optional(),
		format: z.enum(["pe", "elf", "other"]),
		category: z.enum(["derived", "rule-match"]),
		data: z.unknown(),
		coverage: z.string().max(1000),
	})
	.strict();
export async function hashTriageFile(file: string) {
	const h = createHash("sha256");
	for await (const b of createReadStream(file)) h.update(b);
	return h.digest("hex");
}
export async function verifyTriagePack(root: string) {
	if (!isAbsolute(root) || (await lstat(root)).isSymbolicLink())
		throw new Error("Non-linked absolute pack root required");
	const canonical = await realpath(root);
	const manifestFile = join(canonical, "manifest.json");
	if ((await lstat(manifestFile)).size > 1024 * 1024)
		throw new Error("Manifest budget");
	const manifest = Manifest.parse(
		JSON.parse(await readFileStrippingUtf8Bom(manifestFile)),
	);
	const entries = Object.entries(manifest.files);
	if (!entries.length || entries.length > 5000)
		throw new Error("Pack inventory budget");
	let total = 0;
	for (const [name, expected] of entries) {
		if (
			isAbsolute(name) ||
			name.includes("\\") ||
			name.split("/").some((p) => !p || p === "." || p === "..")
		)
			throw new Error("Unsafe pack member");
		const file = join(canonical, name),
			info = await lstat(file),
			path = await realpath(file),
			rel = relative(canonical, path);
		if (
			!info.isFile() ||
			info.isSymbolicLink() ||
			rel.startsWith(`..${sep}`) ||
			isAbsolute(rel)
		)
			throw new Error("Pack member escape");
		total += info.size;
		if (total > 512 * 1024 * 1024 || (await hashTriageFile(file)) !== expected)
			throw new Error("Pack integrity failed");
	}
	let walked = 0;
	async function walk(dir: string, prefix = "") {
		for (const entry of await readdir(dir, { withFileTypes: true })) {
			if (++walked > 6000 || entry.isSymbolicLink())
				throw new Error("Pack directory budget/link");
			const name = prefix + entry.name;
			if (entry.isDirectory()) await walk(join(dir, entry.name), `${name}/`);
			else if (
				!entry.isFile() ||
				(name !== "manifest.json" && !manifest.files[name])
			)
				throw new Error("Untracked pack file");
		}
	}
	await walk(canonical);
	const distribution = JSON.parse(
		await readFileStrippingUtf8Bom(join(canonical, "tools.lock.json")),
	);
	if (JSON.stringify(distribution) !== JSON.stringify(lock))
		throw new Error("Pack distribution pins changed");
	for (const tool of lock.tools)
		if (!manifest.files[`${tool.id}/${tool.executable}`])
			throw new Error("Required engine missing");
	if (!manifest.files["owned-fixture.exe"])
		throw new Error("Owned fixture missing");
	if (!manifest.files["triage.yar"]) throw new Error("Reviewed rules missing");
	return {
		root: canonical,
		identity: await hashTriageFile(manifestFile),
		ruleHash: manifest.files["triage.yar"],
	};
}
export type WorkerOutcome = {
	status:
		| "completed"
		| "failed"
		| "cancelled"
		| "timed-out"
		| "termination-unconfirmed";
	output?: unknown;
	reason?: string;
};
/** Injectable for protocol tests; production always uses this fixed supervised process. */
export function runTriageWorker(
	python: string,
	input: Record<string, unknown>,
	cwd: string,
	signal?: AbortSignal,
	timeoutMs = 90_000,
): Promise<WorkerOutcome> {
	return new Promise((done) => {
		if (signal?.aborted) {
			done({ status: "cancelled" });
			return;
		}
		let status: WorkerOutcome["status"] = "completed",
			output = Buffer.alloc(0),
			finished = false;
		const env: NodeJS.ProcessEnv = {
			PYTHONDONTWRITEBYTECODE: "1",
			PYTHONNOUSERSITE: "1",
			R2_NOPLUGINS: "1",
		};
		for (const key of ["SystemRoot", "WINDIR", "COMSPEC", "TEMP", "TMP"])
			if (process.env[key]) env[key] = process.env[key];
		env.PATH = [
			dirname(python),
			typeof input.executable === "string" ? dirname(input.executable) : "",
			process.env.SystemRoot
				? join(process.env.SystemRoot, "System32")
				: "/usr/bin:/bin",
		]
			.filter(Boolean)
			.join(process.platform === "win32" ? ";" : ":");
		const child = spawn(python, ["-I", "-B", "-c", BINARY_TRIAGE_WORKER], {
			cwd,
			env,
			windowsHide: true,
			detached: process.platform !== "win32",
			stdio: ["pipe", "pipe", "pipe"],
		});
		let drain: ReturnType<typeof setTimeout> | undefined;
		let childClosed = false,
			treeConfirmed = false;
		const finish = (value: WorkerOutcome) => {
			if (finished) return;
			finished = true;
			clearTimeout(timer);
			if (drain) clearTimeout(drain);
			signal?.removeEventListener("abort", abort);
			done(value);
		};
		const stop = (reason: WorkerOutcome["status"]) => {
			if (status !== "completed" || finished) return;
			status = reason;
			if (child.pid) {
				if (process.platform === "win32") {
					const killer = spawn(
						join(
							process.env.SystemRoot || "C:\\Windows",
							"System32",
							"taskkill.exe",
						),
						["/pid", String(child.pid), "/T", "/F"],
						{ windowsHide: true, stdio: "ignore" },
					);
					killer.on("error", () =>
						finish({ status: "termination-unconfirmed" }),
					);
					killer.on("close", (code) => {
						treeConfirmed = code === 0;
						if (childClosed)
							finish({
								status: treeConfirmed ? status : "termination-unconfirmed",
							});
					});
				} else {
					try {
						process.kill(-child.pid, "SIGKILL");
						treeConfirmed = true;
					} catch {
						/* exit confirmation remains authoritative */
					}
				}
			}
			drain = setTimeout(
				() => finish({ status: "termination-unconfirmed" }),
				2500,
			);
		};
		const abort = () => stop("cancelled");
		const timer = setTimeout(() => stop("timed-out"), timeoutMs);
		signal?.addEventListener("abort", abort, { once: true });
		child.stdout.on("data", (chunk: Buffer) => {
			if (output.length + chunk.length > 1024 * 1024) {
				stop("failed");
				return;
			}
			output = Buffer.concat([output, chunk]);
		});
		let stderrBytes = 0;
		child.stderr.on("data", (chunk: Buffer) => {
			stderrBytes += chunk.length;
			if (stderrBytes > 256 * 1024) stop("failed");
		});
		child.stdin.on("error", () => {});
		child.on("error", () => finish({ status: "failed" }));
		child.on("close", (code) => {
			if (status !== "completed") {
				childClosed = true;
				if (treeConfirmed) finish({ status });
				return;
			}
			if (code !== 0) {
				let reason = "worker-exit";
				try {
					const diagnostic = z
						.object({
							errorType: z.enum([
								"ValueError",
								"FileNotFoundError",
								"ModuleNotFoundError",
								"ImportError",
								"OSError",
								"CalledProcessError",
								"PermissionError",
							]),
							phase: z.enum([
								"request",
								"yara-import",
								"yara-rules",
								"r2-import",
								"r2-open",
								"r2-inspect",
								"native-launch",
								"native-result",
							]),
						})
						.parse(JSON.parse(output.toString("utf8")));
					reason = `${diagnostic.phase}:${diagnostic.errorType}`;
				} catch {
					/* Unknown child output is never exposed */
				}
				finish({ status: "failed", reason });
				return;
			}
			try {
				finish({
					status: "completed",
					output: Result.parse(JSON.parse(output.toString("utf8"))),
				});
			} catch {
				finish({ status: "failed" });
			}
		});
		child.stdin.end(JSON.stringify(input));
	});
}

type Pack = Awaited<ReturnType<typeof verifyTriagePack>>;
export class BinaryTriageService {
	private active = new Map<
		string,
		{ owner: string; controller: AbortController }
	>();
	private tested = new Map<string, { identity: string; testedAt: string }>();
	constructor(
		private readonly root = process.env.CLINE_BINARY_TRIAGE_ROOT ||
			join(dirname(process.execPath), "resources", "binary-triage"),
		private readonly worker = runTriageWorker,
	) {}
	private async python() {
		const python = process.env.CLINE_RE_PYTHON;
		if (!python || !isAbsolute(python) || !(await lstat(python)).isFile())
			throw new Error(
				"Verified analysis Python runtime required; use Setup Center",
			);
		return { python, identity: await hashTriageFile(python) };
	}
	private async readinessIdentity(pack: Pack) {
		return `${pack.identity}:${(await this.python()).identity}`;
	}
	async status(): Promise<{
		capabilities: TriageCapability[];
		limitations: readonly string[];
	}> {
		const ids = ["radare2", "yara", "capa", "floss"];
		if (process.platform !== "win32" && !process.env.CLINE_BINARY_TRIAGE_ROOT)
			return {
				capabilities: ids.map((id) => ({
					id,
					state: "unsupported",
					reason: "Bundled distribution targets Windows x64",
				})),
				limitations: TRIAGE_LIMITATIONS,
			};
		let pack: Pack;
		try {
			await lstat(this.root);
		} catch {
			return {
				capabilities: ids.map((id) => ({
					id,
					state: "needs-setup",
					reason: "Install a Windows build containing the Binary Triage Pack",
				})),
				limitations: TRIAGE_LIMITATIONS,
			};
		}
		try {
			pack = await verifyTriagePack(this.root);
		} catch {
			return {
				capabilities: ids.map((id) => ({
					id,
					state: "integrity-failed",
					reason:
						"Pack verification failed; reinstall from the trusted installer",
				})),
				limitations: TRIAGE_LIMITATIONS,
			};
		}
		let identity: string;
		try {
			identity = await this.readinessIdentity(pack);
		} catch {
			return {
				capabilities: ids.map((id) => ({
					id,
					state: "needs-setup",
					reason: "Select a verified core/full Python runtime in Setup Center",
				})),
				limitations: TRIAGE_LIMITATIONS,
			};
		}
		return {
			capabilities: ids.map((id) => {
				const receipt = this.tested.get(id),
					ready = receipt?.identity === identity;
				return {
					id,
					state: ready ? "ready" : "installed-not-tested",
					reason: ready
						? "Owned fixture passed for this pack/interpreter; target compatibility remains separate"
						: "Explicit owned-fixture test required; opening settings runs no tools",
					version:
						id === "yara"
							? "4.5.4"
							: lock.tools.find((t) => t.id === id)?.version,
					...(ready ? { testedAt: receipt.testedAt } : {}),
				};
			}),
			limitations: TRIAGE_LIMITATIONS,
		};
	}
	private args(
		pack: Pack,
		operation: TriageInput["operation"],
		target: string,
		address?: string,
	) {
		const id = triageEngine(operation),
			tool = lock.tools.find((t) => t.id === id);
		return {
			operation,
			target,
			rules: join(pack.root, "triage.yar"),
			...(tool
				? {
						executable: join(pack.root, tool.id, tool.executable),
						engineVersion: tool.version,
					}
				: {}),
			...(address ? { address: Number.parseInt(address.slice(2), 16) } : {}),
		};
	}
	async test() {
		const fixture = join(this.root, "owned-fixture.exe");
		if (this.active.size)
			throw new Error("Wait for active triage jobs before readiness testing");
		const key = "owned-fixtures",
			controller = new AbortController();
		this.active.set(key, { owner: key, controller });
		let confirmed = true;
		try {
			const pack = await verifyTriagePack(this.root),
				{ python } = await this.python(),
				identity = await this.readinessIdentity(pack);
			for (const [id, operation] of [
				["radare2", "inspect_binary"],
				["yara", "scan_yara"],
				["capa", "identify_capabilities"],
				["floss", "extract_strings"],
			] as const) {
				this.tested.delete(id);
				const result = await this.worker(
					python,
					this.args(pack, operation, fixture),
					dirname(fixture),
					controller.signal,
				);
				if (result.status === "termination-unconfirmed") confirmed = false;
				if (result.status !== "completed")
					throw new Error(
						`Owned ${id} fixture failed; not ready (${result.status}; ${result.reason ?? "no diagnostic"})`,
					);
				const body = Result.parse(result.output);
				if (
					body.engine !== id ||
					body.format !== "pe" ||
					body.version.replace(/^v/, "") !==
						(id === "yara"
							? "4.5.4"
							: lock.tools
									.find((tool) => tool.id === id)
									?.version.replace(/^v/, "")) ||
					(id === "floss" &&
						!JSON.stringify(body.data).includes(
							"CLINE_OWNED_TRIAGE_FIXTURE_V1",
						)) ||
					(id === "yara" &&
						!JSON.stringify(body.data).includes("cline_owned_fixture"))
				)
					throw new Error(
						`Owned ${id} fixture contract mismatch; version=${body.version.replace(/[^a-zA-Z0-9.+_-]/g, "").slice(0, 80)}; format=${body.format}; owned-marker=${JSON.stringify(body.data).includes(id === "yara" ? "cline_owned_fixture" : "CLINE_OWNED_TRIAGE_FIXTURE_V1")}`,
					);
				this.tested.set(id, { identity, testedAt: new Date().toISOString() });
			}
		} finally {
			if (confirmed) this.active.delete(key);
		}
		return this.status();
	}
	cancel(owner: string, id: string) {
		const running = this.active.get(id);
		if (!running || running.owner !== owner)
			throw new Error("No controllable owning-session triage job");
		running.controller.abort();
		return { cancellationRequested: true, terminationConfirmed: false };
	}
	async run(
		scope: WorkflowScope,
		raw: unknown,
		store: AnalysisWorkflowStore,
		requestId: string,
	) {
		const input = TriageRequest.parse(raw);
		if (!/^[a-f0-9-]{36}$/i.test(requestId))
			throw new Error("Unique request UUID required");
		if (
			this.active.size >= 2 ||
			this.active.has(requestId) ||
			Array.from(this.active.values()).some((v) => v.owner === scope.sessionId)
		)
			throw new Error("Triage capacity occupied; no automatic replay");
		if (
			store
				.list(scope, "triage")
				.some(
					(r) =>
						r.requestId === requestId ||
						r.status === "running" ||
						r.status === "termination-unconfirmed",
				)
		)
			throw new Error(
				"Prior triage termination unresolved; inspect the prior host before new execution",
			);
		const controller = new AbortController();
		this.active.set(requestId, { owner: scope.sessionId, controller });
		let directory: string | undefined,
			recordId: string | undefined,
			retain = false;
		try {
			const pack = await verifyTriagePack(this.root),
				{ python, identity: pythonIdentity } = await this.python();
			const original = await confinedArtifact(scope.workspace, input.target);
			if (original.bytes > 64 * 1024 * 1024)
				throw new Error("Triage input exceeds 64 MiB");
			const anchor = join(resolveClineDataDir(), "binary-triage");
			await mkdir(anchor, { recursive: true, mode: 0o700 });
			if ((await lstat(anchor)).isSymbolicLink())
				throw new Error("Linked private triage directory forbidden");
			directory = await mkdtemp(join(await realpath(anchor), "job-"));
			const target = join(directory, "input.bin");
			await copyFile(original.path, target, 1);
			if (
				(await hashTriageFile(target)) !== original.sha256 ||
				(await confinedArtifact(scope.workspace, input.target)).sha256 !==
					original.sha256
			)
				throw new Error("Target changed during snapshot");
			const record = store.put(scope, "triage", {
				requestId,
				status: "running",
				question: input.question,
				operation: input.operation,
				target: relative(scope.workspace, original.path),
				targetSha256: original.sha256,
				bytes: original.bytes,
				packHash: pack.identity,
				ruleHash: pack.ruleHash,
				pythonIdentity,
				startedAt: new Date().toISOString(),
			});
			recordId = record.id;
			const result = await this.worker(
				python,
				this.args(pack, input.operation, target, input.address),
				directory,
				controller.signal,
			);
			retain = result.status === "termination-unconfirmed";
			const body =
				result.status === "completed" ? Result.parse(result.output) : undefined;
			if (body && body.engine !== triageEngine(input.operation))
				throw new Error("Engine result mismatch");
			const evidence = body ? sanitizeEvidence(body) : undefined;
			return store.completeTriage(scope, recordId, {
				status: result.status,
				finishedAt: new Date().toISOString(),
				evidence,
				resultHash: evidence
					? createHash("sha256").update(JSON.stringify(evidence)).digest("hex")
					: undefined,
				limitations: TRIAGE_LIMITATIONS,
				unresolved: [
					"Interpretation requires operator review; this result does not answer every part of the investigation question.",
				],
			});
		} catch (error) {
			if (recordId)
				store.completeTriage(scope, recordId, {
					status: "failed",
					finishedAt: new Date().toISOString(),
					error: "Analysis failed; no success claimed",
					limitations: TRIAGE_LIMITATIONS,
				});
			throw error;
		} finally {
			if (!retain) {
				this.active.delete(requestId);
				if (directory) await rm(directory, { recursive: true, force: true });
			}
		}
	}
}
export function triageReport(record: Record<string, unknown>) {
	return {
		schemaVersion: 1,
		observed: { targetSha256: record.targetSha256, bytes: record.bytes },
		findings: record.evidence ?? [],
		unanswered: record.unresolved ?? ["No completed analysis evidence"],
		receipt: record,
		limitations: TRIAGE_LIMITATIONS,
	};
}
