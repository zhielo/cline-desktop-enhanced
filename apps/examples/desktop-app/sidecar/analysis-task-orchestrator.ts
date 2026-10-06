import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import {
	chmodSync,
	createReadStream,
	mkdirSync,
	readFileSync,
	realpathSync,
	renameSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { resolveClineDataDir } from "@cline/shared/storage";
import { assertAnalysisSandboxReady } from "./analysis-sandbox-client";

export type AnalysisTaskKind = "static" | "debugger" | "gui" | "dynamic";
export type AnalysisPermission =
	| "Inspect"
	| "Execute"
	| "Debug"
	| "Modify"
	| "Publish";
export type AnalysisTaskStatus =
	| "awaiting-approval"
	| "approved"
	| "running"
	| "completed"
	| "failed"
	| "cancelled"
	| "expired"
	| "interrupted";

export type AnalysisRequest = Record<string, unknown>;

type TargetIdentity = {
	path: string;
	kind: "file" | "directory" | "missing";
	size?: number;
	mtimeMs?: number;
	sha256?: string;
};

export interface AnalysisTaskPlan {
	id: string;
	workspaceRoot: string;
	kind: AnalysisTaskKind;
	operation: string;
	target?: string;
	targetIdentity?: TargetIdentity;
	request: AnalysisRequest;
	requestHash: string;
	permission: AnalysisPermission;
	status: AnalysisTaskStatus;
	requirements: string[];
	risk: "low" | "moderate" | "high";
	budget: {
		timeoutMs: number;
		maxOutputBytes: number;
		network: "disabled" | "recorded";
	};
	createdAt: string;
	expiresAt: string;
	approvedAt?: string;
	startedAt?: string;
	completedAt?: string;
	error?: string;
	evidence?: {
		resultHash: string;
		tool: string;
		outputPaths: string[];
		requestHash: string;
	};
}

type StoredPlan = AnalysisTaskPlan & { approvalTokenHash?: string };

export interface PrepareAnalysisTaskInput {
	workspaceRoot: string;
	kind: AnalysisTaskKind;
	request: AnalysisRequest;
	allowExternalTarget?: boolean;
	timeoutMs?: number;
	maxOutputBytes?: number;
}

export interface AnalysisTaskOrchestratorOptions {
	ledgerFilePath?: string;
	approvalTtlMs?: number;
	maxPlans?: number;
	now?: () => number;
}

const REQUEST_PATH_FIELDS = new Set([
	"target",
	"compare_target",
	"script_path",
	"output_directory",
	"output_file",
	"report_output_file",
]);
const DEFAULT_APPROVAL_TTL_MS = 10 * 60_000;
const DEFAULT_MAX_PLANS = 500;
const MAX_HASH_BYTES = 512 * 1024 * 1024;

function canonicalJson(value: unknown): string {
	const normalize = (item: unknown): unknown => {
		if (Array.isArray(item)) return item.map(normalize);
		if (item && typeof item === "object") {
			return Object.fromEntries(
				Object.entries(item as Record<string, unknown>)
					.filter(([, child]) => child !== undefined)
					.sort(([left], [right]) => left.localeCompare(right))
					.map(([key, child]) => [key, normalize(child)]),
			);
		}
		return item;
	};
	return JSON.stringify(normalize(value));
}

function sha256(value: string): string {
	return createHash("sha256").update(value).digest("hex");
}

function isWithin(root: string, candidate: string): boolean {
	const child = relative(root, candidate);
	return (
		child === "" ||
		(!child.startsWith(`..${sep}`) && child !== ".." && !isAbsolute(child))
	);
}

function canonicalFuturePath(candidate: string): string {
	const absolute = resolve(candidate);
	const missing: string[] = [];
	let current = absolute;
	for (;;) {
		try {
			return resolve(realpathSync.native(current), ...missing);
		} catch {
			const parent = dirname(current);
			if (parent === current) return absolute;
			missing.unshift(current.slice(parent.length + 1));
			current = parent;
		}
	}
}

function canonicalWorkspaceRoot(root: string): string {
	return realpathSync.native(resolve(root));
}

function permissionFor(
	kind: AnalysisTaskKind,
	operation: string,
): AnalysisPermission {
	if (kind === "static") return "Inspect";
	if (kind === "gui" || kind === "dynamic") return "Execute";
	if (["launch", "continue", "step"].includes(operation)) return "Execute";
	return "Debug";
}

function requirementsFor(
	kind: AnalysisTaskKind,
	operation: string,
	externalTarget: boolean,
	request?: AnalysisRequest,
): string[] {
	const requirements = new Set<string>();
	if (externalTarget) requirements.add("external-target");
	if (
		kind === "static" &&
		operation === "advanced_analysis" &&
		request?.advanced_action === "decrypt_blob"
	) {
		requirements.add("authorized-decryption");
		requirements.add("sensitive-plaintext-processing");
	}
	if (kind === "debugger") requirements.add("authorized-target");
	if (
		kind === "gui" ||
		kind === "dynamic" ||
		["launch", "continue", "step"].includes(operation)
	) {
		requirements.add("execution-control");
	}
	if (kind === "dynamic") {
		requirements.add("isolated-sandbox");
		requirements.add("artifact-upload");
		requirements.add("authorized-target-execution");
		if (operation === "android_capture") {
			requirements.add("sensitive-runtime-capture");
			requirements.add("captured-artifact-write");
		}
	}
	return [...requirements];
}

function publicPlan(plan: StoredPlan): AnalysisTaskPlan {
	const { approvalTokenHash: _secret, ...value } = plan;
	return structuredClone(value);
}

function safeError(error: unknown): string {
	return (error instanceof Error ? error.message : String(error))
		.replace(
			/((?:token|secret|password|authorization|cookie)\s*[:=])\s*[^\s,;]+/gi,
			"$1[REDACTED]",
		)
		.slice(0, 1_000);
}

function hashFile(path: string): Promise<string | undefined> {
	const stat = statSync(path);
	if (!stat.isFile() || stat.size > MAX_HASH_BYTES)
		return Promise.resolve(undefined);
	return new Promise((resolveHash, reject) => {
		const hash = createHash("sha256");
		const stream = createReadStream(path);
		stream.on("data", (chunk) => hash.update(chunk));
		stream.on("error", reject);
		stream.on("end", () => resolveHash(hash.digest("hex")));
	});
}

async function targetIdentity(path: string): Promise<TargetIdentity> {
	try {
		const stat = statSync(path);
		return {
			path,
			kind: stat.isFile() ? "file" : "directory",
			size: stat.size,
			mtimeMs: stat.mtimeMs,
			...(stat.isFile() ? { sha256: await hashFile(path) } : {}),
		};
	} catch {
		return { path, kind: "missing" };
	}
}

function normalizeRequestPaths(
	request: AnalysisRequest,
	workspaceRoot: string,
): AnalysisRequest {
	return Object.fromEntries(
		Object.entries(request).map(([key, value]) => {
			if (
				REQUEST_PATH_FIELDS.has(key) &&
				typeof value === "string" &&
				value.trim()
			) {
				const absolute = isAbsolute(value)
					? value
					: resolve(workspaceRoot, value);
				return [key, canonicalFuturePath(absolute)];
			}
			return [key, value];
		}),
	);
}

export class AnalysisTaskOrchestrator {
	private readonly plans = new Map<string, StoredPlan>();
	private readonly consuming = new Set<string>();
	private readonly active = new Map<
		string,
		{ controller: AbortController; timeout: ReturnType<typeof setTimeout> }
	>();
	private readonly ledgerFilePath?: string;
	private readonly approvalTtlMs: number;
	private readonly maxPlans: number;
	private readonly now: () => number;

	constructor(options: AnalysisTaskOrchestratorOptions = {}) {
		this.ledgerFilePath = options.ledgerFilePath;
		this.approvalTtlMs = options.approvalTtlMs ?? DEFAULT_APPROVAL_TTL_MS;
		this.maxPlans = options.maxPlans ?? DEFAULT_MAX_PLANS;
		if (!Number.isSafeInteger(this.maxPlans) || this.maxPlans < 1)
			throw new Error("Analysis ledger capacity must be a positive integer");
		this.now = options.now ?? Date.now;
		this.restore();
	}

	async prepare(input: PrepareAnalysisTaskInput): Promise<AnalysisTaskPlan> {
		this.expireStale();
		const workspaceRoot = canonicalWorkspaceRoot(input.workspaceRoot);
		const request = normalizeRequestPaths(input.request, workspaceRoot);
		const operation = String(request.operation ?? "").trim();
		if (!operation) throw new Error("Analysis request operation is required.");
		const target =
			typeof request.target === "string" ? request.target : undefined;
		const externalTarget = Boolean(target && !isWithin(workspaceRoot, target));
		if (externalTarget && input.allowExternalTarget !== true) {
			throw new Error(
				"Target resolves outside the workspace. Review it and explicitly allow an external target.",
			);
		}
		if (input.kind === "dynamic") await assertAnalysisSandboxReady();
		const permission = permissionFor(input.kind, operation);
		const identity = target ? await targetIdentity(target) : undefined;
		const plan: StoredPlan = {
			id: randomUUID(),
			workspaceRoot,
			kind: input.kind,
			operation,
			...(target ? { target } : {}),
			...(identity ? { targetIdentity: identity } : {}),
			request,
			requestHash: sha256(canonicalJson(request)),
			permission,
			status: "awaiting-approval",
			requirements: requirementsFor(
				input.kind,
				operation,
				externalTarget,
				request,
			),
			risk:
				input.kind === "dynamic" || permission === "Execute" || externalTarget
					? "high"
					: permission === "Debug" ||
							(operation === "advanced_analysis" &&
								request.advanced_action === "decrypt_blob")
						? "moderate"
						: "low",
			budget: {
				timeoutMs: Math.min(
					Math.max(input.timeoutMs ?? 120_000, 1_000),
					30 * 60_000,
				),
				maxOutputBytes: Math.min(
					Math.max(input.maxOutputBytes ?? 1024 * 1024, 64 * 1024),
					16 * 1024 * 1024,
				),
				network: "disabled",
			},
			createdAt: new Date(this.now()).toISOString(),
			expiresAt: new Date(this.now() + this.approvalTtlMs).toISOString(),
		};
		this.expireStale();
		this.prune(this.maxPlans - 1);
		if (this.plans.size >= this.maxPlans)
			throw new Error(
				"Analysis ledger capacity reached; finish or cancel pending work first",
			);
		this.plans.set(plan.id, plan);
		this.persist();
		return publicPlan(plan);
	}

	approve(
		planId: string,
		acceptedRequirements: string[],
		expectedRequestHash: string,
	): { plan: AnalysisTaskPlan; executionToken: string } {
		this.expireStale();
		const plan = this.require(planId);
		if (plan.status !== "awaiting-approval") {
			throw new Error(
				"Only a pending, unexpired analysis plan can be approved.",
			);
		}
		if (plan.requestHash !== expectedRequestHash) {
			throw new Error("The reviewed request hash does not match this plan.");
		}
		const accepted = new Set(acceptedRequirements);
		const missing = plan.requirements.filter((item) => !accepted.has(item));
		if (missing.length > 0) {
			throw new Error(`Missing required approvals: ${missing.join(", ")}`);
		}
		const executionToken = randomUUID();
		plan.approvalTokenHash = sha256(executionToken);
		plan.status = "approved";
		plan.approvedAt = new Date(this.now()).toISOString();
		this.persist();
		return { plan: publicPlan(plan), executionToken };
	}

	async consume(input: {
		planId: string;
		executionToken: string;
		workspaceRoot: string;
		kind: AnalysisTaskKind;
		request: AnalysisRequest;
	}): Promise<AnalysisTaskPlan> {
		this.expireStale();
		const plan = this.require(input.planId);
		const workspaceRoot = canonicalWorkspaceRoot(input.workspaceRoot);
		const request = normalizeRequestPaths(input.request, workspaceRoot);
		const assertApproval = () => {
			const suppliedHash = Buffer.from(sha256(input.executionToken), "hex");
			const expectedHash = Buffer.from(plan.approvalTokenHash ?? "", "hex");
			const tokenMatches =
				suppliedHash.length === expectedHash.length &&
				timingSafeEqual(suppliedHash, expectedHash);
			if (
				plan.status !== "approved" ||
				!tokenMatches ||
				plan.workspaceRoot !== workspaceRoot ||
				plan.kind !== input.kind ||
				plan.requestHash !== sha256(canonicalJson(request))
			) {
				throw new Error(
					"Analysis approval does not match this exact request envelope.",
				);
			}
		};
		assertApproval();
		if (this.consuming.has(plan.id))
			throw new Error(
				"Analysis approval does not match this exact request envelope.",
			);
		this.consuming.add(plan.id);
		try {
			if (plan.target && plan.targetIdentity) {
				const currentIdentity = await targetIdentity(plan.target);
				if (
					canonicalJson(currentIdentity) !== canonicalJson(plan.targetIdentity)
				) {
					throw new Error(
						"The analysis target changed after review. Prepare a new plan.",
					);
				}
			}
			// Hashing yields to cancellation, expiry and concurrent command handlers.
			this.expireStale();
			assertApproval();
			plan.approvalTokenHash = undefined;
			plan.status = "running";
			plan.startedAt = new Date(this.now()).toISOString();
			const controller = new AbortController();
			const timeout = setTimeout(() => {
				controller.abort(
					new Error(`Analysis timed out after ${plan.budget.timeoutMs}ms`),
				);
				const current = this.plans.get(plan.id);
				if (current?.status === "running") {
					current.status = "failed";
					current.completedAt = new Date(this.now()).toISOString();
					current.error = `Analysis timed out after ${plan.budget.timeoutMs}ms`;
					this.persist();
				}
				this.active.delete(plan.id);
			}, plan.budget.timeoutMs);
			this.active.set(plan.id, { controller, timeout });
			this.persist();
			return publicPlan(plan);
		} finally {
			this.consuming.delete(plan.id);
		}
	}

	signal(planId: string): AbortSignal {
		const active = this.active.get(planId);
		if (!active) throw new Error("Analysis task is not actively running.");
		return active.controller.signal;
	}

	complete(
		planId: string,
		result: unknown,
		tool: string,
		outputPaths: string[] = [],
	): AnalysisTaskPlan {
		const plan = this.require(planId);
		if (plan.status !== "running") {
			throw new Error("Only a running analysis task can be completed.");
		}
		plan.status = "completed";
		plan.completedAt = new Date(this.now()).toISOString();
		plan.evidence = {
			resultHash: sha256(canonicalJson(result)),
			requestHash: plan.requestHash,
			tool,
			outputPaths: outputPaths.slice(0, 50).map(canonicalFuturePath),
		};
		this.clearActive(planId);
		this.persist();
		return publicPlan(plan);
	}

	fail(planId: string, error: unknown): AnalysisTaskPlan {
		const plan = this.require(planId);
		if (plan.status === "cancelled" || plan.status === "failed") {
			this.clearActive(planId);
			return publicPlan(plan);
		}
		plan.status = "failed";
		plan.completedAt = new Date(this.now()).toISOString();
		plan.error = safeError(error);
		this.clearActive(planId);
		this.persist();
		return publicPlan(plan);
	}

	cancel(planId: string): AnalysisTaskPlan {
		const plan = this.require(planId);
		if (!["awaiting-approval", "approved", "running"].includes(plan.status)) {
			throw new Error(
				"Only a pending or running analysis task can be cancelled.",
			);
		}
		this.active
			.get(planId)
			?.controller.abort(new Error("Analysis cancelled by the user."));
		this.clearActive(planId);
		plan.status = "cancelled";
		plan.approvalTokenHash = undefined;
		plan.completedAt = new Date(this.now()).toISOString();
		this.persist();
		return publicPlan(plan);
	}

	list(workspaceRoot: string): AnalysisTaskPlan[] {
		this.expireStale();
		const root = canonicalWorkspaceRoot(workspaceRoot);
		return [...this.plans.values()]
			.filter((plan) => plan.workspaceRoot === root)
			.sort((left, right) => right.createdAt.localeCompare(left.createdAt))
			.slice(0, 100)
			.map(publicPlan);
	}

	evidenceBundle(planId: string, workspaceRoot: string) {
		const plan = this.require(planId);
		if (plan.workspaceRoot !== canonicalWorkspaceRoot(workspaceRoot)) {
			throw new Error("Analysis task does not belong to this workspace.");
		}
		if (plan.status !== "completed" || !plan.evidence) {
			throw new Error("Only a completed task with evidence can be exported.");
		}
		const task = publicPlan(plan);
		const payload = {
			schema: "https://cline.bot/analysis-evidence/v1",
			exportedAt: new Date(this.now()).toISOString(),
			task,
		};
		return {
			payload,
			bundleHash: sha256(canonicalJson(payload)),
		};
	}

	diagnostics() {
		return {
			taskApproval: "canonical full-request one-time token",
			approvalTtlMs: this.approvalTtlMs,
			durableLedger: Boolean(this.ledgerFilePath),
			staticAnalysisDefault: true,
			dynamicAnalysisOnHost: false,
			sandboxWorker: this.sandboxConfiguration(),
			networkDefault: "disabled",
			evidenceIntegrity: "canonical-json sha256",
			taskRetention: `durable, bounded to ${this.maxPlans}`,
		};
	}

	private sandboxConfiguration() {
		const endpoint = process.env.CLINE_ANALYSIS_SANDBOX_WORKER?.trim();
		const publicKey = process.env.CLINE_ANALYSIS_SANDBOX_PUBLIC_KEY?.trim();
		let https = false;
		try {
			https = endpoint ? new URL(endpoint).protocol === "https:" : false;
		} catch {
			https = false;
		}
		return {
			configured: Boolean(endpoint || publicKey),
			configurationValid: Boolean(endpoint && publicKey && https),
			transport: https ? "https" : "unavailable",
			attestation: publicKey ? "pinned-public-key" : "missing",
			execution: "worker-only",
		};
	}

	private expireStale() {
		const now = this.now();
		let changed = false;
		for (const plan of this.plans.values()) {
			if (
				["awaiting-approval", "approved"].includes(plan.status) &&
				Date.parse(plan.expiresAt) <= now
			) {
				plan.status = "expired";
				plan.approvalTokenHash = undefined;
				plan.completedAt = new Date(now).toISOString();
				changed = true;
			}
		}
		if (changed) this.persist();
	}

	private prune(limit = this.maxPlans) {
		const terminal = [...this.plans.values()]
			.filter(
				(plan) =>
					!["awaiting-approval", "approved", "running"].includes(plan.status) &&
					!this.consuming.has(plan.id),
			)
			.sort((left, right) => left.createdAt.localeCompare(right.createdAt));
		for (const plan of terminal) {
			if (this.plans.size <= limit) break;
			this.plans.delete(plan.id);
		}
	}

	private restore() {
		if (!this.ledgerFilePath) return;
		try {
			const stored = JSON.parse(readFileSync(this.ledgerFilePath, "utf8")) as {
				version: 1;
				plans: StoredPlan[];
			};
			if (stored.version !== 1 || !Array.isArray(stored.plans)) return;
			for (const plan of stored.plans) {
				if (plan.status === "running") {
					plan.status = "interrupted";
					plan.completedAt = new Date(this.now()).toISOString();
					plan.error = "Interrupted by application restart.";
				}
				plan.approvalTokenHash = undefined;
				if (plan.status === "approved") plan.status = "expired";
				this.plans.set(plan.id, plan);
			}
			this.prune();
			this.persist();
		} catch {
			// A missing or invalid ledger starts empty; no unverified task is restored.
		}
	}

	private persist() {
		if (!this.ledgerFilePath) return;
		mkdirSync(dirname(this.ledgerFilePath), { recursive: true, mode: 0o700 });
		const temporary = `${this.ledgerFilePath}.${process.pid}.tmp`;
		writeFileSync(
			temporary,
			`${JSON.stringify(
				{ version: 1, plans: [...this.plans.values()] },
				null,
				2,
			)}\n`,
			{ encoding: "utf8", mode: 0o600 },
		);
		chmodSync(temporary, 0o600);
		renameSync(temporary, this.ledgerFilePath);
	}

	private clearActive(planId: string) {
		const active = this.active.get(planId);
		if (active) clearTimeout(active.timeout);
		this.active.delete(planId);
	}

	private require(planId: string): StoredPlan {
		const plan = this.plans.get(planId);
		if (!plan) throw new Error("Analysis plan was not found or expired.");
		return plan;
	}
}

export const desktopAnalysisTaskOrchestrator = new AnalysisTaskOrchestrator({
	ledgerFilePath: resolve(
		resolveClineDataDir(),
		"analysis",
		"task-ledger.json",
	),
});
