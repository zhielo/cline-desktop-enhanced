import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { InvestigationSchemas, isBatchStaticOperation } from "@cline/core";
import { z } from "zod";
import type { AnalysisTaskOrchestrator } from "./analysis-task-orchestrator";
import type { ExecutionControlService } from "./execution-control-service";
import { digest, ownedFile } from "./incident-artifacts";

type Scope = { sessionId: string; workspace: string };
const Names = [
	"plan_batch",
	"preview_batch",
	"run_batch",
	"checkpoint_investigation",
	"cancel_batch",
	"resume_investigation",
] as const;
const limits = [
	"Built-in static file inspection, source/Electron/.NET/mitigation/comparison and saved-graph analysis only; no target execution, shell, candidate writes or external engines. Partial results retain their evidence and allow independent reads; they never pass dependencies. Failures stop the batch.",
	"All inputs must already exist as confined regular files of at most 64 MiB; no producer-output chaining.",
	"Dependencies order stages; they do not imply data flow or runtime causality. Two simultaneous reads maximum.",
	"Resume never retries started stages and blocks unresolved dependencies. Checkpoints are already durable; status reads do not force a flush.",
];
// In the shipped sidecar import.meta.url is the executing bundle. Rebuilt hosts
// cannot silently reuse evidence from an unknown implementation.
let fingerprint: Promise<string> | undefined;
function implementation() {
	if (!fingerprint)
		fingerprint = readFile(fileURLToPath(import.meta.url)).then((bytes) =>
			digest(bytes),
		);
	return fingerprint;
}
export async function handleBatchInvestigation(
	command: string,
	raw: unknown,
	scope: Scope,
	service: ExecutionControlService,
	tasks: AnalysisTaskOrchestrator,
) {
	if (!(Names as readonly string[]).includes(command))
		throw new Error("Unknown batch command");
	const name = command as (typeof Names)[number];
	const envelope = z
		.object({
			phase: z.enum(["prepare", "run"]).optional(),
			planId: z.string().uuid().optional(),
			executionToken: z.string().min(1).optional(),
		})
		.passthrough()
		.parse(raw);
	const { phase, planId, executionToken, ...publicInput } = envelope;
	if (
		(phase || planId || executionToken) &&
		name !== "run_batch" &&
		name !== "resume_investigation"
	)
		throw new Error("This batch operation has no execution phase");
	const input = InvestigationSchemas[name].parse(publicInput);
	const requestHash = digest(JSON.stringify(input));
	const owned = (id: string) => {
		const receipt = service.get(scope.workspace, id);
		if (
			receipt.request.owner_session_id !== scope.sessionId ||
			!receipt.request.client_request_hash
		)
			throw new Error("Batch receipt unavailable in this owning session");
		return receipt;
	};
	const verifyInputsAndResults = async (c: ReturnType<typeof owned>) => {
		if (c.request.implementation_sha256 !== (await implementation()))
			throw new Error("Implementation fingerprint changed; make a fresh plan");
		const reused = new Set(
			c.jobs.filter((j) => j.status === "completed").map((j) => j.id),
		);
		for (const s of c.request.stages) {
			if (s.backend !== "static" || !isBatchStaticOperation(s.request))
				throw new Error("Only built-in static batches can resume here");
			if (
				!s.target_sha256 ||
				(await ownedFile(scope.workspace, String(s.request.target))).sha256 !==
					s.target_sha256
			)
				throw new Error(
					"Batch input changed; stale dependent evidence cannot be reused",
				);
			if (
				s.compare_sha256 &&
				(await ownedFile(scope.workspace, String(s.request.compare_target)))
					.sha256 !== s.compare_sha256
			)
				throw new Error("Comparison input changed");
			const j = c.jobs.find((j) => j.id === s.id);
			if (!j) throw new Error("Checkpoint stage evidence missing");
			if (
				reused.has(j.id) &&
				(j.resultTruncated ||
					!j.resultHash ||
					digest(JSON.stringify(j.result) ?? "null") !== j.resultHash)
			)
				throw new Error("Reused stage result is incomplete or changed");
		}
	};
	if (name === "checkpoint_investigation" || name === "cancel_batch") {
		const receipt = owned((input as { receiptId: string }).receiptId);
		if (
			name === "cancel_batch" &&
			["accepted", "starting", "running"].includes(receipt.status)
		)
			await service.cancel(scope.workspace, receipt.id);
		return { receipt: owned(receipt.id), limitations: limits };
	}
	if (phase === "run") {
		if (!planId || !executionToken)
			throw new Error("Separate hash-bound batch approval required");
		const plan = tasks
			.list(scope.workspace)
			.find((p) => p.id === planId && p.kind === "execution");
		const p = plan?.request as Record<string, unknown> | undefined;
		if (
			!p ||
			p.owner_session_id !== scope.sessionId ||
			p.client_request_hash !== requestHash ||
			p.implementation_sha256 !== (await implementation())
		)
			throw new Error("Approved batch plan does not match this owning request");
		const previous = p.resume_from as
			| { id: string; revision: number; hash: string }
			| undefined;
		if (previous) {
			const r = owned(previous.id);
			if (r.revision !== previous.revision || r.hash !== previous.hash)
				throw new Error("Resume checkpoint changed");
			await verifyInputsAndResults(r);
		}
		return {
			...(await service.start(scope.workspace, planId, executionToken)),
			limitations: limits,
		};
	}
	let pipeline: Record<string, unknown>;
	if (name === "resume_investigation") {
		const req = input as { receiptId: string; revision: number };
		const c = owned(req.receiptId);
		if (
			c.controlUnavailable ||
			["accepted", "starting", "running", "uncertain"].includes(c.status) ||
			c.revision !== req.revision
		)
			throw new Error(
				"Resume requires an exact terminal, certain checkpoint revision",
			);
		if (c.request.implementation_sha256 !== (await implementation()))
			throw new Error("Implementation fingerprint changed; make a fresh plan");
		await verifyInputsAndResults(c);
		const remaining = c.request.stages.filter(
			(s) => !c.jobs.find((j) => j.id === s.id)?.startedAt,
		);
		if (!remaining.length)
			throw new Error(
				"No never-started stages remain; completed or started work is never replayed",
			);
		const reused = new Set(
			c.jobs.filter((j) => j.status === "completed").map((j) => j.id),
		);
		const remainingIds = new Set(remaining.map((s) => s.id));
		if (
			remaining.some((s) =>
				s.depends_on.some((id) => !reused.has(id) && !remainingIds.has(id)),
			)
		)
			throw new Error(
				"Unresolved started dependency; create an explicit new plan instead of replaying it",
			);
		const key = digest(`${scope.sessionId}:${c.id}:${c.revision}:${c.hash}`);
		const continuationId = `${key.slice(0, 8)}-${key.slice(8, 12)}-5${key.slice(13, 16)}-8${key.slice(17, 20)}-${key.slice(20, 32)}`;
		pipeline = {
			...c.request,
			operation_id: continuationId,
			title: `Resume ${c.request.title}`.slice(0, 120),
			resume_from: {
				id: c.id,
				revision: c.revision,
				hash: c.hash,
				reused: [...reused],
			},
			stages: remaining.map(
				({
					target_sha256: _t,
					compare_sha256: _c,
					executable_sha256: _e,
					...s
				}) => ({
					...s,
					depends_on: s.depends_on.filter((id) => !reused.has(id)),
				}),
			),
		};
	} else {
		const req = InvestigationSchemas.run_batch.parse(input);
		pipeline = {
			...req,
			operation: "execution_pipeline",
			trusted_host_work: true,
			archive_logs: false,
			continue_independent_reads: true,
			stages: req.stages.map((s) => ({ ...s, backend: "static" })),
		};
	}
	pipeline.owner_session_id = scope.sessionId;
	pipeline.client_request_hash = requestHash;
	pipeline.implementation_sha256 = await implementation();
	if (name === "plan_batch" || name === "preview_batch")
		return {
			status: "previewed-not-approved",
			request: await service.preview(scope.workspace, pipeline),
			limitations: limits,
		};
	return {
		...(await service.prepare(scope.workspace, pipeline)),
		limitations: limits,
	};
}
