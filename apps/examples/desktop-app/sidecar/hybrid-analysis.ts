import {
	digest,
	HybridProposalSchema,
	HybridContextSchema,
	type HybridContext,
} from "@cline/core";
import { realpathSync } from "node:fs";
import { confinedArtifact } from "./analysis-workflow-store";
export interface HybridEvidencePorts {
	receipt(id: string): unknown;
	task(id: string): unknown;
}
const object = (v: unknown): Record<string, unknown> =>
	v && typeof v === "object" && !Array.isArray(v)
		? (v as Record<string, unknown>)
		: {};
/** Only host-loaded, integrity-checked, owning-session static evidence qualifies. */
export async function bindHybridObservation(
	raw: unknown,
	scope: { sessionId: string; workspace: string },
	ports: HybridEvidencePorts,
	target?: string,
): Promise<HybridContext> {
	const proposal = HybridProposalSchema.parse(raw);
	let hash: string, artifactHashes: string[];
	if (proposal.baselineKind === "receipt") {
		const receipt = object(ports.receipt(proposal.baselineId)),
			result = object(receipt.result);
		if (
			receipt.sessionId !== scope.sessionId ||
			receipt.workspace !== realpathSync(scope.workspace) ||
			!["completed", "partial"].includes(String(receipt.status)) ||
			!receipt.result ||
			digest(receipt.result) !== receipt.resultHash
		)
			throw new Error(
				"Hybrid requires completed owning-session static evidence with intact result hash",
			);
		hash = String(receipt.resultHash);
		artifactHashes = (
			Array.isArray(result.artifacts) ? result.artifacts : []
		).map((a) => String(object(a).sha256));
	} else {
		const task = object(ports.task(proposal.baselineId));
		const { snapshotHash, ...body } = task;
		if (
			task.taskId !== proposal.baselineId ||
			task.sessionId !== scope.sessionId ||
			task.workspace !== realpathSync(scope.workspace) ||
			task.domain !== "static" ||
			!task.result ||
			digest(body) !== snapshotHash ||
			digest(task.result) !== task.resultHash
		)
			throw new Error(
				"Hybrid requires an intact owning-session static task snapshot",
			);
		hash = String(snapshotHash);
		artifactHashes = [String(task.targetSha256)];
	}
	if (
		target &&
		!artifactHashes.includes(
			(await confinedArtifact(scope.workspace, target)).sha256,
		)
	)
		throw new Error(
			"Hybrid target has no matching static artifact hash; inspect the exact current file first",
		);
	return HybridContextSchema.parse({
		...proposal,
		evidenceHash: hash,
		relation: target ? "exact-artifact-hash" : "investigation-context-only",
	});
}
export async function recheckHybridObservation(
	raw: unknown,
	scope: { sessionId: string; workspace: string },
	ports: HybridEvidencePorts,
	target?: string,
) {
	const context = HybridContextSchema.parse(raw);
	const { evidenceHash, relation, ...proposal } = context;
	const current = await bindHybridObservation(proposal, scope, ports, target);
	if (current.evidenceHash !== evidenceHash || current.relation !== relation)
		throw new Error(
			"Hybrid static basis changed; prepare and review a new plan",
		);
	return current;
}
