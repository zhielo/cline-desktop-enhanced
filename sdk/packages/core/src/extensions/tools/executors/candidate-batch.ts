import * as path from "node:path";
import { CandidateBatchSchema } from "../advanced-candidates-schema";
import { canonical } from "../../../analysis/contracts";
import { advancedCandidate } from "./advanced-candidates";
import {
	candidateHash,
	readCandidateFile,
	rejectCandidateLinks,
} from "./candidate-files";
const previewOperation = (op: string) =>
	({
		patch_binary: "preview_binary_patch",
		apply_ast_transform: "preview_ast_transform",
		patch_dotnet_constant: "preview_dotnet_constant",
		patch_jvm_constant: "preview_jvm_constant",
	})[op];
export async function candidateBatch(
	input: { operation: string; target?: string; batch_preview_sha256?: string },
	signal?: AbortSignal,
) {
	if (!input.target || !path.isAbsolute(input.target))
		throw new Error("Candidate batch requires absolute JSON manifest target");
	const manifestBytes = await readCandidateFile(
		input.target,
		1024 * 1024,
		signal,
	);
	const manifest = CandidateBatchSchema.parse(
		JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(manifestBytes)),
	);
	const root = path.dirname(input.target),
		ids = new Set<string>(),
		outputs = new Set<string>();
	const canonicalPath = (p: string) =>
		process.platform === "win32" ? p.toLowerCase() : p;
	const confined = (p: string) => {
		if (path.isAbsolute(p))
			throw new Error("Batch paths must be relative to manifest");
		const file = path.resolve(root, p),
			rel = path.relative(root, file);
		if (
			!rel ||
			rel === ".." ||
			rel.startsWith(`..${path.sep}`) ||
			path.isAbsolute(rel)
		)
			throw new Error("Batch path escapes manifest directory");
		return file;
	};
	const stages = manifest.stages.map((s) => ({
		...s,
		target: confined(s.target),
		output_file: confined(s.output_file),
	}));
	for (const s of stages) {
		if (ids.has(s.id) || outputs.has(canonicalPath(s.output_file)))
			throw new Error("Duplicate batch stage/output");
		ids.add(s.id);
		outputs.add(canonicalPath(s.output_file));
		await rejectCandidateLinks(s.target);
		await rejectCandidateLinks(s.output_file, true);
	}
	for (const s of stages)
		if (
			outputs.has(canonicalPath(s.target)) ||
			canonicalPath(s.output_file) === canonicalPath(input.target)
		)
			throw new Error(
				"Batch outputs may not replace inputs/manifest or feed other stages",
			);
	const previews: Awaited<ReturnType<typeof advancedCandidate>>[] = [];
	for (const s of stages) {
		signal?.throwIfAborted();
		previews.push(
			await advancedCandidate(
				{ ...s, operation: previewOperation(s.operation)! },
				signal,
			),
		);
	}
	const manifestHash = candidateHash(manifestBytes),
		fingerprint = candidateHash(
			canonical({
				version: "candidate-batch/v1",
				manifest: path.resolve(input.target),
				manifestHash,
				previews: previews.map((p) => p.previewSha256),
			}),
		);
	if (input.operation === "preview_candidate_batch")
		return {
			status: "completed",
			published: false,
			manifestHash,
			batchPreviewSha256: fingerprint,
			stages: stages.map((s, i) => ({ id: s.id, ...previews[i] })),
			limitations: [
				"Independent candidate files only; no assembly, signing, target execution or dependent output substitution.",
				"Each output is atomic, but the whole batch is not transactional. Application stops after a failed stage and returns a partial receipt; do not blindly replay.",
			],
		};
	if (input.batch_preview_sha256 !== fingerprint)
		throw new Error(
			"Matching batch_preview_sha256 required; manifest and every source/destination/recipe are bound",
		);
	const results: {
		id: string;
		status: string;
		outputFile?: string;
		outputSha256?: string;
		error?: string;
		cleanupWarning?: string;
	}[] = [];
	for (let i = 0; i < stages.length; i++) {
		const s = stages[i];
		try {
			signal?.throwIfAborted();
			if (
				candidateHash(
					await readCandidateFile(input.target, 1024 * 1024, signal),
				) !== manifestHash
			)
				throw new Error("Batch manifest changed");
			const result = await advancedCandidate(
				{
					...s,
					candidate: {
						...s.candidate,
						preview_sha256: previews[i].previewSha256,
					},
				},
				signal,
			);
			results.push({
				id: s.id,
				status: "completed",
				outputFile: result.outputFile,
				outputSha256: result.outputSha256,
				cleanupWarning: result.cleanupWarning,
			});
		} catch {
			results.push({
				id: s.id,
				status: signal?.aborted ? "cancelled" : "failed",
				error:
					"Stage failed or source/destination changed; inspect existing candidates before a separately approved new manifest",
			});
			break;
		}
	}
	const complete =
		results.length === stages.length &&
		results.every((r) => r.status === "completed");
	return {
		status: complete ? "completed" : signal?.aborted ? "cancelled" : "partial",
		manifestHash,
		batchPreviewSha256: fingerprint,
		results,
		skipped: stages.slice(results.length).map((s) => s.id),
		outputFiles: results
			.filter((s) => s.status === "completed")
			.map((s) => s.outputFile),
		limitations: [
			"Per-file atomic publication; NOT an all-or-nothing transaction. Existing candidates are never overwritten or automatically replayed.",
			"No shell, signing, installation, target execution, dependent stages, automatic rollback or approval expansion.",
		],
	};
}
