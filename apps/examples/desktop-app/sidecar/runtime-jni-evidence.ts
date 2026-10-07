import { basename } from "node:path";
import { z } from "zod";
import type { AnalysisTaskOrchestrator } from "./analysis-task-orchestrator";
import {
	AndroidCaptureInput,
	verifyAndroidObservationReceipt,
} from "./android-runtime-client";
import { digest, ownedFile } from "./incident-artifacts";
import { elfIdentity } from "./incident-correlation";

const Input = z
	.object({
		planId: z.string().uuid(),
		classDescriptor: z.string().regex(/^L[^;\s]{1,500};$/),
		name: z.string().min(1).max(512),
		descriptor: z.string().min(1).max(512),
		processId: z.number().int().positive().optional(),
		classLoaderIdentity: z.string().max(80).optional(),
		confirmRelativeAddressIsElfVA: z.boolean().default(false),
	})
	.strict();
export async function queryRuntimeJni(
	root: string,
	value: unknown,
	tasks: AnalysisTaskOrchestrator,
) {
	const i = Input.parse(value),
		plan = tasks.list(root).find((p) => p.id === i.planId);
	if (
		!plan ||
		plan.kind !== "dynamic" ||
		plan.operation !== "android_capture" ||
		!plan.approvedAt ||
		plan.status !== "completed" ||
		!plan.targetIdentity?.sha256 ||
		!plan.evidence
	)
		throw new Error(
			"Completed approved Android capture plan required; imported JSON is not live JNI evidence",
		);
	const paths = plan.evidence.outputPaths,
		receipts = paths.filter((p) => p.endsWith(".receipt.json"));
	if (receipts.length !== 1)
		throw new Error("Unique bound signed receipt required");
	const file = await ownedFile(root, receipts[0], 1048576);
	if (basename(file.path) !== `${file.sha256}.receipt.json`)
		throw new Error("Stored receipt filename/hash mismatch");
	const envelope = JSON.parse(file.bytes.toString("utf8")),
		input = AndroidCaptureInput.parse(plan.request),
		verified = await verifyAndroidObservationReceipt(
			envelope,
			input,
			plan.requestHash,
			plan.targetIdentity.sha256,
		),
		receipt = verified.receipt;
	const rows = receipt.evidence.registrations.filter(
		(r) =>
			r.classDescriptor === i.classDescriptor &&
			r.name === i.name &&
			r.descriptor === i.descriptor &&
			(i.processId === undefined || r.processId === i.processId) &&
			(i.classLoaderIdentity === undefined ||
				r.classLoaderIdentity === i.classLoaderIdentity),
	);
	const results: Record<string, unknown>[] = [];
	for (const row of rows) {
		const result: Record<string, unknown> = {
			observation: row,
			provenance:
				"signed-worker-observed-registration-not-hardware-attestation",
			staticBinding: "unresolved",
		};
		if (row.moduleSha256) {
			const meta = receipt.evidence.artifacts.find(
					(a) => a.format === "elf" && a.sha256 === row.moduleSha256,
				),
				candidates = paths.filter(
					(p) => basename(p) === `${row.moduleSha256}.so`,
				);
			if (!meta || candidates.length !== 1)
				throw new Error("Captured JNI module identity unavailable");
			const module = await ownedFile(root, candidates[0], 8388608);
			if (
				module.sha256 !== meta.sha256 ||
				module.size !== meta.bytes ||
				digest(module.bytes) !== row.moduleSha256
			)
				throw new Error("Captured JNI module changed");
			const elf = elfIdentity(module.bytes);
			result.module = {
				path: module.path,
				sha256: module.sha256,
				abi: elf.abi,
				buildIds: elf.buildIds,
				identityBasis: row.moduleHashBasis,
			};
			result.staticBinding = "captured-disk-file-match-not-loaded-memory-proof";
			if (i.confirmRelativeAddressIsElfVA && row.relativeAddress) {
				const address = BigInt(row.relativeAddress);
				const symbols = elf.symbols.filter(
					(s) =>
						BigInt(s.address) === address &&
						s.size > 0 &&
						elf.segments.some(
							(seg) =>
								seg.executable &&
								address >= BigInt(seg.address) &&
								address < BigInt(seg.address + seg.bytes),
						),
				);
				if (symbols.length === 1) {
					result.operatorReviewedFunctionCandidate = {
						symbol: symbols[0].name,
						address: row.relativeAddress,
						module: module.path,
						basis: "exact-existing-symbol-at-operator-confirmed-ELF-VA",
						executeAutomatically: false,
					};
				} else
					result.functionCandidateStatus =
						"No unique existing function entry; stripped/aliased symbols stay unresolved";
			}
		}
		results.push(result);
	}
	return {
		planId: plan.id,
		requestHash: plan.requestHash,
		artifactSha256: receipt.artifactSha256,
		captureSessionNonce: receipt.nonce,
		status:
			rows.length === 0
				? "not-observed"
				: rows.length === 1
					? "unique-observation"
					: "ambiguous-observations",
		matches: results,
		limitations: [
			"RegisterNatives hooks cover only observed registrations; absence is not proof of no registration",
			"PID, loader identity hash and session nonce are scoped observations, not globally unique/hardware identities",
			"Frida module-relative offsets are not automatically treated as ELF virtual addresses",
			"Disk module bytes do not prove loaded-memory contents; no automatic debugger attach/resume or decompiler execution",
		],
	};
}
