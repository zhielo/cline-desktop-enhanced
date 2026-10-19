import { randomUUID } from "node:crypto";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { AndroidProjectPatchSchema } from "../android-project-schema";
import type { ReverseEngineeringInput } from "../schemas";
import { scanAndroidProject } from "./android-project-files";
import {
	assertNewCandidate,
	candidateHash,
	readCandidateFile,
	rejectCandidateLinks,
} from "./candidate-files";
import type { InvestigationRunner } from "./investigation-workflows";
import { smaliPatch } from "./smali-patch";

function relativeSmali(value: string) {
	const parts = value.split("/");
	if (
		parts.length < 2 ||
		parts.some(
			(p) =>
				!p ||
				p === "." ||
				p === ".." ||
				/[<>:"\\|?*]/.test(p) ||
				[...p].some((character) => character.charCodeAt(0) < 32) ||
				/[. ]$/.test(p),
		) ||
		!/^smali(?:_classes[2-9][0-9]*|_classes1[0-9]+)?$/.test(parts[0]) ||
		!value.endsWith(".smali")
	)
		throw new Error(
			"Patch path must be a confined Smali-root relative .smali path",
		);
	return parts;
}
function success(r: Record<string, unknown>) {
	return (
		r.succeeded === true &&
		!r.cancelled &&
		!r.timedOut &&
		!r.outputDrainTimedOut
	);
}

/** Fixed composition of exact Smali edits and existing assembler/Apktool builders. */
export async function androidProjectCandidate(
	input: ReverseEngineeringInput,
	run: InvestigationRunner,
	signal?: AbortSignal,
) {
	const config = AndroidProjectPatchSchema.parse(input.android_project_patch);
	if (
		!input.target ||
		!path.isAbsolute(input.target) ||
		!input.output_file ||
		!path.isAbsolute(input.output_file) ||
		!input.output_file.toLowerCase().endsWith(".apk")
	)
		throw new Error("Absolute project and new .apk output_file required");
	const source = await fs.realpath(input.target),
		output = path.resolve(input.output_file);
	await rejectCandidateLinks(input.target);
	const relation = path.relative(source, output);
	if (
		!relation.startsWith(`..${path.sep}`) &&
		relation !== ".." &&
		!path.isAbsolute(relation)
	)
		throw new Error("Candidate APK must be outside the source project");
	await assertNewCandidate(source, output);
	const timeout = Math.min(input.timeout_ms ?? 600000, 600000),
		deadline = Date.now() + timeout;
	const combined = AbortSignal.any([
		...(signal ? [signal] : []),
		AbortSignal.timeout(timeout),
	]);
	combined.throwIfAborted();
	const unique = new Set<string>();
	for (const p of config.patches) {
		relativeSmali(p.path);
		const key = p.path.toLowerCase();
		if (unique.has(key))
			throw new Error(
				"Only one exact-method patch per unique Smali file is supported",
			);
		unique.add(key);
	}
	const inventory = await scanAndroidProject(source, { signal: combined });
	if (
		(config.expected_project_sha256 &&
			inventory.sha256 !== config.expected_project_sha256) ||
		(input.operation !== "preview_android_candidate" &&
			!config.expected_project_sha256)
	)
		throw new Error("Project fingerprint changed; obtain a fresh preview");
	if (!inventory.smaliRoots.length || inventory.smaliRoots.length > 32)
		throw new Error("Expected 1 to 32 decoded Smali roots");
	for (const name of ["apktool.yml", "AndroidManifest.xml"])
		await readCandidateFile(path.join(source, name), 8 * 1024 * 1024, combined);
	const previewSha256 = candidateHash(
		JSON.stringify({
			version: 1,
			source,
			output,
			project: inventory.sha256,
			patches: config.patches,
			api: input.smali_api_level ?? null,
		}),
	);
	const work = await fs.realpath(
		await fs.mkdtemp(path.join(os.tmpdir(), "cline-android-candidate-")),
	);
	const stages: { id: string; result: Record<string, unknown> }[] = [];
	let retain = false,
		published = false,
		publicationTemp: string | undefined;
	const cleanupWarnings: string[] = [];
	const limitations = [
		"Exact-method edits in a copied Apktool project only; no register repair or semantic-equivalence claim.",
		"Existing Smali assembler and Apktool builder are reused. New unsigned APK; no signing, install, device execution or ART compatibility claim.",
		"Filesystem checks are not an OS sandbox; producer receipts are retained as tool evidence, not authenticated attestations.",
	];
	const stage = async (id: string, request: ReverseEngineeringInput) => {
		combined.throwIfAborted();
		let result: Record<string, unknown>;
		try {
			result = await run(
				{ ...request, timeout_ms: Math.max(1, deadline - Date.now()) },
				combined,
			);
		} catch {
			result = {
				status: combined.aborted ? "cancelled" : "failed",
				succeeded: false,
				reason:
					"Approved engine stage failed; no publication or automatic retry",
			};
		}
		const retained: Record<string, unknown> = {};
		for (const key of [
			"status",
			"succeeded",
			"exitCode",
			"timedOut",
			"cancelled",
			"outputDrainTimedOut",
			"outputSha256",
			"sha256",
			"outputValidation",
			"command",
			"args",
			"durationMs",
			"toolIdentity",
			"reason",
		])
			if (result[key] !== undefined) retained[key] = result[key];
		for (const key of ["stdout", "stderr"])
			if (typeof result[key] === "string")
				retained[key] = String(result[key]).slice(0, 4096);
		stages.push({ id, result: retained });
		if (result.outputDrainTimedOut) retain = true;
		return result;
	};
	const receipt = (
		status: "completed" | "blocked" | "failed" | "cancelled",
		extra: Record<string, unknown> = {},
	) => ({
		schemaVersion: 1,
		protocol: "cline-android-project-candidate/v1",
		operation: input.operation,
		status,
		effect:
			input.operation === "preview_android_candidate"
				? "plan-only"
				: "candidate-write",
		projectSha256: inventory.sha256,
		smaliRoots: inventory.smaliRoots,
		previewSha256,
		outputFile: output,
		published,
		observedExecution: false,
		cleanup: retain
			? "deferred-unconfirmed-engine-termination"
			: "private-workspace-removal-scheduled",
		stages,
		cleanupWarnings,
		retainedWorkspace: retain ? work : undefined,
		limitations,
		...extra,
	});
	try {
		const diffs = [];
		for (let i = 0; i < config.patches.length; i++) {
			const p = config.patches[i];
			const preview = await smaliPatch(
				{
					operation: "preview_smali_patch",
					target: path.join(source, ...relativeSmali(p.path)),
					output_file: path.join(work, `preview-${i}.smali`),
					smali_patch: p.patch,
				},
				combined,
			);
			diffs.push({
				path: p.path,
				inputSha256: preview.inputSha256,
				candidateSha256: preview.candidateSha256,
				classDescriptor: preview.classDescriptor,
				methodSignature: preview.methodSignature,
				diff: preview.diff,
			});
		}
		if (
			(await scanAndroidProject(source, { signal: combined })).sha256 !==
			inventory.sha256
		)
			throw new Error("Project changed during preview");
		if (input.operation === "preview_android_candidate")
			return receipt("completed", {
				executed: false,
				diffs,
				smaliRoots: inventory.smaliRoots,
				requiredEngines: ["smali", "apktool"],
				engineReadiness: "not-probed",
				writes: [output],
				downloads: [],
				budgets: {
					timeoutMs: timeout,
					maxEntries: 25000,
					maxProjectBytes: 512 * 1024 * 1024,
					maxPatches: 32,
					maxSmaliRoots: 32,
				},
			});
		if (config.preview_sha256 !== previewSha256)
			throw new Error("Build requires matching project preview_sha256");
		const candidate = path.join(work, "project");
		if (
			(
				await scanAndroidProject(source, {
					copyTo: candidate,
					signal: combined,
				})
			).sha256 !== inventory.sha256 ||
			(await scanAndroidProject(candidate, { signal: combined })).sha256 !==
				inventory.sha256
		)
			throw new Error("Project changed during snapshot");
		for (let i = 0; i < config.patches.length; i++) {
			const p = config.patches[i],
				target = path.join(candidate, ...relativeSmali(p.path)),
				temp = path.join(
					path.dirname(target),
					`.cline-patch-${randomUUID()}.smali`,
				);
			const preview = await smaliPatch(
				{
					operation: "preview_smali_patch",
					target,
					output_file: temp,
					smali_patch: p.patch,
				},
				combined,
			);
			const applied = await smaliPatch(
				{
					operation: "patch_smali_method",
					target,
					output_file: temp,
					smali_patch: { ...p.patch, preview_sha256: preview.previewSha256 },
				},
				combined,
			);
			if (
				applied.candidateSha256 !== diffs[i].candidateSha256 ||
				!applied.published
			)
				throw new Error("Candidate patch did not match approved preview");
			await fs.rename(temp, target);
			stages.push({
				id: `patch-${i}`,
				result: {
					path: p.path,
					inputSha256: applied.inputSha256,
					candidateSha256: applied.candidateSha256,
					status: "completed",
				},
			});
		}
		const candidateProjectSha256 = (
			await scanAndroidProject(candidate, { signal: combined })
		).sha256;
		for (const root of inventory.smaliRoots) {
			const assembled = await stage(`assemble-${root}`, {
				operation: "assemble_smali",
				target: path.join(candidate, root),
				output_file: path.join(work, `${root}.dex`),
				smali_api_level: input.smali_api_level,
				acknowledge_external_output: true,
			});
			if (!success(assembled))
				return receipt(combined.aborted ? "cancelled" : "blocked", {
					reason:
						"Smali assembly did not pass; rebuild and publication not attempted",
					candidateProjectSha256,
				});
		}
		const apk = path.join(work, "candidate.apk");
		const built = await stage("rebuild-apk", {
			operation: "rebuild_apk",
			target: candidate,
			output_file: apk,
			acknowledge_external_output: true,
		});
		if (!success(built))
			return receipt(combined.aborted ? "cancelled" : "blocked", {
				reason: "Apktool build did not pass; publication not attempted",
				candidateProjectSha256,
			});
		const outputBytes = await readCandidateFile(
				apk,
				512 * 1024 * 1024,
				combined,
			),
			outputSha256 = candidateHash(outputBytes);
		if (
			built.outputSha256 !== outputSha256 ||
			typeof built.outputValidation !== "string" ||
			!built.outputValidation.startsWith("bounded-structure-checked")
		)
			throw new Error(
				"Builder output hash or structural validation receipt mismatch",
			);
		if (
			(await scanAndroidProject(source, { signal: combined })).sha256 !==
			inventory.sha256
		)
			throw new Error("Original project changed before publication");
		if (
			(await scanAndroidProject(candidate, { signal: combined })).sha256 !==
			candidateProjectSha256
		)
			throw new Error("Candidate project changed outside the approved patches");
		combined.throwIfAborted();
		await assertNewCandidate(source, output);
		publicationTemp = path.join(
			path.dirname(output),
			`.cline-apk-${randomUUID()}.tmp`,
		);
		const f = await fs.open(publicationTemp, "wx", 0o600);
		try {
			await f.writeFile(outputBytes);
			await f.sync();
		} finally {
			await f.close();
		}
		combined.throwIfAborted();
		await rejectCandidateLinks(output, true);
		await fs.link(publicationTemp, output);
		published = true;
		return receipt("completed", {
			sourceUnchanged: true,
			candidateProjectSha256,
			outputSha256,
			validation: "all-smali-roots-assembled; bounded-apk-structure-checked",
			signingStatus: "new-unsigned-artifact",
			diffs,
		});
	} finally {
		if (publicationTemp)
			await fs.rm(publicationTemp, { force: true }).catch(() => {
				cleanupWarnings.push(
					"Private publication hard-link cleanup failed; inspect the output directory.",
				);
			});
		if (!retain)
			await fs.rm(work, { recursive: true, force: true }).catch(() => {
				cleanupWarnings.push(`Private workspace cleanup failed: ${work}`);
			});
	}
}
