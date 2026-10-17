import ts from "typescript";
import { createHash } from "node:crypto";
import { canonical } from "../../../analysis/contracts";
import {
	CandidateReviewSchema,
	CandidateValidationSchema,
} from "../investigation-workflows-schema";
import type { ReverseEngineeringInput } from "../schemas";
import { candidateBatch } from "./candidate-batch";
import { candidateHash, readCandidateFile } from "./candidate-files";
import type { InvestigationRunner } from "./investigation-workflows";

/** Shared with assembled-output validation; never loads or executes DEX code. */
export function validateDexBytes(bytes: Buffer) {
	if (
		bytes.length < 112 ||
		bytes.length > 512 * 1024 * 1024 ||
		!/^dex\n0(?:3[5-9]|40)\0$/.test(bytes.subarray(0, 8).toString("binary")) ||
		bytes.readUInt32LE(32) !== bytes.length ||
		bytes.readUInt32LE(36) !== 112 ||
		bytes.readUInt32LE(40) !== 0x12345678
	)
		throw new Error("DEX failed bounded supported header validation");
	if (
		!createHash("sha1")
			.update(bytes.subarray(32))
			.digest()
			.equals(bytes.subarray(12, 32))
	)
		throw new Error("DEX SHA1 mismatch");
	let a = 1,
		b = 0;
	for (const value of bytes.subarray(12)) {
		a = (a + value) % 65521;
		b = (b + a) % 65521;
	}
	if (((b << 16) | a) >>> 0 !== bytes.readUInt32LE(8))
		throw new Error("DEX Adler32 mismatch");
	// Fixed-width tables plus data/link extents only, not variable-length DEX verification.
	for (const [at, width] of [
		[56, 4],
		[64, 4],
		[72, 12],
		[80, 8],
		[88, 8],
		[96, 32],
		[104, 1],
		[44, 1],
	]) {
		const count = bytes.readUInt32LE(at),
			offset = bytes.readUInt32LE(at + 4);
		if (
			(count === 0 && offset !== 0) ||
			(count > 0 &&
				(offset < 112 ||
					offset + count * width > bytes.length ||
					(width > 1 && offset % 4 !== 0)))
		)
			throw new Error("DEX declared table extent invalid");
	}
	const mapOffset = bytes.readUInt32LE(52);
	if (
		mapOffset !== 0 &&
		(mapOffset < 112 || mapOffset % 4 !== 0 || mapOffset + 4 > bytes.length)
	)
		throw new Error("DEX map offset invalid");
}

/** Fixed, bounded, read-only orchestration. Host approvals remain outside this module. */
export async function verifyCandidate(
	input: ReverseEngineeringInput,
	run: InvestigationRunner,
	signal?: AbortSignal,
) {
	if (!input.target) throw new Error("Explicit candidate target required");
	if (
		input.output_file ||
		input.output_directory ||
		input.compare_target ||
		input.candidate ||
		input.android_project_patch
	)
		throw new Error(
			"Candidate verification accepts no writes, comparison target or patch recipe",
		);
	const timeout = Math.min(input.timeout_ms ?? 120000, 120000),
		deadline = Date.now() + timeout;
	const combined = AbortSignal.any([
		...(signal ? [signal] : []),
		AbortSignal.timeout(timeout),
	]);
	const maxBytes =
		input.operation === "review_candidate_changes"
			? 1024 * 1024
			: 16 * 1024 * 1024;
	const bytes = await readCandidateFile(input.target, maxBytes, combined),
		hash = candidateHash(bytes);
	const checks: Array<Record<string, unknown>> = [];
	const limitations = [
		"Read-only checks of the exact selected bytes, not behavioral equivalence, producer authentication, build success, target execution, signing, installation or device/VM compatibility.",
	];
	let status = "completed";
	if (input.operation === "review_candidate_changes") {
		const options = CandidateReviewSchema.parse(input.candidate_review);
		if (hash !== options.manifest_sha256)
			throw new Error("Candidate manifest hash changed");
		const audit = await candidateBatch(
			{ operation: "audit_candidate_batch", target: input.target },
			combined,
		);
		checks.push({ id: "exact-recipe-audit", ...audit });
		if (!audit.results)
			throw new Error("Candidate audit returned no declared results");
		status = audit.results.every((r) => r.status === "verified")
			? "completed"
			: audit.results.some(
						(r) => r.status === "mismatch" || r.status === "unverified",
					)
				? "failed"
				: "partial";
		limitations.push(
			"Scope is only manifest-declared source/output pairs. No filesystem baseline exists for undeclared files; whole-project changes are NOT reviewed. Manifest hashes bind a recipe, not human approval of that recipe.",
			...audit.limitations,
		);
	} else if (input.operation === "validate_candidate") {
		const options = CandidateValidationSchema.parse(input.candidate_validation);
		if (hash !== options.expected_sha256)
			throw new Error("Candidate hash changed");
		if (options.kind === "javascript" || options.kind === "typescript") {
			if (bytes.length > 1024 * 1024)
				throw new Error("Source syntax validation exceeds 1 MiB");
			const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
			const filename =
				options.kind === "typescript" ? "/candidate.ts" : "/candidate.js";
			const file = ts.createSourceFile(
				filename,
				text,
				ts.ScriptTarget.Latest,
				true,
				options.kind === "typescript" ? ts.ScriptKind.TS : ts.ScriptKind.JS,
			);
			// The syntactic program pass also rejects TS-only grammar in JavaScript.
			// An in-memory, single-file host cannot load imports, tsconfig or libraries.
			const compilerOptions: ts.CompilerOptions = {
				allowJs: true,
				checkJs: false,
				noResolve: true,
				noLib: true,
				noEmit: true,
				target: ts.ScriptTarget.Latest,
			};
			const host: ts.CompilerHost = {
				getSourceFile: (name) => (name === filename ? file : undefined),
				getDefaultLibFileName: () => "",
				writeFile: () => {},
				getCurrentDirectory: () => "/",
				getDirectories: () => [],
				fileExists: (name) => name === filename,
				readFile: (name) => (name === filename ? text : undefined),
				getCanonicalFileName: (name) => name,
				useCaseSensitiveFileNames: () => true,
				getNewLine: () => "\n",
			};
			const diagnostics = ts
				.createProgram([filename], compilerOptions, host)
				.getSyntacticDiagnostics(file);
			checks.push({
				id: "source-syntax",
				status: diagnostics.length ? "failed" : "completed",
				parserVersion: ts.version,
				diagnosticCount: diagnostics.length,
				truncated: diagnostics.length > 100,
				diagnostics: diagnostics.slice(0, 100).map((d) => ({
					code: d.code,
					start: d.start,
					length: d.length,
					message: ts
						.flattenDiagnosticMessageText(d.messageText, "\n")
						.slice(0, 1000),
				})),
			});
			if (diagnostics.length) status = "failed";
			limitations.push(
				"JS/TS parse diagnostics only; no type checking, dependency resolution, module loading, JSX/TSX support or application test execution.",
			);
		} else if (options.kind === "dex") {
			try {
				validateDexBytes(bytes);
				checks.push({
					id: "dex-header-integrity-extents",
					status: "completed",
				});
			} catch (e) {
				status = "failed";
				checks.push({
					id: "dex-header-integrity-extents",
					status: "failed",
					reason: e instanceof Error ? e.message : "DEX validation failed",
				});
			}
			limitations.push(
				"Supported standard DEX 035–040 header, SHA1, Adler32 and fixed-width table bounds only; not full map, instruction, reference, register, verifier, ART or multidex compatibility validation. Compact DEX/041 unsupported.",
			);
		} else {
			// Reuse installed parser and signer verifier; never build/sign/install or fetch engines.
			for (const operation of ["inspect", "verify_apk_signature"] as const) {
				combined.throwIfAborted();
				try {
					const result = await run(
						{
							operation,
							target: input.target,
							timeout_ms: Math.max(1, deadline - Date.now()),
						},
						combined,
					);
					const valid =
						operation === "inspect"
							? result.sha256 === hash &&
								result.kind === "apk" &&
								(result.android as { hasManifest?: boolean } | undefined)
									?.hasManifest === true &&
								(
									result.archive as
										| { extractionRecommended?: boolean }
										| undefined
								)?.extractionRecommended === true
							: result.verified === true && result.sha256 === hash;
					const failed =
						result.verified === false ||
						result.cancelled === true ||
						result.timedOut === true ||
						result.outputDrainTimedOut === true ||
						(typeof result.exitCode === "number" && result.exitCode !== 0) ||
						["failed", "cancelled", "blocked"].includes(
							String(result.status),
						) ||
						(operation === "inspect" &&
							((typeof result.kind === "string" && result.kind !== "apk") ||
								(result.android as { hasManifest?: boolean } | undefined)
									?.hasManifest === false ||
								(
									result.archive as
										| { extractionRecommended?: boolean }
										| undefined
								)?.extractionRecommended === false));
					const checkStatus = failed
						? "failed"
						: valid
							? "completed"
							: "partial";
					const encoded = JSON.stringify(result);
					checks.push({
						id: operation,
						status: checkStatus,
						result:
							Buffer.byteLength(encoded) <= 128 * 1024
								? result
								: {
										evidenceSha256: candidateHash(encoded),
										truncated: true,
										sha256: result.sha256,
										kind: result.kind,
										verified: result.verified,
										reason:
											"Engine evidence exceeded inline budget; only integrity and decision fields retained.",
									},
					});
					if (checkStatus === "failed") status = "failed";
					else if (checkStatus === "partial" && status !== "failed")
						status = "partial";
				} catch {
					combined.throwIfAborted();
					checks.push({
						id: operation,
						status: "blocked",
						reason:
							"Parser or installed signature verifier unavailable/failed; no download, retry or signature bypass.",
					});
					if (status !== "failed") status = "partial";
				}
			}
			limitations.push(
				"APK container inspection and installed apksigner verification only. Missing tools or unverifiable results are not passes; no build receipt, certificate trust policy or device proof.",
			);
		}
	} else throw new Error("Unsupported candidate verification command");
	combined.throwIfAborted();
	if (
		candidateHash(await readCandidateFile(input.target, maxBytes, combined)) !==
		hash
	)
		throw new Error("Candidate changed during verification");
	const receipt = {
		protocol: "cline-candidate-verification/v1",
		operation: input.operation,
		effect: "read",
		status,
		inputSha256: hash,
		inputBytes: bytes.length,
		checks,
		limitations,
		published: false,
		observedExecution: false,
	};
	return { ...receipt, receiptSha256: candidateHash(canonical(receipt)) };
}
