import { inspectManagedPE } from "../../../analysis/dotnet";
import { HypothesisSchema } from "../investigation-workflows-schema";
import type { ReverseEngineeringInput } from "../schemas";
import { prepareNotebook } from "./analysis-notebook";
import { inspectBinaryMitigations } from "./binary-mitigations";
import { candidateHash, readCandidateFile } from "./candidate-files";
import { declaredEvidence } from "./evidence-trace";
import {
	dependencyInventory,
	sourceInvestigation,
} from "./source-investigation";
import { SelectedNativeEvidenceSchema } from "./targeted-native-evidence";
export type InvestigationRunner = (
	request: ReverseEngineeringInput,
	signal: AbortSignal,
) => Promise<Record<string, unknown>>;
const sourceCommands = new Set([
	"trace_electron_ipc",
	"audit_preload_bridge",
	"trace_source_symbol",
	"explain_behavior",
	"compare_public_api",
]);
function json(bytes: Buffer) {
	return JSON.parse(
		new TextDecoder("utf-8", { fatal: true }).decode(bytes),
	) as unknown;
}
/** Preserve the signed/provenance wrapper; inspect only the known child result shape. */
function outcome(value: Record<string, unknown>): Record<string, unknown> {
	const nested = value.result;
	return value.schemaVersion === 1 &&
		nested &&
		typeof nested === "object" &&
		!Array.isArray(nested) &&
		(nested as Record<string, unknown>).protocol ===
			"cline-advanced-analysis/v1"
		? (nested as Record<string, unknown>)
		: value;
}
function failed(value: Record<string, unknown>) {
	const r = outcome(value);
	return (
		["failed", "blocked", "cancelled"].includes(String(r.status)) ||
		r.succeeded === false ||
		r.verified === false
	);
}
function ok(value: Record<string, unknown>) {
	const r = outcome(value);
	return (
		!failed(value) &&
		(r.succeeded === true ||
			r.verified === true ||
			r.status === "completed" ||
			r.reusedAnalysis === true)
	);
}
function usable(value: Record<string, unknown>) {
	return !failed(value) && (ok(value) || outcome(value).status === "partial");
}
/** Fixed orchestration only. Caller still owns exact-request approval and write capability. */
export async function investigationWorkflow(
	input: ReverseEngineeringInput,
	run: InvestigationRunner,
	signal?: AbortSignal,
) {
	if (!input.target) throw new Error("Explicit investigation target required");
	const timeout = Math.min(input.timeout_ms ?? 120000, 600000),
		deadline = Date.now() + timeout;
	const combined = AbortSignal.any([
		...(signal ? [signal] : []),
		AbortSignal.timeout(timeout),
	]);
	combined.throwIfAborted();
	const stages: {
		id: string;
		request: ReverseEngineeringInput;
		result: Record<string, unknown>;
	}[] = [];
	const stage = async (id: string, request: ReverseEngineeringInput) => {
		const bounded = {
			...request,
			timeout_ms: Math.max(1, deadline - Date.now()),
		};
		let result: Record<string, unknown>;
		if (combined.aborted) {
			result = {
				status: "cancelled",
				executed: false,
				reason: "Cancelled before this stage; earlier receipts retained.",
			};
		} else
			try {
				result = await run(bounded, combined);
			} catch {
				result = {
					status: combined.aborted ? "cancelled" : "failed",
					reason:
						"Stage execution failed; inspect approved tool diagnostics. No automatic retry.",
				};
			}
		stages.push({ id, request: bounded, result });
		return result;
	};
	const envelope = (limitations: string[], forcePartial = false) => ({
		schemaVersion: 1,
		operation: input.operation,
		effect:
			input.operation === "build_android_candidate"
				? "candidate-write"
				: "read",
		status:
			combined.aborted ||
			stages.some((s) => outcome(s.result).status === "cancelled")
				? "cancelled"
				: stages.length > 0 &&
						stages.every((s) => outcome(s.result).status === "blocked")
					? "blocked"
					: stages.length > 0 && stages.every((s) => failed(s.result))
						? "failed"
						: forcePartial || stages.some((s) => !ok(s.result))
							? "partial"
							: "completed",
		stages,
		limitations,
		observedExecution: false,
	});

	if (
		sourceCommands.has(input.operation) ||
		(input.operation === "map_attack_surface" &&
			!input.target.toLowerCase().endsWith(".apk"))
	)
		return sourceInvestigation(input, combined);
	if (input.operation === "map_dotnet_interop") {
		const bytes = await readCandidateFile(
				input.target,
				16 * 1024 * 1024,
				combined,
			),
			parsed = inspectManagedPE(bytes, 200);
		return {
			status: "partial",
			effect: "read",
			inputSha256: candidateHash(bytes),
			evidence: parsed.interop,
			limitations: [
				...parsed.limitations,
				"P/Invoke ImplMap declarations only, not observed library resolution, calling convention validation, marshaling correctness, COM or reverse P/Invoke discovery.",
			],
		};
	}
	if (input.operation === "inspect_dependency_risk")
		return dependencyInventory(input.target, combined);
	if (input.operation === "inspect_binary_mitigations") {
		const bytes = await readCandidateFile(
			input.target,
			16 * 1024 * 1024,
			combined,
		);
		return {
			...inspectBinaryMitigations(bytes),
			inputSha256: candidateHash(bytes),
			effect: "read",
		};
	}
	if (input.operation === "verify_hypothesis") {
		const q = HypothesisSchema.parse(input.hypothesis),
			bytes = await readCandidateFile(input.target, 4 * 1024 * 1024, combined),
			evidence = declaredEvidence(json(bytes));
		const known =
			evidence.lookup.has(q.node_id) &&
			(q.kind === "declared-node" || evidence.lookup.has(q.target_id!));
		const found =
			q.kind === "declared-node"
				? evidence.lookup.has(q.node_id)
				: evidence.edges.some(
						(e) =>
							e.source === q.node_id &&
							e.target === q.target_id &&
							e.relation === q.relation,
					);
		return {
			status: "completed",
			effect: "read",
			statement: q.statement,
			hypothesis: q,
			conclusion: !known
				? "inconclusive"
				: found === q.expected
					? "supported"
					: "contradicted",
			scope: "exact-declaration-in-selected-report-only",
			inputSha256: candidateHash(bytes),
			evidence: found
				? {
						node: evidence.lookup.get(q.node_id),
						edges: evidence.edges
							.filter(
								(e) =>
									e.source === q.node_id &&
									e.target === q.target_id &&
									e.relation === q.relation,
							)
							.slice(0, 10),
					}
				: [],
			limitations: [
				"Verifies only the exact declared relationship predicate, not the truth of descriptive statement text or target behavior.",
				"Report is untrusted and may be incomplete. Unknown endpoints are inconclusive; absence of a declared edge says nothing about runtime behavior.",
				...(Array.isArray(evidence.sourceCoverage)
					? evidence.sourceCoverage.filter(
							(x): x is string => typeof x === "string",
						)
					: []),
			],
		};
	}
	if (input.operation === "preview_batch") {
		const p = await prepareNotebook(input.target);
		return {
			schemaVersion: 1,
			status: "completed",
			executed: false,
			effect: "plan-only",
			notebookHash: p.notebookHash,
			totalInputBytes: p.totalBytes,
			stages: p.notebook.cells.map((c) => ({
				id: c.id,
				dependsOn: c.dependsOn,
				effect: "read",
				action: c.action,
				...p.paths.get(c.id),
				approval: "exact run_batch request approval required",
			})),
			downloads: [],
			writes: [],
			runtime: [],
			budgets: {
				stages: 20,
				timeoutMs: 300000,
				artifactBytes: 128 * 1024 * 1024,
				totalInputBytes: 512 * 1024 * 1024,
			},
			limitations: [
				"Preview validates the existing static notebook and confined files only, not installed engines. No candidate writes, signing, runtime operations or permission expansion.",
			],
		};
	}
	if (input.operation === "explain_decompiler_disagreement") {
		if (!input.compare_target)
			throw new Error("Two selected-function evidence JSON files required");
		const [a, b] = await Promise.all([
			readCandidateFile(input.target, 2 * 1024 * 1024, combined),
			readCandidateFile(input.compare_target, 2 * 1024 * 1024, combined),
		]);
		const left = SelectedNativeEvidenceSchema.parse(json(a)),
			right = SelectedNativeEvidenceSchema.parse(json(b));
		return {
			status: "partial",
			effect: "read",
			leftSha256: candidateHash(a),
			rightSha256: candidateHash(b),
			comparison: {
				namesEqual: left.name === right.name,
				signaturesEqual: left.signature === right.signature,
				pseudocodeEqual: left.pseudocode === right.pseudocode,
				left,
				right,
			},
			winner: null,
			limitations: [
				"Selected evidence outputs are imported, untrusted declarations, not authenticated engine execution. Equal symbols/addresses do not prove the same image or semantics.",
				"Difference report only; neither decompiler is assumed correct. Validate original input hashes, architectures, bases, versions and ranges independently.",
			],
		};
	}
	if (input.operation === "build_android_candidate") {
		if (!input.output_file?.toLowerCase().endsWith(".apk"))
			throw new Error("New candidate .apk output_file required");
		const built = await stage("rebuild", {
			operation: "rebuild_apk",
			target: input.target,
			output_file: input.output_file,
			acknowledge_external_output: input.acknowledge_external_output,
		});
		if (!ok(built))
			return envelope([
				"Build did not complete; inspection not run. No signing, install or runtime verification.",
			]);
		await stage("inspect-candidate", {
			operation: "inspect",
			target: input.output_file,
		});
		return envelope(
			[
				"Existing Apktool builder and no-overwrite candidate publication are reused. New unsigned APK; no original-signature preservation, automatic signing/install, ART/device compatibility or behavioral equivalence.",
			],
			true,
		);
	}
	if (input.operation === "verify_android_candidate") {
		await stage("structure", { operation: "inspect", target: input.target });
		await stage("signature", {
			operation: "verify_apk_signature",
			target: input.target,
		});
		if (input.compare_target)
			await stage("differences", {
				operation: "compare_apks",
				target: input.compare_target,
				compare_target: input.target,
				max_results: input.max_results ?? 200,
			});
		return envelope(
			[
				"Structure/signature checks and optional ZIP-entry comparison only. Signature failure is retained, not ignored. Build/assembly success requires its separate immutable build receipt; no ART/device/runtime verification.",
			],
			true,
		);
	}
	if (
		["find_android_entrypoints", "map_attack_surface"].includes(input.operation)
	) {
		const report = await stage("apk-security", {
			operation: "apk_security_report",
			target: input.target,
			max_results: input.max_results ?? 200,
		});
		if (!ok(report) && typeof report.reportFile !== "string")
			return envelope(
				["APK security stage failed; no manifest evidence was read."],
				true,
			);
		if (typeof report.reportFile !== "string")
			throw new Error("APK report did not return a report file");
		const bytes = await readCandidateFile(
				report.reportFile,
				4 * 1024 * 1024,
				combined,
			),
			doc = json(bytes) as Record<string, unknown>;
		return {
			...envelope(
				[
					"Manifest component/export evidence only. Supported manifest decoding depends on available Android tools; lifecycle/callback expansion, reachability and execution remain unresolved.",
				],
				true,
			),
			manifestEvidence: doc.apkSecurity,
			reportSha256: candidateHash(bytes),
		};
	}
	if (input.operation === "trace_android_method") {
		if (!input.advanced_options?.method)
			throw new Error("Exact advanced_options.method required");
		const bytecode = await stage("selected-bytecode", {
			operation: "advanced_analysis",
			advanced_action: "android_method_code",
			target: input.target,
			advanced_options: { method: input.advanced_options.method },
			max_results: input.max_results ?? 200,
		});
		if (!usable(bytecode))
			return envelope(
				[
					"Selected bytecode stage failed; dependent relationship stage was not run.",
				],
				true,
			);
		await stage("selected-relationships", {
			operation: "advanced_analysis",
			advanced_action: "android_method",
			target: input.target,
			advanced_options: { method: input.advanced_options.method },
			max_results: input.max_results ?? 200,
		});
		return envelope(
			[
				"Exact selected DEX method bytecode and bounded reference candidates, preserving DEX origin; reflection, dynamic dispatch, full call graph and runtime reachability remain unresolved.",
			],
			true,
		);
	}
	if (
		input.operation === "diff_android_resources" ||
		(input.operation === "compare_versions" &&
			input.target.toLowerCase().endsWith(".apk"))
	) {
		if (!input.compare_target)
			throw new Error("Explicit compare_target required");
		await stage("apk-entry-differences", {
			operation: "compare_apks",
			target: input.target,
			compare_target: input.compare_target,
			max_results: input.max_results ?? 200,
		});
		return envelope(
			[
				"Combined manifest/resources/assets/DEX/native ZIP-entry size/CRC differences; CRC equality is not cryptographic byte equivalence or decoded semantic/API comparison. Inspect bounded resultsTruncated and categoryCounts. No code executes.",
			],
			true,
		);
	}
	if (input.operation === "compare_versions") {
		if (!input.compare_target)
			throw new Error("Explicit compare_target required");
		const [a, b] = await Promise.all([
			readCandidateFile(input.target, 16 * 1024 * 1024, combined),
			readCandidateFile(input.compare_target, 16 * 1024 * 1024, combined),
		]);
		const spans: {
			offset: number;
			originalBytes: number;
			candidateBytes: number;
		}[] = [];
		let changed = 0,
			spanCount = 0,
			activeSpan = -1;
		for (let i = 0; i < Math.max(a.length, b.length); i++) {
			if ((i & 65535) === 0) combined.throwIfAborted();
			if (a[i] !== b[i]) {
				changed++;
				if (i === 0 || a[i - 1] === b[i - 1]) {
					spanCount++;
					activeSpan =
						spans.length < 200
							? spans.push({ offset: i, originalBytes: 0, candidateBytes: 0 }) -
								1
							: -1;
				}
				if (activeSpan >= 0) {
					const s = spans[activeSpan];
					if (i < a.length) s.originalBytes++;
					if (i < b.length) s.candidateBytes++;
				}
			} else activeSpan = -1;
		}
		return {
			status: "partial",
			effect: "read",
			original: { sha256: candidateHash(a), bytes: a.length },
			candidate: { sha256: candidateHash(b), bytes: b.length },
			identical: a.equals(b),
			changedOffsets: changed,
			differenceSpans: spans,
			spanCount,
			spansTruncated: spanCount > spans.length,
			limitations: [
				"Bounded fixed-offset byte comparison only, not instruction alignment, source/resources/API semantic changes or runtime equivalence. At most 200 differing spans are included; use compare_public_api for JS/TS export declarations.",
			],
		};
	}
	if (
		[
			"resolve_native_symbol",
			"decompile_function_bundle",
			"trace_native_calls",
			"compare_native_functions",
		].includes(input.operation)
	) {
		const selector =
			input.function_selector ?? input.advanced_options?.function;
		if (!selector) throw new Error("Exact function_selector required");
		const selected = {
			operation: "advanced_analysis" as const,
			advanced_action: "native_function" as const,
			target: input.target,
			advanced_options: {
				function: {
					...selector,
					max_bytes: input.advanced_options?.function?.max_bytes ?? 4096,
				},
			},
			max_results: input.max_results ?? 200,
		};
		if (
			input.operation === "decompile_function_bundle" &&
			!["ghidra", "ida"].includes(input.engine ?? "")
		)
			throw new Error(
				"decompile_function_bundle requires explicit ghidra or ida",
			);
		if (input.operation === "compare_native_functions" && !input.compare_target)
			throw new Error("compare_native_functions requires compare_target");
		const first = await stage("selected-native-evidence", selected);
		if (!usable(first))
			return envelope(
				["Selected native evidence failed; dependent stages were not run."],
				true,
			);
		if (input.operation === "decompile_function_bundle") {
			await stage("selected-decompiler", {
				operation: "decompile",
				target: input.target,
				engine: input.engine,
				function_selector: selector,
			});
		}
		if (input.operation === "compare_native_functions") {
			await stage("comparison-selected-native-evidence", {
				...selected,
				target: input.compare_target,
			});
		}
		return {
			...envelope(
				[
					"Bounded selected ELF function, preferred image base, direct/indirect call candidates, selected strings/references and optional exact decompiler output. Inspect each nested stage's ambiguity/truncation/limitations; no absent function or dynamic call is invented.",
					"Caller discovery and transitive call traversal are not complete; compare selects the same exact symbol/address in both images, not an inferred semantic match. No runtime behavior or equivalence proof.",
				],
				true,
			),
			matchConfidence:
				input.operation === "compare_native_functions"
					? "same-exact-selector-only-not-semantic-match"
					: undefined,
		};
	}
	throw new Error("Unknown investigation workflow");
}
