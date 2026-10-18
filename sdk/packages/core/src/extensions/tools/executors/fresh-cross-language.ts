import { analyzeSources } from "../../../analysis/parser";
import { digest } from "../../../analysis/contracts";
import { CrossLanguageOptionsSchema } from "../investigation-workflows-schema";
import type { ReverseEngineeringInput } from "../schemas";
import type { InvestigationRunner } from "./investigation-workflows";
import { collectWorkflowSources } from "./source-investigation";

/** Fresh supported static evidence only. No imported report acquires fresh authority. */
export async function freshCrossLanguage(
	input: ReverseEngineeringInput,
	run: InvestigationRunner,
	signal?: AbortSignal,
) {
	if (!input.target)
		throw new Error("Explicit fresh cross-language target required");
	const options = CrossLanguageOptionsSchema.parse(input.cross_language);
	const combined = AbortSignal.any([
		...(signal ? [signal] : []),
		AbortSignal.timeout(Math.min(input.timeout_ms ?? 120000, 600000)),
	]);
	combined.throwIfAborted();
	if (options.kind === "android-jni") {
		const { kind: _, method, ...jni_trace } = options;
		const request: ReverseEngineeringInput = {
			operation: "advanced_analysis",
			advanced_action: "android_relationships",
			target: input.target,
			max_results: 200,
			advanced_options: { method, jni_trace },
			timeout_ms: Math.min(input.timeout_ms ?? 120000, 600000),
		};
		const receipt = await run(request, combined),
			raw = receipt.result as Record<string, unknown> | undefined;
		const status = raw?.status ?? receipt.status;
		return {
			schemaVersion: 1,
			operation: input.operation,
			mode: "fresh-android-jni-candidates",
			status: ["blocked", "failed", "cancelled"].includes(String(status))
				? status
				: "partial",
			effect: "read",
			observedExecution: false,
			stages: [{ id: "fresh-android-jni-native", request, result: receipt }],
			limitations: [
				"Fresh bounded DEX native declaration to JNI export-name candidates, optionally followed into one uniquely selected retained ELF symbol call graph. Not observed JNI registration, executed Java-to-native flow or a complete binding resolver.",
				"Ambiguous/missing/non-native methods, ambiguous exports, unavailable LIEF/Capstone and bounded coverage remain explicit. No imported-report or runtime fallback.",
			],
		};
	}
	const inventory = await collectWorkflowSources(input.target, combined);
	combined.throwIfAborted();
	const report = analyzeSources(inventory.sources, inventory.limitations);
	combined.throwIfAborted();
	const channelFacts = report.facts.filter(
		(f) =>
			(["ipc-send", "ipc-handler"].includes(f.kind) &&
				f.value === options.channel) ||
			(f.kind === "preload-member" &&
				JSON.parse(f.value).channel === options.channel),
	);
	const allowed = new Set(channelFacts.map((f) => f.id));
	for (const f of report.facts)
		if (["preload-call", "preload-api"].includes(f.kind)) allowed.add(f.id);
	const candidates = report.edges.filter(
		(e) =>
			["ipc-candidate", "preload-candidate"].includes(e.kind) &&
			allowed.has(e.source) &&
			allowed.has(e.target),
	);
	const adjacent = new Map<string, typeof candidates>();
	for (const e of candidates)
		for (const id of [e.source, e.target]) {
			const rows = adjacent.get(id) ?? [];
			rows.push(e);
			adjacent.set(id, rows);
		}
	const lookup = new Map(report.facts.map((f) => [f.id, f])),
		selected = new Set<string>(),
		depths = new Map<string, number>(),
		queue: string[] = [],
		edges: typeof candidates = [],
		seen = new Set<string>();
	const limits = new Set<string>();
	let used = Buffer.byteLength(JSON.stringify(report.artifacts));
	const add = (id: string, depth: number) => {
		if (selected.has(id)) return true;
		if (selected.size >= options.max_nodes) {
			limits.add("max_nodes");
			return false;
		}
		const cost = Buffer.byteLength(JSON.stringify(lookup.get(id)));
		if (used + cost > 98304) {
			limits.add("max_output_bytes");
			return false;
		}
		used += cost;
		selected.add(id);
		depths.set(id, depth);
		queue.push(id);
		return true;
	};
	for (const fact of channelFacts) add(fact.id, 0);
	for (let i = 0; i < queue.length; i++) {
		combined.throwIfAborted();
		const id = queue[i],
			depth = depths.get(id)!;
		for (const e of adjacent.get(id) ?? []) {
			const key = `${e.source}:${e.target}:${e.kind}`;
			if (seen.has(key)) continue;
			if (depth >= options.max_depth) {
				limits.add("max_depth");
				continue;
			}
			if (edges.length >= options.max_edges) {
				limits.add("max_edges");
				continue;
			}
			const cost = Buffer.byteLength(JSON.stringify(e));
			if (used + cost > 98304) {
				limits.add("max_output_bytes");
				continue;
			}
			const other = e.source === id ? e.target : e.source;
			if (!add(other, depth + 1)) continue;
			// A newly added node may consume the remaining byte budget; don't overrun it with the edge.
			if (used + cost > 98304) {
				limits.add("max_output_bytes");
				continue;
			}
			used += cost;
			edges.push(e);
			seen.add(key);
		}
	}
	return {
		schemaVersion: 1,
		operation: input.operation,
		protocol: "cline-fresh-cross-language/v1",
		mode: "fresh-electron-ipc-candidates",
		status: "partial",
		effect: "read",
		observedExecution: false,
		selection: {
			channel: options.channel,
			matchingFacts: channelFacts.length,
			status: channelFacts.length
				? "found-candidates"
				: "not-found-in-covered-sources",
			handlerCandidates: channelFacts.filter((f) => f.kind === "ipc-handler")
				.length,
		},
		nodes: [...selected].map((id) => lookup.get(id)),
		edges,
		artifacts: report.artifacts,
		inputFingerprint: digest(report.artifacts),
		coverage: {
			budgets: options,
			limitsReached: [...limits],
			selectedEvidenceBudgetBytes: 98304,
			sourceStatus: report.status,
			parserVersion: report.parserVersion,
		},
		limitations: [
			...report.limitations,
			"Fresh JS/TS literal channel and preload member/call syntax candidates only; declared edge direction is preserved, but neighborhood selection walks both directions. No target source is imported or executed, no channel delivery, unique routing, argument validation, process role or executed renderer-to-main chain is proven.",
			"Directory scope excludes node_modules, .git, dist, build and .cline. Maximum 128 source files, 1 MiB/file, 8 MiB total, 4096 entries and depth 8. Missing paths are not proof of absent behavior; unsupported dynamic channels/aliases remain unresolved.",
		],
	};
}
