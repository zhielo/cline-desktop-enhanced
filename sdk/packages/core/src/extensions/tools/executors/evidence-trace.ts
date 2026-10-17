import { ResultSchema } from "../../../analysis/contracts";
import { EvidenceTraceSchema } from "../advanced-candidates-schema";
import { EvidenceGraphSchema } from "./analysis-evidence-graph";
/** Traverses declared evidence relationships only; never infers whole-program semantics. */
export function traceEvidence(
	document: unknown,
	options: unknown,
	dataFlowOnly: boolean,
) {
	const q = EvidenceTraceSchema.parse(options);
	let nodes: {
		id: string;
		label: string;
		domain: string;
		provenance: unknown;
	}[];
	let edges: {
		source: string;
		target: string;
		relation: string;
		provenance: unknown;
	}[];
	let sourceCoverage: unknown;
	const staticResult = ResultSchema.safeParse(document);
	if (staticResult.success) {
		nodes = staticResult.data.facts.map((f) => ({
			id: f.id,
			label: f.value,
			domain: f.kind,
			provenance: {
				location: f.location,
				confidence: f.confidence,
				limitations: f.limitations,
			},
		}));
		edges = staticResult.data.edges.map((e) => ({
			source: e.source,
			target: e.target,
			relation: e.kind,
			provenance: { confidence: e.confidence, limitations: e.limitations },
		}));
		sourceCoverage = staticResult.data.limitations;
	} else {
		const graph = EvidenceGraphSchema.parse(document);
		nodes = graph.nodes.map((n) => ({
			id: n.id,
			label: n.label,
			domain: n.kind,
			provenance: {
				artifactSha256: n.artifactSha256,
				confidence: n.confidence,
				evidenceIndex: n.evidenceIndex,
			},
		}));
		edges = graph.edges.map((e) => ({
			source: e.source,
			target: e.target,
			relation: e.relation,
			provenance: { confidence: e.confidence },
		}));
		sourceCoverage = graph.coverage;
	}
	const lookup = new Map(nodes.map((n) => [n.id, n]));
	if (lookup.size !== nodes.length)
		throw new Error("Duplicate evidence node IDs");
	for (const e of edges)
		if (!lookup.has(e.source) || !lookup.has(e.target))
			throw new Error("Dangling evidence edge");
	if (!lookup.has(q.start_id) || (q.end_id && !lookup.has(q.end_id)))
		throw new Error("Unknown evidence trace endpoint");
	const outgoing = new Map<string, typeof edges>();
	for (const e of edges) {
		if (dataFlowOnly && e.relation !== "data-flow") continue;
		const list = outgoing.get(e.source) ?? [];
		list.push(e);
		outgoing.set(e.source, list);
	}
	const selected = new Set([q.start_id]),
		depths = new Map([[q.start_id, 0]]),
		parents = new Map<string, string>();
	const chosen: typeof edges = [];
	const queue = [q.start_id];
	let truncated = false,
		used = Buffer.byteLength(
			JSON.stringify({ seed: lookup.get(q.start_id), sourceCoverage }),
		);
	if (used > 98304)
		throw new Error("Trace seed/coverage exceeds output byte budget");
	for (let i = 0; i < queue.length; i++) {
		const id = queue[i],
			depth = depths.get(id)!;
		for (const e of outgoing.get(id) ?? []) {
			if (depth >= q.max_depth) {
				truncated = true;
				continue;
			}
			if (chosen.length >= q.max_edges) {
				truncated = true;
				continue;
			}
			if (!selected.has(e.target) && selected.size >= q.max_nodes) {
				truncated = true;
				continue;
			}
			const budget =
				Buffer.byteLength(JSON.stringify(e)) +
				(!selected.has(e.target)
					? Buffer.byteLength(JSON.stringify(lookup.get(e.target)))
					: 0);
			if (used + budget > 98304) {
				truncated = true;
				continue;
			}
			used += budget;
			chosen.push(e);
			if (!selected.has(e.target)) {
				selected.add(e.target);
				depths.set(e.target, depth + 1);
				parents.set(e.target, id);
				queue.push(e.target);
			}
		}
	}
	const route: string[] = [];
	if (q.end_id && selected.has(q.end_id)) {
		let id: string | undefined = q.end_id;
		while (id) {
			route.unshift(id);
			id = parents.get(id);
		}
	}
	return {
		status: truncated ? "partial" : "completed",
		mode: dataFlowOnly
			? "declared-data-flow-edges-only"
			: "declared-evidence-relationship-paths",
		nodes: [...selected].map((id) => lookup.get(id)),
		edges: chosen,
		route,
		endpointReachableInSelectedGraph: q.end_id
			? selected.has(q.end_id)
			: undefined,
		truncated,
		sourceCoverage,
		authority: "untrusted-imported-report",
		observedExecution: false,
		limitations: [
			"Traverses supplied declared edges only. No universal cross-language resolution, taint solver, call-chain proof, execution or inference of absent relationships.",
			"Candidate JNI/IPC relationships remain candidates; a graph path is not a proven runtime path. No route does not establish absence of behavior.",
			"Imported report hashes and confidence labels are not producer authentication; verify source artifacts and provenance independently.",
		],
	};
}
