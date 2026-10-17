import { SourceSinkSchema } from "../advanced-candidates-schema";
import { declaredEvidence } from "./evidence-trace";

/** Multi-source witness search, NOT a whole-program taint or sanitizer solver. */
export function traceSourceSink(document: unknown, options: unknown) {
	const q = SourceSinkSchema.parse(options);
	const { lookup, edges, sourceCoverage } = declaredEvidence(document);
	for (const ids of [q.source_ids, q.sink_ids, q.stop_ids]) {
		if (new Set(ids).size !== ids.length)
			throw new Error("Duplicate source/sink/stop IDs");
		for (const id of ids)
			if (!lookup.has(id)) throw new Error("Unknown source/sink/stop endpoint");
	}
	const outgoing = new Map<string, typeof edges>();
	for (const e of edges) {
		if (q.relation === "data-flow" && e.relation !== "data-flow") continue;
		const list = outgoing.get(e.source) ?? [];
		list.push(e);
		outgoing.set(e.source, list);
	}
	const sinks = new Set(q.sink_ids),
		stops = new Set(q.stop_ids);
	const witnesses: {
		sourceId: string;
		sinkId: string;
		route: string[];
		edges: typeof edges;
	}[] = [];
	const selected = new Map<
		string,
		NonNullable<ReturnType<typeof lookup.get>>
	>();
	const stoppedAt = new Set<string>();
	const reached = new Set<string>();
	let stateCount = 0,
		edgeVisits = 0,
		truncated = false;
	const pairs = q.source_ids.flatMap((sourceId) =>
		q.sink_ids.map((sinkId) => ({
			sourceId,
			sinkId,
			result: "not-reached-within-query",
		})),
	);
	let usedBytes = Buffer.byteLength(
		JSON.stringify({ sourceCoverage, query: q, pairs, stoppedAt: q.stop_ids }),
	);
	if (usedBytes > 65536)
		throw new Error("Source/sink query coverage exceeds output byte budget");
	outer: for (const sourceId of q.source_ids) {
		if (stateCount >= q.max_states) {
			truncated = true;
			break;
		}
		const queue = [{ id: sourceId, depth: 0 }];
		const parents = new Map<string, (typeof edges)[number] | null>([
			[sourceId, null],
		]);
		stateCount++;
		for (let i = 0; i < queue.length; i++) {
			const { id, depth } = queue[i];
			if (sinks.has(id)) {
				const route = [id],
					routeEdges: typeof edges = [];
				let cursor = id;
				while (parents.get(cursor)) {
					const edge = parents.get(cursor)!;
					routeEdges.unshift(edge);
					route.unshift(edge.source);
					cursor = edge.source;
				}
				const witness = { sourceId, sinkId: id, route, edges: routeEdges };
				const extraNodes = route.filter((n) => !selected.has(n));
				const bytes =
					Buffer.byteLength(JSON.stringify(witness)) +
					extraNodes.reduce(
						(n, key) => n + Buffer.byteLength(JSON.stringify(lookup.get(key))),
						0,
					);
				if (usedBytes + bytes > 65536 || witnesses.length >= 64) {
					truncated = true;
					break outer;
				}
				witnesses.push(witness);
				usedBytes += bytes;
				for (const key of route) selected.set(key, lookup.get(key)!);
				reached.add(`${sourceId}\0${id}`);
			}
			if (stops.has(id)) {
				stoppedAt.add(id);
				continue;
			}
			for (const edge of outgoing.get(id) ?? []) {
				if (edgeVisits >= q.max_edge_visits) {
					truncated = true;
					break outer;
				}
				edgeVisits++;
				if (parents.has(edge.target)) continue;
				if (depth >= q.max_depth) {
					truncated = true;
					continue;
				}
				if (stateCount >= q.max_states) {
					truncated = true;
					break outer;
				}
				parents.set(edge.target, edge);
				stateCount++;
				queue.push({ id: edge.target, depth: depth + 1 });
			}
		}
	}
	return {
		status: truncated ? "partial" : "completed",
		mode:
			q.relation === "data-flow"
				? "declared-data-flow-source-sink-witnesses"
				: "declared-relationship-source-sink-witnesses",
		witnesses,
		nodes: [...selected.values()],
		sourceCoverage,
		pairs: pairs.map((pair) => ({
			...pair,
			result: reached.has(`${pair.sourceId}\0${pair.sinkId}`)
				? "declared-path-found"
				: pair.result,
		})),
		stoppedAt: [...stoppedAt],
		counters: { states: stateCount, edgeVisits },
		truncated,
		authority: "untrusted-imported-report",
		observedExecution: false,
		limitations: [
			"Searches declared report edges only. No whole-program taint, alias, sanitizer, control-flow or runtime-path proof. A missing witness does not establish absence of behavior.",
			"Stop IDs are user-specified traversal boundaries, NOT validated sanitizers or proof that taint is removed. Paths keep original evidence confidence and provenance.",
			"At most 64 source/sink witnesses, bounded states, depth, edge visits and output bytes. Imported hashes and labels are not producer authentication.",
		],
	};
}
