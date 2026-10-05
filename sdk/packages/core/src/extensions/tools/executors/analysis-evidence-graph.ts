import { createHash } from "node:crypto";
import { z } from "zod";
import type { AdvancedResult } from "./advanced-analysis";
const hash = (value: string) =>
	createHash("sha256").update(value).digest("hex");
const Confidence = z.enum(["reported", "candidate", "unresolved"]);
const Node = z
	.object({
		id: z.string().max(80),
		kind: z.enum([
			"artifact",
			"dex-class",
			"dex-method",
			"native-symbol",
			"archive-member",
			"unresolved-call",
		]),
		label: z.string().max(4096),
		artifactSha256: z.string().regex(/^[a-f0-9]{64}$/),
		confidence: Confidence,
		evidenceIndex: z.number().int().nonnegative(),
	})
	.strict();
const Edge = z
	.object({
		source: z.string().max(80),
		target: z.string().max(80),
		relation: z.enum(["contains", "declares", "invokes-candidate"]),
		confidence: Confidence,
	})
	.strict();
export const EvidenceGraphSchema = z
	.object({
		schemaVersion: z.literal(1),
		nodes: z.array(Node).max(10000),
		edges: z.array(Edge).max(20000),
		coverage: z.array(z.string().max(1000)).max(100),
		sourceHashes: z.array(z.string().regex(/^[a-f0-9]{64}$/)).max(100),
	})
	.strict();
export const GraphQuerySchema = z
	.object({
		kind: Node.shape.kind.optional(),
		text: z.string().max(512).optional(),
		startId: z.string().max(80).optional(),
		depth: z.number().int().min(0).max(8).optional(),
		limit: z.number().int().min(1).max(1000).optional(),
	})
	.strict();
export type GraphQuery = z.infer<typeof GraphQuerySchema>;
const InputResult = z.object({
	protocol: z.literal("cline-advanced-analysis/v1"),
	status: z.enum(["completed", "partial", "blocked", "failed", "cancelled"]),
	engine: z.string().max(100),
	engineVersion: z.string().nullable(),
	evidence: z.record(z.string(), z.unknown()),
	limitations: z.array(z.string().max(1000)).max(100),
	input: z
		.object({
			sha256: z.string().regex(/^[a-f0-9]{64}$/),
			bytes: z.number().nonnegative(),
			format: z.string().max(100),
		})
		.optional(),
});
const Manifest = z
	.object({
		schemaVersion: z.literal(1),
		results: z.array(InputResult).min(1).max(50),
	})
	.strict();
function records(value: unknown): Record<string, unknown>[] {
	return Array.isArray(value)
		? value
				.filter(
					(item): item is Record<string, unknown> =>
						!!item && typeof item === "object" && !Array.isArray(item),
				)
				.slice(0, 2000)
		: [];
}
function label(value: unknown) {
	return typeof value === "string" && value.length <= 4096 ? value : undefined;
}
/** Imported reports are data, never authenticated instructions or complete program semantics. */
export function buildEvidenceGraph(document: unknown) {
	const manifest = Manifest.parse(document);
	const nodes = new Map<string, z.infer<typeof Node>>();
	const edges = new Map<string, z.infer<typeof Edge>>();
	const coverage = new Set<string>();
	const sourceHashes: string[] = [];
	const edge = (
		source: string,
		target: string,
		relation: z.infer<typeof Edge>["relation"],
		confidence: z.infer<typeof Confidence>,
	) => {
		const key = `${source}:${target}:${relation}`;
		if (!edges.has(key) && edges.size >= 20000)
			throw new Error("Graph edge budget exceeded");
		edges.set(key, { source, target, relation, confidence });
	};
	manifest.results.forEach((result, index) => {
		const reportHash = hash(JSON.stringify(result));
		sourceHashes.push(reportHash);
		const artifact = result.input?.sha256 ?? reportHash;
		const node = (
			kind: z.infer<typeof Node>["kind"],
			name: string,
			confidence: z.infer<typeof Confidence> = "reported",
		) => {
			const id = `e-${hash(`${artifact}:${kind}:${name}`)}`;
			if (!nodes.has(id) && nodes.size >= 10000)
				throw new Error("Graph node budget exceeded");
			nodes.set(id, {
				id,
				kind,
				label: name,
				artifactSha256: artifact,
				confidence,
				evidenceIndex: index,
			});
			return id;
		};
		const root = node("artifact", result.input?.format ?? result.engine);
		coverage.add(
			`Report ${index}: ${result.status}; ${result.engine}/${result.engineVersion ?? "unknown"}`,
		);
		for (const item of result.limitations)
			if (coverage.size < 100) coverage.add(item);
		const data = result.evidence;
		for (const cls of Array.isArray(data.classes)
			? data.classes.slice(0, 2000)
			: []) {
			const name = label(cls);
			if (name) edge(root, node("dex-class", name), "contains", "reported");
		}
		const methods = new Map<string, string>();
		for (const method of records(data.methods)) {
			const name = label(method.id);
			if (!name) continue;
			const id = node("dex-method", name);
			methods.set(name, id);
			edge(root, id, "declares", "reported");
		}
		for (const call of records(data.calls)) {
			const source = label(call.source),
				operand = label(call.operand);
			if (!source || !operand || !methods.has(source)) continue;
			const candidate = /L[^\s,;]{1,512};->[^\s,]{1,2048}/.exec(operand)?.[0];
			const target = candidate ? methods.get(candidate) : undefined;
			edge(
				methods.get(source) ?? root,
				target ?? node("unresolved-call", operand, "unresolved"),
				"invokes-candidate",
				"candidate",
			);
		}
		for (const symbol of records(data.symbols)) {
			const name = label(symbol.name);
			if (name !== undefined)
				edge(
					root,
					node(
						"native-symbol",
						`${name}@${String(symbol.address).slice(0, 64)}`,
					),
					"contains",
					"reported",
				);
		}
		for (const member of records(data.entries)) {
			const name = label(member.name);
			if (name)
				edge(root, node("archive-member", name), "contains", "reported");
		}
	});
	return EvidenceGraphSchema.parse({
		schemaVersion: 1,
		nodes: [...nodes.values()].sort((a, b) => a.id.localeCompare(b.id)),
		edges: [...edges.values()].sort((a, b) =>
			`${a.source}:${a.target}:${a.relation}`.localeCompare(
				`${b.source}:${b.target}:${b.relation}`,
			),
		),
		coverage: [...coverage].slice(0, 100),
		sourceHashes,
	});
}
export function queryEvidenceGraph(
	document: unknown,
	options: GraphQuery = {},
) {
	const graph = EvidenceGraphSchema.parse(document);
	const query = GraphQuerySchema.parse(options);
	const limit = query.limit ?? 100;
	const ids = new Set(graph.nodes.map((node) => node.id));
	for (const edge of graph.edges)
		if (!ids.has(edge.source) || !ids.has(edge.target))
			throw new Error("Dangling graph edge");
	const reachable = new Set<string>();
	if (query.startId) {
		if (!ids.has(query.startId)) throw new Error("Unknown startId");
		reachable.add(query.startId);
		let frontier = [query.startId];
		for (let i = 0; i < (query.depth ?? 1); i++) {
			const current = new Set(frontier);
			const next: string[] = [];
			for (const edge of graph.edges)
				if (current.has(edge.source) && !reachable.has(edge.target)) {
					reachable.add(edge.target);
					next.push(edge.target);
				}
			frontier = next;
		}
	}
	const matches = graph.nodes.filter(
		(node) =>
			(!query.startId || reachable.has(node.id)) &&
			(!query.kind || query.kind === node.kind) &&
			(!query.text ||
				node.label.toLowerCase().includes(query.text.toLowerCase())),
	);
	const nodes = matches.slice(0, limit);
	const selected = new Set(nodes.map((node) => node.id));
	return {
		nodes,
		edges: graph.edges
			.filter((edge) => selected.has(edge.source) && selected.has(edge.target))
			.slice(0, 2000),
		matchedNodes: matches.length,
		truncated: matches.length > limit,
		coverage: graph.coverage,
		graphSha256: hash(JSON.stringify(graph)),
		integrity: "content-identity-not-authentication",
	};
}
export function graphResult(
	action: "graph_build" | "graph_query",
	document: unknown,
	query?: GraphQuery,
): AdvancedResult {
	const evidence =
		action === "graph_build"
			? { graph: buildEvidenceGraph(document) }
			: queryEvidenceGraph(document, query);
	if (Buffer.byteLength(JSON.stringify(evidence)) > 8 * 1024 * 1024)
		throw new Error("Graph output exceeds byte budget");
	return {
		protocol: "cline-advanced-analysis/v1",
		status: "completed",
		engine: "evidence-graph",
		engineVersion: "1",
		evidence,
		limitations: [
			"Imported reports are untrusted data; hashes establish content identity, not authenticity.",
			"Graph coverage is limited to supplied reports. JNI registration, reflection and dynamic calls remain unresolved.",
		],
	};
}
