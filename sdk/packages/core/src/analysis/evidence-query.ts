import { z } from "zod";
import { javaScriptSemanticQueryInputSchema } from "./semantic-engine/upstream/src/domain/javascript/javascriptSemanticQuerySchemas";
export const EvidenceQuerySchema = z
	.object({
		receiptId: z.string().uuid(),
		view: z
			.enum([
				"artifacts",
				"findings",
				"graph",
				"comparison",
				"verification",
				"semantic-summary",
				"semantic-nodes",
				"semantic-relations",
				"semantic-unknowns",
				"semantic-fingerprints",
				"semantic-contexts",
				"semantic-trace",
			])
			.default("findings"),
		offset: z.number().int().min(0).max(1_000_000).default(0),
		limit: z.number().int().min(1).max(50).default(20),
		filter: z.string().max(200).default(""),
		trace: javaScriptSemanticQueryInputSchema.optional(),
		traceSection: z
			.enum(["nodes", "relations", "unknowns", "evidence_contexts"])
			.default("nodes"),
	})
	.strict()
	.superRefine((value, ctx) => {
		if ((value.view === "semantic-trace") !== (value.trace !== undefined))
			ctx.addIssue({
				code: "custom",
				message: "trace is required only for semantic-trace",
			});
		if (value.trace && Buffer.byteLength(JSON.stringify(value.trace)) > 16_384)
			ctx.addIssue({
				code: "custom",
				message: "Semantic trace request exceeds byte budget",
			});
	});
/** Bound model display without truncating stored evidence. */
export function semanticEvidencePage(
	graph: Record<string, unknown>,
	input: z.infer<typeof EvidenceQuerySchema>,
) {
	const keys: Record<string, string> = {
		"semantic-nodes": "nodes",
		"semantic-relations": "relations",
		"semantic-unknowns": "unknowns",
		"semantic-fingerprints": "fingerprints",
		"semantic-contexts": "evidence_contexts",
	};
	const key =
		input.view === "semantic-trace" ? input.traceSection : keys[input.view];
	if (!key || !Array.isArray(graph[key]))
		throw new Error("Semantic view unavailable");
	const all = graph[key] as unknown[];
	const filtered = input.filter
		? all.filter((v) =>
				JSON.stringify(v).toLowerCase().includes(input.filter.toLowerCase()),
			)
		: all;
	const items: unknown[] = [];
	let bytes = 0;
	for (const item of filtered.slice(input.offset, input.offset + input.limit)) {
		const text = JSON.stringify(item);
		const identity =
			item && typeof item === "object" ? (item as Record<string, unknown>) : {};
		const shown =
			Buffer.byteLength(text) > 65_536
				? {
						node_id: identity.node_id,
						relation_id: identity.relation_id,
						unknown_id: identity.unknown_id,
						displayOmitted: true,
						note: "Record exceeds display budget; full evidence remains retained.",
					}
				: item;
		const size = Buffer.byteLength(JSON.stringify(shown));
		if (bytes + size > 196_608 && items.length) break;
		items.push(shown);
		bytes += size;
	}
	return {
		view: input.view,
		total: filtered.length,
		offset: input.offset,
		items,
		nextOffset:
			input.offset + items.length < filtered.length
				? input.offset + items.length
				: null,
	};
}
