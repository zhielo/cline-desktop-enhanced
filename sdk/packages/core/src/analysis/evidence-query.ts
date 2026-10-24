import { z } from "zod";
import { applicationFeatureSeedSchema } from "./semantic-engine/upstream/src/domain/javascript/javascriptFeatureTraceSchemas";
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
				"source-acquisition",
				"source-containers",
				"electron-fuses",
				"artifact-metadata",
				"bundle-recovery",
				"application-summary",
				"application-nodes",
				"application-edges",
				"application-trace",
				"application-comparison",
				"application-exports",
				"application-source-bundle",
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
		fuseSection: z
			.enum(["slices", "sentinels", "runtime_implications"])
			.optional(),
		trace: javaScriptSemanticQueryInputSchema.optional(),
		applicationTrace: z
			.object({
				seed: applicationFeatureSeedSchema,
				direction: z.enum(["outgoing", "incoming", "both"]).default("both"),
			})
			.strict()
			.optional(),
		compareReceiptId: z.string().uuid().optional(),
		exportSelectors: z
			.object({
				left: z
					.object({
						modulePath: z.string().min(1).max(4096),
						exportName: z.string().max(4096),
					})
					.strict(),
				right: z
					.object({
						modulePath: z.string().min(1).max(4096),
						exportName: z.string().max(4096),
					})
					.strict(),
			})
			.strict()
			.optional(),
		applicationSection: z
			.enum([
				"nodes",
				"edges",
				"items",
				"changes",
				"paths",
				"seed_matches",
				"native_handoffs",
				"property_inventories",
			])
			.optional(),
		traceSection: z
			.enum(["nodes", "relations", "unknowns", "evidence_contexts"])
			.default("nodes"),
	})
	.strict()
	.superRefine((value, ctx) => {
		if (value.fuseSection && value.view !== "electron-fuses")
			ctx.addIssue({
				code: "custom",
				message: "fuseSection is only for electron-fuses",
			});
		if (
			(value.view === "application-trace") !==
			(value.applicationTrace !== undefined)
		)
			ctx.addIssue({
				code: "custom",
				message: "applicationTrace is required only for application-trace",
			});
		const comparing =
			value.view === "application-comparison" ||
			value.view === "application-exports" ||
			value.view === "application-source-bundle";
		if (
			(value.view === "application-comparison" ||
				value.view === "application-exports") &&
			value.compareReceiptId === value.receiptId
		)
			ctx.addIssue({
				code: "custom",
				message: "Comparison requires two distinct receipts",
			});
		if (comparing !== (value.compareReceiptId !== undefined))
			ctx.addIssue({
				code: "custom",
				message:
					"compareReceiptId is required only for application comparisons",
			});
		if (
			(value.view === "application-exports") !==
			(value.exportSelectors !== undefined)
		)
			ctx.addIssue({
				code: "custom",
				message: "exportSelectors are required only for application-exports",
			});
		if (
			value.applicationSection &&
			![
				"application-trace",
				"application-comparison",
				"application-exports",
				"application-source-bundle",
			].includes(value.view)
		)
			ctx.addIssue({
				code: "custom",
				message: "applicationSection is only for application workflows",
			});
		if (Buffer.byteLength(JSON.stringify(value.applicationTrace ?? {})) > 16384)
			ctx.addIssue({
				code: "custom",
				message: "Application trace request exceeds byte budget",
			});
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
		"artifact-metadata": "records",
		"bundle-recovery": "modules",
		"source-acquisition": "sources",
		"source-containers": "containers",
		"application-nodes": "nodes",
		"application-edges": "edges",
		"semantic-nodes": "nodes",
		"semantic-relations": "relations",
		"semantic-unknowns": "unknowns",
		"semantic-fingerprints": "fingerprints",
		"semantic-contexts": "evidence_contexts",
	};
	const key =
		input.view === "electron-fuses"
			? (input.fuseSection ?? "slices")
			: input.view === "semantic-trace"
				? input.traceSection
				: input.view === "application-trace"
					? (input.applicationSection ?? "nodes")
					: input.view === "application-comparison" ||
							input.view === "application-source-bundle"
						? (input.applicationSection ?? "items")
						: input.view === "application-exports"
							? (input.applicationSection ?? "changes")
							: keys[input.view];
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
						edge_id: identity.edge_id,
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
