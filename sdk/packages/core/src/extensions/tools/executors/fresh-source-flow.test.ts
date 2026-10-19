import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, expect, it } from "vitest";
import { createReverseEngineeringExecutor } from "./reverse-engineering";
import { ReverseEngineeringInputSchema } from "../schemas";
const roots: string[] = [];
afterEach(async () => {
	for (const root of roots) await rm(root, { recursive: true, force: true });
	roots.length = 0;
});
async function fixture(
	source = 'const url = "https://example.invalid/owned";\nfetch(url);\n',
) {
	const root = await mkdtemp(join(tmpdir(), "fresh-source-flow-"));
	roots.push(root);
	const target = join(root, "owned.ts");
	await writeFile(target, source);
	const execute = createReverseEngineeringExecutor();
	const call = (input: Record<string, unknown>) =>
		execute(ReverseEngineeringInputSchema.parse(input), {
			sessionId: "owned",
			agentId: "owned",
			iteration: 0,
			toolCallId: "fixture",
		}).then(JSON.parse);
	return {
		target,
		call,
		source_flow: {
			kind: "js-ts",
			start: { path: "owned.ts", line: 1, column: 7, kind: "configuration" },
			end: { path: "owned.ts", line: 2, column: 1, kind: "resolved-endpoint" },
		},
	};
}
it("derives fresh exact constant-to-fetch edges without executing source", async () => {
	const f = await fixture(),
		result = await f.call({
			operation: "trace_data_flow",
			target: f.target,
			source_flow: f.source_flow,
		});
	expect(result.status).toBe("partial");
	expect(result.mode).toBe("fresh-js-ts-constant-endpoint-flow");
	expect(result.observedExecution).toBe(false);
	expect(result.endpointReachableInSelectedGraph).toBe(true);
	expect(result.edges).toHaveLength(1);
	expect(result.route).toHaveLength(2);
	expect(result.artifacts[0].sha256).toMatch(/^[a-f0-9]{64}$/);
	expect(result.nodes[0].provenance.location).toMatchObject({
		path: "owned.ts",
		line: 1,
		column: 7,
	});
});
it("does not invent a relationship for mutable state or a shadowed fetch", async () => {
	for (const source of [
		'let url = "https://example.invalid/owned";\nfetch(url);',
		'const url = "https://example.invalid/owned";\nfunction fetch(x:unknown){}; fetch(url);',
	]) {
		const f = await fixture(source);
		await expect(
			f.call({
				operation: "trace_data_flow",
				target: f.target,
				source_flow: f.source_flow,
			}),
		).rejects.toThrow("exact source-flow fact");
	}
});
it("rejects mixed modes, wrong command, inaccurate location and selector authority", async () => {
	const f = await fixture();
	await expect(
		f.call({
			operation: "trace_data_flow",
			target: f.target,
			source_flow: f.source_flow,
			evidence_trace: { start_id: "invented" },
		}),
	).rejects.toThrow("rejects imported");
	await expect(
		f.call({
			operation: "inspect",
			target: f.target,
			source_flow: f.source_flow,
		}),
	).rejects.toThrow("only by trace_data_flow");
	await expect(
		f.call({
			operation: "trace_data_flow",
			target: f.target,
			source_flow: {
				...f.source_flow,
				start: { ...f.source_flow.start, line: 3 },
			},
		}),
	).rejects.toThrow("exact source-flow fact");
	expect(
		ReverseEngineeringInputSchema.safeParse({
			operation: "trace_data_flow",
			target: f.target,
			source_flow: { ...f.source_flow, execute: true },
		}).success,
	).toBe(false);
});
it("reports bounded traversal without turning partial source coverage into a pass", async () => {
	const f = await fixture();
	const result = await f.call({
		operation: "trace_data_flow",
		target: f.target,
		source_flow: { ...f.source_flow, max_nodes: 1 },
	});
	expect(result.status).toBe("partial");
	expect(result.truncated).toBe(true);
	expect(result.endpointReachableInSelectedGraph).toBe(false);
});
