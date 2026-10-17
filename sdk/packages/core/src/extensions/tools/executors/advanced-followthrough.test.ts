import { mkdtemp, writeFile, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { it, expect } from "vitest";
import { createReverseEngineeringExecutor } from "./reverse-engineering";
import { ReverseEngineeringInputSchema } from "../schemas";
import { candidateHash } from "./candidate-files";

it("routes schema-parsed multi-edit preview/apply and read-only audit through the real executor", async () => {
	const root = await mkdtemp(join(tmpdir(), "cline-followthrough-"));
	try {
		const original = Buffer.from([0, 1, 2, 3]);
		const source = join(root, "owned.bin"),
			output = join(root, "candidate.bin"),
			manifest = join(root, "manifest.json");
		await writeFile(source, original);
		const candidate = {
			expected_sha256: candidateHash(original),
			byte_patches: [
				{ offset: 0, expected_hex: "00", replacement_hex: "aa" },
				{ offset: 3, expected_hex: "03", replacement_hex: "bb" },
			],
		};
		await writeFile(
			manifest,
			JSON.stringify({
				schemaVersion: 1,
				stages: [
					{
						id: "owned",
						operation: "patch_binary",
						target: "owned.bin",
						output_file: "candidate.bin",
						candidate,
					},
				],
			}),
		);
		const execute = createReverseEngineeringExecutor();
		const run = async (input: unknown) =>
			JSON.parse(
				await execute(ReverseEngineeringInputSchema.parse(input), {} as never),
			);
		const preview = await run({
			operation: "preview_candidate_batch",
			target: manifest,
		});
		await run({
			operation: "apply_candidate_batch",
			target: manifest,
			batch_preview_sha256: preview.batchPreviewSha256,
		});
		const files = await readdir(root);
		const audit = await run({
			operation: "audit_candidate_batch",
			target: manifest,
		});
		expect(audit.status).toBe("completed");
		expect(audit.verifiedStageIds).toEqual(["owned"]);
		expect(audit.published).toBe(false);
		expect(await readdir(root)).toEqual(files);
		expect(await readFile(source)).toEqual(original);
		expect(await readFile(output)).toEqual(Buffer.from([0xaa, 1, 2, 0xbb]));
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
it("routes declared source/sink evidence and binds returned receipt to exact report bytes", async () => {
	const root = await mkdtemp(join(tmpdir(), "cline-witness-"));
	try {
		const target = join(root, "graph.json"),
			h = "a".repeat(64);
		const bytes = Buffer.from(
			JSON.stringify({
				schemaVersion: 1,
				nodes: ["a", "b"].map((id) => ({
					id,
					kind: "native-symbol",
					label: id,
					artifactSha256: h,
					confidence: "candidate",
					evidenceIndex: 0,
				})),
				edges: [
					{
						source: "a",
						target: "b",
						relation: "references-candidate",
						confidence: "candidate",
					},
				],
				sourceHashes: [h],
				coverage: ["owned"],
			}),
		);
		await writeFile(target, bytes);
		const execute = createReverseEngineeringExecutor();
		const result = JSON.parse(
			await execute(
				ReverseEngineeringInputSchema.parse({
					operation: "trace_source_sink",
					target,
					source_sink: {
						source_ids: ["a"],
						sink_ids: ["b"],
						relation: "declared-relationships",
					},
				}),
				{} as never,
			),
		);
		expect(result.witnesses[0].route).toEqual(["a", "b"]);
		expect(result.inputSha256).toBe(candidateHash(bytes));
		expect(result.observedExecution).toBe(false);
		expect(await readdir(root)).toEqual(["graph.json"]);
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
