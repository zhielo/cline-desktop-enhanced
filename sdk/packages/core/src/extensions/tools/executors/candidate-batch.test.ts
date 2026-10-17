import { mkdtemp, writeFile, readFile, rm, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { beforeEach, afterEach, it, expect, vi } from "vitest";
import { candidateBatch } from "./candidate-batch";
import { candidateHash } from "./candidate-files";
let root: string, target: string;
beforeEach(async () => {
	root = await mkdtemp(join(tmpdir(), "cline-candidate-batch-"));
	target = join(root, "manifest.json");
	await writeFile(join(root, "a.bin"), Buffer.from([0, 1]));
	await writeFile(join(root, "b.bin"), Buffer.from([0, 1]));
});
afterEach(async () => {
	vi.restoreAllMocks();
	await rm(root, { recursive: true, force: true });
});
const stage = (id: string) => ({
	id,
	operation: "patch_binary",
	target: `${id}.bin`,
	output_file: `${id}.candidate.bin`,
	candidate: {
		expected_sha256: candidateHash(Buffer.from([0, 1])),
		byte_patch: { offset: 1, expected_hex: "01", replacement_hex: "02" },
	},
});
async function manifest(stages: unknown[] = [stage("a"), stage("b")]) {
	await writeFile(target, JSON.stringify({ schemaVersion: 1, stages }));
}
it("previews all independent stages then applies exact whole-batch approval", async () => {
	await manifest();
	const p = await candidateBatch({
		operation: "preview_candidate_batch",
		target,
	});
	expect(p.status).toBe("completed");
	expect(existsSync(join(root, "a.candidate.bin"))).toBe(false);
	const a = await candidateBatch({
		operation: "apply_candidate_batch",
		target,
		batch_preview_sha256: p.batchPreviewSha256,
	});
	expect(a.status).toBe("completed");
	expect(a.results).toHaveLength(2);
	expect(await readFile(join(root, "a.bin"))).toEqual(Buffer.from([0, 1]));
	expect(await readFile(join(root, "a.candidate.bin"))).toEqual(
		Buffer.from([0, 2]),
	);
	await expect(
		candidateBatch({
			operation: "apply_candidate_batch",
			target,
			batch_preview_sha256: p.batchPreviewSha256,
		}),
	).rejects.toThrow("exists");
});
it("preflights every source before publishing any output", async () => {
	await manifest();
	await writeFile(join(root, "b.bin"), "changed");
	await expect(
		candidateBatch({ operation: "preview_candidate_batch", target }),
	).rejects.toThrow("SHA256");
	expect(existsSync(join(root, "a.candidate.bin"))).toBe(false);
});
it("requires matching manifest/preview hash and never autoexecutes", async () => {
	await manifest();
	const p = await candidateBatch({
		operation: "preview_candidate_batch",
		target,
	});
	await expect(
		candidateBatch({ operation: "apply_candidate_batch", target }),
	).rejects.toThrow("batch_preview_sha256");
	await writeFile(target, (await readFile(target, "utf8")) + " ");
	await expect(
		candidateBatch({
			operation: "apply_candidate_batch",
			target,
			batch_preview_sha256: p.batchPreviewSha256,
		}),
	).rejects.toThrow("batch_preview_sha256");
	expect(existsSync(join(root, "a.candidate.bin"))).toBe(false);
});
it.each(
	[
		[{ ...stage("a"), target: "../escape.bin" }],
		[{ ...stage("a"), output_file: "../escape.bin" }],
		[stage("a"), stage("a")],
		[stage("a"), { ...stage("b"), target: "a.candidate.bin" }],
		[{ ...stage("a"), output_file: "manifest.json" }],
		[{ ...stage("a"), operation: "sign_apk" }],
		[...Array.from({ length: 9 }, (_, i) => stage(`n${i}`))],
	].map((stages) => ({ stages })),
)("rejects escape, duplicate, dependency substitution and arbitrary batches", async ({
	stages,
}) => {
	await manifest(stages);
	await expect(
		candidateBatch({ operation: "preview_candidate_batch", target }),
	).rejects.toThrow();
});
it("returns truthful partial publications on cancellation between stages", async () => {
	await manifest();
	const p = await candidateBatch({
		operation: "preview_candidate_batch",
		target,
	});
	const c = new AbortController();
	const original = c.signal.throwIfAborted.bind(c.signal);
	vi.spyOn(c.signal, "throwIfAborted").mockImplementation(() => {
		if (existsSync(join(root, "a.candidate.bin"))) c.abort();
		original();
	});
	const result = await candidateBatch(
		{
			operation: "apply_candidate_batch",
			target,
			batch_preview_sha256: p.batchPreviewSha256,
		},
		c.signal,
	);
	expect(result.status).toBe("cancelled");
	expect(result.results?.[0]).toMatchObject({ id: "a", status: "completed" });
	expect(result.results?.[1]).toMatchObject({ id: "b", status: "cancelled" });
	expect(existsSync(join(root, "a.candidate.bin"))).toBe(true);
	await expect(stat(join(root, "b.candidate.bin"))).rejects.toThrow();
});

it("audits existing exact outputs without replaying or requiring a publication preview", async () => {
	await manifest();
	let audit = await candidateBatch({
		operation: "audit_candidate_batch",
		target,
	});
	expect(audit.remainingStageIds).toEqual(["a", "b"]);
	expect(audit.published).toBe(false);
	const p = await candidateBatch({
		operation: "preview_candidate_batch",
		target,
	});
	await candidateBatch({
		operation: "apply_candidate_batch",
		target,
		batch_preview_sha256: p.batchPreviewSha256,
	});
	const before = (await stat(join(root, "a.candidate.bin"))).mtimeMs;
	audit = await candidateBatch({ operation: "audit_candidate_batch", target });
	expect(audit.status).toBe("completed");
	expect(audit.verifiedStageIds).toEqual(["a", "b"]);
	expect(audit.results?.[0]).toMatchObject({
		status: "verified",
		sourcePreserved: true,
	});
	expect((await stat(join(root, "a.candidate.bin"))).mtimeMs).toBe(before);
});
it("blocks recovery recommendations on changed outputs or originals", async () => {
	await manifest();
	await writeFile(join(root, "a.candidate.bin"), "mismatch");
	let audit = await candidateBatch({
		operation: "audit_candidate_batch",
		target,
	});
	expect(audit.recoveryBlocked).toBe(true);
	expect(audit.remainingStageIds).toEqual([]);
	expect(audit.results?.[0].status).toBe("mismatch");
	await rm(join(root, "a.candidate.bin"));
	await writeFile(join(root, "a.bin"), "changed");
	audit = await candidateBatch({ operation: "audit_candidate_batch", target });
	expect(audit.results?.[0]).toMatchObject({
		status: "unverified",
		sourcePreserved: null,
	});
	expect(audit.recoveryBlocked).toBe(true);
});
it("audits a partial batch and proposes only missing stage IDs without writing", async () => {
	await manifest();
	await writeFile(join(root, "a.candidate.bin"), Buffer.from([0, 2]));
	const audit = await candidateBatch({
		operation: "audit_candidate_batch",
		target,
	});
	expect(audit.verifiedStageIds).toEqual(["a"]);
	expect(audit.remainingStageIds).toEqual(["b"]);
	expect(audit.recoveryBlocked).toBe(false);
	expect(existsSync(join(root, "b.candidate.bin"))).toBe(false);
});
it("does not interpret arbitrary command names as candidate apply", async () => {
	await manifest();
	await expect(
		candidateBatch({ operation: "replay_everything", target }),
	).rejects.toThrow("Unknown");
});
