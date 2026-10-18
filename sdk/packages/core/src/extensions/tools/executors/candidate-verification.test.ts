import { mkdtemp, readFile, writeFile, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import { canonical } from "../../../analysis/contracts";
import { InvestigationSchemas } from "../investigation";
import { ReverseEngineeringInputSchema } from "../schemas";
import { candidateHash } from "./candidate-files";
import { verifyCandidate, validateDexBytes } from "./candidate-verification";
import { createReverseEngineeringExecutor } from "./reverse-engineering";
const roots: string[] = [];
afterEach(async () => {
	await Promise.all(
		roots.splice(0).map((p) => rm(p, { recursive: true, force: true })),
	);
});
async function fixture(text = "export function owned(){return 1;}") {
	const root = await mkdtemp(join(tmpdir(), "candidate-validation-"));
	roots.push(root);
	const target = join(root, "owned.ts");
	await writeFile(target, text);
	return { root, target, text };
}
const request = (target: string, bytes: string | Buffer, kind = "typescript") =>
	ReverseEngineeringInputSchema.parse({
		operation: "validate_candidate",
		target,
		candidate_validation: { kind, expected_sha256: candidateHash(bytes) },
	});
async function execute(input: unknown) {
	return JSON.parse(
		await createReverseEngineeringExecutor()(
			ReverseEngineeringInputSchema.parse(input),
			{} as never,
		),
	);
}
it("validates immutable source syntax without evaluating code, returns reproducible receipt integrity", async () => {
	const { target, text } = await fixture(
		"globalThis.__candidateExecuted=true; export function owned(){return 1;}",
	);
	const runner = vi.fn();
	const result = await verifyCandidate(request(target, text), runner);
	expect(result.status).toBe("completed");
	expect(result.published).toBe(false);
	expect(result.observedExecution).toBe(false);
	expect(runner).not.toHaveBeenCalled();
	const { receiptSha256, ...receipt } = result;
	expect(receiptSha256).toBe(candidateHash(canonical(receipt)));
	expect(
		(globalThis as Record<string, unknown>).__candidateExecuted,
	).toBeUndefined();
	expect(await readFile(target, "utf8")).toBe(text);
	expect((await execute(request(target, text))).inputSha256).toBe(
		candidateHash(text),
	);
});
it("syntax failure is failed, not a completed target validation", async () => {
	const { target, text } = await fixture("export function broken( {");
	const result = await verifyCandidate(request(target, text), vi.fn());
	expect(result.status).toBe("failed");
	expect(result.checks[0].status).toBe("failed");
	expect(result.checks[0].diagnosticCount).toBeGreaterThan(0);
});
it("rejects stale hashes, invalid UTF8, oversized source and symbolic links", async () => {
	const { root, target, text } = await fixture();
	await expect(
		verifyCandidate(request(target, "stale"), vi.fn()),
	).rejects.toThrow("hash changed");
	await writeFile(target, Buffer.from([255]));
	await expect(
		verifyCandidate(request(target, Buffer.from([255])), vi.fn()),
	).rejects.toThrow();
	const big = " ".repeat(1024 * 1024 + 1);
	await writeFile(target, big);
	await expect(verifyCandidate(request(target, big), vi.fn())).rejects.toThrow(
		"1 MiB",
	);
	await writeFile(target, text);
	const link = join(root, "link.ts");
	await symlink(target, link);
	await expect(verifyCandidate(request(link, text), vi.fn())).rejects.toThrow(
		"symbolic link",
	);
});
function dex() {
	const b = Buffer.alloc(112);
	b.write("dex\n035\0", 0, "binary");
	b.writeUInt32LE(112, 32);
	b.writeUInt32LE(112, 36);
	b.writeUInt32LE(0x12345678, 40);
	return seal(b);
}
function seal(b: Buffer) {
	createHash("sha1").update(b.subarray(32)).digest().copy(b, 12);
	let a = 1,
		c = 0;
	for (const v of b.subarray(12)) {
		a = (a + v) % 65521;
		c = (c + a) % 65521;
	}
	b.writeUInt32LE(((c << 16) | a) >>> 0, 8);
	return b;
}
it("checks DEX integrity and declared extents; explicitly no ART validation", async () => {
	const { target } = await fixture();
	const b = dex();
	validateDexBytes(b);
	await writeFile(target, b);
	expect(
		(await verifyCandidate(request(target, b, "dex"), vi.fn())).status,
	).toBe("completed");
	for (const mutate of [
		(x: Buffer) => x.writeUInt32LE(1, 56),
		(x: Buffer) => x.writeUInt32LE(200, 52),
		(x: Buffer) => x.writeUInt32LE(4, 104),
	]) {
		const bad = Buffer.from(b);
		mutate(bad);
		seal(bad);
		expect(() => validateDexBytes(bad)).toThrow();
	}
	const bad = Buffer.from(b);
	bad[12] ^= 1;
	await writeFile(target, bad);
	const r = await verifyCandidate(request(target, bad, "dex"), vi.fn());
	expect(r.status).toBe("failed");
	expect(r.limitations.join(" ")).toContain("not full map");
});
it("APK validation uses only fixed read operations and keeps negative signature status", async () => {
	const { target, text } = await fixture();
	const run = vi.fn(async (r) =>
		r.operation === "inspect"
			? {
					sha256: candidateHash(text),
					kind: "apk",
					android: { hasManifest: true },
					archive: { extractionRecommended: true },
				}
			: { sha256: candidateHash(text), verified: false },
	);
	const r = await verifyCandidate(request(target, text, "apk"), run);
	expect(r.status).toBe("failed");
	expect(run.mock.calls.map(([r]) => r.operation)).toEqual([
		"inspect",
		"verify_apk_signature",
	]);
});
it("missing APK verifier, generic ZIP or malformed structure cannot pass", async () => {
	const { target, text } = await fixture();
	const run = vi.fn(async (r) => {
		if (r.operation === "verify_apk_signature") throw new Error("unavailable");
		return { sha256: candidateHash(text), kind: "zip" };
	});
	const r = await verifyCandidate(request(target, text, "apk"), run);
	expect(r.status).toBe("failed");
	expect(r.checks[1].status).toBe("blocked");
});
it("rejects mid-check mutation, cancellation, write fields and authority smuggling", async () => {
	const { target, text } = await fixture();
	const run = vi.fn(async () => {
		await writeFile(target, "changed");
		return { verified: true, sha256: candidateHash(text) };
	});
	await expect(
		verifyCandidate(request(target, text, "apk"), run),
	).rejects.toThrow("changed during");
	const c = new AbortController();
	c.abort();
	await expect(
		verifyCandidate(request(target, "changed"), vi.fn(), c.signal),
	).rejects.toThrow();
	await expect(
		verifyCandidate(
			{ ...request(target, "changed"), output_file: join(target, "out") },
			vi.fn(),
		),
	).rejects.toThrow("no writes");
	for (const name of [
		"validate_candidate",
		"review_candidate_changes",
	] as const)
		expect(() =>
			InvestigationSchemas[name].parse({
				artifactId: "11111111-1111-4111-8111-111111111111",
				executionToken: "fake",
			}),
		).toThrow();
});
it("reviews exact declared recipe outputs; mismatch, missing, source mutation and manifest hash cannot pass", async () => {
	const { root, target, text } = await fixture("export const value=1;");
	const manifest = join(root, "manifest.json"),
		output = join(root, "candidate.ts");
	const body = JSON.stringify({
		schemaVersion: 1,
		stages: [
			{
				id: "source",
				operation: "apply_ast_transform",
				target: "owned.ts",
				output_file: "candidate.ts",
				candidate: {
					expected_sha256: candidateHash(text),
					literal: {
						start: text.indexOf("1"),
						expected: "1",
						replacement: "2",
					},
				},
			},
		],
	});
	await writeFile(manifest, body);
	const req = ReverseEngineeringInputSchema.parse({
		operation: "review_candidate_changes",
		target: manifest,
		candidate_review: { manifest_sha256: candidateHash(body) },
	});
	expect((await execute(req)).status).toBe("partial");
	await writeFile(output, text.replace("1", "2"));
	const pass = await execute(req);
	expect(pass.status).toBe("completed");
	expect(pass.checks[0].verifiedStageIds).toEqual(["source"]);
	expect(pass.limitations.join(" ")).toContain(
		"whole-project changes are NOT reviewed",
	);
	await writeFile(output, "unexpected");
	expect((await execute(req)).status).toBe("failed");
	await writeFile(target, "changed");
	expect((await execute(req)).status).toBe("failed");
	await writeFile(manifest, body + " ");
	await expect(execute(req)).rejects.toThrow("manifest hash changed");
});
it("rejects manifests escaping their directory and operation-specific option confusion", async () => {
	const { root, target, text } = await fixture();
	const manifest = join(root, "manifest.json");
	const body = JSON.stringify({
		schemaVersion: 1,
		stages: [
			{
				id: "escape",
				operation: "apply_ast_transform",
				target: "../outside.ts",
				output_file: "candidate.ts",
				candidate: {
					expected_sha256: candidateHash(text),
					literal: { start: 0, expected: "1", replacement: "2" },
				},
			},
		],
	});
	await writeFile(manifest, body);
	await expect(
		execute({
			operation: "review_candidate_changes",
			target: manifest,
			candidate_review: { manifest_sha256: candidateHash(body) },
		}),
	).rejects.toThrow("escapes");
	await expect(
		execute({ ...request(target, text), operation: "inspect" }),
	).rejects.toThrow("only accepted");
});

it("negative engine outcome overrides contradictory positive evidence", async () => {
	const { target, text } = await fixture();
	const run = vi.fn(async () => ({
		sha256: candidateHash(text),
		kind: "apk",
		android: { hasManifest: true },
		archive: { extractionRecommended: true },
		verified: true,
		status: "failed",
	}));
	expect(
		(await verifyCandidate(request(target, text, "apk"), run)).status,
	).toBe("failed");
});
it("unavailable signature check alone remains partial and oversized diagnostics stay bounded", async () => {
	const { target, text } = await fixture();
	const run = vi.fn(async (r) => {
		if (r.operation === "verify_apk_signature") throw new Error("missing");
		return {
			sha256: candidateHash(text),
			kind: "apk",
			android: { hasManifest: true },
			archive: { extractionRecommended: true },
			detail: "x".repeat(150000),
		};
	});
	const result = await verifyCandidate(request(target, text, "apk"), run);
	expect(result.status).toBe("partial");
	expect(result.checks[0].result).toMatchObject({ truncated: true });
	expect(JSON.stringify(result).length).toBeLessThan(10000);
});

it("JavaScript syntax rejects TypeScript-only grammar and never resolves imports", async () => {
	const { target, text } = await fixture("const value: number = 1;");
	expect(
		(await verifyCandidate(request(target, text, "javascript"), vi.fn()))
			.status,
	).toBe("failed");
	const js =
		"import value from './not-resolved-or-loaded.js'; export const own = 1;";
	await writeFile(target, js);
	expect(
		(await verifyCandidate(request(target, js, "javascript"), vi.fn())).status,
	).toBe("completed");
});

it("project-files review binds complete inventories and rejects undeclared files without changing the recipe default",async()=>{
 const {root}=await fixture();const {mkdir}=await import("node:fs/promises"),{projectInventoryHash}=await import("./project-review");
 await mkdir(join(root,"before"));await mkdir(join(root,"after"));await writeFile(join(root,"before/a.ts"),"export const a=1;");await writeFile(join(root,"after/a.ts"),"export const a=2;");
 const before="export const a=1;",after="export const a=2;",body=JSON.stringify({protocol:"cline-project-review/v1",baseline:{directory:"before",inventory_sha256:projectInventoryHash([{path:"a.ts",bytes:Buffer.byteLength(before),sha256:candidateHash(before)}])},candidate:{directory:"after",inventory_sha256:projectInventoryHash([{path:"a.ts",bytes:Buffer.byteLength(after),sha256:candidateHash(after)}])},approved_changes:[{path:"a.ts",before_sha256:candidateHash(before),after_sha256:candidateHash(after)}]});
 const target=join(root,"project-review.json");await writeFile(target,body);
 const req={operation:"review_candidate_changes",target,candidate_review:{manifest_sha256:candidateHash(body),scope:"project-files"}};
 const pass=await execute(req);expect(pass.status).toBe("completed");expect(pass.checks[0]).toMatchObject({id:"full-project-file-scope",changedFiles:1,unexpectedChanges:0,passes:2});expect(pass.limitations.join(" ")).toContain("no ignore rules");
 const {receiptSha256,...receipt}=pass;expect(receiptSha256).toBe(candidateHash(canonical(receipt)));
 await writeFile(join(root,"after/undeclared"),"unexpected");await expect(execute(req)).rejects.toThrow("inventory fingerprint");
 for(const extra of [{url:"https://invalid.example"},{executionToken:"fake"},{ignore:["undeclared"]}])expect(()=>InvestigationSchemas.review_candidate_changes.parse({artifactId:"11111111-1111-4111-8111-111111111111",scope:"project-files",...extra})).toThrow();
 expect(await readFile(join(root,"before/a.ts"),"utf8")).toBe(before);
});

it("public inventory mode returns partial preview evidence, never a passing candidate",async()=>{
 const {root}=await fixture();const {mkdir}=await import("node:fs/promises");await mkdir(join(root,"before"));await mkdir(join(root,"after"));await writeFile(join(root,"after/owned.ts"),"owned");const body=JSON.stringify({protocol:"cline-project-inventory-request/v1",baseline_directory:"before",candidate_directory:"after"}),target=join(root,"inventory.json");await writeFile(target,body);
 const result=await execute({operation:"review_candidate_changes",target,candidate_review:{manifest_sha256:candidateHash(body),scope:"project-inventory"}});expect(result.status).toBe("partial");expect(result.checks[0]).toMatchObject({id:"full-project-file-inventory-draft",status:"previewed-not-approved",changedFiles:1,published:false});
});
