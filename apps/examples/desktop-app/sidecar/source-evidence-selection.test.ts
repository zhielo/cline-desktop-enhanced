import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { type AnalysisReceipt, digest } from "@cline/core";
import { afterEach, beforeEach, expect, it } from "vitest";
import { selectSourceEvidence } from "./source-evidence-selection";

let root: string;
const receiptId = "00000000-0000-4000-8000-000000000001",
	factId = `ev_${"a".repeat(64)}`;
const source = 'const value = "owned";\nfetch(value);\n';
const hash = (text: string) => createHash("sha256").update(text).digest("hex");
let receipt: AnalysisReceipt;
const scope = () => ({ sessionId: "owning-session", workspace: root });
const request = () => ({ receiptId, selector: { kind: "fact", factId } });
const load = () => receipt;
function seal() {
	receipt.resultHash = digest(receipt.result);
}
beforeEach(async () => {
	root = realpathSync(
		await mkdtemp(path.join(tmpdir(), "cline-source-selection-")),
	);
	await writeFile(path.join(root, "owned.ts"), source);
	receipt = {
		id: receiptId,
		sessionId: "owning-session",
		workspace: root,
		profile: "cline-js-static/7",
		input: { target: "owned.ts" },
		requestHash: "b".repeat(64),
		createdAt: new Date().toISOString(),
		status: "completed",
		result: {
			profile: "cline-js-static/7",
			parserVersion: "5.9.3",
			status: "completed",
			artifacts: [
				{
					path: "owned.ts",
					sha256: hash(source),
					bytes: Buffer.byteLength(source),
					role: "source",
				},
			],
			facts: [
				{
					id: factId,
					kind: "call",
					value: "fetch",
					confidence: "observed",
					authority: "shipped-artifact",
					location: {
						path: "owned.ts",
						sha256: hash(source),
						line: 2,
						column: 1,
					},
					limitations: [],
				},
			],
			edges: [],
			limitations: [],
			counters: { entries: 1, bytes: Buffer.byteLength(source), nodes: 1 },
		},
	};
	seal();
});
afterEach(async () => {
	await rm(root, { recursive: true, force: true });
});
it("resolves the exact saved source and coordinates without evaluating target code", async () => {
	await writeFile(
		path.join(root, "owned.ts"),
		'throw new Error("NEVER_EXECUTE");',
	);
	receipt.result!.artifacts[0]!.sha256 = hash(
		'throw new Error("NEVER_EXECUTE");',
	);
	receipt.result!.facts[0]!.location = {
		path: "owned.ts",
		sha256: receipt.result!.artifacts[0]!.sha256,
		line: 1,
		column: 1,
	};
	seal();
	const r = await selectSourceEvidence(request(), scope(), load);
	expect(r).toMatchObject({
		status: "matched",
		receiptId,
		sessionId: "owning-session",
		factId,
		location: { line: 1, column: 1 },
		expectedSha256: receipt.result!.artifacts[0]!.sha256,
		requestHash: receipt.requestHash,
		resultHash: receipt.resultHash,
	});
	expect(r.preview?.lines[0]?.text).toContain("NEVER_EXECUTE");
	expect(r.note).toContain("not continuous freshness");
});
it("selects an exact saved artifact without inventing a fact coordinate", async () => {
	const r = await selectSourceEvidence(
		{ receiptId, selector: { kind: "artifact", path: "owned.ts" } },
		scope(),
		load,
	);
	expect(r.status).toBe("matched");
	expect(r.location).toBeUndefined();
	expect(r.factId).toBeUndefined();
});
it("retains saved identity but withholds a preview after bytes change", async () => {
	await writeFile(
		path.join(root, "owned.ts"),
		'const secret = "CURRENT_NOT_SAVED";',
	);
	const r = await selectSourceEvidence(request(), scope(), load);
	expect(r.status).toBe("stale");
	expect(r.preview).toBeUndefined();
	expect(r.expectedSha256).toBe(hash(source));
	expect(JSON.stringify(r)).not.toContain("CURRENT_NOT_SAVED");
	expect(r).not.toHaveProperty("currentSha256");
});
it("reports missing source without deleting retained evidence", async () => {
	await rm(path.join(root, "owned.ts"));
	const before = JSON.stringify(receipt);
	expect((await selectSourceEvidence(request(), scope(), load)).status).toBe(
		"missing",
	);
	expect(JSON.stringify(receipt)).toBe(before);
});
it.each([
	"session",
	"workspace",
	"receipt",
	"integrity",
	"running",
])("rejects mismatched %s authority or integrity", async (kind) => {
	if (kind === "session") receipt.sessionId = "other";
	if (kind === "workspace") receipt.workspace = path.dirname(root);
	if (kind === "receipt") receipt.id = "00000000-0000-4000-8000-000000000002";
	if (kind === "integrity")
		receipt.result!.artifacts[0]!.sha256 = "f".repeat(64);
	if (kind === "running") receipt.status = "running";
	await expect(
		selectSourceEvidence(request(), scope(), load),
	).rejects.toThrow();
});
it("does not accept caller-supplied paths, hashes, shell options or unknown fact IDs", async () => {
	for (const extra of [
		{ path: "/etc/passwd" },
		{ expectedSha256: hash(source) },
		{ execute: true },
		{ command: "echo no" },
	])
		await expect(
			selectSourceEvidence({ ...request(), ...extra }, scope(), load),
		).rejects.toThrow();
	await expect(
		selectSourceEvidence(
			{ receiptId, selector: { kind: "fact", factId: `ev_${"c".repeat(64)}` } },
			scope(),
			load,
		),
	).rejects.toThrow("missing");
	await expect(
		selectSourceEvidence(
			{ receiptId, selector: { kind: "artifact", path: "not-saved.ts" } },
			scope(),
			load,
		),
	).rejects.toThrow("missing");
});
it.each([
	"../outside.ts",
	"/outside.ts",
	"nested/../owned.ts",
	"C:/outside.ts",
	"nested\\owned.ts",
])("blocks unsafe saved path %s", async (name) => {
	receipt.result!.facts[0]!.location.path = name;
	receipt.result!.artifacts[0]!.path = name;
	seal();
	expect((await selectSourceEvidence(request(), scope(), load)).status).toBe(
		"blocked",
	);
});
it("rejects ambiguous facts and artifacts and inconsistent saved hashes", async () => {
	receipt.result!.facts.push({ ...receipt.result!.facts[0]! });
	seal();
	await expect(selectSourceEvidence(request(), scope(), load)).rejects.toThrow(
		"ambiguous",
	);
	receipt.result!.facts.pop();
	receipt.result!.artifacts.push({ ...receipt.result!.artifacts[0]! });
	seal();
	await expect(selectSourceEvidence(request(), scope(), load)).rejects.toThrow(
		"ambiguous",
	);
	receipt.result!.artifacts.pop();
	receipt.result!.facts[0]!.location.sha256 = "f".repeat(64);
	seal();
	await expect(selectSourceEvidence(request(), scope(), load)).rejects.toThrow(
		"inconsistent",
	);
});
it("does not follow directory links even within the workspace", async () => {
	await mkdir(path.join(root, "real"));
	await writeFile(path.join(root, "real", "owned.ts"), source);
	await symlink(
		path.join(root, "real"),
		path.join(root, "linked"),
		process.platform === "win32" ? "junction" : "dir",
	);
	receipt.result!.artifacts[0]!.path = "linked/owned.ts";
	receipt.result!.facts[0]!.location.path = "linked/owned.ts";
	seal();
	expect((await selectSourceEvidence(request(), scope(), load)).status).toBe(
		"blocked",
	);
});
it.each([
	"app.asar!/owned.ts",
	"library.dll",
])("reports unsupported virtual or binary artifact %s without reading it", async (name) => {
	receipt.result!.artifacts[0]!.path = name;
	receipt.result!.facts[0]!.location.path = name;
	seal();
	expect((await selectSourceEvidence(request(), scope(), load)).status).toBe(
		"unsupported",
	);
});
it("enforces byte and preview budgets", async () => {
	await writeFile(path.join(root, "owned.ts"), "x".repeat(1024 * 1024 + 1));
	expect((await selectSourceEvidence(request(), scope(), load)).status).toBe(
		"unsupported",
	);
	const large = Array.from({ length: 30 }, () => "x".repeat(1500)).join("\n");
	await writeFile(path.join(root, "owned.ts"), large);
	receipt.result!.artifacts[0]!.sha256 = hash(large);
	receipt.result!.facts[0]!.location.sha256 = hash(large);
	receipt.result!.facts[0]!.location.line = 15;
	seal();
	const r = await selectSourceEvidence(request(), scope(), load);
	expect(r.preview?.lines).toHaveLength(9);
	expect(r.preview?.truncated).toBe(true);
	expect(r.preview?.lines.every((l) => l.text.length <= 1000)).toBe(true);
});
it("never substitutes approximate locations and can display partial static evidence honestly", async () => {
	receipt.result!.facts[0]!.location.line = 100;
	seal();
	expect((await selectSourceEvidence(request(), scope(), load)).status).toBe(
		"unavailable",
	);
	receipt.result!.facts[0]!.location = {
		path: "owned.ts",
		sha256: hash(source),
		line: 2,
		column: 1,
	};
	receipt.status = "partial";
	receipt.result!.status = "partial";
	seal();
	expect((await selectSourceEvidence(request(), scope(), load)).status).toBe(
		"matched",
	);
});

it("preserves BOM and UTF-16 columns and recognizes TypeScript Unicode line breaks", async () => {
	const text = "\ufeffconst emoji = '😀';\u2028fetch(emoji);\u2029done();";
	await writeFile(path.join(root, "owned.ts"), text);
	receipt.result!.artifacts[0]!.sha256 = hash(text);
	receipt.result!.facts[0]!.location = {
		path: "owned.ts",
		sha256: hash(text),
		line: 2,
		column: 1,
	};
	seal();
	const r = await selectSourceEvidence(request(), scope(), load);
	expect(r.status).toBe("matched");
	expect(r.preview?.lines).toEqual([
		{ line: 1, text: "\ufeffconst emoji = '😀';", truncated: false },
		{ line: 2, text: "fetch(emoji);", truncated: false },
		{ line: 3, text: "done();", truncated: false },
	]);
});
it("withholds invalid UTF-8 and NUL-bearing source even when hashes match", async () => {
	for (const bytes of [
		Buffer.from([0xc3, 0x28]),
		Buffer.from("const x = 1;\0"),
	]) {
		await writeFile(path.join(root, "owned.ts"), bytes);
		const sha = createHash("sha256").update(bytes).digest("hex");
		receipt.result!.artifacts[0]!.sha256 = sha;
		receipt.result!.facts[0]!.location.sha256 = sha;
		seal();
		const r = await selectSourceEvidence(request(), scope(), load);
		expect(r.status).toBe("unsupported");
		expect(r.preview).toBeUndefined();
	}
});

it("rejects a directory carrying a supported source suffix before opening it", async () => {
	await rm(path.join(root, "owned.ts"));
	await mkdir(path.join(root, "owned.ts"));
	const r = await selectSourceEvidence(request(), scope(), load);
	expect(r.status).toBe("unsupported");
	expect(r.preview).toBeUndefined();
});
