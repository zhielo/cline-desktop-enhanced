import {
	mkdtemp,
	mkdir,
	writeFile,
	rm,
	symlink,
	realpath,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, expect, it } from "vitest";
import { analyzeSources } from "./parser";
import { analyzeTarget } from "./worker";
import {
	byteDigest,
	digest,
	ANALYSIS_PROFILE,
	type AnalysisReceipt,
	type AnalysisResult,
} from "./contracts";
import { FirstPartyAnalysisStore } from "./store";
import { runFirstPartyAnalysis } from "./service";
import { queryFirstPartyEvidence } from "./index";
let root: string;
beforeEach(async () => {
	root = await realpath(
		await mkdtemp(join(tmpdir(), "cline-first-party-test-")),
	);
});
afterEach(async () => {
	await rm(root, { recursive: true, force: true });
});
const source = (path: string, text: string) => ({
	path,
	source: text,
	sha256: byteDigest(Buffer.from(text)),
	bytes: Buffer.byteLength(text),
});
const receipt = (id: string): AnalysisReceipt => ({
	id,
	sessionId: "s",
	workspace: root,
	status: "running",
	profile: ANALYSIS_PROFILE,
	input: { target: "." },
	requestHash: digest({ id }),
	createdAt: new Date().toISOString(),
});
it("maps literal modules, ES/CommonJS Electron IPC and preload candidates without execution", () => {
	const r = analyzeSources([
		source(
			"main.js",
			'import {ipcMain} from "electron";import "./helper";ipcMain.handle("sum",()=>42);',
		),
		source(
			"helper.js",
			'export function helper(){throw new Error("MUST_NOT_EXECUTE")}',
		),
		source(
			"preload.js",
			'const {ipcRenderer,contextBridge}=require("electron");contextBridge.exposeInMainWorld("api",{});ipcRenderer.invoke("sum");',
		),
	]);
	expect(r.edges.map((e) => e.kind)).toEqual(
		expect.arrayContaining(["imports", "ipc-candidate"]),
	);
	expect(r.facts.some((f) => f.kind === "preload-api")).toBe(true);
	expect(r.facts.every((f) => f.id.startsWith("ev_"))).toBe(true);
	expect(r.limitations.join(" ")).toContain("no complete alias analysis");
});
it("preserves unknown computed channels and rejects shadowed IPC/require", () => {
	for (const text of [
		'import {ipcMain} from "electron";function f(ipcMain){ipcMain.handle("fake",()=>1)}',
		'function require(x){return fake};const {ipcMain}=require("electron");ipcMain.handle("fake",()=>0)',
	])
		expect(
			analyzeSources([source("x.js", text)]).facts.some(
				(f) => f.kind === "ipc-handler",
			),
		).toBe(false);
	expect(
		analyzeSources([
			source(
				"x.js",
				'import {ipcRenderer} from "electron";ipcRenderer.invoke(name)',
			),
		]).facts.some((f) => f.kind === "dynamic"),
	).toBe(true);
});
it("uses deterministic hashes and marks malformed syntax partial", () => {
	const s = [source("x.ts", "export function f(){return 42}")];
	expect(analyzeSources(s)).toEqual(analyzeSources(s));
	expect(analyzeSources([source("bad.js", "function broken( {")]).status).toBe(
		"partial",
	);
});
it("never imports target source and inventories declared metadata", async () => {
	await writeFile(
		join(root, "x.js"),
		'throw new Error("TARGET_MUST_NOT_EXECUTE");',
	);
	await writeFile(join(root, "package.json"), '{"main":"x.js"}');
	const r = await analyzeTarget(root, { target: "." });
	expect(r.artifacts).toHaveLength(2);
	expect(r.facts.some((f) => f.kind === "entrypoint")).toBe(true);
});
it("rejects workspace escapes, oversized files and linked sources", async () => {
	await expect(analyzeTarget(root, { target: "../" })).rejects.toThrow(
		"workspace",
	);
	await writeFile(join(root, "big.js"), Buffer.alloc(1024 * 1024 + 1));
	expect((await analyzeTarget(root, { target: "big.js" })).status).toBe(
		"partial",
	);
	if (process.platform !== "win32") {
		await writeFile(join(root, "safe.js"), "const x=1");
		await symlink(join(root, "safe.js"), join(root, "link.js"));
		expect(
			(await analyzeTarget(root, { target: "." })).artifacts.map((s) => s.path),
		).toEqual(["safe.js"]);
	}
});
it("reads bounded ASAR payloads and rejects unsafe entry names", async () => {
	const make = (name: string) => {
		const data = Buffer.from("export const value=42;"),
			json = Buffer.from(
				JSON.stringify({
					files: { [name]: { size: data.length, offset: "0" } },
				}),
			);
		const padding = (4 - (json.length % 4)) % 4,
			headerSize = 8 + json.length + padding,
			header = Buffer.alloc(16 + json.length + padding);
		header.writeUInt32LE(4, 0);
		header.writeUInt32LE(headerSize, 4);
		header.writeUInt32LE(headerSize - 4, 8);
		header.writeUInt32LE(json.length, 12);
		json.copy(header, 16);
		return Buffer.concat([header, data]);
	};
	await writeFile(join(root, "app.asar"), make("main.js"));
	expect(
		(await analyzeTarget(root, { target: "app.asar" })).artifacts[0].path,
	).toBe("app.asar!/main.js");
	await writeFile(join(root, "bad.asar"), make("../evil.js"));
	const bad = await analyzeTarget(root, { target: "bad.asar" });
	expect(bad.status).toBe("partial");
	expect(bad.artifacts).toEqual([]);
});
it("compares relative source bytes without asserting behavior equivalence", async () => {
	await mkdir(join(root, "new"));
	await mkdir(join(root, "old"));
	await writeFile(join(root, "new", "x.js"), "const x=2");
	await writeFile(join(root, "old", "x.js"), "const x=1");
	const r = await analyzeTarget(root, { target: "new", compareTarget: "old" });
	expect(r.comparison?.changed).toEqual(["x.js"]);
	expect(r.comparison?.limitations[0]).toContain("behavior equivalence");
});
it("defaults Off and preserves evidence after Off/restart with session isolation", () => {
	const path = join(root, "evidence.sqlite"),
		db = new FirstPartyAnalysisStore(path);
	expect(db.session("s")).toBeUndefined();
	expect(() => db.start(receipt("a"))).toThrow("Enable");
	db.setMode("s", root, "static");
	const r = receipt("a");
	db.start(r);
	expect(() => db.setMode("s", root, "off")).toThrow("active");
	r.status = "completed";
	r.result = analyzeSources([source("x.js", "const x=42")]);
	r.resultHash = digest(r.result);
	db.save(r);
	db.setMode("s", root, "off");
	db.close();
	const next = new FirstPartyAnalysisStore(path);
	expect(next.get("s", "a").resultHash).toBe(r.resultHash);
	expect(next.session("s")?.mode).toBe("off");
	expect(() => next.get("foreign", "a")).toThrow("not found");
	next.close();
});
it("enforces shared admission limits and evidence integrity", () => {
	const db = new FirstPartyAnalysisStore(join(root, "db.sqlite"));
	db.setMode("s", root, "static");
	db.start(receipt("a"));
	db.start(receipt("b"));
	expect(() => db.start(receipt("c"))).toThrow("Two");
	const r = receipt("a");
	r.result = analyzeSources([]);
	r.resultHash = "bad";
	expect(() => db.save(r)).toThrow("hash mismatch");
	db.close();
});
it("blocks disabled sessions and absent worker hosts", async () => {
	const db = new FirstPartyAnalysisStore(join(root, "db.sqlite"));
	db.setMode("s", root, "off");
	await expect(
		runFirstPartyAnalysis("s", { target: "." }, undefined, db, "{}"),
	).rejects.toThrow("Off");
	db.setMode("s", root, "static");
	await expect(
		runFirstPartyAnalysis("s", { target: "." }, undefined, db, ""),
	).rejects.toThrow("unavailable");
	db.close();
});
it("supervises a real child, strips credentials and exposes retained paginated evidence", async () => {
	const db = new FirstPartyAnalysisStore(join(root, "db.sqlite"));
	db.setMode("s", root, "static");
	const expected = analyzeSources([source("x.js", "const x=42")]),
		entry = join(root, "host.mjs");
	await writeFile(
		entry,
		`if(process.env.OPENAI_API_KEY)process.exit(9);process.stdin.resume();process.stdin.on('end',()=>process.stdout.write(${JSON.stringify(JSON.stringify(expected))}));`,
	);
	const old = process.env.OPENAI_API_KEY;
	process.env.OPENAI_API_KEY = "owned-test-secret";
	try {
		const r = await runFirstPartyAnalysis(
			"s",
			{ target: "." },
			undefined,
			db,
			JSON.stringify({ executable: process.execPath, args: [entry] }),
		);
		expect(r.status).toBe("completed");
		expect(r.pid).toBeGreaterThan(0);
		expect(r.exitCode).toBe(0);
		expect(
			queryFirstPartyEvidence(
				"s",
				{ receiptId: r.id, view: "findings", limit: 1 },
				db,
			),
		).toMatchObject({ total: 2, items: [expected.facts[0]], nextOffset: 1 });
		db.setMode("s", root, "off");
		expect(
			queryFirstPartyEvidence(
				"s",
				{ receiptId: r.id, view: "verification" },
				db,
			),
		).toMatchObject({ verifiedBehavior: false });
	} finally {
		if (old === undefined) delete process.env.OPENAI_API_KEY;
		else process.env.OPENAI_API_KEY = old;
		db.close();
	}
});
it("cancels an owned child without replay", async () => {
	const db = new FirstPartyAnalysisStore(join(root, "db.sqlite"));
	db.setMode("s", root, "static");
	const entry = join(root, "slow.mjs");
	await writeFile(entry, "process.stdin.resume();setInterval(()=>{},1000)");
	const abort = new AbortController();
	setTimeout(() => abort.abort(), 150);
	const r = await runFirstPartyAnalysis(
		"s",
		{ target: "." },
		abort.signal,
		db,
		JSON.stringify({ executable: process.execPath, args: [entry] }),
	);
	expect(r.status).toBe("cancelled");
	expect(r.result).toBeUndefined();
	expect(db.summaries("s")).toHaveLength(1);
	db.close();
});

it("retains version-one receipt hashes without rewriting evidence during a profile upgrade", () => {
	const file = join(root, "legacy.sqlite"),
		db = new FirstPartyAnalysisStore(file);
	db.setMode("s", root, "static");
	const r = receipt("00000000-0000-4000-8000-000000000001");
	r.profile = "cline-js-static/1";
	db.start(r);
	r.status = "completed";
	r.result = {
		profile: "cline-js-static/1",
		parserVersion: "5.9.3",
		status: "completed",
		artifacts: [],
		facts: [],
		edges: [],
		limitations: ["Legacy static syntax only"],
		counters: { entries: 0, bytes: 0, nodes: 0 },
	} as unknown as AnalysisResult;
	r.resultHash = digest(r.result);
	db.save(r);
	db.setMode("s", root, "off");
	db.close();
	const reopened = new FirstPartyAnalysisStore(file);
	try {
		expect(reopened.get("s", r.id).result).toEqual(r.result);
		expect(
			queryFirstPartyEvidence(
				"s",
				{ receiptId: r.id, view: "verification" },
				reopened,
			),
		).toMatchObject({
			profile: "cline-js-static/1",
			resultHash: r.resultHash,
			verifiedBehavior: false,
		});
		expect(
			queryFirstPartyEvidence(
				"s",
				{ receiptId: r.id, view: "comparison" },
				reopened,
			),
		).toMatchObject({ available: false, total: 0 });
	} finally {
		reopened.close();
	}
});
