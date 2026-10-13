import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { analyzeSources } from "./parser";
import { analyzeTarget } from "./worker";
import { byteDigest, ResultSchema } from "./contracts";
import { sourceMapLocations } from "./source-maps";
const source = (text: string) => ({
	path: "main.js",
	source: text,
	bytes: Buffer.byteLength(text),
	sha256: byteDigest(Buffer.from(text)),
});
it("reduces immutable local strings and pure-return arguments with supporting flow edges", () => {
	const r = analyzeSources([
		source(
			'const host="https://owned.invalid"; const route="/v1"; function endpoint(h,r){return h+r;} fetch(endpoint(host,route));',
		),
	]);
	const endpoint = r.facts.find((f) => f.kind === "resolved-endpoint");
	expect(endpoint?.value).toBe("https://owned.invalid/v1");
	expect(endpoint?.confidence).toBe("derived");
	expect(r.edges.filter((e) => e.kind === "data-flow")).toHaveLength(2);
	expect(r.edges.some((e) => e.kind === "calls")).toBe(true);
	const ids = new Set(r.facts.map((f) => f.id));
	for (const e of r.edges) {
		expect(ids.has(e.source)).toBe(true);
		expect(ids.has(e.target)).toBe(true);
	}
	expect(() => ResultSchema.parse(r)).not.toThrow();
});
it("does not resolve imported, mutable, shadowed, recursive or side-effecting expressions", () => {
	for (const code of [
		'let host="https://owned.invalid";fetch(host);',
		'import {host} from "./unknown";fetch(host);',
		'function fetch(x){};fetch("https://owned.invalid");',
		'function make(){console.log("side effect");return "https://owned.invalid";}fetch(make());',
		'function loop(x){return loop(x);}fetch(loop("x"));',
		'const host="https://owned.invalid";host="bad";fetch(host);',
		'function endpoint(){return "wrong";}endpoint=unknown;fetch(endpoint());',
		'function endpoint(x){return process.env.SECRET+x;}fetch(endpoint("/v1"));',
	])
		expect(
			analyzeSources([source(code)]).facts.filter(
				(f) => f.kind === "resolved-endpoint",
			),
		).toHaveLength(0);
});
it("uses lexical symbol identity rather than variable spelling", () => {
	const r = analyzeSources([
		source(
			'const host="https://owned.invalid";function f(host){return host;}function g(host){fetch(host);}fetch(f(host));',
		),
	]);
	expect(
		r.facts.filter((f) => f.kind === "resolved-endpoint").map((f) => f.value),
	).toEqual(["https://owned.invalid"]);
});
it("folds templates without executing arbitrary target code", () => {
	const r = analyzeSources([
		source(
			'const n=2;fetch(`https://owned.invalid/v${n}`);throw new Error("MUST_NOT_EXECUTE");',
		),
	]);
	expect(r.facts.find((f) => f.kind === "resolved-endpoint")?.value).toBe(
		"https://owned.invalid/v2",
	);
});
it("reads basic source maps with exact embedded hashes without opening remote source labels", () => {
	const map = JSON.stringify({
		version: 3,
		sources: ["https://owned.invalid/original.ts"],
		sourcesContent: ["const x=1;"],
		names: ["x"],
		mappings: "AAAAA;AACA",
	});
	const m = sourceMapLocations(map);
	expect(m.partial).toBe(false);
	expect(m.locations[0]).toMatchObject({
		generatedLine: 1,
		generatedColumn: 1,
		originalLine: 1,
		originalColumn: 1,
		name: "x",
		embeddedSha256: byteDigest(Buffer.from("const x=1;")),
	});
	const s = { ...source(map), path: "bundle.js.map" };
	const r = analyzeSources([s]);
	expect(r.artifacts[0].role).toBe("source-map");
	expect(r.facts).toHaveLength(2);
	expect(r.facts.every((f) => f.confidence === "derived")).toBe(true);
	expect(() => ResultSchema.parse(r)).not.toThrow();
});
it("rejects malformed, indexed and out-of-range maps, and marks truncated mapping coverage", () => {
	for (const map of [
		null,
		{ version: 3, sources: ["a"], mappings: "!" },
		{ version: 3, sources: ["a"], mappings: "ACAA" },
		{ version: 3, sources: ["a"], mappings: "g" },
		{ version: 3, sources: ["a"], mappings: "AAA" },
		{ version: 3, sections: [], sources: [], mappings: "" },
	])
		expect(() => sourceMapLocations(JSON.stringify(map))).toThrow();
	expect(
		sourceMapLocations(
			JSON.stringify({ version: 3, sources: ["a"], mappings: "AAAA,CAAA" }),
			1,
		),
	).toMatchObject({ partial: true });
});
it("compares findings by relative path and retains hashed evidence for removed endpoints", async () => {
	const root = await mkdtemp(join(tmpdir(), "cline-semantic-compare-"));
	try {
		await mkdir(join(root, "old"));
		await mkdir(join(root, "new"));
		await writeFile(
			join(root, "old", "main.js"),
			'const host="https://old.invalid";fetch(host);',
		);
		await writeFile(
			join(root, "new", "main.js"),
			'const host="https://new.invalid";fetch(host);',
		);
		await writeFile(
			join(root, "new", "main.js.map"),
			JSON.stringify({
				version: 3,
				sources: ["original.ts"],
				sourcesContent: ["x"],
				mappings: "AAAA",
			}),
		);
		const r = await analyzeTarget(root, {
			target: "new",
			compareTarget: "old",
		});
		expect(
			r.comparison?.findings?.find(
				(f) => f.kind === "resolved-endpoint" && f.change === "removed",
			)?.value,
		).toBe("https://old.invalid");
		expect(
			r.comparison?.findings?.find(
				(f) => f.kind === "resolved-endpoint" && f.change === "added",
			)?.value,
		).toBe("https://new.invalid");
		expect(
			r.comparison?.findings?.every((f) => f.location.sha256.length === 64),
		).toBe(true);
		expect(r.artifacts.some((a) => a.role === "source-map")).toBe(true);
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});

it("does not report identical modules as changed merely because version folders differ", async () => {
	const root = await mkdtemp(join(tmpdir(), "cline-semantic-same-"));
	try {
		await mkdir(join(root, "old"));
		await mkdir(join(root, "new"));
		for (const version of ["old", "new"])
			await writeFile(join(root, version, "main.js"), 'const x="same";');
		const r = await analyzeTarget(root, {
			target: "new",
			compareTarget: "old",
		});
		expect(r.comparison?.findings).toEqual([]);
		expect(r.comparison?.changed).toEqual([]);
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});

it("reduces const arrow and function-expression returns without executing either", () => {
	const r = analyzeSources([
		source(
			'const host="https://owned.invalid"; const arrow=x=>x+"/arrow"; const normal=function(x){return x+"/normal";};fetch(arrow(host));fetch(normal(host));',
		),
	]);
	expect(
		r.facts.filter((f) => f.kind === "resolved-endpoint").map((f) => f.value),
	).toEqual(["https://owned.invalid/arrow", "https://owned.invalid/normal"]);
});

it("retains sourceRoot and source labels separately without inventing resolved paths", () => {
	const m = sourceMapLocations(
		JSON.stringify({
			version: 3,
			sourceRoot: "https://owned.invalid/src",
			sources: ["original.ts"],
			mappings: "AAAA",
		}),
	);
	expect(m.locations[0]).toMatchObject({
		sourceRootLabel: "https://owned.invalid/src",
		sourceLabel: "original.ts",
	});
});
