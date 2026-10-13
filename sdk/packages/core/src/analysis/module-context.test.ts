import { expect, it } from "vitest";
import { analyzeSources } from "./parser";
import { byteDigest, ResultSchema } from "./contracts";
const source = (path: string, source: string) => ({
	path,
	source,
	bytes: Buffer.byteLength(source),
	sha256: byteDigest(Buffer.from(source)),
});
it("resolves named exports, reexports and pure return functions across inventory only", () => {
	const r = analyzeSources([
		source(
			"config.ts",
			'export const host="https://owned.invalid";export function route(h){return h+"/v2";}',
		),
		source("bridge.ts", 'export {host,route} from "./config"'),
		source(
			"main.ts",
			'import {host,route} from "./bridge";fetch(route(host));',
		),
	]);
	expect(r.facts.find((f) => f.kind === "resolved-endpoint")?.value).toBe(
		"https://owned.invalid/v2",
	);
	expect(r.facts.some((f) => f.kind === "module-value")).toBe(true);
	expect(() => ResultSchema.parse(r)).not.toThrow();
});
it("reduces const scalar object properties but refuses mutation and escaping aliases", () => {
	const base = source(
		"config.ts",
		'export const config={host:"https://owned.invalid",route:"/object"};',
	);
	const read =
		'import {config} from "./config";fetch(config.host+config["route"]);';
	expect(
		analyzeSources([base, source("main.ts", read)]).facts.some(
			(f) => f.kind === "resolved-endpoint",
		),
	).toBe(true);
	for (const extra of [
		'config.host="changed";',
		'const alias=config;alias.host="changed";',
		"unknown(config);",
	])
		expect(
			analyzeSources([base, source("main.ts", extra + read)]).facts.some(
				(f) => f.kind === "resolved-endpoint",
			),
		).toBe(false);
});
it("keeps missing external modules, ambiguous extensions, cyclic bindings and getters unknown", () => {
	for (const sources of [
		[source("main.ts", 'import {host} from "not-in-inventory";fetch(host);')],
		[
			source("a.js", 'export const host="https://owned.invalid"'),
			source("a.ts", 'export const host="https://other.invalid"'),
			source("main.ts", 'import {host} from "./a";fetch(host);'),
		],
		[
			source("a.ts", 'import {b} from "./b";export const a=b;'),
			source("b.ts", 'import {a} from "./a";export const b=a;'),
			source("main.ts", 'import {a} from "./a";fetch(a);'),
		],
		[
			source(
				"main.ts",
				'const config={get host(){throw "DO_NOT_EXECUTE"}};fetch(config.host);',
			),
		],
	])
		expect(
			analyzeSources(sources).facts.some((f) => f.kind === "resolved-endpoint"),
		).toBe(false);
});
it("foreign symbols never acquire consumer hash as declaration proof", () => {
	const a = source("a.ts", 'export const host="https://owned.invalid"'),
		b = source("main.ts", 'import {host} from "./a";fetch(host);');
	const r = analyzeSources([a, b]);
	expect(r.facts.find((f) => f.kind === "configuration")?.location.sha256).toBe(
		a.sha256,
	);
	expect(
		r.facts.find((f) => f.kind === "module-value")?.limitations.join(" "),
	).toContain("consumer");
});

it("never attributes one duplicate virtual/filesystem label's AST to another source hash", () => {
	const a = source("same.ts", 'export const host="https://one.invalid"'),
		b = source("same.ts", 'export const host="https://two.invalid"');
	const result = analyzeSources([
		a,
		b,
		source("main.ts", 'import {host} from "./same";fetch(host);'),
	]);
	expect(result.status).toBe("partial");
	expect(result.facts.some((f) => f.kind === "resolved-endpoint")).toBe(false);
	expect(result.artifacts.some((x) => x.path === "same.ts")).toBe(false);
	expect(result.limitations.join(" ")).toContain("Ambiguous duplicate");
});
