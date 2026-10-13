import { expect, it } from "vitest";
import { analyzeSources } from "./parser";
import { byteDigest, ResultSchema } from "./contracts";
import { inspectElectronBoundaries } from "./electron-boundaries";
import { closedModuleContext } from "./module-context";
const sources = (items: Record<string, string>) =>
	Object.entries(items).map(([path, source]) => ({
		path,
		source,
		sha256: byteDigest(Buffer.from(source)),
		bytes: Buffer.byteLength(source),
	}));
const run = (
	preload: string,
	renderer = "window.owned.read(1);",
	extra: Record<string, string> = {},
) =>
	analyzeSources(
		sources({
			"preload.ts": preload,
			"renderer.js": renderer,
			"main.js":
				'import {ipcMain} from "electron";ipcMain.handle("owned:read",()=>42);',
			...extra,
		}),
	);
it("links literal preload methods to renderer and IPC candidates with exact source hashes", () => {
	const r = run(
		'import {contextBridge as cb,ipcRenderer as ir} from "electron";const api={read:(x)=>ir.invoke("owned:read",x),nested:{ping(){return ir.send("owned:ping");}}};cb.exposeInMainWorld("owned",api);',
	);
	expect(() => ResultSchema.parse(r)).not.toThrow();
	const member = r.facts.find(
		(f) =>
			f.kind === "preload-member" && JSON.parse(f.value).path[0] === "read",
	);
	expect(member).toBeDefined();
	expect(JSON.parse(member!.value)).toMatchObject({
		api: "owned",
		callable: true,
		ipcMethod: "invoke",
		channel: "owned:read",
	});
	expect(
		r.edges.some(
			(e) => e.kind === "preload-candidate" && e.target === member!.id,
		),
	).toBe(true);
	expect(
		r.edges.some((e) => e.kind === "ipc-candidate" && e.source === member!.id),
	).toBe(true);
	expect(member!.location.sha256).toBe(
		byteDigest(
			Buffer.from(
				'import {contextBridge as cb,ipcRenderer as ir} from "electron";const api={read:(x)=>ir.invoke("owned:read",x),nested:{ping(){return ir.send("owned:ping");}}};cb.exposeInMainWorld("owned",api);',
			),
		),
	);
});
it("uses lexical shadowing and supports CommonJS/namespace Electron bindings", () => {
	const r = run(
		'const {contextBridge:cb,ipcRenderer:ir}=require("electron");function shadow(ir){ir.invoke("bad");}cb.exposeInMainWorld("owned",{read:(x)=>ir.invoke("owned:read",x)});',
		"function shadow(window){window.owned.read();}window.owned.read();",
	);
	expect(r.facts.filter((f) => f.kind === "preload-call")).toHaveLength(1);
	expect(r.edges.some((e) => e.kind === "preload-candidate")).toBe(true);
	const ns = run(
		'import * as e from "electron";e.contextBridge.exposeInMainWorld("owned",{read:()=>e.ipcRenderer.invoke("owned:read")});',
	);
	expect(
		ns.facts.some(
			(f) =>
				f.kind === "preload-member" &&
				JSON.parse(f.value).channel === "owned:read",
		),
	).toBe(true);
});
it("leaves getters, spreads, duplicate keys, prototypes and escaped/mutated objects unresolved", () => {
	for (const shape of [
		"{get read(){return ()=>1}}",
		"{...unknown}",
		"{read:()=>1,read:()=>2}",
		'{"__proto__":{},read:()=>1}',
	]) {
		const r = run(
			`import {contextBridge as cb} from "electron";cb.exposeInMainWorld("owned",${shape});`,
		);
		expect(r.facts.some((f) => f.kind === "preload-unresolved")).toBe(true);
		expect(r.edges.some((e) => e.kind === "preload-candidate")).toBe(false);
	}
	for (const mutation of [
		"api.read=()=>9;",
		"(api as any)[key]=()=>9;",
		"other.value=api;",
		"consume(api);",
		"const list=[api];",
	]) {
		const r = run(
			`import {contextBridge as cb} from "electron";const api={read:()=>1};${mutation}cb.exposeInMainWorld("owned",api);`,
		);
		expect(r.facts.some((f) => f.kind === "preload-member")).toBe(false);
	}
});
it("does not link ambiguous exposures, overwritten windows or dotted-key lookalikes", () => {
	const pre =
		'import {contextBridge as cb} from "electron";cb.exposeInMainWorld("owned",{read:()=>1});cb.exposeInMainWorld("owned",{read:()=>2});';
	expect(run(pre).edges.some((e) => e.kind === "preload-candidate")).toBe(
		false,
	);
	const r = run(
		'import {contextBridge as cb} from "electron";cb.exposeInMainWorld("owned",{"a.b":{c:()=>1},a:{b:{c:()=>2}}});',
		"window.owned.a.b.c();",
	);
	expect(r.edges.filter((e) => e.kind === "preload-candidate")).toHaveLength(1);
	expect(
		run(pre, "window.owned={read:()=>7};window.owned.read();").facts.some(
			(f) => f.kind === "preload-call",
		),
	).toBe(false);
});
it("records native call sites only for lexical literal .node bindings, excluding mutation and escape", () => {
	const r = run(
		'import addon from "./owned.node";addon.hash(1);function f(addon){addon.hash(2)}',
		"",
		{},
	);
	expect(r.facts.filter((f) => f.kind === "native-boundary")).toHaveLength(1);
	expect(
		JSON.parse(r.facts.find((f) => f.kind === "native-boundary")!.value),
	).toMatchObject({
		module: "./owned.node",
		exportPath: ["hash"],
		argumentCount: 1,
	});
	for (const change of [
		"addon.hash=other;",
		"(addon as any)[key]=other;",
		"other.value=addon;",
	])
		expect(
			run(
				`const addon=require("./owned.node");${change}addon.hash();`,
				"",
			).facts.some((f) => f.kind === "native-boundary"),
		).toBe(false);
	expect(
		run(
			'function require(x){return unknown;}const addon=require("./owned.node");addon.hash();',
			"",
		).facts.some((f) => f.kind === "native-boundary"),
	).toBe(false);
});
it("does not guess callable aliases or derive findings after an incomplete mutation scan", () => {
	const r = run(
		'import {contextBridge as cb} from "electron";cb.exposeInMainWorld("owned",{read:unknownFunction});',
	);
	expect(
		JSON.parse(r.facts.find((f) => f.kind === "preload-member")!.value)
			.callable,
	).toBe("unknown");
	expect(r.edges.some((e) => e.kind === "preload-candidate")).toBe(false);
	const context = closedModuleContext(
		sources({
			"preload.js":
				'import {contextBridge} from "electron";contextBridge.exposeInMainWorld("owned",{read:()=>1});',
		}),
	);
	const partial = inspectElectronBoundaries(context, 1);
	expect(partial.findings).toEqual([]);
	expect(partial.notes[0]).toContain("budget");
});

it("associates a literal exposed wrapper with its native call without validating native exports", () => {
	const r = run(
		'import {contextBridge as cb} from "electron";const addon=require("./owned.node");cb.exposeInMainWorld("owned",{hash:(x)=>addon.hash(x)});',
		"window.owned.hash(42);",
	);
	expect(r.edges.some((e) => e.kind === "preload-candidate")).toBe(true);
	expect(r.edges.some((e) => e.kind === "native-boundary-candidate")).toBe(
		true,
	);
	const value = JSON.parse(
		r.facts.find((f) => f.kind === "preload-member")!.value,
	);
	expect(value.nativeModule).toBe("./owned.node");
	expect(value.nativeExportPath).toEqual(["hash"]);
});

it("conservatively excludes mutated module identities across source files", () => {
	const r = run(
		'import {contextBridge as cb,ipcRenderer} from "electron";cb.exposeInMainWorld("owned",{read:()=>ipcRenderer.invoke("owned:read")});',
		"window.owned.read();",
		{
			"mutation.ts":
				'import {ipcRenderer as ir} from "electron";ir[key]=other;',
		},
	);
	expect(r.edges.some((e) => e.kind === "preload-candidate")).toBe(false);
	expect(
		r.limitations.some((x) => x.includes("module identities excluded")),
	).toBe(true);
	const native = run('import addon from "./owned.node";addon.hash();', "", {
		"mutation.ts": 'import other from "./owned.node";other[key]=modified;',
	});
	expect(native.facts.some((f) => f.kind === "native-boundary")).toBe(false);
});

it("handles synthetic TypeScript CommonJS require symbols in actual .js inventory, but rejects shipped shadows", () => {
	const r = analyzeSources(
		sources({
			"preload.js":
				'const {contextBridge:cb,ipcRenderer:ir}=require("electron");const addon=require("./owned.node");cb.exposeInMainWorld("owned",{read:()=>ir.invoke("owned:read"),hash:(x)=>addon.hash(x)});',
			"renderer.js": "window.owned.read();window.owned.hash(42);",
		}),
	);
	expect(r.facts.filter((f) => f.kind === "preload-member")).toHaveLength(2);
	expect(r.edges.filter((e) => e.kind === "preload-candidate")).toHaveLength(2);
	expect(r.edges.some((e) => e.kind === "native-boundary-candidate")).toBe(
		true,
	);
	const shadow = analyzeSources(
		sources({
			"preload.js":
				'function require(x){return unknown;}const {contextBridge:cb}=require("electron");cb.exposeInMainWorld("owned",{read:()=>1});',
		}),
	);
	expect(shadow.facts.some((f) => f.kind === "preload-member")).toBe(false);
});

it("does not qualify CommonJS bindings after loader reassignment, mutation or escape", () => {
	for (const prefix of [
		"require=()=>fake;",
		"require[key]=other;",
		"installHook(require);",
	]) {
		const r = analyzeSources(
			sources({
				"preload.js": `${prefix}const {contextBridge:cb}=require("electron");const addon=require("./owned.node");cb.exposeInMainWorld("owned",{read:()=>addon.hash()});addon.hash();`,
			}),
		);
		expect(
			r.facts.some(
				(f) => f.kind === "preload-member" || f.kind === "native-boundary",
			),
		).toBe(false);
	}
});

it("tracks lexical function/shorthand exposure aliases and awaited IPC wrappers", () => {
	for (const declaration of [
		'const read=(x)=>ir.invoke("owned:read",x);',
		'function read(x){return ir.invoke("owned:read",x);}',
		'const read=async(x)=>await ir.invoke("owned:read",x);',
	]) {
		const r = run(
			`import {contextBridge as cb,ipcRenderer as ir} from "electron";${declaration}cb.exposeInMainWorld("owned",{read});`,
		);
		expect(
			r.facts.some(
				(f) =>
					f.kind === "preload-member" &&
					JSON.parse(f.value).channel === "owned:read",
			),
		).toBe(true);
		expect(r.edges.some((e) => e.kind === "preload-candidate")).toBe(true);
	}
});
it("does not resolve mutable, overwritten or cyclic exposure function aliases", () => {
	for (const declaration of [
		'let read=(x)=>ir.invoke("owned:read",x);',
		'function read(x){return ir.invoke("owned:read",x);} read=()=>9;',
		"const read=other;const other=read;",
	]) {
		const r = run(
			`import {contextBridge as cb,ipcRenderer as ir} from "electron";${declaration}cb.exposeInMainWorld("owned",{read});`,
		);
		expect(
			r.facts.some(
				(f) =>
					f.kind === "preload-member" &&
					JSON.parse(f.value).channel === "owned:read",
			),
		).toBe(false);
	}
});
