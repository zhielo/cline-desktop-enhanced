import { mkdtemp, readFile, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, it, vi } from "vitest";
import { ReverseEngineeringInputSchema } from "../schemas";
import { freshCrossLanguage } from "./fresh-cross-language";
import type { InvestigationRunner } from "./investigation-workflows";
import { createReverseEngineeringExecutor } from "./reverse-engineering";
const scripts = resolve(
	dirname(fileURLToPath(import.meta.url)),
	"../../../../scripts",
);
const dirs: string[] = [];
afterEach(async () => {
	vi.unstubAllEnvs();
	await Promise.all(
		dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })),
	);
});
async function directory() {
	const d = await mkdtemp(join(tmpdir(), "cross-language-"));
	dirs.push(d);
	return d;
}
async function execute(input: unknown) {
	return JSON.parse(
		await createReverseEngineeringExecutor()(
			ReverseEngineeringInputSchema.parse(input),
			{} as never,
		),
	);
}
const method = {
	class_descriptor: "LFixture;",
	name: "native_work",
	descriptor: "()V",
};
it("routes Android/JNI through one fresh immutable artifact scan, preserving exact selectors and native budgets", async () => {
	const runner = vi.fn<InvestigationRunner>().mockResolvedValue({
		schemaVersion: 1,
		result: {
			protocol: "cline-advanced-analysis/v1",
			status: "partial",
			evidence: { crossLanguageTrace: { bindingVerified: false } },
		},
	});
	const r = await freshCrossLanguage(
		ReverseEngineeringInputSchema.parse({
			operation: "trace_cross_language",
			target: "/owned.apk",
			cross_language: {
				kind: "android-jni",
				method,
				native_artifact: "lib/x86_64/libowned.so",
				native_calls: {
					max_depth: 0,
					max_functions: 1,
					max_edges: 1,
					max_total_bytes: 16,
				},
			},
		}),
		runner,
	);
	expect(r).toMatchObject({
		status: "partial",
		observedExecution: false,
		effect: "read",
	});
	expect(runner).toHaveBeenCalledTimes(1);
	expect(runner.mock.calls[0][0]).toMatchObject({
		operation: "advanced_analysis",
		advanced_action: "android_relationships",
		advanced_options: {
			method,
			jni_trace: {
				native_artifact: "lib/x86_64/libowned.so",
				native_calls: {
					max_depth: 0,
					max_functions: 1,
					max_edges: 1,
					max_total_bytes: 16,
				},
			},
		},
	});
});
it.each([
	"blocked",
	"failed",
	"cancelled",
])("never falls back or claims success after %s", async (status) => {
	const runner = vi.fn<InvestigationRunner>().mockResolvedValue({
		schemaVersion: 1,
		result: { protocol: "cline-advanced-analysis/v1", status },
	});
	const r = await freshCrossLanguage(
		ReverseEngineeringInputSchema.parse({
			operation: "trace_cross_language",
			target: "/owned",
			cross_language: { kind: "android-jni", method },
		}),
		runner,
	);
	expect(r.status).toBe(status);
	expect(runner).toHaveBeenCalledTimes(1);
});
it("rejects conflicting fresh/imported modes, misplaced options and unbounded contracts", async () => {
	for (const cross_language of [
		{ kind: "android-jni", method, native_calls: { max_depth: 5 } },
		{ kind: "electron-ipc", channel: "" },
		{ kind: "electron-ipc", channel: "owned", max_nodes: 201 },
		{ kind: "android-jni", method, max_candidates: 0 },
		{ kind: "android-jni", method, arbitrary_script: "x" },
	])
		expect(() =>
			ReverseEngineeringInputSchema.parse({
				operation: "trace_cross_language",
				cross_language,
			}),
		).toThrow();
	await expect(
		execute({
			operation: "trace_data_flow",
			cross_language: { kind: "electron-ipc", channel: "owned" },
		}),
	).rejects.toThrow("only by trace_cross_language");
	for (const overrides of [
		{ evidence_trace: { start_id: "owned" } },
		{ advanced_action: "android_relationships" },
		{ advanced_options: {} },
	])
		await expect(
			execute({
				operation: "trace_cross_language",
				cross_language: { kind: "electron-ipc", channel: "owned" },
				...overrides,
			}),
		).rejects.toThrow("rejects imported graph");
	await expect(
		execute({
			operation: "advanced_analysis",
			advanced_action: "artifact_discovery",
			advanced_options: { jni_trace: {} },
		}),
	).rejects.toThrow("fixed android_relationships");
});
const sources = {
	"preload.ts":
		'import {contextBridge as cb,ipcRenderer as ir} from "electron";cb.exposeInMainWorld("owned",{read:(x)=>ir.invoke("owned:read",x)});',
	"renderer.js":
		"window.owned.read(1);globalThis.__crossLanguageShouldNotExecute=true;",
	"main.js":
		'import {ipcMain} from "electron";ipcMain.handle("owned:read",()=>42);ipcMain.handle("other:channel",()=>0);',
};
async function electronFixture() {
	const d = await directory();
	for (const [name, content] of Object.entries(sources))
		await writeFile(join(d, name), content);
	return d;
}
it("freshly connects renderer/preload/main candidates with source hashes and no source execution", async () => {
	const target = await electronFixture();
	const r = await execute({
		operation: "trace_cross_language",
		target,
		cross_language: { kind: "electron-ipc", channel: "owned:read" },
	});
	expect(r).toMatchObject({
		status: "partial",
		observedExecution: false,
		mode: "fresh-electron-ipc-candidates",
		selection: { status: "found-candidates", handlerCandidates: 1 },
	});
	expect(r.nodes.some((n: { kind: string }) => n.kind === "preload-call")).toBe(
		true,
	);
	expect(
		r.edges.some((e: { kind: string }) => e.kind === "preload-candidate"),
	).toBe(true);
	expect(
		r.edges.some((e: { kind: string }) => e.kind === "ipc-candidate"),
	).toBe(true);
	expect(
		r.nodes.some((n: { value: string }) => n.value === "other:channel"),
	).toBe(false);
	expect(r.artifacts).toHaveLength(3);
	expect(r.inputFingerprint).toMatch(/^[a-f0-9]{64}$/);
	expect(
		(globalThis as Record<string, unknown>).__crossLanguageShouldNotExecute,
	).toBeUndefined();
	for (const [file, source] of Object.entries(sources))
		expect(await readFile(join(target, file), "utf8")).toBe(source);
	const changed = await execute({
		operation: "trace_cross_language",
		target,
		cross_language: { kind: "electron-ipc", channel: "missing" },
	});
	expect(changed.selection.status).toBe("not-found-in-covered-sources");
	expect(changed.nodes).toEqual([]);
	expect(changed.status).toBe("partial");
});
it("keeps missing, ambiguous, dynamic and budget-limited IPC evidence explicitly partial", async () => {
	const target = await electronFixture();
	await writeFile(
		join(target, "other-main.js"),
		'import {ipcMain} from "electron";ipcMain.handle("owned:read",()=>0);',
	);
	const ambiguous = await execute({
		operation: "trace_cross_language",
		target,
		cross_language: { kind: "electron-ipc", channel: "owned:read" },
	});
	expect(ambiguous.selection.handlerCandidates).toBe(2);
	expect(ambiguous.status).toBe("partial");
	const capped = await execute({
		operation: "trace_cross_language",
		target,
		cross_language: {
			kind: "electron-ipc",
			channel: "owned:read",
			max_depth: 0,
			max_nodes: 1,
			max_edges: 1,
		},
	});
	expect(capped.nodes).toHaveLength(1);
	expect(capped.edges).toEqual([]);
	expect(capped.coverage.limitsReached).toContain("max_nodes");
	await mkdir(join(target, "node_modules"));
	await writeFile(
		join(target, "node_modules", "ignored.js"),
		'import {ipcMain} from "electron";ipcMain.handle("owned:read",()=>0);',
	);
	const ignored = await execute({
		operation: "trace_cross_language",
		target,
		cross_language: { kind: "electron-ipc", channel: "owned:read" },
	});
	expect(ignored.artifacts).toHaveLength(4);
	expect(ignored.limitations.join(" ")).toContain("Excluded directory");
	const controller = new AbortController();
	controller.abort();
	const runner = vi.fn<InvestigationRunner>();
	await expect(
		freshCrossLanguage(
			ReverseEngineeringInputSchema.parse({
				operation: "trace_cross_language",
				target,
				cross_language: { kind: "electron-ipc", channel: "owned:read" },
			}),
			runner,
			controller.signal,
		),
	).rejects.toThrow();
	expect(runner).not.toHaveBeenCalled();
});
it("retains fresh JNI export/native-call evidence through the public executor without claiming a binding", async () => {
	const fixture = JSON.parse(
		await readFile(
			join(scripts, "owned-jni-cross-language-fixture.json"),
			"utf8",
		),
	);
	const d = await directory(),
		target = join(d, "owned.apk"),
		bytes = Buffer.from(fixture.base64, "base64");
	await writeFile(target, bytes);
	vi.stubEnv("CLINE_RE_CACHE_DIR", join(d, "cache"));
	const result = await execute({
		operation: "trace_cross_language",
		target,
		cross_language: {
			kind: "android-jni",
			method,
			native_artifact: "lib/x86_64/libowned.so",
			native_calls: {
				max_depth: 2,
				max_functions: 3,
				max_edges: 4,
				max_total_bytes: 32,
			},
		},
	});
	expect(result.status).toBe("partial");
	expect(result.observedExecution).toBe(false);
	const worker = result.stages[0].result.result;
	expect(worker.input.sha256).toBe(fixture.sha256);
	const trace = worker.evidence.crossLanguageTrace;
	expect(trace).toMatchObject({
		bindingVerified: false,
		observedExecution: false,
		selectedMethodCount: 1,
		registrationStatus: "unresolved-not-observed",
	});
	// stdlib-only developer machines retain explicit missing-parser evidence, never fabricated graph nodes.
	if (trace.nativeTraversal.callGraph) {
		expect(trace.nativeTraversal.nativeArtifactSha256).toBe(
			fixture.nativeSha256,
		);
		expect(
			trace.nativeTraversal.callGraph.nodes.map(
				(n: { name: string }) => n.name,
			),
		).toEqual(["Java_Fixture_native_1work", "owned_child", "owned_leaf"]);
		expect(trace.nativeTraversal.callGraph.edges[2].resolution).toBe(
			"already-scheduled-or-visited",
		);
	} else
		expect(["blocked", "not-started"]).toContain(trace.nativeTraversal.status);
	expect(await readFile(target)).toEqual(bytes);
});
