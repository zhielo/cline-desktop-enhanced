import { mkdtemp, writeFile, readFile, rm, symlink } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect, afterEach, vi } from "vitest";
import {
	validateNotebook,
	prepareNotebook,
	runAnalysisNotebook,
	readAnalysisJson,
} from "./analysis-notebook";
import type { NotebookRunner } from "./analysis-notebook";
const dirs: string[] = [];
afterEach(async () => {
	await Promise.all(
		dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })),
	);
});
const cell = { id: "a", action: "triage", target: "owned.bin" };
const document = {
	schemaVersion: 1,
	title: "Owned investigation",
	cells: [cell],
};
async function fixture(doc: unknown = document) {
	const dir = await mkdtemp(join(tmpdir(), "notebook-test-"));
	dirs.push(dir);
	await writeFile(join(dir, "owned.bin"), "owned artifact");
	const target = join(dir, "analysis.json");
	await writeFile(target, JSON.stringify(doc));
	return { dir, target, cache: join(dir, "cache") };
}
function runner(version = "1") {
	return vi.fn<NotebookRunner>(async (request) => {
		const data = request.target ? await readFile(request.target) : undefined;
		return {
			protocol: "cline-advanced-analysis/v1",
			status: "completed",
			engine: "builtin",
			engineVersion: version,
			evidence: { action: request.action },
			limitations: [],
			...(data
				? {
						input: {
							sha256: createHash("sha256").update(data).digest("hex"),
							bytes: data.length,
							format: "opaque",
						},
					}
				: {}),
		};
	});
}
describe("durable static notebooks", () => {
	it("preflights inputs without an engine", async () => {
		const f = await fixture();
		expect((await prepareNotebook(f.target)).totalBytes).toBe(14);
	});
	it("rejects scripts and runtime actions", () => {
		expect(() =>
			validateNotebook({
				...document,
				cells: [{ ...cell, action: "trace_native_region" }],
			}),
		).toThrow();
		expect(() => validateNotebook({ ...document, script: "bad" })).toThrow();
	});
	it("rejects duplicates, missing dependencies and cycles", () => {
		expect(() =>
			validateNotebook({ ...document, cells: [cell, cell] }),
		).toThrow("Duplicate");
		expect(() =>
			validateNotebook({
				...document,
				cells: [{ ...cell, dependsOn: ["missing"] }],
			}),
		).toThrow("Unknown");
		expect(() =>
			validateNotebook({ ...document, cells: [{ ...cell, dependsOn: ["a"] }] }),
		).toThrow("cycle");
	});
	it("rejects traversal before invoking engines", async () => {
		const f = await fixture({
			...document,
			cells: [{ ...cell, target: "../outside.bin" }],
		});
		const run = runner();
		await expect(runAnalysisNotebook(f.target, f.cache, run)).rejects.toThrow(
			"confined",
		);
		expect(run).not.toHaveBeenCalled();
	});
	it.skipIf(process.platform === "win32")(
		"rejects escaping symlinks",
		async () => {
			const f = await fixture();
			const other = await fixture();
			await symlink(join(other.dir, "owned.bin"), join(f.dir, "escaped.bin"));
			await writeFile(
				f.target,
				JSON.stringify({
					...document,
					cells: [{ ...cell, target: "escaped.bin" }],
				}),
			);
			await expect(prepareNotebook(f.target)).rejects.toThrow("escapes");
		},
	);
	it("checkpoints and reuses unchanged completed cells", async () => {
		const f = await fixture();
		const run = runner();
		const first = await runAnalysisNotebook(f.target, f.cache, run);
		expect(first.status).toBe("completed");
		const second = await runAnalysisNotebook(f.target, f.cache, run);
		expect(second.status).toBe("completed");
		expect(run.mock.calls.filter(([r]) => r.action === "triage")).toHaveLength(
			1,
		);
		expect(
			(second.evidence.cellReceipts as { reused: boolean }[])[0].reused,
		).toBe(true);
	});
	it("invalidates changed input content", async () => {
		const f = await fixture();
		const run = runner();
		await runAnalysisNotebook(f.target, f.cache, run);
		await writeFile(join(f.dir, "owned.bin"), "changed");
		await runAnalysisNotebook(f.target, f.cache, run);
		expect(run.mock.calls.filter(([r]) => r.action === "triage")).toHaveLength(
			2,
		);
	});
	it("invalidates changed engine fingerprints", async () => {
		const f = await fixture();
		await runAnalysisNotebook(f.target, f.cache, runner("1"));
		const run = runner("2");
		await runAnalysisNotebook(f.target, f.cache, run);
		expect(run.mock.calls.some(([r]) => r.action === "triage")).toBe(true);
	});
	it("runs dependencies in order despite manifest ordering", async () => {
		const f = await fixture({
			...document,
			cells: [{ ...cell, id: "b", dependsOn: ["a"] }, cell],
		});
		const run = runner();
		const result = await runAnalysisNotebook(f.target, f.cache, run);
		expect(
			(result.evidence.cellReceipts as { id: string }[]).map((r) => r.id),
		).toEqual(["a", "b"]);
	});
	it("blocks dependent cells after an engine failure", async () => {
		const f = await fixture({
			...document,
			cells: [cell, { ...cell, id: "b", dependsOn: ["a"] }],
		});
		const run = runner();
		run.mockImplementation(async (r) => ({
			protocol: "cline-advanced-analysis/v1",
			status: r.action === "toolchain" ? "completed" : "blocked",
			engine: "builtin",
			engineVersion: "1",
			evidence: {},
			limitations: [],
		}));
		const result = await runAnalysisNotebook(f.target, f.cache, run);
		expect(result.status).toBe("blocked");
		expect(
			(result.evidence.cellReceipts as { status: string }[]).map(
				(r) => r.status,
			),
		).toEqual(["blocked", "blocked"]);
		expect(
			run.mock.calls.filter(([r]) => r.action !== "toolchain"),
		).toHaveLength(1);
	});
	it("discards corrupt checkpoints", async () => {
		const f = await fixture();
		const run = runner();
		const first = await runAnalysisNotebook(f.target, f.cache, run);
		await writeFile(first.evidence.checkpoint as string, "not-json");
		expect((await runAnalysisNotebook(f.target, f.cache, run)).status).toBe(
			"completed",
		);
		expect(run.mock.calls.filter(([r]) => r.action === "triage")).toHaveLength(
			2,
		);
	});
	it("does not reuse interrupted running cells", async () => {
		const f = await fixture();
		const run = runner();
		const first = await runAnalysisNotebook(f.target, f.cache, run);
		const path = first.evidence.checkpoint as string;
		const state = JSON.parse(await readFile(path, "utf8"));
		state.cells[0].status = "running";
		await writeFile(path, JSON.stringify(state));
		await runAnalysisNotebook(f.target, f.cache, run);
		expect(run.mock.calls.filter(([r]) => r.action === "triage")).toHaveLength(
			2,
		);
	});
	it("rejects stale worker input identity", async () => {
		const f = await fixture();
		const run = runner();
		run.mockImplementation(async (r) => ({
			protocol: "cline-advanced-analysis/v1",
			status: "completed",
			engine: "builtin",
			engineVersion: "1",
			evidence: {},
			limitations: [],
			...(r.target
				? { input: { sha256: "0".repeat(64), bytes: 14, format: "opaque" } }
				: {}),
		}));
		expect((await runAnalysisNotebook(f.target, f.cache, run)).status).toBe(
			"failed",
		);
	});
	it("bounds JSON input before parsing", async () => {
		const f = await fixture();
		await expect(readAnalysisJson(f.target, 4)).rejects.toThrow("byte budget");
	});
});
