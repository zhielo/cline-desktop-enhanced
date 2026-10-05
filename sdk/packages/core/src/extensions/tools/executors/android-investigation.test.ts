import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it, vi } from "vitest";
import { ReverseEngineeringInputSchema } from "../schemas";
import { runAdvancedAnalysis } from "./advanced-analysis";
import { ANDROID_INVESTIGATION_WORKER } from "./android-investigation-worker";
import { createReverseEngineeringExecutor } from "./reverse-engineering";

const scripts = resolve(
	dirname(fileURLToPath(import.meta.url)),
	"../../../../scripts",
);
describe("fixed Android investigation worker", () => {
	it("matches the reviewable Python source", async () => {
		expect(ANDROID_INVESTIGATION_WORKER).toBe(
			await readFile(join(scripts, "android-investigation-worker.py"), "utf8"),
		);
	});
	it("passes the stdlib fixture corpus including malformed containers and DEX", async () => {
		const python =
			process.env.CLINE_RE_PYTHON ??
			(process.platform === "win32" ? "python.exe" : "python3");
		const { stderr } = await promisify(execFile)(
			python,
			["-I", join(scripts, "android-investigation-worker.test.py")],
			{ timeout: 60000, maxBuffer: 1024 * 1024 },
		);
		expect(stderr).toContain("OK");
	});
	it("runs through the real supervised fixed worker, not a user script", async () => {
		const dir = await mkdtemp(join(tmpdir(), "android-supervised-"));
		try {
			const target = join(dir, "blob");
			await writeFile(target, Buffer.from([1, 2, 3]));
			const result = await runAdvancedAnalysis({
				action: "artifact_discovery",
				target,
			});
			expect(result.engine).toBe("android-static");
			expect(result.input?.bytes).toBe(3);
			expect(result.evidence.artifacts).toEqual([
				expect.objectContaining({
					format: "opaque",
					validation: "unclassified",
				}),
			]);
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});
	it("saves and queries investigation evidence through the public executor", async () => {
		const dir = await mkdtemp(join(tmpdir(), "android-executor-"));
		vi.stubEnv("CLINE_RE_CACHE_DIR", join(dir, "cache"));
		try {
			const target = join(dir, "blob");
			await writeFile(target, Buffer.from([1, 2, 3]));
			const executor = createReverseEngineeringExecutor();
			const first = JSON.parse(
				await executor(
					ReverseEngineeringInputSchema.parse({
						operation: "advanced_analysis",
						advanced_action: "artifact_discovery",
						target,
					}),
					{} as never,
				),
			);
			expect(first.investigationIndex.file).toContain("investigations");
			const query = JSON.parse(
				await executor(
					ReverseEngineeringInputSchema.parse({
						operation: "advanced_analysis",
						advanced_action: "investigation_query",
						target: first.investigationIndex.file,
						advanced_options: {
							investigation_query: { kind: "artifact", limit: 1 },
						},
					}),
					{} as never,
				),
			);
			expect(query.result.evidence.totalMatches).toBe(1);
			expect(query.result.input.sha256).toBe(first.result.input.sha256);
		} finally {
			vi.unstubAllEnvs();
			await rm(dir, { recursive: true, force: true });
		}
	});
	it("requires a precise bounded selector and rejects unrecognized options", () => {
		expect(
			ReverseEngineeringInputSchema.safeParse({
				operation: "advanced_analysis",
				advanced_action: "android_method",
				advanced_options: {
					method: {
						class_descriptor: "LFixture;",
						name: "x",
						descriptor: "()V",
					},
				},
			}).success,
		).toBe(true);
		for (const advanced_options of [
			{ discovery: { max_depth: 5 } },
			{ discovery: { max_artifacts: 501 } },
			{ investigation_query: { sql: "delete from evidence" } },
			{ method: { class_descriptor: "Fixture", name: "x", descriptor: "bad" } },
		])
			expect(
				ReverseEngineeringInputSchema.safeParse({
					operation: "advanced_analysis",
					advanced_action: "artifact_discovery",
					advanced_options,
				}).success,
			).toBe(false);
	});
});
