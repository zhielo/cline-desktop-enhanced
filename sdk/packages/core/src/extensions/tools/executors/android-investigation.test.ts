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
	it.each([0, 1, 2, 3, 4, 5, 6, 7])("passes complete stdlib fixture group %i including malformed containers and DEX", async (index) => {
		const count = 8;
		const python = process.env.CLINE_RE_PYTHON ??
			(process.platform === "win32" ? "python.exe" : "python3");
		// Smaller disjoint groups retain every discovered case while keeping
		// Windows process startup inside the unchanged 18-second child budget.
		const { stdout, stderr } = await promisify(execFile)(python,
			["-I", "-B", join(scripts, "android-investigation-worker.test.py"), "--fixture-shard", String(index), String(count)],
			{ timeout: 18_000, maxBuffer: 1024 * 1024, windowsHide: true }).catch((error) => {
			throw new Error(`Android fixture shard ${index}/${count} failed: ${JSON.stringify({
				code: error.code, killed: error.killed, signal: error.signal,
				stdout: String(error.stdout ?? "").slice(-4000),
				stderr: String(error.stderr ?? "").slice(-4000),
			})}`, { cause: error });
		});
		const receipt = JSON.parse(stdout) as {protocol:string;index:number;count:number;allCaseIds:string[];caseIds:string[]};
		expect(receipt).toMatchObject({protocol:"android-fixture-shard/v1",index,count});
		expect(receipt.allCaseIds.length).toBeGreaterThan(0);
		expect(new Set(receipt.allCaseIds).size).toBe(receipt.allCaseIds.length);
		expect(receipt.caseIds).toEqual(receipt.allCaseIds.filter((_, position) => position % count === index));
		expect(receipt.caseIds.length).toBeGreaterThan(0);
		expect(stderr).toContain(`Ran ${receipt.caseIds.length} tests`);
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
	it("runs owned static readiness without requiring a target", async () => {
		const result = await runAdvancedAnalysis({ action: "analysis_readiness" });
		expect(["completed", "partial"]).toContain(result.status);
		expect(result.engine).toBe("android-static-readiness");
		const checks = result.evidence.checks as Array<{
			status: string;
			executionVerified: boolean;
		}>;
		expect(checks.length).toBe(4);
		expect(
			checks.every((c) => c.executionVerified === (c.status === "completed")),
		).toBe(true);
	});
	it("retains bounded native traversal evidence through the public executor", async () => {
		const fixture = JSON.parse(
			await readFile(join(scripts, "owned-native-call-fixture.json"), "utf8"),
		);
		const dir = await mkdtemp(join(tmpdir(), "native-traversal-"));
		vi.stubEnv("CLINE_RE_CACHE_DIR", join(dir, "cache"));
		try {
			const target = join(dir, "owned.so");
			const bytes = Buffer.from(fixture.base64, "base64");
			await writeFile(target, bytes);
			const result = JSON.parse(
				await createReverseEngineeringExecutor()(
					ReverseEngineeringInputSchema.parse({
						operation: "trace_native_calls",
						target,
						function_selector: { symbol: "owned_root" },
						advanced_options: {
							native_calls: {
								max_depth: 2,
								max_functions: 3,
								max_edges: 4,
								max_total_bytes: 32,
							},
						},
					}),
					{} as never,
				),
			);
			expect(result.observedExecution).toBe(false);
			const worker = result.stages[0].result.result;
			if (worker.status === "blocked") {
				expect(result.status).toBe("blocked");
				expect(worker.evidence.callGraph).toBeUndefined();
				return;
			}
			const graph = worker.evidence.callGraph;
			expect(result.status).toBe("partial");
			expect(graph.observedExecution).toBe(false);
			// Capstone may be absent on a stdlib-only developer machine; never fabricate a decoded descendant.
			if (graph.nodes[0].status === "blocked") {
				expect(graph.nodes).toHaveLength(1);
				expect(graph.coverage.limitsReached).toContain(
					"partial-or-blocked-function",
				);
				return;
			}
			expect(worker.input.sha256).toBe(fixture.sha256);
			expect(graph.nodes.map((n: { name: string }) => n.name)).toEqual([
				"owned_root",
				"owned_child",
				"owned_leaf",
			]);
			expect(graph.edges[2].resolution).toBe("already-scheduled-or-visited");
			expect(graph.usage.requestedBytes).toBe(18);
			expect(await readFile(target)).toEqual(bytes);
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

it("identifies nested content through the public command, preserves input and refuses over-depth completion", async () => {
	const dir = await mkdtemp(join(tmpdir(), "identify-public-"));
	vi.stubEnv("CLINE_RE_CACHE_DIR", join(dir, "cache"));
	try {
		const fixture = JSON.parse(
				await readFile(
					join(scripts, "owned-artifact-discovery-fixture.json"),
					"utf8",
				),
			),
			bytes = Buffer.from(fixture.base64, "base64"),
			target = join(dir, "misleading.exe");
		await writeFile(target, bytes);
		const execute = async (artifact_discovery?: unknown) =>
			JSON.parse(
				await createReverseEngineeringExecutor()(
					ReverseEngineeringInputSchema.parse({
						operation: "identify_artifact",
						target,
						artifact_discovery,
					}),
					{} as never,
				),
			);
		const r = await execute();
		expect(r).toMatchObject({ status: "partial", observedExecution: false });
		const worker = r.stages[0].result.result;
		expect(worker.input.sha256).toBe(fixture.sha256);
		expect(worker.evidence.identification).toMatchObject({
			protocol: "cline-artifact-identification/v1",
			unknownCount: 1,
			ambiguousCount: 1,
			observedExecution: false,
		});
		expect(
			worker.evidence.artifacts.map((a: { format: string }) => a.format),
		).toEqual(["zip", "gzip", "dex", "opaque", "opaque"]);
		const limited = await execute({ max_depth: 0, max_artifacts: 5 });
		expect(limited.status).toBe("partial");
		expect(limited.stages[0].result.result.evidence.artifacts).toHaveLength(1);
		expect(await readFile(target)).toEqual(bytes);
		expect(
			(globalThis as Record<string, unknown>).__artifactShouldNotExecute,
		).toBeUndefined();
	} finally {
		vi.unstubAllEnvs();
		await rm(dir, { recursive: true, force: true });
	}
});


it("retains exact Android caller/callee evidence or an explicit missing-engine result through the public command", async () => {
 const dir = await mkdtemp(join(tmpdir(), "android-method-calls-"));
 vi.stubEnv("CLINE_RE_CACHE_DIR", join(dir,"cache"));
 try {
  const f = JSON.parse(await readFile(join(scripts,"owned-android-method-calls-fixture.json"),"utf8"));
  const bytes = Buffer.from(f.base64,"base64"), target = join(dir,"owned.dex");
  await writeFile(target,bytes);
  const request = {operation:"trace_android_method",target,advanced_options:{method:{class_descriptor:"LCalls;",name:"root",descriptor:"()V"}}};
  const execute = async (extra:Record<string,unknown>={}) => JSON.parse(await createReverseEngineeringExecutor()(ReverseEngineeringInputSchema.parse({...request,...extra}),{} as never));
  const result = await execute();
  expect(result).toMatchObject({status:"partial",observedExecution:false});
  // If the selected-code stage itself is blocked, the dependency must not be run.
  if(result.stages.length === 1) {
   expect(result.stages[0].result.result.evidence.selectedCode[0].status).toBe("blocked");
  } else {
   const worker = result.stages[1].result.result, calls = worker.evidence.methodCalls;
   expect(worker.input.sha256).toBe(f.sha256);
   if(calls.status === "blocked") {
    expect(calls).toMatchObject({reason:"Androguard is not installed",observedExecution:false,dispatchVerified:false});
    expect(result.stages[0].result.result.evidence.selectedCode[0].status).toBe("blocked");
   } else {
   expect(calls).toMatchObject({protocol:"cline-android-method-calls/v1",status:"partial",selectedDefinitionCount:1,referenceCount:2,dispatchVerified:false,observedExecution:false});
   expect(calls.references.map((r:{relativeToSelection:string})=>r.relativeToSelection).sort()).toEqual(["callee","caller"]);
   expect(calls.references.every((r:{artifactSha256:string;bytecodeOffset:number;dispatchVerified:boolean})=>r.artifactSha256===f.sha256&&r.bytecodeOffset===0&&!r.dispatchVerified)).toBe(true);
   const limited=await execute({max_results:1});expect(limited.stages[1].result.result.evidence.methodCalls).toMatchObject({referenceCount:2,referencesTruncated:true});
   const ambiguous=join(dir,"ambiguous.apk");await writeFile(ambiguous,Buffer.from(f.ambiguousBase64,"base64"));
   const duplicate=await execute({target:ambiguous});expect(duplicate.stages[1].result.result.evidence.methodCalls).toMatchObject({selectionStatus:"ambiguous-definition",references:[]});
   }
  }
  expect(await readFile(target)).toEqual(bytes);
 } finally { vi.unstubAllEnvs(); await rm(dir,{recursive:true,force:true}); }
});

it("preserves bounded Android transitive traversal through the supervised public executor", async () => {
	const dir = await mkdtemp(join(tmpdir(), "android-traversal-"));
	vi.stubEnv("CLINE_RE_CACHE_DIR", join(dir, "cache"));
	try {
		const f = JSON.parse(
			await readFile(
				join(scripts, "owned-android-call-traversal-fixture.json"),
				"utf8",
			),
		);
		const bytes = Buffer.from(f.cycle.base64, "base64"),
			target = join(dir, "owned.dex");
		await writeFile(target, bytes);
		const request = {
			operation: "trace_android_method",
			target,
			advanced_options: {
				method: {
					class_descriptor: "LCalls;",
					name: "root",
					descriptor: "()V",
				},
				android_calls: { max_depth: 4, direction: "callees" },
			},
		};
		const execute = async (extra: Record<string, unknown> = {}) =>
			JSON.parse(
				await createReverseEngineeringExecutor()(
					ReverseEngineeringInputSchema.parse({ ...request, ...extra }),
					{} as never,
				),
			);
		const result = await execute();
		expect(result).toMatchObject({
			status: "partial",
			observedExecution: false,
		});
		if (result.stages.length === 1) {
			expect(
				result.stages[0].result.result.evidence.selectedCode[0].status,
			).toBe("blocked");
		} else {
			const worker = result.stages[1].result.result,
				calls = worker.evidence.methodCalls;
			if (calls.status === "blocked")
				expect(calls.reason).toBe("Androguard is not installed");
			else {
				expect(worker.input.sha256).toBe(f.cycle.sha256);
				expect(calls.traversal).toMatchObject({
					protocol: "cline-android-call-traversal/v1",
					status: "partial",
					dispatchVerified: false,
					observedExecution: false,
				});
				expect(
					calls.traversal.nodes.map((n: { name: string }) => n.name),
				).toEqual(["root", "middle", "leaf", "external"]);
				expect(calls.traversal.edges).toHaveLength(4);
				expect(calls.traversal.edges[2].resolution).toBe(
					"already-scheduled-or-visited",
				);
				const limited = await execute({
					advanced_options: {
						...request.advanced_options,
						android_calls: { max_nodes: 1, direction: "callees" },
					},
				});
				expect(
					limited.stages[1].result.result.evidence.methodCalls.traversal,
				).toMatchObject({
					nodes: [{ name: "root" }],
					limitsReached: ["node-budget"],
				});
			}
		}
		expect(await readFile(target)).toEqual(bytes);
	} finally {
		vi.unstubAllEnvs();
		await rm(dir, { recursive: true, force: true });
	}
});

it.each([ {operation:"analyze"}, {operation:"advanced_analysis",advanced_action:"android_method_code"} ])("rejects Android traversal options on unrelated public actions %j",async(action)=>{
 await expect(createReverseEngineeringExecutor()(ReverseEngineeringInputSchema.parse({...action,advanced_options:{android_calls:{}}}),{} as never)).rejects.toThrow("android_calls budgets require Android method relationship analysis");
});
