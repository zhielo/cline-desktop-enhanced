// Real production-adapter acceptance on a pinned owned ELF; never executes it.
import { createHash, randomUUID } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { tmpdir } from "node:os";
import { TARGETED_GHIDRA_SCRIPT } from "../sdk/packages/core/src/extensions/tools/executors/targeted-decompiler-scripts";
import { TargetedNativeEvidenceSchema } from "../sdk/packages/core/src/extensions/tools/executors/targeted-native-evidence";
import { createReverseEngineeringExecutor } from "../sdk/packages/core/src/extensions/tools/executors/reverse-engineering";
import { querySavedNativeValueFlow } from "../sdk/packages/core/src/analysis/native-value-flow";
import { digest } from "../sdk/packages/core/src/analysis/contracts";
import fixture from "./fixtures/owned-value-flow-elf.json";
const root = resolve(
	process.argv[2] ?? mkdtempSync(join(tmpdir(), "cline-native-flow-")),
);
if (!process.env.GHIDRA_HOME)
	throw new Error(
		"Explicit GHIDRA_HOME and supported JDK required; never substitute mocked success",
	);
mkdirSync(root, { recursive: true });
const sha = (v: Uint8Array | string) =>
	createHash("sha256").update(v).digest("hex");
const bytes = Buffer.from(fixture.base64, "base64");
if (
	sha(bytes) !== fixture.sha256 ||
	sha(readFileSync(resolve(import.meta.dir, "fixtures/owned-decompiler.c"))) !==
		fixture.sourceSha256
)
	throw new Error("Owned native fixture/source identity mismatch");
const target = join(root, "owned.so");
writeFileSync(target, bytes);
const execute = createReverseEngineeringExecutor();
const scope = { sessionId: "owned-native-value-flow-fixture", workspace: root };
const snapshots: unknown[] = [];
async function selected(symbol: string) {
	const report = JSON.parse(
		await execute(
			{
				engine: "ghidra",
				operation: "decompile",
				target,
				output_directory: join(root, symbol),
				function_selector: { symbol },
				timeout_ms: 120000,
				max_cpu: 2,
				acknowledge_external_output: !!process.argv[2],
			},
			{} as never,
		),
	);
	if (
		!report.succeeded ||
		!report.artifactVerified ||
		!report.databaseVerified ||
		report.input?.sha256 !== fixture.sha256
	)
		throw new Error(
			`Real Ghidra selected fixture failed for ${symbol}: ${JSON.stringify(report)}`,
		);
	const value = TargetedNativeEvidenceSchema.parse(
		report.evidence?.selectedFunctions?.[0],
	);
	const raw = {
		...scope,
		id: sha(symbol),
		taskId: randomUUID(),
		domain: "static",
		operation: "decompile",
		tool: "reverse-engineering",
		targetSha256: fixture.sha256,
		resultHash: digest(report),
		requestHash: sha(symbol),
		at: new Date().toISOString(),
		result: report,
	};
	snapshots.push({ ...raw, snapshotHash: digest(raw) });
	return value;
}
const direct = await selected("owned_direct"),
	indirect = await selected("owned_indirect"),
	add = await selected("owned_value"),
	memory = await selected("owned_memory");
if (
	!direct.callees.some((c) =>
		c.argumentFlows?.some(
			(a) =>
				a.index === 0 &&
				a.sources.some((s) => s.kind === "parameter" && s.parameterIndex === 0),
		),
	) ||
	!direct.returnFlows?.some((r) =>
		r.flow?.sources.some(
			(s) =>
				s.kind === "call-return" &&
				direct.callees.some((c) => c.fromAddressHex === s.fromAddressHex),
		),
	) ||
	!add.returnFlows?.some(
		(r) =>
			r.flow?.sources.some(
				(s) => s.kind === "parameter" && s.parameterIndex === 0,
			) &&
			r.flow.sources.some((s) => s.kind === "constant" && s.valueHex === "0x7"),
	) ||
	!memory.returnFlows?.some((r) => r.flow?.frontiers.includes("memory-load")) ||
	!indirect.callees.some(
		(c) =>
			c.kind === "indirect" &&
			c.resolution === "unknown-memory-register-or-ambiguous-phi",
	)
)
	throw new Error("Real selected-function flow known answers failed");
await selected("owned_flow_leaf");
await selected("owned_flow_mid");
const chain = await selected("owned_flow_root");
const tasks = snapshots as Array<{ taskId: string }>;
const traced = querySavedNativeValueFlow(
	scope,
	{
		action: "trace",
		taskIds: tasks.map((s) => s.taskId),
		rootTaskId: tasks.at(-1)!.taskId,
		rootAddress: chain.addressHex,
		maxDepth: 3,
	},
	snapshots,
);
if (
	!traced.steps.some(
		(s) => s.kind === "constant-dependency" && s.valueHex === "0x7",
	) ||
	!traced.steps.some(
		(s) => s.kind === "constant-dependency" && s.valueHex === "0x3",
	) ||
	!traced.steps.some(
		(s) => s.reason === "root-parameter-without-caller-binding",
	) ||
	traced.truncated
)
	throw new Error("Real interprocedural known answers failed");
const report = {
	scope:
		"actual Ghidra owned ELF selected def-use and bounded cross-function dependency candidates; no target execution",
	status: "passed",
	adapterSha256: sha(TARGETED_GHIDRA_SCRIPT),
	fixtureSourceSha256: fixture.sourceSha256,
	fixtureArtifactSha256: fixture.sha256,
	directCalls: direct.callees,
	directReturnFlows: direct.returnFlows,
	addReturnFlows: add.returnFlows,
	memoryReturnFlows: memory.returnFlows,
	indirectCalls: indirect.callees,
	nativeFlow: traced,
	releaseCertification: false,
};
writeFileSync(
	join(root, "report.json"),
	JSON.stringify(report, null, 2) + "\n",
);
console.log(
	JSON.stringify({
		status: report.status,
		checks:
			"real Ghidra parameters, constants, memory, indirect targets, and three-function argument/return binding",
		report: join(root, "report.json"),
	}),
);
