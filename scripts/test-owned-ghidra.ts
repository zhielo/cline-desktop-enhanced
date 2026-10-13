import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { TARGETED_GHIDRA_SCRIPT } from "../sdk/packages/core/src/extensions/tools/executors/targeted-decompiler-scripts";
import { TargetedNativeEvidenceSchema } from "../sdk/packages/core/src/extensions/tools/executors/targeted-native-evidence";
const root = resolve(process.argv[2] ?? ".cline-ghidra-owned"),
	home = process.env.GHIDRA_HOME;
if (!home || process.platform !== "linux")
	throw new Error(
		"Explicit authorized GHIDRA_HOME, supported JAVA_HOME and Linux GCC required for this owned fixture test; never substitute a mocked success",
	);
mkdirSync(root, { recursive: true });
const source = resolve(import.meta.dir, "fixtures/owned-decompiler.c"),
	target = join(root, "owned.so"),
	script = join(root, "ClineDecompileSelected.java");
writeFileSync(script, TARGETED_GHIDRA_SCRIPT);
const build = spawnSync(
	"gcc",
	["-O0", "-g", "-fPIC", "-shared", source, "-o", target],
	{ encoding: "utf8", timeout: 30000 },
);
if (build.status !== 0) throw new Error("Owned native compile failed");
const run = spawnSync(
	join(resolve(home), "support", "analyzeHeadless"),
	[
		root,
		"project",
		"-import",
		target,
		"-scriptPath",
		root,
		"-postScript",
		"ClineDecompileSelected.java",
		join(root, "indirect.c"),
		"symbol",
		Buffer.from("owned_indirect").toString("base64"),
		"-postScript",
		"ClineDecompileSelected.java",
		join(root, "direct.c"),
		"symbol",
		Buffer.from("owned_direct").toString("base64"),
		"-deleteProject",
	],
	{ encoding: "utf8", timeout: 120000, maxBuffer: 2 * 1024 * 1024 },
);
writeFileSync(
	join(root, "headless.log"),
	String(run.stdout) + String(run.stderr),
);
if (run.status !== 0)
	throw new Error("Real Ghidra owned fixture failed; see headless.log");
const indirect = TargetedNativeEvidenceSchema.parse(
		JSON.parse(readFileSync(join(root, "indirect.c.native.json"), "utf8")),
	),
	direct = TargetedNativeEvidenceSchema.parse(
		JSON.parse(readFileSync(join(root, "direct.c.native.json"), "utf8")),
	);
if (
	!direct.pseudocode.includes("owned_add") ||
	!direct.callees.some((c) => c.kind === "direct" && c.targetAddressHex) ||
	!indirect.callees.some(
		(c) =>
			c.kind === "indirect" &&
			c.resolution === "unknown-memory-register-or-ambiguous-phi",
	)
)
	throw new Error(
		"Actual selected pseudocode/call fixtures did not match owned expectations",
	);
const sha = (v: Uint8Array | string) =>
	createHash("sha256").update(v).digest("hex");
const report = {
	scope:
		"actual Ghidra selected owned ELF pseudocode and p-code calls only; no target execution",
	status: "passed",
	adapterSha256: sha(TARGETED_GHIDRA_SCRIPT),
	fixtureSourceSha256: sha(readFileSync(source)),
	fixtureArtifactSha256: sha(readFileSync(target)),
	directCalls: direct.callees,
	indirectCalls: indirect.callees,
};
writeFileSync(
	join(root, "report.json"),
	JSON.stringify(report, null, 2) + "\n",
);
console.log(JSON.stringify(report));
