/**
 * Explicit local acceptance on an authorized licensed IDA installation.
 * Runs IDA against an owned static fixture; never executes that ELF.
 */
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, isAbsolute } from "node:path";
import { createReverseEngineeringExecutor } from "@cline/core";
if (
	process.env.CLINE_TEST_IDA_LICENSED !== "1" ||
	!process.env.IDA_HOME ||
	!isAbsolute(process.env.IDA_HOME)
)
	throw new Error(
		"Explicit CLINE_TEST_IDA_LICENSED=1 and absolute authorized IDA_HOME required",
	);
const root = join(
	process.cwd(),
	".cline-validation",
	`licensed-ida-${Date.now()}`,
);
await mkdir(root, { recursive: true });
const fixture = JSON.parse(
	await readFile(
		new URL("./fixtures/owned-native-elf.json", import.meta.url),
		"utf8",
	),
);
const bytes = Buffer.from(fixture.base64, "base64");
if (createHash("sha256").update(bytes).digest("hex") !== fixture.sha256)
	throw new Error("Owned fixture identity mismatch");
const target = join(root, "owned.so");
await writeFile(target, bytes, { flag: "wx" });
const result = JSON.parse(
	await createReverseEngineeringExecutor()(
		{
			engine: "ida",
			operation: "decompile",
			target,
			function_selector: { address: fixture.functionAddress },
			output_directory: join(root, "analysis"),
			timeout_ms: 120_000,
		},
		{} as never,
	),
);
await writeFile(
	join(root, "acceptance.json"),
	JSON.stringify(
		{
			status: result.succeeded ? "passed" : "failed",
			fixtureSha256: fixture.sha256,
			coverage:
				"owned-selected-x86_64-function-only-not-universal-license-or-architecture-validation",
			result,
		},
		null,
		2,
	),
);
if (!result.succeeded || !result.artifactVerified)
	throw new Error(
		`Licensed selected-function IDA acceptance failed; inspect ${root}`,
	);
console.log(`Licensed selected-function IDA acceptance passed: ${root}`);
