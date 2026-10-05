import { describe, expect, it } from "bun:test";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { recoverNativeCrosscheck } from "../src/extensions/tools/executors/native-crosscheck";

const ghidra = process.env.CLINE_RE_GHIDRA,
	rizin = process.env.CLINE_RE_RIZIN;
if (!ghidra || !rizin || !isAbsolute(ghidra) || !isAbsolute(rizin))
	throw new Error(
		"Both reviewed absolute static engines are required; this real corpus never skips",
	);
describe("real two-engine same-artifact reconciliation", () => {
	it("reconciles entry locations on the same owned ELF without claiming semantic equivalence", async () => {
		const directory = await mkdtemp(
			join(tmpdir(), "cline-native-crosscheck-corpus-"),
		);
		try {
			const source = join(directory, "owned.c"),
				artifact = join(directory, "owned.so");
			await writeFile(
				source,
				"unsigned analyze_fixture(unsigned x) { unsigned y=(x^90)+7; for(unsigned i=0;i<3;i++)y=(y<<1)^i; return y; }",
			);
			execFileSync(
				"gcc",
				["-shared", "-fPIC", "-O1", "-g", source, "-o", artifact],
				{ cwd: directory, timeout: 30000, stdio: "pipe" },
			);
			const bytes = await readFile(artifact);
			const result = await recoverNativeCrosscheck(
				{ ghidra, rizin },
				artifact,
				{ functionName: "analyze_fixture", maxFunctions: 1, maxPcodeOps: 512 },
				120000,
			);
			expect(result.status).toBe("completed");
			expect(result.input?.sha256).toBe(
				createHash("sha256").update(bytes).digest("hex"),
			);
			expect(result.input?.bytes).toBe(bytes.length);
			expect(result.evidence.scope).toBe("selected-static-functions");
			expect(result.evidence.agreements).toHaveLength(1);
			expect(result.evidence.agreements).toMatchObject([
				{
					classification: "entry-location-agreement",
					namesAgreeAfterVendorPrefix: true,
					equivalence: "not-proven",
				},
			]);
			expect(result.evidence.nameCandidates).toEqual([]);
			expect(result.evidence.unresolved).toEqual([]);
			expect(result.evidence.blockCountsComparable).toBe(false);
			expect(result.evidence.equivalence).toBe("not-proven");
			expect(result.evidence.sourcePrograms).toMatchObject({
				ghidra: { version: "12.1.4" },
				rizin: { version: "0.9.1" },
			});
			expect(result.limitations.join(" ")).toContain("No target execution");
		} finally {
			await rm(directory, { recursive: true, force: true });
		}
	}, 180000);
});
