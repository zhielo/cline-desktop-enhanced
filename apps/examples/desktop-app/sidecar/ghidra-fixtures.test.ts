import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";
import {
	GHIDRA_ACCEPTANCE_ARCHITECTURES,
	ghidraAcceptanceFixture,
} from "./ghidra-fixtures";
it("owned architecture fixtures bind exact ELF machine, bitness, bytes and function", () => {
	const expected = {
		x86_64: [2, 62],
		arm32: [1, 40],
		arm64: [2, 183],
	} as const;
	for (const arch of GHIDRA_ACCEPTANCE_ARCHITECTURES) {
		const f = ghidraAcceptanceFixture(arch),
			b = Buffer.from(f.base64, "base64");
		expect(b.subarray(0, 4).toString("hex")).toBe("7f454c46");
		expect(b[4]).toBe(expected[arch][0]);
		expect(b[5]).toBe(1);
		expect(b.readUInt16LE(18)).toBe(expected[arch][1]);
		expect(createHash("sha256").update(b).digest("hex")).toBe(f.sha256);
		expect(f.functionAddress).toMatch(/^0x[0-9a-f]+$/);
	}
	expect(() => ghidraAcceptanceFixture("all")).toThrow("Unsupported");
});
it("ARM32 fixture is reproducible from checked-in generator without executing it", () => {
	execFileSync(
		!!process.versions.bun ? "node" : process.execPath,
		[
			fileURLToPath(
				new URL(
					"../../../../scripts/generate-owned-arm32-fixture.mjs",
					import.meta.url,
				),
			),
			"--check",
		],
		{ timeout: 10000 },
	);
});
