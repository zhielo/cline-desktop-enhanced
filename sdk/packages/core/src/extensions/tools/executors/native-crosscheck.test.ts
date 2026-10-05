import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import type { AdvancedResult } from "./advanced-analysis";
import {
	compareNativeLocations,
	recoverNativeCrosscheck,
} from "./native-crosscheck";
import type { NativeProgram } from "./native-program";
import type { RizinProgram } from "./rizin-program";

function reports() {
	const g: NativeProgram = {
		schemaVersion: 1,
		producer: "ghidra-high-pcode",
		engineVersion: "unit-ghidra",
		language: "x86:LE:64:default",
		imageBase: "100000",
		addressSpace: "ram",
		executableFormat: "Executable and Linking Format (ELF)",
		functions: [
			{
				name: "owned",
				entry: "00101000",
				entryAddress: { space: "ram", offsetHex: "101000" },
				entryBlock: "b0",
				entryBlockEvidence: "contains-function-entry",
				status: "recovered",
				pseudocode: "return 0;",
				pseudocodeTruncated: false,
				blocks: [{ id: "b0", start: "101000", stop: "10100f", successors: [] }],
				pcode: [],
			},
		],
		coverage: {
			consideredFunctions: 1,
			failedFunctions: 0,
			pcodeOperations: 0,
			truncated: false,
			externalAndThunkFunctionsExcluded: true,
		},
	};
	const r: RizinProgram = {
		schemaVersion: 1,
		producer: "rizin-function-inventory",
		engineVersion: "unit-rizin",
		imageBase: "0",
		byteOrder: "LE",
		architecture: "x86",
		bits: 64,
		format: "elf",
		functions: [
			{ name: "dbg.owned", entry: "1000", size: 16, assemblyBlockCount: 7 },
		],
		coverage: { reportedFunctions: 1, selectedFunctions: 1, truncated: false },
	};
	const input = { sha256: "a".repeat(64), bytes: 100, format: "elf" };
	const ghidra: AdvancedResult = {
		protocol: "cline-advanced-analysis/v1",
		status: "completed",
		engine: "ghidra",
		engineVersion: g.engineVersion,
		input: { ...input },
		evidence: { program: g },
		limitations: [],
	};
	const rizin: AdvancedResult = {
		...ghidra,
		engine: "rizin",
		engineVersion: r.engineVersion,
		input: { ...input },
		evidence: { program: r },
	};
	return { g, r, ghidra, rizin };
}
describe("conservative same-artifact native location reconciliation", () => {
	it("matches image-relative entries with different absolute load bases", () => {
		const { ghidra, rizin } = reports();
		const result = compareNativeLocations(ghidra, rizin);
		expect(result.status).toBe("completed");
		expect(result.evidence.agreements).toMatchObject([
			{
				classification: "entry-location-agreement",
				relativeEntry: "1000",
				equivalence: "not-proven",
			},
		]);
		expect(result.input?.sha256).toBe("a".repeat(64));
		expect(result.evidence.blockCountsComparable).toBe(false);
	});
	it("does not compare high-p-code and assembly block counts", () => {
		const { ghidra, rizin } = reports();
		const result = compareNativeLocations(ghidra, rizin);
		expect(result.evidence.blockCountsComparable).toBe(false);
		expect(result.evidence.equivalence).toBe("not-proven");
	});
	it("rejects distinct artifact hashes", () => {
		const d = reports();
		d.rizin.input!.sha256 = "b".repeat(64);
		expect(compareNativeLocations(d.ghidra, d.rizin).status).toBe("failed");
	});
	it("rejects distinct artifact byte counts", () => {
		const d = reports();
		d.rizin.input!.bytes++;
		expect(compareNativeLocations(d.ghidra, d.rizin).status).toBe("failed");
	});
	it("requires valid nonempty bounded artifact identity", () => {
		const d = reports();
		d.rizin.input!.bytes = 0;
		expect(() => compareNativeLocations(d.ghidra, d.rizin)).toThrow();
	});
	it("preserves exact 64-bit addresses above JavaScript numeric precision", () => {
		const d = reports();
		d.g.imageBase = "ffffffffffff0000";
		d.g.functions[0].entryAddress!.offsetHex = "ffffffffffff0001";
		d.r.imageBase = "ffffffffffff0000";
		d.r.functions[0].entry = "ffffffffffff0001";
		expect(
			compareNativeLocations(d.ghidra, d.rizin).evidence.agreements,
		).toMatchObject([{ relativeEntry: "1" }]);
	});
	it("refuses coordinates wider than the declared address width", () => {
		const d = reports();
		d.g.language = "x86:LE:32:default";
		d.r.bits = 32;
		d.r.functions[0].entry = "100001000";
		expect(
			compareNativeLocations(d.ghidra, d.rizin).evidence.unresolved,
		).toHaveLength(1);
	});
	it("normalizes leading zero coordinates without rounding", () => {
		const d = reports();
		d.r.functions[0].entry = "00001000";
		expect(compareNativeLocations(d.ghidra, d.rizin).status).toBe("completed");
	});
	it("keeps names-only same-name different-location matches heuristic", () => {
		const d = reports();
		d.r.functions[0].entry = "2000";
		const result = compareNativeLocations(d.ghidra, d.rizin);
		expect(result.status).toBe("partial");
		expect(result.evidence.agreements).toEqual([]);
		expect(result.evidence.nameCandidates).toMatchObject([
			{ classification: "name-only-candidate", equivalence: "not-proven" },
		]);
	});
	it("does not manufacture candidates for ambiguous duplicate names", () => {
		const d = reports();
		d.r.functions[0].entry = "2000";
		d.r.functions.push({ ...d.r.functions[0], entry: "3000" });
		d.r.coverage.reportedFunctions = d.r.coverage.selectedFunctions = 2;
		expect(
			compareNativeLocations(d.ghidra, d.rizin).evidence.nameCandidates,
		).toEqual([]);
	});
	it("retains selected-only unmatched functions without claiming absence", () => {
		const d = reports();
		d.r.functions[0].name = "unrelated";
		d.r.functions[0].entry = "2000";
		const result = compareNativeLocations(d.ghidra, d.rizin);
		expect(result.status).toBe("partial");
		expect(result.evidence.ghidraOnlyInSelection).toHaveLength(1);
		expect(result.evidence.rizinOnlyInSelection).toHaveLength(1);
	});
	it("records renamed symbols as location agreement, not name agreement", () => {
		const d = reports();
		d.r.functions[0].name = "renamed";
		expect(
			compareNativeLocations(d.ghidra, d.rizin).evidence.agreements,
		).toMatchObject([{ namesAgreeAfterVendorPrefix: false }]);
	});
	it("keeps truncated recovery partial", () => {
		const d = reports();
		d.ghidra.status = "partial";
		d.g.coverage.truncated = true;
		expect(compareNativeLocations(d.ghidra, d.rizin).status).toBe("partial");
	});
	it("does not upgrade incomplete coverage hidden by a completed wrapper", () => {
		const d = reports();
		d.g.coverage.truncated = true;
		expect(compareNativeLocations(d.ghidra, d.rizin).status).toBe("partial");
		d.g.coverage.truncated = false;
		d.r.coverage.selectedFunctions = d.r.coverage.reportedFunctions = 2;
		expect(compareNativeLocations(d.ghidra, d.rizin).status).toBe("partial");
	});
	it("does not guess legacy image bases or entry coordinates", () => {
		const d = reports();
		delete d.g.imageBase;
		expect(compareNativeLocations(d.ghidra, d.rizin).status).toBe("partial");
		d.g.imageBase = "100000";
		delete d.g.functions[0].entryAddress;
		expect(
			compareNativeLocations(d.ghidra, d.rizin).evidence.unresolved,
		).toHaveLength(1);
	});
	it("refuses overlay address spaces", () => {
		const d = reports();
		d.g.functions[0].entryAddress!.space = "overlay";
		expect(
			compareNativeLocations(d.ghidra, d.rizin).evidence.unresolved,
		).toHaveLength(1);
	});
	it("does not wrap negative relative entries", () => {
		const d = reports();
		d.r.imageBase = "2000";
		expect(
			compareNativeLocations(d.ghidra, d.rizin).evidence.unresolved,
		).toHaveLength(1);
	});
	it("rejects duplicate normalized entries even with distinct textual spellings", () => {
		const d = reports();
		d.r.functions.push({ ...d.r.functions[0], entry: "00001000" });
		d.r.coverage.reportedFunctions = d.r.coverage.selectedFunctions = 2;
		expect(() => compareNativeLocations(d.ghidra, d.rizin)).toThrow(
			"Duplicate normalized",
		);
	});
	it("does not infer architecture, endian or format compatibility", () => {
		for (const mutate of [
			(d: ReturnType<typeof reports>) => {
				d.r.bits = 32;
			},
			(d: ReturnType<typeof reports>) => {
				d.r.byteOrder = "BE";
			},
			(d: ReturnType<typeof reports>) => {
				delete d.r.byteOrder;
			},
			(d: ReturnType<typeof reports>) => {
				d.r.format = "pe";
			},
			(d: ReturnType<typeof reports>) => {
				d.g.language = "AARCH64:LE:64:v8A";
			},
		]) {
			const d = reports();
			mutate(d);
			expect(compareNativeLocations(d.ghidra, d.rizin).status).toBe("partial");
		}
	});
	it("rejects engine identity and version contradictions", () => {
		const d = reports();
		d.ghidra.engineVersion = "different";
		expect(() => compareNativeLocations(d.ghidra, d.rizin)).toThrow(
			"version provenance",
		);
		d.ghidra.engine = "imported";
		expect(() => compareNativeLocations(d.ghidra, d.rizin)).toThrow("Expected");
	});
	it("propagates blocked, failed and cancelled engines without claiming agreement", () => {
		for (const status of ["blocked", "failed", "cancelled"] as const) {
			const d = reports();
			d.rizin.status = status;
			expect(compareNativeLocations(d.ghidra, d.rizin).status).toBe(status);
		}
	});
	it("rejects oversized source evidence", () => {
		const d = reports();
		d.ghidra.evidence.padding = "x".repeat(2 * 1048576);
		expect(() => compareNativeLocations(d.ghidra, d.rizin)).toThrow(
			"byte budget",
		);
	});
	it("does not manufacture agreement from empty selections", () => {
		const d = reports();
		d.g.functions = [];
		d.g.coverage.consideredFunctions = 0;
		expect(compareNativeLocations(d.ghidra, d.rizin).status).toBe("partial");
	});
	it("blocks missing toolchains before artifact acquisition", async () => {
		expect((await recoverNativeCrosscheck({}, resolve("missing"))).status).toBe(
			"blocked",
		);
	});
	it("honors pre-acquisition cancellation", async () => {
		const a = new AbortController();
		a.abort();
		expect(
			(
				await recoverNativeCrosscheck(
					{},
					resolve("missing"),
					{},
					1000,
					a.signal,
				)
			).status,
		).toBe("cancelled");
	});
	it("rejects caller scripts, relative commands and invalid shared deadlines", async () => {
		await expect(
			recoverNativeCrosscheck({}, resolve("missing"), { script: "caller" }),
		).rejects.toThrow();
		await expect(
			recoverNativeCrosscheck(
				{ ghidra: "ghidra", rizin: "rizin" },
				resolve("missing"),
			),
		).rejects.toThrow("absolute");
		await expect(
			recoverNativeCrosscheck({}, resolve("missing"), {}, 999),
		).rejects.toThrow("timeout");
	});
});
