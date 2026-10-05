import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";
import { z } from "zod";
import type { AdvancedResult } from "./advanced-analysis";
import {
	NativeRecoveryOptionsSchema,
	recoverNativeProgram,
	validateNativeProgram,
} from "./native-program";
import { RizinProgramSchema, recoverRizinProgram } from "./rizin-program";

const VERSION = "native-location-crosscheck/v1";
const MAX_BYTES = 128 * 1024 * 1024;
const Identity = z.object({
	sha256: z.string().regex(/^[a-f0-9]{64}$/),
	bytes: z.number().int().min(1).max(MAX_BYTES),
});
const LIMITATIONS = [
	"Entry-location agreement concerns static engine interpretations, not function boundaries, behavior or native equivalence.",
	"Ghidra high-p-code CFG blocks and Rizin assembly blocks are different abstractions and are not compared.",
	"Unpaired functions are only absent from the other selected report, not proved absent from the artifact.",
	"Only explicit x86 ELF loaded virtual addresses with matching width and byte order are reconciled in this version.",
	"No target execution, binary patching, measured OS/network containment or whole-program proof.",
];
function outcome(
	status: AdvancedResult["status"],
	reason: string,
): AdvancedResult {
	return {
		protocol: "cline-advanced-analysis/v1",
		status,
		engine: "ghidra-rizin",
		engineVersion: VERSION,
		evidence: { reason, equivalence: "not-proven" },
		limitations: LIMITATIONS,
	};
}
function digest(value: unknown) {
	return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function canonicalName(name: string) {
	// Literal vendor prefixes only; names remain heuristic hints, never keys for agreement.
	return name.replace(/^(?:dbg\.|sym\.)/, "");
}
function relative(address: string, base: string, bits: number): string | null {
	const a = BigInt(`0x${address}`),
		b = BigInt(`0x${base}`);
	const ceiling = BigInt(1) << BigInt(bits);
	return a >= b && a < ceiling && b < ceiling ? (a - b).toString(16) : null;
}
/** Compare bounded reports, not trusted assertions. Engine-produced hashes bind bytes, not semantic truth. */
export function compareNativeLocations(
	ghidra: AdvancedResult,
	rizin: AdvancedResult,
): AdvancedResult {
	if (Buffer.byteLength(JSON.stringify([ghidra, rizin]), "utf8") > 2 * 1048576)
		throw new Error("Crosscheck source evidence byte budget exceeded");
	if (ghidra.engine !== "ghidra" || rizin.engine !== "rizin")
		throw new Error("Expected Ghidra and Rizin reports");
	for (const report of [ghidra, rizin]) {
		if (report.status === "cancelled")
			return outcome("cancelled", "One static engine was cancelled");
		if (report.status !== "completed" && report.status !== "partial")
			return outcome(
				report.status,
				"Both static engines must recover evidence before comparison",
			);
	}
	const gIdentity = Identity.parse(ghidra.input),
		rIdentity = Identity.parse(rizin.input);
	if (
		gIdentity.sha256 !== rIdentity.sha256 ||
		gIdentity.bytes !== rIdentity.bytes
	)
		return outcome(
			"failed",
			"Artifact identity mismatch; engine reports cannot be reconciled",
		);
	const g = validateNativeProgram(ghidra.evidence.program);
	const r = RizinProgramSchema.parse(rizin.evidence.program);
	if (
		ghidra.engineVersion !== g.engineVersion ||
		rizin.engineVersion !== r.engineVersion
	)
		throw new Error("Conflicting engine version provenance");
	// Deliberately conservative: do not guess architecture aliases, overlays or legacy coordinates.
	const language = /^x86:(LE|BE):(32|64):[^:]+$/.exec(g.language);
	if (
		!language ||
		r.architecture !== "x86" ||
		r.bits !== Number(language[2]) ||
		r.byteOrder !== language[1] ||
		g.executableFormat !== "Executable and Linking Format (ELF)" ||
		r.format !== "elf"
	)
		return outcome(
			"partial",
			"Unsupported or conflicting architecture, byte order or executable format",
		);
	if (!g.imageBase || g.addressSpace !== "ram" || r.imageBase === null)
		return outcome(
			"partial",
			"Explicit compatible image bases and address spaces are required",
		);

	type Location = { name: string; entry: string; relativeEntry: string };
	const unresolved: Array<{ engine: string; name: string; reason: string }> =
		[];
	const gLocations: Location[] = [],
		rLocations: Location[] = [];
	for (const fn of g.functions) {
		const address = fn.entryAddress;
		const offset =
			address?.space === "ram"
				? relative(address.offsetHex, g.imageBase, r.bits)
				: null;
		if (!address || offset === null || fn.status === "failed") {
			unresolved.push({
				engine: "ghidra",
				name: fn.name,
				reason: "Missing, non-ram, below-base or failed entry evidence",
			});
		} else
			gLocations.push({
				name: fn.name,
				entry: address.offsetHex,
				relativeEntry: offset,
			});
	}
	for (const fn of r.functions) {
		const offset = relative(fn.entry, r.imageBase, r.bits);
		if (offset === null)
			unresolved.push({
				engine: "rizin",
				name: fn.name,
				reason: "Entry is below the declared image base",
			});
		else
			rLocations.push({
				name: fn.name,
				entry: fn.entry,
				relativeEntry: offset,
			});
	}
	for (const locations of [gLocations, rLocations])
		if (
			new Set(locations.map((fn) => fn.relativeEntry)).size !== locations.length
		)
			throw new Error("Duplicate normalized function entry");
	const rByEntry = new Map(rLocations.map((fn) => [fn.relativeEntry, fn]));
	const matched = new Set<string>();
	const agreements = gLocations.flatMap((fn) => {
		const other = rByEntry.get(fn.relativeEntry);
		if (!other) return [];
		matched.add(fn.relativeEntry);
		return [
			{
				classification: "entry-location-agreement",
				relativeEntry: fn.relativeEntry,
				ghidra: fn,
				rizin: other,
				namesAgreeAfterVendorPrefix:
					canonicalName(fn.name) === canonicalName(other.name),
				equivalence: "not-proven",
			},
		];
	});
	const ghidraOnly = gLocations.filter((fn) => !matched.has(fn.relativeEntry));
	const rizinOnly = rLocations.filter((fn) => !matched.has(fn.relativeEntry));
	const nameCandidates = ghidraOnly.flatMap((fn) => {
		const name = canonicalName(fn.name);
		const sameG = ghidraOnly.filter((x) => canonicalName(x.name) === name);
		const sameR = rizinOnly.filter((x) => canonicalName(x.name) === name);
		if (!name || sameG.length !== 1 || sameR.length !== 1) return [];
		return [
			{
				classification: "name-only-candidate",
				ghidra: fn,
				rizin: sameR[0],
				entryInterpretation: "different-relative-entry",
				equivalence: "not-proven",
			},
		];
	});
	const evidence = {
		scope: "selected-static-functions",
		coordinateSystem: "image-relative-loaded-virtual-address",
		equivalence: "not-proven",
		sourcePrograms: {
			ghidra: {
				sha256: digest(g),
				version: g.engineVersion,
				imageBase: g.imageBase,
				coverage: g.coverage,
			},
			rizin: {
				sha256: digest(r),
				version: r.engineVersion,
				imageBase: r.imageBase,
				coverage: r.coverage,
			},
		},
		agreements,
		ghidraOnlyInSelection: ghidraOnly,
		rizinOnlyInSelection: rizinOnly,
		nameCandidates,
		unresolved,
		blockCountsComparable: false,
	};
	if (Buffer.byteLength(JSON.stringify(evidence), "utf8") > 1048576)
		throw new Error("Crosscheck output byte budget exceeded");
	return {
		protocol: "cline-advanced-analysis/v1",
		engine: "ghidra-rizin",
		engineVersion: VERSION,
		status:
			ghidra.status === "partial" ||
			rizin.status === "partial" ||
			g.coverage.truncated ||
			g.coverage.failedFunctions > 0 ||
			g.functions.some(
				(fn) => fn.status !== "recovered" || fn.entryBlock === null,
			) ||
			r.coverage.truncated ||
			r.functions.length !== r.coverage.selectedFunctions ||
			unresolved.length ||
			ghidraOnly.length ||
			rizinOnly.length ||
			!agreements.length
				? "partial"
				: "completed",
		input: { ...gIdentity, format: "elf" },
		evidence,
		limitations: LIMITATIONS,
	};
}
/** Existing fixed static adapters only; caller cannot select commands or scripts. */
export async function recoverNativeCrosscheck(
	commands: { ghidra?: string; rizin?: string },
	target: string,
	options: unknown = {},
	timeoutMs = 120000,
	signal?: AbortSignal,
): Promise<AdvancedResult> {
	const policy = NativeRecoveryOptionsSchema.parse(options);
	if (
		!isAbsolute(target) ||
		!Number.isInteger(timeoutMs) ||
		timeoutMs < 1000 ||
		timeoutMs > 300000
	)
		throw new Error("Absolute target and bounded shared timeout required");
	if (signal?.aborted)
		return outcome("cancelled", "Cancelled before either static engine");
	if (!commands.ghidra || !commands.rizin)
		return outcome(
			"blocked",
			"Both reviewed Ghidra and Rizin toolchains must be configured",
		);
	if (!isAbsolute(commands.ghidra) || !isAbsolute(commands.rizin))
		throw new Error("Reviewed absolute engine paths required");
	const deadline = Date.now() + timeoutMs;
	const g = await recoverNativeProgram(
		commands.ghidra,
		target,
		policy,
		timeoutMs,
		signal,
	);
	if (signal?.aborted || g.status === "cancelled")
		return outcome("cancelled", "Cancelled during Ghidra recovery");
	if (g.status !== "completed" && g.status !== "partial")
		return outcome(g.status, "Ghidra did not recover bounded evidence");
	const remaining = deadline - Date.now();
	if (remaining < 1000)
		return outcome(
			"failed",
			"Shared crosscheck deadline exhausted before Rizin",
		);
	const r = await recoverRizinProgram(
		commands.rizin,
		target,
		policy,
		remaining,
		signal,
	);
	if (signal?.aborted)
		return outcome("cancelled", "Cancelled during Rizin recovery");
	return compareNativeLocations(g, r);
}
