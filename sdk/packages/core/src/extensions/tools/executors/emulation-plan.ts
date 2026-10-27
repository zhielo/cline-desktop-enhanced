import { canonical } from "../../../analysis/contracts";
import {
	EmulationPlanSchema,
	EMULATION_PROFILE_SHA256,
} from "../emulation-schema";
import type { ReverseEngineeringInput } from "../schemas";
import { candidateHash, readCandidateFile } from "./candidate-files";
/** Admission checks only; no engine import, network, upload or target execution. */
export function inspectEmulationElf(
	data: Uint8Array,
	engine: string,
	architecture: string,
) {
	const b = Buffer.from(data);
	if (
		b.length < 64 ||
		b.length > 16777216 ||
		b.subarray(0, 4).toString("hex") !== "7f454c46" ||
		b[5] !== 1 ||
		b[6] !== 1
	)
		throw new Error("Bounded little-endian ELF required");
	const bits = architecture === "arm32" ? 32 : 64,
		machine =
			architecture === "arm32" ? 40 : architecture === "arm64" ? 183 : 62;
	if (
		b[4] !== (bits === 32 ? 1 : 2) ||
		b.readUInt16LE(18) !== machine ||
		b.readUInt16LE(16) !== (engine === "qiling" ? 2 : 3)
	)
		throw new Error("ELF type or architecture unsupported");
	const number = (n: bigint) => {
		if (n > BigInt(Number.MAX_SAFE_INTEGER))
			throw new Error("ELF integer exceeds exact range");
		return Number(n);
	};
	const entry =
			bits === 64 ? number(b.readBigUInt64LE(24)) : b.readUInt32LE(24),
		off = bits === 64 ? number(b.readBigUInt64LE(32)) : b.readUInt32LE(28),
		size = b.readUInt16LE(bits === 64 ? 54 : 42),
		count = b.readUInt16LE(bits === 64 ? 56 : 44);
	if (
		size !== (bits === 64 ? 56 : 32) ||
		count < 1 ||
		count > 64 ||
		off + size * count > b.length
	)
		throw new Error("Invalid program headers");
	let mapped = 0,
		loaded = false,
		exec = false;
	for (let i = 0; i < count; i++) {
		const p = off + i * size,
			t = b.readUInt32LE(p),
			flags = b.readUInt32LE(p + (bits === 64 ? 4 : 24));
		const offset =
				bits === 64 ? number(b.readBigUInt64LE(p + 8)) : b.readUInt32LE(p + 4),
			addr =
				bits === 64 ? number(b.readBigUInt64LE(p + 16)) : b.readUInt32LE(p + 8),
			filesz =
				bits === 64
					? number(b.readBigUInt64LE(p + 32))
					: b.readUInt32LE(p + 16),
			memsz =
				bits === 64
					? number(b.readBigUInt64LE(p + 40))
					: b.readUInt32LE(p + 20);
		if ((engine === "qiling" ? [2, 3, 7] : [3, 7]).includes(t))
			throw new Error("Interpreter, dynamic or TLS profile unsupported");
		if (t === 1) {
			if (filesz > memsz || offset + filesz > b.length || memsz > 67108864)
				throw new Error("ELF load budget");
			mapped += memsz;
			loaded = true;
			exec ||= !!(flags & 1) && entry >= addr && entry < addr + filesz;
		}
		if (t === 2 && engine !== "qiling") {
			const step = bits === 64 ? 16 : 8;
			if (filesz > 1048576 || offset + filesz > b.length || filesz % step)
				throw new Error("Invalid dynamic table");
			for (let d = offset; d < offset + filesz; d += step) {
				const tag =
					bits === 64 ? b.readBigUInt64LE(d) : BigInt(b.readUInt32LE(d));
				if (tag === 0n) break;
				if (tag === 1n)
					throw new Error("External DT_NEEDED dependencies unsupported");
			}
		}
	}
	if (!loaded || mapped > 67108864 || (engine === "qiling" && !exec))
		throw new Error("Mapped image/entry unsupported");
	return { mappedBytes: mapped, entry: `0x${entry.toString(16)}` };
}
export async function planEmulation(
	input: ReverseEngineeringInput,
	signal?: AbortSignal,
) {
	if (!input.target) throw new Error("Exact target required");
	if (
		input.output_file ||
		input.output_directory ||
		input.compare_target ||
		input.candidate ||
		input.android_project_patch ||
		input.candidate_review ||
		input.candidate_validation ||
		input.runtime_observation_plan
	)
		throw new Error("Emulation planning accepts no writes or other recipes");
	const options = EmulationPlanSchema.parse(input.emulation_plan),
		abort = AbortSignal.any([
			...(signal ? [signal] : []),
			AbortSignal.timeout(Math.min(input.timeout_ms ?? 20000, 20000)),
		]);
	const bytes = await readCandidateFile(input.target, 16777216, abort);
	if (candidateHash(bytes) !== options.expected_sha256)
		throw new Error("Artifact hash changed");
	let compatible = true,
		reason =
			"Header admission passed; loader, JNI exports and behavior remain unverified";
	let admission: unknown;
	try {
		admission = inspectEmulationElf(
			bytes,
			options.engine,
			options.architecture,
		);
	} catch (e) {
		compatible = false;
		reason = e instanceof Error ? e.message : String(e);
	}
	const { expected_sha256, ...selected } = options;
	const nextRequest = compatible
		? {
				operation: "emulate_profile",
				target: input.target,
				...selected,
				timeout_ms: 60000,
			}
		: null;
	if (
		candidateHash(await readCandidateFile(input.target, 16777216, abort)) !==
		expected_sha256
	)
		throw new Error("Artifact changed during planning");
	const receipt = {
		protocol: "cline-emulation-plan/v1",
		operation: "plan_emulation",
		status: "completed",
		effect: "plan-only",
		input: { path: input.target, sha256: expected_sha256, bytes: bytes.length },
		engine: options.engine,
		experimental: options.engine === "rnidbg",
		profileSha256: EMULATION_PROFILE_SHA256,
		compatibility: compatible ? "admission-only" : "unsupported",
		reason,
		admission,
		nextRequest,
		nextRequestSha256: nextRequest
			? candidateHash(canonical(nextRequest))
			: null,
		approval: {
			granted: false,
			requiredMode: ["runtime", "hybrid"],
			requiredTaskKind: "dynamic",
			requiredHumanReview: [
				"artifact-upload",
				"authorized-target-execution",
				"isolated-sandbox",
			],
			prepareCommand: "prepare_analysis_task",
			runCommand: "run_dynamic_analysis",
			hybridStaticEvidenceRequired: true,
		},
		observedExecution: false,
		workerConnected: false,
		limitations: [
			"Optional operator-provisioned offline disposable Linux worker; missing runtime stays blocked. No engine download or automatic fallback.",
			"Qiling: static x86-64 ELF entry, write to stdout/stderr and exit only. Android: no-dependency ARM JNI initialize or exact static (I)I export, no APK/custom stubs or complete Android.",
			"rnidbg is experimental with pinned reviewed upstream compatibility patches; not a mature replacement for unidbg.",
			"A matching scenario assertion never certifies application behavior, target safety or native execution. Unicorn and Speakeasy routes are unchanged.",
		],
	};
	return { ...receipt, receiptSha256: candidateHash(canonical(receipt)) };
}
