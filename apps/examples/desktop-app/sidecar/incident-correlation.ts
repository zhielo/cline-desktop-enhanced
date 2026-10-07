import { z } from "zod";
import { archiveRead, digest, ownedFile } from "./incident-artifacts";

const Hash = z.string().regex(/^[a-f0-9]{64}$/);
const Input = z.discriminatedUnion("kind", [
	z
		.object({
			kind: z.literal("java"),
			apkSha256: Hash,
			mapping: z.string().min(1),
			mappingSha256: Hash,
			className: z.string().min(1).max(500),
			method: z.string().min(1).max(300),
		})
		.strict(),
	z
		.object({
			kind: z.literal("native"),
			apkSha256: Hash,
			module: z.string().min(1),
			moduleSha256: Hash,
			buildId: z.string().regex(/^[a-f0-9]{8,128}$/),
			abi: z.enum(["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]),
			pc: z.string().regex(/^0x[0-9a-fA-F]{1,16}$/),
			loadBias: z
				.string()
				.regex(/^0x[0-9a-fA-F]{1,16}$/)
				.default("0x0"),
		})
		.strict(),
]);
/** ELF file-backed address resolution, never a recovered runtime CFG or guessed symbol. */
export function elfIdentity(b: Buffer) {
	const check = (at: number, size: number) => {
		if (!Number.isSafeInteger(at) || at < 0 || size < 0 || at + size > b.length)
			throw new Error("ELF bounds invalid");
	};
	check(0, 52);
	if (
		b.subarray(0, 4).toString("hex") !== "7f454c46" ||
		b[5] !== 1 ||
		![1, 2].includes(b[4])
	)
		throw new Error("Only little-endian ELF32/64 supported");
	const wide = b[4] === 2;
	if (wide) check(0, 64);
	const u = (at: number, size: number) => {
		check(at, size);
		const n = size === 8 ? b.readBigUInt64LE(at) : BigInt(b.readUInt32LE(at));
		if (n > BigInt(Number.MAX_SAFE_INTEGER))
			throw new Error("ELF integer exceeds address budget");
		return Number(n);
	};
	const machine = b.readUInt16LE(18),
		abi = (
			{ 183: "arm64-v8a", 40: "armeabi-v7a", 3: "x86", 62: "x86_64" } as Record<
				number,
				string
			>
		)[machine];
	if (!abi) throw new Error("Unsupported ELF architecture");
	const offset = u(wide ? 32 : 28, wide ? 8 : 4),
		width = b.readUInt16LE(wide ? 54 : 42),
		count = b.readUInt16LE(wide ? 56 : 44);
	if (count > 1024 || width < (wide ? 56 : 32))
		throw new Error("ELF segment budget");
	check(offset, width * count);
	const segments: {
		address: number;
		offset: number;
		bytes: number;
		executable: boolean;
	}[] = [];
	const buildIds: string[] = [];
	for (let i = 0; i < count; i++) {
		const at = offset + i * width,
			type = b.readUInt32LE(at),
			file = u(at + (wide ? 8 : 4), wide ? 8 : 4),
			address = u(at + (wide ? 16 : 8), wide ? 8 : 4),
			bytes = u(at + (wide ? 32 : 16), wide ? 8 : 4),
			flags = b.readUInt32LE(at + (wide ? 4 : 24));
		check(file, bytes);
		if (type === 1)
			segments.push({
				address,
				offset: file,
				bytes,
				executable: !!(flags & 1),
			});
		if (type === 4) {
			if (bytes > 1048576) throw new Error("ELF note budget");
			let p = file;
			while (p + 12 <= file + bytes) {
				const names = b.readUInt32LE(p),
					desc = b.readUInt32LE(p + 4),
					note = b.readUInt32LE(p + 8);
				p += 12;
				const np = p,
					dp = p + Math.ceil(names / 4) * 4,
					end = dp + Math.ceil(desc / 4) * 4;
				if (end > file + bytes) throw new Error("ELF note bounds");
				if (
					note === 3 &&
					names === 4 &&
					b.subarray(np, np + 4).equals(Buffer.from("GNU\0")) &&
					desc >= 4 &&
					desc <= 64
				)
					buildIds.push(b.subarray(dp, dp + desc).toString("hex"));
				p = end;
			}
		}
	}
	const symbols: { name: string; address: number; size: number }[] = [];
	const sh = u(wide ? 40 : 32, wide ? 8 : 4),
		sw = b.readUInt16LE(wide ? 58 : 46),
		sc = b.readUInt16LE(wide ? 60 : 48);
	if (sc > 4096 || (sc && sw < (wide ? 64 : 40)))
		throw new Error("ELF section budget");
	check(sh, sw * sc);
	for (let i = 0; i < sc; i++) {
		const at = sh + i * sw,
			type = b.readUInt32LE(at + 4);
		if (type !== 2 && type !== 11) continue;
		const start = u(at + (wide ? 24 : 16), wide ? 8 : 4),
			bytes = u(at + (wide ? 32 : 20), wide ? 8 : 4),
			link = b.readUInt32LE(at + (wide ? 40 : 24)),
			entry = u(at + (wide ? 56 : 36), wide ? 8 : 4);
		if (link >= sc || entry < (wide ? 24 : 16) || bytes / entry > 100000)
			throw new Error("ELF symbol budget");
		check(start, bytes);
		const str = sh + link * sw,
			so = u(str + (wide ? 24 : 16), wide ? 8 : 4),
			ss = u(str + (wide ? 32 : 20), wide ? 8 : 4);
		check(so, ss);
		for (let p = start; p + entry <= start + bytes; p += entry) {
			const name = b.readUInt32LE(p),
				info = b[p + (wide ? 4 : 12)];
			if ((info & 15) !== 2 || name >= ss) continue;
			const address = u(p + (wide ? 8 : 4), wide ? 8 : 4),
				size = u(p + (wide ? 16 : 8), wide ? 8 : 4);
			if (!size) continue;
			const end = b.indexOf(0, so + name);
			if (end < so + name || end >= so + ss || end - so - name > 1000) continue;
			symbols.push({
				name: b.subarray(so + name, end).toString("utf8"),
				address,
				size,
			});
			if (symbols.length >= 20000) throw new Error("ELF function budget");
		}
	}
	return { abi, buildIds: [...new Set(buildIds)], segments, symbols };
}
export async function correlateIncident(
	root: string,
	request: {
		target_sha256?: string;
		candidate_sha256?: string;
		operation: string;
		target?: string;
		compare_target?: string;
	},
	value: unknown,
): Promise<Record<string, unknown>> {
	const input = Input.parse(value),
		expected =
			request.operation === "validate_apk_patch"
				? request.candidate_sha256
				: request.target_sha256;
	if (input.apkSha256 !== expected)
		throw new Error("Correlation APK hash differs from the observed build");
	if (input.kind === "java") {
		const f = await ownedFile(root, input.mapping, 8 * 1024 * 1024);
		if (f.sha256 !== input.mappingSha256)
			throw new Error("Mapping SHA-256 mismatch");
		let original: string | undefined,
			inClass = false;
		const matches: string[] = [];
		for (const line of f.bytes.toString("utf8").split(/\r?\n/)) {
			const klass = line.match(/^([^\s].*?) -> ([^\s]+):$/);
			if (klass) {
				inClass = klass[2] === input.className;
				original = klass[1];
				continue;
			}
			if (!inClass) continue;
			const method = line.match(/^\s+(.+?) -> (\S+)$/);
			if (method && method[2] === input.method && method[1].includes("("))
				matches.push(`${original}.${method[1]}`);
		}
		const candidates = [...new Set(matches)].slice(0, 100);
		return {
			kind: "java",
			apkSha256: input.apkSha256,
			mappingSha256: f.sha256,
			status: candidates.length === 1 ? "candidate-match" : "unresolved",
			candidates,
			proof:
				"Operator-bound mapping hash, not proof that this mapping was generated for the APK. Overloads/line-number recovery require exact build mapping and retrace validation.",
		};
	}
	const apkPath =
		request.operation === "validate_apk_patch"
			? request.compare_target
			: request.target;
	if (!apkPath)
		throw new Error("Observed APK path required for native module provenance");
	const container = await ownedFile(root, apkPath);
	if (container.sha256 !== input.apkSha256)
		throw new Error("Observed APK file changed");
	const moduleName = input.module.split(/[\\/]/).at(-1)!;
	const embedded = archiveRead(
		container.bytes,
		`lib/${input.abi}/${moduleName}`,
		64 * 1024 * 1024,
	);
	if (embedded.sha256 !== input.moduleSha256)
		throw new Error("Native module is not the exact observed APK library");
	const f = await ownedFile(root, input.module),
		elf = elfIdentity(f.bytes);
	if (
		f.sha256 !== input.moduleSha256 ||
		elf.abi !== input.abi ||
		elf.buildIds.length !== 1 ||
		elf.buildIds[0] !== input.buildId
	)
		throw new Error(
			"Native module SHA-256/ABI/build-ID mismatch or unavailable",
		);
	const addressBig = BigInt(input.pc) - BigInt(input.loadBias);
	if (addressBig < 0 || addressBig > BigInt(Number.MAX_SAFE_INTEGER))
		throw new Error("Invalid load-bias/PC address");
	const address = Number(addressBig),
		segments = elf.segments.filter(
			(s) =>
				s.executable && address >= s.address && address < s.address + s.bytes,
		);
	if (segments.length !== 1)
		throw new Error("PC is not in a unique executable file-backed range");
	const symbols = elf.symbols
		.filter((s) => address >= s.address && address < s.address + s.size)
		.slice(0, 100);
	return {
		kind: "native",
		apkSha256: input.apkSha256,
		moduleSha256: digest(f.bytes),
		buildId: input.buildId,
		abi: elf.abi,
		virtualAddress: `0x${address.toString(16)}`,
		fileOffset: segments[0].offset + address - segments[0].address,
		status: symbols.length === 1 ? "symbol-range-match" : "unresolved",
		symbols,
		proof:
			"Exact module identity and ELF range only. Runtime load bias/module provenance supplied by operator; not independently attested. Stripped/ambiguous functions remain unresolved; use approval-gated exact-function IDA/Ghidra analysis.",
	};
}
