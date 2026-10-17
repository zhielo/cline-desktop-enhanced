/** Header declarations only. Never loads/executes an image or infers live OS policy. */
export function inspectBinaryMitigations(bytes: Uint8Array) {
	const b = Buffer.from(bytes);
	const range = (o: number, n: number) => {
		if (
			!Number.isSafeInteger(o) ||
			!Number.isSafeInteger(n) ||
			o < 0 ||
			n < 0 ||
			o + n > b.length
		)
			throw new Error("Truncated binary header/range");
	};
	range(0, 4);
	if (b[0] === 0x4d && b[1] === 0x5a) {
		range(0x3c, 4);
		const pe = b.readUInt32LE(0x3c);
		range(pe, 24);
		if (b.readUInt32LE(pe) !== 0x4550) throw new Error("Invalid PE signature");
		const opt = pe + 24,
			size = b.readUInt16LE(pe + 20);
		range(opt, size);
		if (size < 72 || ![0x10b, 0x20b].includes(b.readUInt16LE(opt)))
			throw new Error("Unsupported/truncated PE optional header");
		const flags = b.readUInt16LE(opt + 70);
		return {
			schemaVersion: 1,
			status: "partial",
			format: "pe",
			architecture: `machine:0x${b.readUInt16LE(pe + 4).toString(16)}`,
			evidence: {
				dllCharacteristics: flags,
				aslrDeclared: !!(flags & 0x40),
				nxCompatibleDeclared: !!(flags & 0x100),
				highEntropyVaDeclared: !!(flags & 0x20),
				controlFlowGuardDeclared: !!(flags & 0x4000),
				noSehDeclared: !!(flags & 0x400),
			},
			limitations: [
				"PE optional-header flag declarations only. Relocation usability, load-config/CFG tables, OS enforcement, signed status, exploitability and runtime policy are not validated.",
			],
		};
	}
	if (b.subarray(0, 4).equals(Buffer.from([0x7f, 69, 76, 70]))) {
		const wide = b[4] === 2,
			little = b[5] === 1;
		if (![1, 2].includes(b[4]) || ![1, 2].includes(b[5]))
			throw new Error("Unsupported ELF encoding");
		const u16 = (o: number) => {
			range(o, 2);
			return little ? b.readUInt16LE(o) : b.readUInt16BE(o);
		};
		const u32 = (o: number) => {
			range(o, 4);
			return little ? b.readUInt32LE(o) : b.readUInt32BE(o);
		};
		const word = (o: number) => {
			if (!wide) return u32(o);
			range(o, 8);
			const v = little ? b.readBigUInt64LE(o) : b.readBigUInt64BE(o);
			if (v > BigInt(Number.MAX_SAFE_INTEGER))
				throw new Error("ELF file range exceeds safe integer");
			return Number(v);
		};
		range(0, wide ? 64 : 52);
		const ph = word(wide ? 32 : 28),
			entry = u16(wide ? 54 : 42),
			count = u16(wide ? 56 : 44);
		if (count === 65535 || count > 1024 || entry < (wide ? 56 : 32))
			throw new Error("ELF program header count/layout unsupported");
		range(ph, entry * count);
		const segments: {
			type: number;
			flags: number;
			offset: number;
			size: number;
		}[] = [];
		for (let i = 0; i < count; i++) {
			const at = ph + i * entry;
			const s = {
				type: u32(at),
				flags: u32(at + (wide ? 4 : 24)),
				offset: word(at + (wide ? 8 : 4)),
				size: word(at + (wide ? 32 : 16)),
			};
			range(s.offset, s.size);
			segments.push(s);
		}
		const stacks = segments.filter((s) => s.type === 0x6474e551),
			relro = segments.some((s) => s.type === 0x6474e552);
		let bindNow = false,
			dynamicEntries = 0;
		for (const seg of segments.filter((s) => s.type === 2)) {
			const width = wide ? 16 : 8;
			if (seg.size % width) throw new Error("Invalid ELF dynamic range");
			for (let at = seg.offset; at < seg.offset + seg.size; at += width) {
				if (++dynamicEntries > 4096)
					throw new Error("ELF dynamic entry budget exceeded");
				const tag = word(at),
					v = word(at + width / 2);
				if (tag === 0) break;
				if (
					tag === 24 ||
					(tag === 30 && !!(v & 8)) ||
					(tag === 0x6ffffffb && !!(v & 1))
				)
					bindNow = true;
			}
		}
		return {
			schemaVersion: 1,
			status: "partial",
			format: "elf",
			architecture: `machine:${u16(18)}`,
			evidence: {
				elfType: u16(16),
				positionIndependentImageCandidate: u16(16) === 3,
				gnuStack:
					stacks.length === 1
						? { executable: !!(stacks[0].flags & 1) }
						: "absent-or-ambiguous",
				gnuRelroSegment: relro,
				bindNowDeclared: bindNow,
				relroMetadata: relro
					? bindNow
						? "full-relro-candidate"
						: "partial-relro-candidate"
					: "not-declared",
				writableExecutableLoadSegments: segments.filter(
					(s) => s.type === 1 && (s.flags & 3) === 3,
				).length,
			},
			limitations: [
				"ELF program-header/dynamic declarations only, not live page protections, exploitability or loader enforcement. ET_DYN can be a library; PIE executable status is not established.",
				"Absent/ambiguous GNU_STACK is unknown, not proof of executable or non-executable stack. Extended program-header counts are unsupported.",
			],
		};
	}
	throw new Error("Mitigation adapter supports bounded PE/ELF headers only");
}
