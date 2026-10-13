import type { ILDecoded } from "./il";
import { byteDigest } from "./contracts";
/** Validates bounded EH region declarations, not exception dispatch, stack validity or execution. */
export function inspectExceptionSections(
	bytes: Uint8Array,
	methodRva: number,
	afterCode: number,
	codeLength: number,
	decoded: ILDecoded,
	map: (relative: number, size: number) => number,
) {
	const b = Buffer.from(bytes),
		regions: Array<{
			offset: number;
			kind: "catch" | "filter" | "finally" | "fault";
			tryOffset: number;
			tryLength: number;
			handlerOffset: number;
			handlerLength: number;
			catchTypeToken?: string;
			filterOffset?: number;
			sha256: string;
		}> = [];
	try {
		if (
			!Number.isSafeInteger(methodRva) ||
			methodRva < 0 ||
			methodRva > 0xffffffff ||
			!Number.isSafeInteger(afterCode) ||
			afterCode < codeLength ||
			codeLength < 1 ||
			codeLength > 4096
		)
			throw new Error("Invalid EH method bounds");
		if (decoded.status !== "completed")
			throw new Error(
				"Complete decoded instruction boundaries required for EH regions",
			);
		const starts = new Set<number>();
		let prefix = false;
		for (const i of decoded.instructions) {
			if (!prefix) starts.add(i.offset);
			prefix = i.flow === "prefix";
		}
		const endpoint = (n: number) => n === codeLength || starts.has(n);
		let relative = Math.ceil((methodRva + afterCode) / 4) * 4 - methodRva,
			more = true,
			sections = 0;
		while (more) {
			if (++sections > 4) throw new Error("EH section budget exceeded");
			const at = map(relative, 4),
				flags = b[at],
				fat = !!(flags & 64);
			more = !!(flags & 128);
			if ((flags & 63) !== 1)
				throw new Error("Unsupported additional method section");
			if (!Number.isSafeInteger(at) || at < 0 || at + 4 > b.length)
				throw new Error("EH header mapping outside file");
			const size = fat
					? b[at + 1] | (b[at + 2] << 8) | (b[at + 3] << 16)
					: b[at + 1],
				width = fat ? 24 : 12;
			if (
				size < 4 ||
				size > 4096 ||
				(size - 4) % width ||
				(!fat && (b[at + 2] || b[at + 3]))
			)
				throw new Error("Invalid EH section size/header");
			const whole = map(relative, size);
			if (whole !== at || at + size > b.length)
				throw new Error("EH section mapping changed/outside file");
			const count = (size - 4) / width;
			if (regions.length + count > 64)
				throw new Error("EH clause budget exceeded");
			for (let i = 0; i < count; i++) {
				const o = at + 4 + i * width;
				const flag = fat ? b.readUInt32LE(o) : b.readUInt16LE(o),
					tryOffset = fat ? b.readUInt32LE(o + 4) : b.readUInt16LE(o + 2),
					tryLength = fat ? b.readUInt32LE(o + 8) : b[o + 4],
					handlerOffset = fat ? b.readUInt32LE(o + 12) : b.readUInt16LE(o + 5),
					handlerLength = fat ? b.readUInt32LE(o + 16) : b[o + 7],
					value = b.readUInt32LE(o + (fat ? 20 : 8));
				const kind = (
					{ 0: "catch", 1: "filter", 2: "finally", 4: "fault" } as const
				)[flag as 0 | 1 | 2 | 4];
				if (
					!kind ||
					!tryLength ||
					!handlerLength ||
					!starts.has(tryOffset) ||
					!starts.has(handlerOffset) ||
					tryOffset + tryLength > codeLength ||
					handlerOffset + handlerLength > codeLength ||
					!endpoint(tryOffset + tryLength) ||
					!endpoint(handlerOffset + handlerLength) ||
					(tryOffset < handlerOffset + handlerLength &&
						handlerOffset < tryOffset + tryLength)
				)
					throw new Error("Invalid EH flags/ranges/instruction boundaries");
				if (
					kind === "catch" &&
					(![1, 2, 27].includes(value >>> 24) || !(value & 0xffffff))
				)
					throw new Error("Invalid EH catch type token");
				if (kind === "filter" && (!starts.has(value) || value >= handlerOffset))
					throw new Error("Invalid EH filter offset");
				if ((kind === "finally" || kind === "fault") && value !== 0)
					throw new Error("Unexpected EH reserved value");
				regions.push({
					offset: o,
					kind,
					tryOffset,
					tryLength,
					handlerOffset,
					handlerLength,
					...(kind === "catch"
						? { catchTypeToken: `0x${value.toString(16).padStart(8, "0")}` }
						: {}),
					...(kind === "filter" ? { filterOffset: value } : {}),
					sha256: byteDigest(b.subarray(o, o + width)),
				});
			}
			relative = Math.ceil((methodRva + relative + size) / 4) * 4 - methodRva;
		}
		return {
			status: "completed" as const,
			regions,
			limitations: [
				"EH region declarations/entry associations only; nesting/dispatch precedence, filter outcomes, stack/type validity and execution are not established.",
			],
		};
	} catch (e) {
		return {
			status: "partial" as const,
			regions: [],
			limitations: [e instanceof Error ? e.message : "Malformed EH sections"],
		};
	}
}
