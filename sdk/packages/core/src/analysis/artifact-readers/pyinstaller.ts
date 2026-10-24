/** Bounded CArchive cookie/TOC inventory. Format reference: PyInstaller archive/writers.py.
 * No decompression, PYZ/marshal parsing, extraction or bootloader execution. */
export function readPyInstallerInventory(bytes: Buffer) {
	const magic = Buffer.from("MEI\x0c\x0b\x0a\x0b\x0e"),
		floor = Math.max(0, bytes.length - 16 * 1024 * 1024);
	let cursor = bytes.length,
		attempts = 0;
	while (cursor > floor) {
		const at = bytes.lastIndexOf(magic, cursor - 1);
		if (at < floor) break;
		cursor = at;
		if (++attempts > 4096)
			throw new Error("CArchive cookie candidate budget exceeded");
		if (at + 24 > bytes.length) continue;
		const packageLength = bytes.readUInt32BE(at + 8),
			tocOffset = bytes.readUInt32BE(at + 12),
			tocLength = bytes.readUInt32BE(at + 16),
			pythonVersion = bytes.readUInt32BE(at + 20);
		for (const size of [88, 24]) {
			const start = at + size - packageLength,
				end = at;
			if (
				start < 0 ||
				at + size > bytes.length ||
				packageLength < size ||
				tocLength > 8 * 1024 * 1024 ||
				start + tocOffset > end ||
				start + tocOffset + tocLength > end
			)
				continue;
			let p = start + tocOffset;
			const tocEnd = p + tocLength,
				entries: Array<Record<string, unknown>> = [];
			let valid = true;
			while (p < tocEnd) {
				if (entries.length >= 4096)
					throw new Error("CArchive entry budget exceeded");
				if (p + 18 > tocEnd) {
					valid = false;
					break;
				}
				const recordBytes = bytes.readUInt32BE(p),
					offset = bytes.readUInt32BE(p + 4),
					compressedBytes = bytes.readUInt32BE(p + 8),
					uncompressedBytes = bytes.readUInt32BE(p + 12),
					compression = bytes[p + 16],
					type = String.fromCharCode(bytes[p + 17]);
				if (
					recordBytes < 19 ||
					p + recordBytes > tocEnd ||
					compression > 1 ||
					start + offset + compressedBytes > start + tocOffset
				) {
					valid = false;
					break;
				}
				const raw = bytes.subarray(p + 18, p + recordBytes),
					zero = raw.indexOf(0);
				if (zero < 0 || zero > 4096) {
					valid = false;
					break;
				}
				const name = raw.subarray(0, zero).toString("utf8");
				entries.push({
					index: entries.length,
					name,
					type,
					offset: start + offset,
					compressedBytes,
					uncompressedBytes,
					compression,
					declaration: type === "o" || type === "d",
				});
				p += recordBytes;
			}
			if (valid && p === tocEnd)
				return {
					layout: size === 88 ? "2.1+" : "2.0",
					archiveOffset: start,
					cookieOffset: at,
					packageLength,
					pythonVersion,
					pythonLibrary:
						size === 88
							? bytes
									.subarray(at + 24, at + 88)
									.toString("utf8")
									.split("\0")[0]
							: null,
					entries,
					limitations: [
						"CArchive inventory only. Entries are untrusted declarations, not extracted paths or verified Python behavior. Nested PYZ, encrypted payloads and decompressed content are not decoded.",
					],
				};
		}
	}
	throw new Error(
		"No supported structurally valid PyInstaller CArchive cookie and TOC",
	);
}
