/** Stored ZIP writer for a small fixed owned test corpus, never target-controlled archive rewriting. */
export function ownedZip(
	entries: Array<{ name: string; bytes: Buffer }>,
): Buffer {
	const local: Buffer[] = [],
		central: Buffer[] = [];
	let offset = 0;
	for (const { name, bytes } of entries) {
		const filename = Buffer.from(name);
		let crc = 0xffffffff;
		for (const b of bytes) {
			crc ^= b;
			for (let n = 0; n < 8; n++)
				crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
		}
		crc = (crc ^ 0xffffffff) >>> 0;
		const h = Buffer.alloc(30);
		h.writeUInt32LE(0x04034b50);
		h.writeUInt16LE(20, 4);
		h.writeUInt16LE(0x800, 6);
		h.writeUInt32LE(crc, 14);
		h.writeUInt32LE(bytes.length, 18);
		h.writeUInt32LE(bytes.length, 22);
		h.writeUInt16LE(filename.length, 26);
		local.push(h, filename, bytes);
		const c = Buffer.alloc(46);
		c.writeUInt32LE(0x02014b50);
		c.writeUInt16LE(20, 4);
		c.writeUInt16LE(20, 6);
		c.writeUInt16LE(0x800, 8);
		c.writeUInt32LE(crc, 16);
		c.writeUInt32LE(bytes.length, 20);
		c.writeUInt32LE(bytes.length, 24);
		c.writeUInt16LE(filename.length, 28);
		c.writeUInt32LE(offset, 42);
		central.push(c, filename);
		offset += h.length + filename.length + bytes.length;
	}
	const directory = Buffer.concat(central),
		e = Buffer.alloc(22);
	e.writeUInt32LE(0x06054b50);
	e.writeUInt16LE(entries.length, 8);
	e.writeUInt16LE(entries.length, 10);
	e.writeUInt32LE(directory.length, 12);
	e.writeUInt32LE(offset, 16);
	return Buffer.concat([...local, directory, e]);
}
