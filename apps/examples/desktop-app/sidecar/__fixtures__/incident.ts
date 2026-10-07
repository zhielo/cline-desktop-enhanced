export function crc32(b: Buffer) {
	let c = 0xffffffff;
	for (const v of b) {
		c ^= v;
		for (let i = 0; i < 8; i++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
	}
	return (c ^ 0xffffffff) >>> 0;
}
export function zip(
	entries: { name: string; bytes: Buffer; flags?: number }[],
) {
	const local: Buffer[] = [],
		central: Buffer[] = [];
	let offset = 0;
	for (const e of entries) {
		const name = Buffer.from(e.name),
			h = Buffer.alloc(30);
		h.writeUInt32LE(0x04034b50);
		h.writeUInt16LE(e.flags ?? 0, 6);
		h.writeUInt32LE(crc32(e.bytes), 14);
		h.writeUInt32LE(e.bytes.length, 18);
		h.writeUInt32LE(e.bytes.length, 22);
		h.writeUInt16LE(name.length, 26);
		local.push(h, name, e.bytes);
		const c = Buffer.alloc(46);
		c.writeUInt32LE(0x02014b50);
		c.writeUInt16LE(e.flags ?? 0, 8);
		c.writeUInt32LE(crc32(e.bytes), 16);
		c.writeUInt32LE(e.bytes.length, 20);
		c.writeUInt32LE(e.bytes.length, 24);
		c.writeUInt16LE(name.length, 28);
		c.writeUInt32LE(offset, 42);
		central.push(c, name);
		offset += h.length + name.length + e.bytes.length;
	}
	const directory = Buffer.concat(central),
		end = Buffer.alloc(22);
	end.writeUInt32LE(0x06054b50);
	end.writeUInt16LE(entries.length, 8);
	end.writeUInt16LE(entries.length, 10);
	end.writeUInt32LE(directory.length, 12);
	end.writeUInt32LE(offset, 16);
	return Buffer.concat([...local, directory, end]);
}
export function manifest(pkg = "com.example.app") {
	const strings = ["manifest", "package", pkg],
		data = Buffer.concat(
			strings.map((s) =>
				Buffer.concat([
					Buffer.from([s.length, s.length]),
					Buffer.from(s),
					Buffer.from([0]),
				]),
			),
		),
		size = 28 + strings.length * 4 + data.length,
		pool = Buffer.alloc(size);
	pool.writeUInt16LE(1);
	pool.writeUInt16LE(28, 2);
	pool.writeUInt32LE(size, 4);
	pool.writeUInt32LE(strings.length, 8);
	pool.writeUInt32LE(256, 16);
	pool.writeUInt32LE(40, 20);
	let offset = 0;
	strings.forEach((s, i) => {
		pool.writeUInt32LE(offset, 28 + i * 4);
		offset += s.length + 3;
	});
	data.copy(pool, 40);
	const node = Buffer.alloc(56);
	node.writeUInt16LE(0x102);
	node.writeUInt16LE(16, 2);
	node.writeUInt32LE(56, 4);
	node.writeUInt32LE(0, 20);
	node.writeUInt16LE(20, 24);
	node.writeUInt16LE(20, 26);
	node.writeUInt16LE(1, 28);
	node.writeUInt32LE(0xffffffff, 36);
	node.writeUInt32LE(1, 40);
	node.writeUInt32LE(2, 44);
	node.writeUInt16LE(8, 48);
	node[51] = 3;
	node.writeUInt32LE(2, 52);
	const h = Buffer.alloc(8);
	h.writeUInt16LE(3);
	h.writeUInt16LE(8, 2);
	h.writeUInt32LE(8 + pool.length + node.length, 4);
	return Buffer.concat([h, pool, node]);
}
export function apk(pkg = "com.example.app", extra = "baseline") {
	return zip([
		{ name: "AndroidManifest.xml", bytes: manifest(pkg) },
		{ name: "fixture.txt", bytes: Buffer.from(extra) },
	]);
}
export function elf() {
	const b = Buffer.alloc(256);
	b.write("\x7fELF", 0, "binary");
	b[4] = 2;
	b[5] = 1;
	b[6] = 1;
	b.writeUInt16LE(183, 18);
	b.writeBigUInt64LE(BigInt(64), 32);
	b.writeUInt16LE(56, 54);
	b.writeUInt16LE(2, 56);
	b.writeUInt32LE(1, 64);
	b.writeUInt32LE(5, 68);
	b.writeBigUInt64LE(BigInt(0), 72);
	b.writeBigUInt64LE(BigInt(0x1000), 80);
	b.writeBigUInt64LE(BigInt(256), 96);
	b.writeUInt32LE(4, 120);
	b.writeBigUInt64LE(BigInt(192), 128);
	b.writeBigUInt64LE(BigInt(20), 152);
	b.writeUInt32LE(4, 192);
	b.writeUInt32LE(4, 196);
	b.writeUInt32LE(3, 200);
	b.write("GNU\0", 204, "binary");
	b.writeUInt32LE(0x12345678, 208);
	return b;
}
