/** Bounded class-file metadata/Code reader; never loads a JVM or executes bytecode. */
export function inspectJvmMethod(
	bytes: Buffer,
	name: string,
	descriptor: string,
) {
	let p = 0;
	const take = (n: number) => {
		if (!Number.isSafeInteger(n) || n < 0 || p + n > bytes.length)
			throw new Error("Truncated JVM class range");
		const at = p;
		p += n;
		return at;
	};
	const u1 = () => bytes.readUInt8(take(1)),
		u2 = () => bytes.readUInt16BE(take(2)),
		u4 = () => bytes.readUInt32BE(take(4));
	if (u4() !== 0xcafebabe) throw new Error("Not a JVM class file");
	const minor = u2(),
		major = u2();
	if (major < 45 || major > 70)
		throw new Error("Unsupported JVM class version");
	const count = u2();
	if (count > 8192) throw new Error("JVM constant-pool budget exceeded");
	const strings = new Map<number, string>();
	for (let i = 1; i < count; i++) {
		const tag = u1();
		if (tag === 1) {
			const n = u2(),
				at = take(n);
			strings.set(i, bytes.subarray(at, at + n).toString("utf8"));
		} else if ([3, 4, 9, 10, 11, 12, 17, 18].includes(tag)) take(4);
		else if ([5, 6].includes(tag)) {
			take(8);
			if (++i >= count) throw new Error("Invalid double-width constant");
		} else if ([7, 8, 16, 19, 20].includes(tag)) take(2);
		else if (tag === 15) take(3);
		else throw new Error("Unsupported JVM constant-pool tag");
	}
	take(6);
	take(u2() * 2);
	const attributes = (
		visit?: (attribute: string | undefined, at: number, size: number) => void,
	) => {
		const n = u2();
		if (n > 4096) throw new Error("JVM attribute budget exceeded");
		for (let i = 0; i < n; i++) {
			const key = u2(),
				size = u4(),
				at = take(size);
			visit?.(strings.get(key), at, size);
		}
	};
	const fields = u2();
	if (fields > 4096) throw new Error("JVM field budget exceeded");
	for (let i = 0; i < fields; i++) {
		take(6);
		attributes();
	}
	const methods = u2();
	if (methods > 4096) throw new Error("JVM method budget exceeded");
	const matches: {
		offset: number;
		bytes: Buffer;
		maxStack: number;
		maxLocals: number;
		exceptionCount: number;
		codeAttributes: number;
		accessFlags: number;
	}[] = [];
	for (let i = 0; i < methods; i++) {
		const accessFlags = u2(),
			methodName = strings.get(u2()),
			signature = strings.get(u2());
		attributes((attribute, at, size) => {
			if (
				attribute !== "Code" ||
				methodName !== name ||
				signature !== descriptor
			)
				return;
			if (size < 12) throw new Error("Truncated JVM Code attribute");
			const length = bytes.readUInt32BE(at + 4),
				end = at + size;
			if (length > 65535 || at + 8 + length + 4 > end)
				throw new Error("JVM Code exceeds bounds");
			const exceptions = bytes.readUInt16BE(at + 8 + length),
				attrsAt = at + 10 + length + exceptions * 8;
			if (attrsAt + 2 > end) throw new Error("Truncated JVM exception table");
			let q = attrsAt + 2;
			const codeAttributes = bytes.readUInt16BE(attrsAt);
			if (codeAttributes > 4096)
				throw new Error("JVM nested attribute budget exceeded");
			for (let j = 0; j < codeAttributes; j++) {
				if (q + 6 > end) throw new Error("Truncated JVM nested attribute");
				q += 6 + bytes.readUInt32BE(q + 2);
				if (q > end) throw new Error("JVM nested attribute exceeds bounds");
			}
			if (q !== end) throw new Error("Trailing JVM Code attribute bytes");
			matches.push({
				offset: at + 8,
				bytes: bytes.subarray(at + 8, at + 8 + length),
				maxStack: bytes.readUInt16BE(at),
				maxLocals: bytes.readUInt16BE(at + 2),
				exceptionCount: exceptions,
				codeAttributes,
				accessFlags,
			});
		});
	}
	attributes();
	if (p !== bytes.length) throw new Error("Trailing JVM class bytes");
	if (matches.length !== 1)
		throw new Error("Expected one unambiguous selected JVM method with Code");
	return {
		...matches[0],
		major,
		minor,
		name,
		descriptor,
		limitations: [
			"Selected class-file Code bytes only; not Java source decompilation, verifier acceptance, signature validity, or runtime behavior.",
			"Names use bounded UTF-8 decoding; exotic modified-UTF8 identifiers are not a completeness guarantee.",
		],
	};
}
