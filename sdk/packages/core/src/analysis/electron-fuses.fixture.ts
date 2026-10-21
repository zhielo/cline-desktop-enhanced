import { ELECTRON_FUSE_SENTINEL } from "./semantic-engine/upstream/src/domain/electron/electronFuses";
/** Owned structural PE fixture; deliberately no executable entrypoint or code. */
export function ownedFusePe(
	wire: readonly number[] = [1, 9, 49, 48, 49, 48, 49, 49, 48, 48, 49],
	offset = 255,
) {
	const b = Buffer.alloc(Math.max(512, offset + 32 + wire.length));
	b.write("MZ");
	b.writeUInt32LE(0x80, 0x3c);
	b.writeUInt32LE(0x4550, 0x80);
	b.writeUInt16LE(0x8664, 0x84);
	b.write(ELECTRON_FUSE_SENTINEL, offset, "ascii");
	Buffer.from(wire).copy(b, offset + 32);
	return b;
}
