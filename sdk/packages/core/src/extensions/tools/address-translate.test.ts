import { describe, expect, it } from "vitest";
import { createAddressTranslateTool } from "./address-translate";

const context = { agentId: "translation-test", iteration: 1 };
const segment = { id: "load", file_offset: "0x200", virtual_address: "0x1000", file_size: "0x100", memory_size: "0x200" };
const tool = createAddressTranslateTool();

describe("address translation adapter", () => {
	it("translates a file offset without claiming observed provenance", async () => {
		const result = await tool.execute({ input_kind: "file_offset", address: "0x220", image_base: "0x1000", segments: [segment] }, context);
		expect(result).toMatchObject({ status: "mapped", inputProvenanceVerified: false, imageBaseObserved: false, matches: [{ virtualAddress: "0x1020", fileOffset: "0x220", rva: "0x20", backing: "file_backed" }] });
	});
	it("translates RVA only with an explicit image base", async () => {
		const result = await tool.execute({ input_kind: "rva", address: "0x20", image_base: "0x1000", segments: [segment] }, context);
		expect(result.matches[0].virtualAddress).toBe("0x1020");
		await expect(tool.execute({ input_kind: "rva", address: "0x20", segments: [segment] }, context)).rejects.toThrow("image_base");
	});
	it("never invents a file offset for zero-filled memory", async () => {
		const result = await tool.execute({ input_kind: "va", address: "0x1180", segments: [segment] }, context);
		expect(result.matches[0]).toMatchObject({ fileOffset: null, rva: null, backing: "zero_filled" });
	});
	it("uses half-open boundaries and reports unmapped addresses", async () => {
		expect((await tool.execute({ input_kind: "file_offset", address: "0x300", segments: [segment] }, context)).status).toBe("unmapped");
		expect((await tool.execute({ input_kind: "va", address: "0x1200", segments: [segment] }, context)).status).toBe("unmapped");
	});
	it("retains precision above Number.MAX_SAFE_INTEGER", async () => {
		const large = { ...segment, virtual_address: "0x20000000000000" };
		const result = await tool.execute({ input_kind: "file_offset", address: "0x201", segments: [large] }, context);
		expect(result.matches[0].virtualAddress).toBe("0x20000000000001");
	});
	it("reports overlaps rather than choosing an arbitrary mapping", async () => {
		const other = { ...segment, id: "alias", virtual_address: "0x3000" };
		const result = await tool.execute({ input_kind: "file_offset", address: "0x220", segments: [segment, other] }, context);
		expect(result.status).toBe("ambiguous");
		expect(result.totalMatches).toBe(2);
	});
	it("bounds evidence for many overlapping segments", async () => {
		const segments = Array.from({ length: 20 }, (_, index) => ({ ...segment, id: `alias-${index}` }));
		const result = await tool.execute({ input_kind: "file_offset", address: "0x220", segments }, context);
		expect(result).toMatchObject({ status: "ambiguous", totalMatches: 20, truncated: true });
		expect(result.matches).toHaveLength(16);
	});
	it("rejects overflow, invalid backing sizes and duplicate identities", async () => {
		await expect(tool.execute({ input_kind: "va", address: "0x1", segments: [{ ...segment, virtual_address: "0xfffffffffffffff0" }] }, context)).rejects.toThrow("overflows");
		await expect(tool.execute({ input_kind: "va", address: "0x1", segments: [{ ...segment, memory_size: "0x10" }] }, context)).rejects.toThrow("memory_size");
		await expect(tool.execute({ input_kind: "va", address: "0x1000", segments: [segment, segment] }, context)).rejects.toThrow("unique");
	});
	it("rejects unsafe input formats and authority fields", async () => {
		await expect(tool.execute({ input_kind: "va", address: "-1", segments: [segment] }, context)).rejects.toThrow();
		await expect(tool.execute({ input_kind: "va", address: "18446744073709551616", segments: [segment] }, context)).rejects.toThrow("64-bit");
		await expect(tool.execute({ input_kind: "va", address: "0x1000", segments: [segment], confirm_write: true } as never, context)).rejects.toThrow();
	});
	it("honors host cancellation without any target execution", async () => {
		const controller = new AbortController();
		controller.abort(new Error("stop"));
		await expect(tool.execute({ input_kind: "va", address: "0x1000", segments: [segment] }, { ...context, signal: controller.signal })).rejects.toThrow("stop");
	});
});
