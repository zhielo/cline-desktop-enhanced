import { mkdtemp, writeFile, rm, readFile, realpath } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { expect, it } from "vitest";
import { createHash } from "node:crypto";
import {
	EmulationOptionsSchema,
	EmulationRuntimeSchema,
	EMULATION_PROFILE_SHA256,
} from "../emulation-schema";
import { InvestigationSchemas } from "../investigation";
import { ReverseEngineeringInputSchema } from "../schemas";
import { planEmulation, inspectEmulationElf } from "./emulation-plan";
import { createReverseEngineeringExecutor } from "./reverse-engineering";
const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
function elf() {
	const b = Buffer.alloc(128);
	Buffer.from("7f454c46020101", "hex").copy(b);
	b.writeUInt16LE(2, 16);
	b.writeUInt16LE(62, 18);
	b.writeBigUInt64LE(0x1000n, 24);
	b.writeBigUInt64LE(64n, 32);
	b.writeUInt16LE(56, 54);
	b.writeUInt16LE(1, 56);
	b.writeUInt32LE(1, 64);
	b.writeUInt32LE(5, 68);
	b.writeBigUInt64LE(0x1000n, 80);
	b.writeBigUInt64LE(128n, 96);
	b.writeBigUInt64LE(128n, 104);
	return b;
}
const options = {
	engine: "qiling",
	architecture: "x86_64",
	scenario: { kind: "entry" },
	instruction_limit: 10000,
};
it("shares a byte-exact profile and rejects unsupported combinations and authority", async () => {
	expect(
		sha(
			await readFile(
				new URL(
					"../../../../../../../workers/emulation/profiles.json",
					import.meta.url,
				),
			),
		),
	).toBe(EMULATION_PROFILE_SHA256);
	for (const patch of [
		{ engine: "rnidbg", architecture: "arm32" },
		{ scenario: { kind: "entry", script: "x" } },
		{ instruction_limit: 100001 },
		{ instruction_limit: true },
		{ rootfs: "/" },
	])
		expect(() =>
			EmulationOptionsSchema.parse({ ...options, ...patch }),
		).toThrow();
	for (const key of [
		"executionToken",
		"approved",
		"mode",
		"sessionId",
		"phase",
	]) {
		expect(() =>
			InvestigationSchemas.plan_emulation.parse({
				artifactId: "11111111-1111-4111-8111-111111111111",
				options,
				[key]: true,
			}),
		).toThrow();
	}
});
it("plans through reverse_engineer without worker access, mutation or execution", async () => {
	const root = await realpath(await mkdtemp(join(tmpdir(), "emulation-plan-"))),
		target = join(root, "owned.elf"),
		bytes = elf();
	await writeFile(target, bytes);
	try {
		const input = ReverseEngineeringInputSchema.parse({
			operation: "plan_emulation",
			target,
			emulation_plan: { ...options, expected_sha256: sha(bytes) },
		});
		const r = JSON.parse(
			await createReverseEngineeringExecutor()(input, {} as never),
		);
		expect(r).toMatchObject({
			effect: "plan-only",
			compatibility: "admission-only",
			observedExecution: false,
			workerConnected: false,
			approval: { granted: false },
			nextRequest: { operation: "emulate_profile", engine: "qiling" },
		});
		expect(await readFile(target)).toEqual(bytes);
		await expect(
			planEmulation({ ...input, output_file: join(root, "out") }),
		).rejects.toThrow("no writes");
		await expect(
			createReverseEngineeringExecutor()(
				{ ...input, operation: "inspect" },
				{} as never,
			),
		).rejects.toThrow("only accepted");
		const abort = new AbortController();
		abort.abort();
		await expect(planEmulation(input, abort.signal)).rejects.toThrow();
		await writeFile(target, Buffer.alloc(128));
		await expect(planEmulation(input)).rejects.toThrow("hash changed");
		const unsupported = await planEmulation({
			...input,
			emulation_plan: {
				...input.emulation_plan!,
				expected_sha256: sha(Buffer.alloc(128)),
			},
		});
		expect(unsupported).toMatchObject({
			compatibility: "unsupported",
			nextRequest: null,
		});
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
it("fails closed on malformed ELF admission and preserves existing Unicorn profile", () => {
	expect(inspectEmulationElf(elf(), "qiling", "x86_64")).toMatchObject({
		mappedBytes: 128,
	});
	for (const modify of [
		(b: Buffer) => b.writeBigUInt64LE(0xffffffffffffffffn, 32),
		(b: Buffer) => b.writeUInt32LE(3, 64),
		(b: Buffer) => b.writeBigUInt64LE(129n, 96),
	]) {
		const b = elf();
		modify(b);
		expect(() => inspectEmulationElf(b, "qiling", "x86_64")).toThrow();
	}
});

it("accepts real opaque desktop session IDs without granting execution authority", () => {
	const request = {
		...options,
		operation: "emulate_profile",
		target: "/owned.elf",
		analysis_mode: "runtime",
	};
	for (const owner_session_id of [
		"installer-owned-triage",
		"session_1793083714059_ahgxt",
		"11111111-1111-4111-8111-111111111111",
	])
		expect(
			EmulationRuntimeSchema.parse({ ...request, owner_session_id })
				.owner_session_id,
		).toBe(owner_session_id);
	for (const owner_session_id of [
		"",
		"x".repeat(129),
		"owner\nother",
		"owner other",
		"../owner",
	])
		expect(() =>
			EmulationRuntimeSchema.parse({ ...request, owner_session_id }),
		).toThrow();
	expect(() =>
		EmulationRuntimeSchema.parse({
			...request,
			owner_session_id: "owner",
			approved: true,
		}),
	).toThrow();
});
