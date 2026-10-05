import { fileURLToPath } from "node:url";
import { test, expect } from "bun:test";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, isAbsolute } from "node:path";
import { createCipheriv, createHash } from "node:crypto";
import {
	runAdvancedAnalysis,
	type AdvancedRequest,
} from "../src/extensions/tools/executors/advanced-analysis";

test("real portable analysis engines through SDK worker", async () => {
	if (!process.env.CLINE_RE_PYTHON || !isAbsolute(process.env.CLINE_RE_PYTHON))
		throw new Error(
			"Trusted absolute Python is required; missing engines do not skip",
		);
	const root = await mkdtemp(join(tmpdir(), "cline-windows-engines-"));
	const prior = {
		enabled: process.env.CLINE_RE_ALLOW_DECRYPTION,
		key: process.env.CLINE_RE_PRIVATE_KEY_FILE,
	};
	async function run(
		name: string,
		data: Uint8Array,
		action: AdvancedRequest["action"],
		options?: AdvancedRequest["options"],
	) {
		const path = join(root, name);
		await writeFile(path, data);
		const result = await runAdvancedAnalysis({
			action,
			target: path,
			options,
			timeoutMs: 30000,
		});
		expect(["completed", "partial"], JSON.stringify(result)).toContain(
			result.status,
		);
		return result;
	}
	try {
		const readiness = await runAdvancedAnalysis({
			action: "analysis_readiness",
		});
		expect(readiness.status, JSON.stringify(readiness)).toBe("completed");
		const checks = readiness.evidence.checks as Array<{
			executionVerified: boolean;
		}>;
		expect(checks.every((c) => c.executionVerified)).toBe(true);
		const inventory = await runAdvancedAnalysis({ action: "toolchain" });
		const engines = inventory.evidence.engines as Array<{
			id: string;
			installedVersion: string | null;
		}>;
		for (const id of [
			"lief",
			"capstone",
			"z3",
			"androguard",
			"miasm",
			"cryptography",
		])
			expect(engines.find((x) => x.id === id)?.installedVersion).toBeTruthy();
		const native = Buffer.from("9090c3", "hex");
		expect(
			(
				await run("native.bin", native, "native_disassemble", {
					architecture: "x86_64",
					bytes: 3,
				})
			).engine,
		).toBe("capstone");
		expect(
			(
				await run(
					"expr.json",
					Buffer.from(
						'{"expression":{"op":"xor","args":[{"var":"x"},{"var":"x"}]},"compare":0}',
					),
					"compare_expressions",
				)
			).evidence.equivalence,
		).toBe("unsat");
		expect(
			(
				await run("native-ir.bin", native, "lift_native_ir", {
					architecture: "x86_64",
					bytes: 3,
				})
			).engine,
		).toBe("miasm");
		const elf = Buffer.alloc(120);
		Buffer.from("7f454c46020101000000000000000000", "hex").copy(elf);
		elf.writeUInt16LE(3, 16);
		elf.writeUInt16LE(62, 18);
		elf.writeUInt32LE(1, 20);
		elf.writeBigUInt64LE(64n, 32);
		elf.writeUInt16LE(64, 52);
		elf.writeUInt16LE(56, 54);
		elf.writeUInt16LE(1, 56);
		elf.writeUInt32LE(1, 64);
		elf.writeUInt32LE(4, 68);
		elf.writeBigUInt64LE(4096n, 80);
		elf.writeBigUInt64LE(4096n, 88);
		elf.writeBigUInt64LE(120n, 96);
		elf.writeBigUInt64LE(120n, 104);
		elf.writeBigUInt64LE(4096n, 112);
		expect((await run("owned.so", elf, "native_inventory")).engine).toBe(
			"lief",
		);
		const dex = Buffer.alloc(240);
		Buffer.from("dex\n035\0").copy(dex);
		const header = [
			240, 112, 0x12345678, 0, 0, 164, 1, 148, 1, 144, 0, 0, 0, 0, 0, 0, 1, 112,
			88, 152,
		];
		header.forEach((x, i) => {
			dex.writeUInt32LE(x, 32 + i * 4);
		});
		[0, 1, 0xffffffff, 0, 0xffffffff, 0, 0, 0].forEach((x, i) => {
			dex.writeUInt32LE(x, 112 + i * 4);
		});
		dex.writeUInt32LE(0, 144);
		dex.writeUInt32LE(152, 148);
		Buffer.from("\x09LFixture;\0").copy(dex, 152);
		dex.writeUInt32LE(6, 164);
		[
			[0, 1, 0],
			[6, 1, 112],
			[2, 1, 144],
			[1, 1, 148],
			[0x2002, 1, 152],
			[0x1000, 1, 164],
		].forEach(([type, size, offset], i) => {
			const n = 168 + i * 12;
			dex.writeUInt16LE(type, n);
			dex.writeUInt32LE(size, n + 4);
			dex.writeUInt32LE(offset, n + 8);
		});
		createHash("sha1").update(dex.subarray(32)).digest().copy(dex, 12);
		let a = 1,
			b = 0;
		for (const x of dex.subarray(12)) {
			a = (a + x) % 65521;
			b = (b + a) % 65521;
		}
		dex.writeUInt32LE(((b << 16) | a) >>> 0, 8);
		expect((await run("owned.dex", dex, "dex_index")).engine).toBe(
			"androguard",
		);
		const key = Buffer.alloc(32, 7),
			nonce = Buffer.alloc(12, 3),
			keyPath = join(root, "owned-key.bin");
		await writeFile(keyPath, key, { mode: 0o600 });
		process.env.CLINE_RE_ALLOW_DECRYPTION = "1";
		process.env.CLINE_RE_PRIVATE_KEY_FILE = keyPath;
		const cipher = createCipheriv("aes-256-gcm", key, nonce);
		const blob = Buffer.concat([
			cipher.update(Buffer.from("owned fixture")),
			cipher.final(),
			cipher.getAuthTag(),
		]);
		expect(
			(
				await run("cipher.bin", blob, "decrypt_blob", {
					decrypt: {
						algorithm: "aes-256-gcm",
						nonce_hex: nonce.toString("hex"),
					},
				})
			).engine,
		).toBe("cryptography");
		blob[0] ^= 1;
		const bad = join(root, "bad.bin");
		await writeFile(bad, blob);
		expect(
			(
				await runAdvancedAnalysis({
					action: "decrypt_blob",
					target: bad,
					options: {
						decrypt: {
							algorithm: "aes-256-gcm",
							nonce_hex: nonce.toString("hex"),
						},
					},
				})
			).status,
		).toBe("failed");
	} finally {
		if (prior.enabled === undefined)
			delete process.env.CLINE_RE_ALLOW_DECRYPTION;
		else process.env.CLINE_RE_ALLOW_DECRYPTION = prior.enabled;
		if (prior.key === undefined) delete process.env.CLINE_RE_PRIVATE_KEY_FILE;
		else process.env.CLINE_RE_PRIVATE_KEY_FILE = prior.key;
		await rm(root, { recursive: true, force: true });
	}
}, 180000);

test("targeted ELF, DEX and JNI real-engine corpus", async () => {
	const python = process.env.CLINE_RE_PYTHON;
	if (!python || !isAbsolute(python))
		throw new Error("Trusted absolute Python required; no engine skips");
	const script = new URL(
		"./android-investigation-worker.test.py",
		import.meta.url,
	);
	const child = Bun.spawn([python, "-I", fileURLToPath(script)], {
		stdout: "pipe",
		stderr: "pipe",
	});
	const [out, err, status] = await Promise.all([
		new Response(child.stdout).text(),
		new Response(child.stderr).text(),
		child.exited,
	]);
	expect(status, out + err).toBe(0);
	expect(err).toContain("OK");
	expect(err).not.toContain("skipped=");
}, 120000);
