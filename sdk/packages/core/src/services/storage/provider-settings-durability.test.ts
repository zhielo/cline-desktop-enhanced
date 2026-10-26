import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ProviderSettingsManager } from "./provider-settings-manager";
import { withProviderSettingsTransaction } from "./provider-settings-transaction";
const dirs: string[] = [];
const fixture = () => {
	const dir = mkdtempSync(join(tmpdir(), "cline-provider-durable-"));
	dirs.push(dir);
	return join(dir, "providers.json");
};
afterEach(() => {
	for (const dir of dirs.splice(0))
		rmSync(dir, { recursive: true, force: true });
});
describe("provider settings durability", () => {
	it("preserves independent provider and voice updates from two managers", () => {
		const filePath = fixture(),
			a = new ProviderSettingsManager({ filePath }),
			b = new ProviderSettingsManager({ filePath });
		a.saveProviderSettings({
			provider: "anthropic",
			model: "fixture",
			apiKey: "synthetic-only",
		});
		b.saveProviderSettings({ provider: "openai", model: "fixture" });
		a.setVoiceInputSettings({ providerId: "openai", modelId: "whisper-1" });
		expect(Object.keys(b.read().providers).sort()).toEqual([
			"anthropic",
			"openai",
		]);
		expect(b.getVoiceInputSettings()?.modelId).toBe("whisper-1");
	});
	it("rejects stale whole-file replacements, including a blind retry", () => {
		const filePath = fixture(),
			a = new ProviderSettingsManager({ filePath }),
			b = new ProviderSettingsManager({ filePath });
		const stale = a.read();
		b.saveProviderSettings({ provider: "openai", model: "fixture" });
		expect(() => a.write(stale)).toThrow(/changed in another process/);
		expect(() => a.write(stale)).toThrow(/changed in another process/);
		expect(b.getProviderSettings("openai")).toBeDefined();
	});
	it("does not revalidate an old snapshot when another read occurs on the same manager", () => {
		const filePath = fixture(),
			a = new ProviderSettingsManager({ filePath }),
			b = new ProviderSettingsManager({ filePath });
		const stale = a.read();
		b.saveProviderSettings({ provider: "openai", model: "fixture" });
		a.read();
		expect(() => a.write(stale)).toThrow(/changed in another process/);
		expect(() => a.write({ ...stale })).toThrow(/original read snapshot/);
		const fresh = a.read();
		a.write({ ...fresh }, fresh);
		expect(a.getProviderSettings("openai")).toBeDefined();
	});
	it.each([
		"{broken",
		JSON.stringify({ providers: "invalid" }),
	])("preserves corrupt or unsupported input", (input) => {
		const filePath = fixture(),
			manager = new ProviderSettingsManager({ filePath });
		writeFileSync(filePath, input);
		expect(() => manager.read()).toThrow(/corrupt|unsupported schema/);
		expect(() =>
			manager.saveProviderSettings({ provider: "openai", model: "fixture" }),
		).toThrow(/corrupt|unsupported schema/);
		expect(readFileSync(filePath, "utf8")).toBe(input);
	});
	it("releases its kernel lock after an exception and rejects reentrancy", () => {
		const filePath = fixture();
		expect(() =>
			withProviderSettingsTransaction(filePath, () => {
				throw new Error("fixture");
			}),
		).toThrow("fixture");
		expect(withProviderSettingsTransaction(filePath, () => 42)).toBe(42);
		expect(() =>
			withProviderSettingsTransaction(filePath, () =>
				withProviderSettingsTransaction(filePath, () => 0),
			),
		).toThrow(/Reentrant/);
		expect(withProviderSettingsTransaction(filePath, () => 43)).toBe(43);
	});
});

function child(script: string, filePath: string) {
	return spawn(process.env.CLINE_TEST_BUN ?? "bun", ["-e", script], {
		env: {
			...process.env,
			CLINE_DIR: join(filePath, "..", "isolated-home"),
			IS_TEST: "true",
		},
		stdio: ["ignore", "pipe", "pipe"],
		windowsHide: true,
	});
}
function completed(process: ReturnType<typeof child>): Promise<void> {
	return new Promise((resolve, reject) => {
		let error = "";
		const timer = setTimeout(() => {
			process.kill("SIGKILL");
			reject(new Error("Owned provider fixture timed out"));
		}, 15_000);
		process.stderr.on("data", (data) => {
			error = (error + String(data)).slice(-4000);
		});
		process.once("error", (error) => {
			clearTimeout(timer);
			reject(error);
		});
		process.once("close", (code) => {
			clearTimeout(timer);
			code === 0
				? resolve()
				: reject(new Error(`Owned provider fixture exited ${code}: ${error}`));
		});
	});
}
describe("real provider settings process coordination", () => {
	it("serializes independent writers across two OS processes", async () => {
		const filePath = fixture();
		const source = fileURLToPath(
			new URL("./provider-settings-manager.ts", import.meta.url),
		);
		const script = (provider: string) =>
			`import {ProviderSettingsManager} from ${JSON.stringify(source)}; const manager=new ProviderSettingsManager({filePath:${JSON.stringify(filePath)}}); for(let i=0;i<12;i++)manager.saveProviderSettings({provider:${JSON.stringify(provider)},model:"fixture-"+i});`;
		await Promise.all([
			completed(child(script("openai"), filePath)),
			completed(child(script("anthropic"), filePath)),
		]);
		const manager = new ProviderSettingsManager({ filePath });
		expect(Object.keys(manager.read().providers).sort()).toEqual([
			"anthropic",
			"openai",
		]);
		expect(manager.getProviderSettings("openai")?.model).toBe("fixture-11");
		expect(manager.getProviderSettings("anthropic")?.model).toBe("fixture-11");
	});
	it("recovers the OS transaction lock after its owned holder is terminated", async () => {
		const filePath = fixture(),
			source = fileURLToPath(
				new URL("./provider-settings-transaction.ts", import.meta.url),
			);
		const process = child(
			`import {withProviderSettingsTransaction} from ${JSON.stringify(source)}; withProviderSettingsTransaction(${JSON.stringify(filePath)},()=>{ console.log("OWNED_LOCK_HELD"); Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,30000); });`,
			filePath,
		);
		try {
			await new Promise<void>((resolve, reject) => {
				const timer = setTimeout(
					() => reject(new Error("Owned lock fixture did not become ready")),
					10000,
				);
				let output = "";
				process.stdout.on("data", (data) => {
					output = (output + String(data)).slice(-100);
					if (output.includes("OWNED_LOCK_HELD")) {
						clearTimeout(timer);
						resolve();
					}
				});
				process.once("error", (error) => {
					clearTimeout(timer);
					reject(error);
				});
				process.once("exit", () => {
					clearTimeout(timer);
					reject(new Error("Owned lock fixture exited before ready"));
				});
			});
			const closed = new Promise<void>((resolve) =>
				process.once("close", () => resolve()),
			);
			process.kill("SIGKILL");
			await closed;
			expect(withProviderSettingsTransaction(filePath, () => 44)).toBe(44);
		} finally {
			process.kill("SIGKILL");
		}
	});
});

describe("atomic provider patches", () => {
	it("preserves record metadata and untouched credential fields", () => {
		const filePath = fixture(),
			manager = new ProviderSettingsManager({ filePath });
		manager.saveProviderSettings(
			{ provider: "openai", model: "old", apiKey: "synthetic-only" },
			{ tokenSource: "oauth" },
		);
		const patched = manager.updateProviderSettings(
			"openai",
			(current) => ({ ...current, provider: "openai", model: "new" }),
			{ setLastUsed: false },
		);
		expect(patched).toMatchObject({
			provider: "openai",
			model: "new",
			apiKey: "synthetic-only",
		});
		expect(manager.read().providers.openai?.tokenSource).toBe("oauth");
		expect(manager.read().lastUsedProvider).toBe("openai");
	});
	it("declines stale mutations without rewriting file bytes", () => {
		const filePath = fixture(),
			manager = new ProviderSettingsManager({ filePath });
		expect(
			manager.updateProviderSettings("openai", () => undefined),
		).toBeUndefined();
		manager.saveProviderSettings({ provider: "openai", model: "fixture" });
		const original = readFileSync(filePath);
		expect(
			manager.updateProviderSettings("openai", () => undefined),
		).toBeUndefined();
		expect(readFileSync(filePath)).toEqual(original);
		expect(() =>
			manager.updateProviderSettings("openai", () => ({
				provider: "anthropic",
			})),
		).toThrow(/provider identity/);
		expect(readFileSync(filePath)).toEqual(original);
	});
	it("preserves two independent field streams for the same provider across real processes", async () => {
		const filePath = fixture(),
			source = fileURLToPath(
				new URL("./provider-settings-manager.ts", import.meta.url),
			);
		const script = (field: string) =>
			`import {ProviderSettingsManager} from ${JSON.stringify(source)};const manager=new ProviderSettingsManager({filePath:${JSON.stringify(filePath)}});for(let i=0;i<16;i++)manager.updateProviderSettings("openai",current=>({...current,provider:"openai",[${JSON.stringify(field)}]:${field === "model" ? '"fixture-"+i' : '"https://fixture-"+i+".invalid/v1"'}}));`;
		await Promise.all([
			completed(child(script("model"), filePath)),
			completed(child(script("baseUrl"), filePath)),
		]);
		expect(
			new ProviderSettingsManager({ filePath }).getProviderSettings("openai"),
		).toMatchObject({
			model: "fixture-15",
			baseUrl: "https://fixture-15.invalid/v1",
		});
	});
});
