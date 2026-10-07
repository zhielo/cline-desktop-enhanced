import { z } from "zod";
import { ownedFile } from "./incident-artifacts";

const Selector = z
	.object({
		symbol: z.string().min(1).max(300).optional(),
		address: z
			.string()
			.regex(/^0x[0-9a-fA-F]{1,16}$/)
			.optional(),
	})
	.strict()
	.refine(
		(s) => Number(!!s.symbol) + Number(!!s.address) === 1,
		"Exactly one symbol/address",
	);
export async function planEvidenceAnalysis(root: string, value: unknown) {
	const input = z
			.object({
				target: z.string().min(1),
				engine: z.enum(["auto", "ida", "ghidra", "jadx"]).default("auto"),
				function: Selector.optional(),
				method: z
					.object({
						class_descriptor: z.string().min(1).max(500),
						name: z.string().min(1).max(300),
						descriptor: z.string().min(1).max(500),
					})
					.strict()
					.optional(),
			})
			.strict()
			.parse(value),
		f = await ownedFile(root, input.target);
	const format = f.bytes.subarray(0, 4).equals(Buffer.from([0x7f, 69, 76, 70]))
		? "elf"
		: f.bytes.subarray(0, 4).toString() === "dex\n"
			? "dex"
			: f.bytes.subarray(0, 2).toString() === "PK"
				? "apk-or-zip"
				: f.bytes.subarray(0, 2).toString() === "MZ"
					? "pe"
					: "opaque";
	const stages: {
		id: string;
		backend: string;
		depends_on: string[];
		request: Record<string, unknown>;
		timeout_ms: number;
		reason: string;
	}[] = [
		{
			id: "identify",
			backend: "static",
			depends_on: [],
			request: { engine: "auto", operation: "inspect", target: f.path },
			timeout_ms: 30000,
			reason: "Verify actual file format before choosing an engine",
		},
	];
	const add = (id: string, action: string, options?: unknown) =>
		stages.push({
			id,
			backend: "static",
			depends_on: [stages.at(-1)!.id],
			request: {
				engine: "auto",
				operation: "advanced_analysis",
				advanced_action: action,
				target: f.path,
				...(options ? { advanced_options: options } : {}),
			},
			timeout_ms: 120000,
			reason:
				"Bounded evidence only; missing engines, ambiguity and parser limits must remain visible",
		});
	if (format === "apk-or-zip") {
		add("inventory", "apk_inventory");
		add("embedded-discovery", "artifact_discovery");
		if (input.method)
			add("exact-method", "android_method_code", { method: input.method });
	} else if (format === "dex") {
		add("dex-index", "dex_index");
		if (input.method)
			add("exact-method", "android_method_code", { method: input.method });
	} else if (format === "elf") {
		add("native-inventory", "native_inventory");
		if (input.function)
			add("exact-function", "native_function", {
				function: { ...input.function, max_bytes: 4096 },
			});
	}
	if (input.function && ["ida", "ghidra"].includes(input.engine)) {
		stages.push({
			id: "decompile-selection",
			backend: "static",
			depends_on: [stages.at(-1)!.id],
			request: {
				engine: input.engine,
				operation: "decompile",
				target: f.path,
				function_selector: input.function,
			},
			timeout_ms: 300000,
			reason:
				"Explicit exact selector; a supplied selector is not automatically a proven function",
		});
	}
	return {
		target: f.path,
		sha256: f.sha256,
		format,
		stages,
		limitations: [
			"Plan creation does not execute anything",
			"APK/ZIP magic does not prove APK validity",
			"Stripped function boundaries and JNI registration are not guessed",
			"Encrypted/hostile inputs require approved isolated recovery; no automatic unknown-key decryption",
		],
		nextSteps:
			input.function || input.method
				? []
				: [
						"Inspect bounded inventory, then supply an exact method descriptor or validated function selector before deep analysis",
					],
	};
}
