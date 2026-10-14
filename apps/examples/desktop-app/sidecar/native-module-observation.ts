import { spawn } from "node:child_process";
import { join } from "node:path";
import { z } from "zod";
import { HybridContextSchema } from "@cline/core";
import { probeProcessStartTokenAsync } from "@cline/core";
import {
	installedJavaScriptIsolationResources,
	verifyJavaScriptIsolationResources,
	type IsolationResources,
} from "./javascript-isolation";
const Hex = z.string().regex(/^0x[a-f0-9]{1,16}$/i),
	Hash = z.string().regex(/^[a-f0-9]{64}$/);
export const NativeModuleRequestSchema = z
	.object({
		operation: z.literal("native_module_observe"),
		hybrid: z
			.unknown()
			.transform((value) => HybridContextSchema.parse(value))
			.optional(),
		target: z.string().min(1).max(4096),
		pid: z.number().int().positive(),
		processToken: z.string().regex(/^win32:\d{15,20}$/),
		runtimeAddress: Hex,
		resourceDigest: Hash,
	})
	.strict();
const Report = z
	.object({
		profile: z.literal("cline-native-module/1"),
		artifactSha256: Hash,
		pid: z.number().int().positive(),
		processToken: z.string(),
		architecture: z.enum(["x86_64", "x86", "arm64"]),
		runtimeImageBase: Hex,
		runtimeAddress: Hex,
		rva: Hex,
		observedBytes: z.literal(32),
		memorySha256: Hash,
		fileRangeSha256: Hash,
		byteMatch: z.boolean(),
		scope: z.literal(
			"host-read-process-memory-exact-birth-and-module-32-byte-range",
		),
	})
	.strict();
export async function bindNativeModuleObservation(input: unknown) {
	const value = z
		.object({
			operation: z.literal("native_module_observe"),
			target: z.string(),
			pid: z.number().int().positive(),
			runtimeAddress: Hex,
		})
		.strict()
		.parse(input);
	const resources = installedJavaScriptIsolationResources();
	await verifyJavaScriptIsolationResources(resources);
	const birth = await probeProcessStartTokenAsync(value.pid);
	if (birth.status !== "found")
		throw new Error("Exact native process birth unavailable");
	return NativeModuleRequestSchema.parse({
		...value,
		processToken: birth.token,
		resourceDigest: resources.manifestDigest,
	});
}
export async function observeNativeModule(
	input: unknown,
	artifactSha256: string,
	signal?: AbortSignal,
	resources: IsolationResources = installedJavaScriptIsolationResources(),
) {
	const request = NativeModuleRequestSchema.parse(input);
	if (request.resourceDigest !== resources.manifestDigest)
		throw new Error("Native observer build changed after approval");
	const { root } = await verifyJavaScriptIsolationResources(resources);
	const raw = await new Promise<string>((resolve, reject) => {
		const child = spawn(
			join(root, "javascript-isolation-host.exe"),
			[
				"--module",
				String(request.pid),
				request.processToken.slice(6),
				artifactSha256,
				request.target,
				request.runtimeAddress,
			],
			{
				stdio: ["ignore", "pipe", "ignore"],
				windowsHide: true,
				env: { SystemRoot: process.env.SystemRoot ?? "C:\\Windows" },
			},
		);
		let output = "",
			failure: Error | undefined;
		const stop = (reason: string) => {
			failure = new Error(reason);
			child.kill();
		};
		const abort = () => stop("Native observation cancelled");
		signal?.addEventListener("abort", abort, { once: true });
		if (signal?.aborted) abort();
		const timeout = setTimeout(
			() => stop("Native observation deadline"),
			10000,
		);
		child.stdout.on("data", (b) => {
			if (Buffer.byteLength(output) + b.length > 8192)
				stop("Native observation output budget");
			else output += b.toString("utf8");
		});
		child.once("error", (e) => {
			clearTimeout(timeout);
			signal?.removeEventListener("abort", abort);
			reject(e);
		});
		child.once("close", (code) => {
			clearTimeout(timeout);
			signal?.removeEventListener("abort", abort);
			if (failure || code !== 0)
				reject(
					failure ??
						new Error(
							"Exact native observation unavailable; no relocation guessed",
						),
				);
			else resolve(output);
		});
	});
	const report = Report.parse(JSON.parse(raw));
	if (
		report.artifactSha256 !== artifactSha256 ||
		report.pid !== request.pid ||
		report.processToken !== request.processToken ||
		BigInt(report.runtimeAddress) !== BigInt(request.runtimeAddress) ||
		BigInt(report.runtimeAddress) - BigInt(report.runtimeImageBase) !==
			BigInt(report.rva) ||
		report.byteMatch !== (report.memorySha256 === report.fileRangeSha256)
	)
		throw new Error("Native observer exact request binding mismatch");
	return {
		input: { sha256: artifactSha256 },
		moduleObservation: report,
		verifiedBehavior: false,
		limitations: [
			"Observed 32-byte mapped PE range only, not whole-image identity or relocation semantics. ASLR conversion is tied to this exact process birth and observed module; not reusable on another run.",
			"Process memory reads require independent Debug approval; do not imply target execution or function equivalence. Import/IAT-patched ranges can correctly disagree with file bytes.",
		],
	};
}
