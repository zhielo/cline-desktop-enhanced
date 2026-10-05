import { SEMANTIC_PCODE_WORKER } from "./semantic-pcode-worker";
import { validateNativeProgram } from "./native-program";
import { readAnalysisJson } from "./analysis-notebook";
import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, writeFile, rm, stat, realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, isAbsolute } from "node:path";
import { z } from "zod";
import { ADVANCED_ANALYSIS_WORKER } from "./advanced-analysis-worker";
import {
	prepareProcessEnvironment,
	redactSensitiveText,
} from "./process-environment-policy";
export const ADVANCED_ACTIONS = [
	"toolchain",
	"suite",
	"triage",
	"apk_inventory",
	"dex_index",
	"native_inventory",
	"native_disassemble",
	"simplify_expression",
	"compare_expressions",
	"transform_blob",
	"triton_expression",
	"match_native_functions",
	"trace_native_region",
	"trace_input_influence",
	"trace_android_dataflow",
	"lift_native_ir",
	"deobfuscation_pass",
	"jeb_analysis",
	"virtual_dispatch",
	"graph_build",
	"graph_query",
	"notebook_validate",
	"notebook_run", "cfg_analyze", "trace_slice", "trace_taint",
	"decrypt_blob",
	"native_functions_rizin",
	"native_program",
	"native_semantics",
] as const;
export type AdvancedAction = (typeof ADVANCED_ACTIONS)[number];
const LOCAL_ACTIONS = new Set<AdvancedAction>([
	...ADVANCED_ACTIONS.slice(0, 12),
	"lift_native_ir",
	"deobfuscation_pass",
	"decrypt_blob",
	"native_semantics",
]);
export const ADVANCED_BACKENDS = [
	{ id: "rizin", integration: "bounded-static-function-recovery" },
	{ id: "cryptography", integration: "host-gated-authenticated-decryption" },
	{ id: "z3", integration: "local-fixed-worker" },
	{ id: "triton", integration: "expression-only-worker" },
	{ id: "lief", integration: "local-fixed-worker" },
	{ id: "capstone", integration: "local-fixed-worker" },
	{ id: "androguard", integration: "local-fixed-worker" },
	{ id: "qbindiff", integration: "local-binexport-worker" },
	{ id: "qbdi", integration: "isolated-runtime-required" },
	{ id: "flowdroid", integration: "external-adapter-required" },
	{ id: "remill", integration: "external-adapter-required" },
	{ id: "miasm", integration: "bounded-static-ir-worker" },
	{ id: "jeb", integration: "licensed-adapter-required" },
	{ id: "ida-d810", integration: "licensed-adapter-required" },
] as const;
const ResultSchema = z.object({
	protocol: z.literal("cline-advanced-analysis/v1"),
	status: z.enum(["completed", "partial", "blocked", "failed", "cancelled"]),
	engine: z.string(),
	engineVersion: z.string().nullable(),
	evidence: z.record(z.string(), z.unknown()),
	limitations: z.array(z.string()),
	input: z
		.object({
			sha256: z.string().regex(/^[a-f0-9]{64}$/),
			bytes: z.number(),
			format: z.string(),
		})
		.optional(),
});
export type AdvancedResult = z.infer<typeof ResultSchema>;
export interface AdvancedRequest {
	action: AdvancedAction;
	target?: string;
	compareTarget?: string;
	limit?: number;
	timeoutMs?: number;
	options?: {
		native?: { functionName?: string; maxFunctions?: number; maxPcodeOps?: number };
		architecture?: string;
		offset?: number;
		address?: number;
		bytes?: number;
		steps?: string[];
		decrypt?: {
			algorithm: "aes-256-gcm" | "chacha20-poly1305";
			nonce_hex: string;
			aad_hex?: string;
			analysis?: "triage" | "structured";
		};
	};
}
function outcome(
	status: AdvancedResult["status"],
	reason: string,
): AdvancedResult {
	return {
		protocol: "cline-advanced-analysis/v1",
		status,
		engine: "host",
		engineVersion: "1",
		evidence: { reason },
		limitations: [],
	};
}
function killTree(child: ChildProcess) {
	if (!child.pid) return;
	if (process.platform === "win32") {
		const killer = spawn("taskkill", ["/pid", String(child.pid), "/t", "/f"], {
			stdio: "ignore",
			windowsHide: true,
		});
		killer.on("error", () => {
			child.kill();
		});
		killer.unref();
	} else {
		try {
			process.kill(-child.pid, "SIGKILL");
		} catch {
			child.kill("SIGKILL");
		}
	}
}
export async function runAdvancedAnalysis(
	request: AdvancedRequest,
	signal?: AbortSignal,
): Promise<AdvancedResult> {
	if (!ADVANCED_ACTIONS.includes(request.action))
		throw new Error("Unknown advanced action");
	if (!LOCAL_ACTIONS.has(request.action))
		return outcome(
			"blocked",
			"No reviewed adapter is shipped. Runtime execution needs an externally provisioned isolated backend; engine presence alone does not enable it.",
		);
	if (signal?.aborted)
		return outcome("cancelled", "Cancelled before execution");
	if (request.action === "decrypt_blob") {
		if (process.env.CLINE_RE_ALLOW_DECRYPTION !== "1")
			return outcome("blocked", "Host has not enabled known-key decryption");
		const keyPath = process.env.CLINE_RE_PRIVATE_KEY_FILE;
		if (
			!keyPath ||
			!isAbsolute(keyPath) ||
			!process.env.CLINE_RE_PYTHON ||
			!isAbsolute(process.env.CLINE_RE_PYTHON)
		)
			return outcome(
				"blocked",
				"Host-owned absolute private key file and trusted Python interpreter required",
			);
		const key = await stat(await realpath(keyPath));
		if (
			!key.isFile() ||
			key.size !== 32 ||
			(process.platform !== "win32" &&
				((key.mode & 0o077) !== 0 ||
					(process.getuid && key.uid !== process.getuid())))
		)
			return outcome(
				"blocked",
				"Private key file size, ownership or permissions are unsafe",
			);
	}
	const paths =
		request.action === "toolchain"
			? []
			: [
					request.target,
					...(request.action === "match_native_functions"
						? [request.compareTarget]
						: []),
				];
	for (const input of paths) {
		if (!input || !isAbsolute(input))
			throw new Error("Absolute artifact/compare_target required");
		const info = await stat(await realpath(input));
		if (
			!info.isFile() ||
			info.size > (request.action === "decrypt_blob" ? 16 : 128) * 1024 * 1024
		)
			throw new Error("Input must be file <=128 MiB");
	}
	const executable =
		process.env.CLINE_RE_PYTHON?.trim() ||
		(process.platform === "win32" ? "python.exe" : "python3");
	if (process.env.CLINE_RE_PYTHON && !isAbsolute(executable))
		throw new Error("CLINE_RE_PYTHON must be an absolute interpreter path");
	if (request.action === "native_semantics" && (!process.env.CLINE_RE_PYTHON || !isAbsolute(executable))) return outcome("blocked", "Semantic analysis requires a trusted absolute Python interpreter");
	const nativeDocument = request.action === "native_semantics" ? validateNativeProgram(await readAnalysisJson(request.target!,1048576)) : undefined;
	const directory = await mkdtemp(join(tmpdir(), "cline-advanced-"));
	const script = join(directory, "worker.py");
	await writeFile(script, request.action === "native_semantics" ? SEMANTIC_PCODE_WORKER : ADVANCED_ANALYSIS_WORKER, { mode: 0o600 });
	if (nativeDocument) await writeFile(join(directory,"program.json"),JSON.stringify(nativeDocument),{flag:"wx",mode:0o600});
	const policy = prepareProcessEnvironment({
		overrides: { PYTHONNOUSERSITE: "1" },
		allowedSensitiveEnvironmentVariables:
			request.action === "decrypt_blob" ? ["CLINE_RE_PRIVATE_KEY_FILE"] : [],
	});
	try {
		return await new Promise<AdvancedResult>((resolve) => {
			let child: ChildProcess;
			try {
				child = spawn(
					executable,
					[
						"-I",
						script,
						JSON.stringify({
							action: request.action,
							target: nativeDocument ? join(directory,"program.json") : request.target,
							compare_target: request.compareTarget,
							limit: request.limit ?? 200,
							options: request.options,
						}),
					],
					{
						cwd: directory,
						env: policy.environment,
						detached: process.platform !== "win32",
						windowsHide: true,
						stdio: ["ignore", "pipe", "pipe"],
					},
				);
			} catch {
				resolve(outcome("blocked", "Unable to start interpreter"));
				return;
			}
			let stdout = "";
			let bytes = 0;
			let interrupted: "failed" | "cancelled" | undefined;
			let reason = "";
			let settled = false;
			const stop = (status: "failed" | "cancelled", detail: string) => {
				if (interrupted) return;
				interrupted = status;
				reason = detail;
				killTree(child);
			};
			const timer = setTimeout(
				() => stop("failed", "Analysis time budget exceeded"),
				Math.min(request.timeoutMs ?? 120000, 300000),
			);
			const abort = () => stop("cancelled", "Analysis cancelled");
			const finish = (result: AdvancedResult) => {
				if (settled) return;
				settled = true;
				clearTimeout(timer);
				signal?.removeEventListener("abort", abort);
				resolve(result);
			};
			signal?.addEventListener("abort", abort, { once: true });
			if (signal?.aborted) abort();
			child.stdout?.on("data", (chunk: Buffer) => {
				bytes += chunk.length;
				if (bytes > 1024 * 1024) {
					stop("failed", "Worker output budget exceeded");
					return;
				}
				stdout += chunk.toString("utf8");
			});
			child.stderr?.on("data", () => undefined);
			child.on("error", () =>
				finish(outcome("blocked", "Configured interpreter unavailable")),
			);
			child.on("close", (code) => {
				if (interrupted) {
					finish(outcome(interrupted, reason));
					return;
				}
				if (code !== 0) {
					finish(outcome("failed", "Worker exited unsuccessfully"));
					return;
				}
				try {
					finish(
						ResultSchema.parse(
							JSON.parse(redactSensitiveText(stdout, policy.secretValues)),
						),
					);
				} catch {
					finish(outcome("failed", "Worker returned invalid evidence"));
				}
			});
		});
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
}
export function advancedEvidenceBundle(
	action: AdvancedAction,
	result: AdvancedResult,
) {
	const body = {
		schemaVersion: 1,
		action,
		result,
		coverage: "bounded-selected-analysis",
		backendContracts: ADVANCED_BACKENDS,
	};
	return {
		...body,
		resultSha256: createHash("sha256")
			.update(JSON.stringify(body))
			.digest("hex"),
	};
}
