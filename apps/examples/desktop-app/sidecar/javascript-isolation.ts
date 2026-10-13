import { isolationHostEnvironment } from "./isolation-host-environment";
import { isolationHostFailureMessage } from "./isolation-host-failure";
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
	lstat,
	mkdtemp,
	mkdir,
	readFile,
	realpath,
	rm,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, isAbsolute } from "node:path";
import { z } from "zod";
import {
	ScenarioExpectationSchema,
	reconcileProcessScenario,
} from "@cline/core";
const Hash = z.string().regex(/^[a-f0-9]{64}$/);
const Scenario = z
	.unknown()
	.transform((value) => ScenarioExpectationSchema.parse(value));
export const JavaScriptExecutionSchema = z
	.object({
		operation: z.literal("js_isolated_execute"),
		target: z.string().min(1).max(4096),
		timeoutMs: z.number().int().min(1000).max(30000).default(5000),
		scenario: Scenario,
		resourceDigest: Hash,
	})
	.strict();
export type IsolationResources = { root: string; manifestDigest: string };
const Manifest = z
	.object({
		schemaVersion: z.literal(1),
		profile: z.literal("cline-js-appcontainer/1"),
		files: z
			.object({
				"javascript-isolation-host.exe": Hash,
				"javascript-isolation-runtime.exe": Hash,
			})
			.strict(),
	})
	.strict();
const Receipt = z
	.object({
		profile: z.literal("cline-js-appcontainer/1"),
		isolation: z.literal("appcontainer"),
		sid: z.string().regex(/^S-1-15-2-(?:\d+-){6}\d+$/),
		capabilityCount: z.literal(0),
		verifiedBeforeResume: z.literal(true),
		pid: z.number().int().positive(),
		creationFileTime: z.string().regex(/^\d{15,20}$/),
		exitCode: z.number().int().min(0).max(4294967295),
		timedOut: z.boolean(),
		overflow: z.boolean(),
		stdoutBase64: z.string().max(87384),
		stderrBase64: z.string().max(87384),
	})
	.strict();
const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
export function installedJavaScriptIsolationResources(): IsolationResources {
	if (process.platform !== "win32" || process.arch !== "x64")
		throw new Error(
			"Active JavaScript isolation supports Windows x64 only; no unsandboxed fallback",
		);
	const manifestDigest = process.env.CLINE_JS_ISOLATION_MANIFEST_SHA256;
	if (!manifestDigest || !Hash.safeParse(manifestDigest).success)
		throw new Error(
			"Trusted packaged AppContainer resources unavailable; build/reinstall the updated desktop",
		);
	return {
		root: join(dirname(process.execPath), "bin", "javascript-isolation"),
		manifestDigest,
	};
}
async function boundedFile(file: string, max: number) {
	const s = await lstat(file);
	if (!s.isFile() || s.isSymbolicLink() || s.size > max)
		throw new Error("Isolation file type/byte budget");
	const bytes = await readFile(file);
	if (bytes.length > max)
		throw new Error("Isolation file grew beyond byte budget");
	return bytes;
}
export async function verifyJavaScriptIsolationResources(
	resources: IsolationResources,
) {
	if (process.platform !== "win32" || process.arch !== "x64")
		throw new Error("Windows x64 isolation required");
	// Windows realpath can expand RUNNER~1 / 8.3 names and normalize separators.
	// Text inequality is not proof of a link. Use actual directory/file types,
	// reject leaf links and pin every executable's bytes to the build manifest.
	const stat = await lstat(resources.root);
	if (
		!isAbsolute(resources.root) ||
		!stat.isDirectory() ||
		stat.isSymbolicLink()
	)
		throw new Error("Non-linked absolute packaged isolation root required");
	const root = await realpath(resources.root);
	const bytes = await boundedFile(join(root, "manifest.json"), 4096);
	if (sha(bytes) !== resources.manifestDigest)
		throw new Error(
			"Isolation resource manifest changed; reinstall trusted desktop",
		);
	const manifest = Manifest.parse(JSON.parse(bytes.toString("utf8")));
	for (const [name, hash] of Object.entries(manifest.files)) {
		const file = join(root, name);
		if (sha(await boundedFile(file, 128 * 1024 * 1024)) !== hash)
			throw new Error(
				"Isolation executable changed; reinstall trusted desktop",
			);
	}
	return { root, manifest };
}
export async function bindJavaScriptExecution(input: unknown) {
	const resources = installedJavaScriptIsolationResources();
	await verifyJavaScriptIsolationResources(resources);
	const supplied = z
		.object({
			operation: z.literal("js_isolated_execute"),
			target: z.string(),
			timeoutMs: z.number().optional(),
			scenario: Scenario,
		})
		.strict()
		.parse(input);
	return JavaScriptExecutionSchema.parse({
		...supplied,
		resourceDigest: resources.manifestDigest,
	});
}
function base64(value: string) {
	const bytes = Buffer.from(value, "base64");
	if (bytes.length > 65536 || bytes.toString("base64") !== value)
		throw new Error("Malformed bounded capture");
	return bytes;
}
export async function runIsolatedJavaScript(
	input: unknown,
	approved: { targetSha256: string; requestHash: string },
	signal?: AbortSignal,
	resources = installedJavaScriptIsolationResources(),
) {
	const request = JavaScriptExecutionSchema.parse(input);
	if (request.resourceDigest !== resources.manifestDigest)
		throw new Error("Isolation resources changed after approval");
	const { root: resourceRoot, manifest } =
		await verifyJavaScriptIsolationResources(resources);
	const source = await boundedFile(request.target, 1024 * 1024);
	if (sha(source) !== approved.targetSha256)
		throw new Error("Target bytes changed after Execute approval");
	if (signal?.aborted)
		throw new Error("Isolated execution cancelled before staging");
	const helperEnvironment = isolationHostEnvironment(process.env, tmpdir());
	const profileName = `cline-js-${randomUUID().replaceAll("-", "")}`;
	const root = await mkdtemp(join(tmpdir(), "cline-js-isolated-"));
	try {
		await mkdir(join(root, "scratch"));
		await writeFile(join(root, "target.cjs"), source, { mode: 0o400 });
		// Copy verified bytes, not an executable path from PATH or the target inventory.
		const runtimeBytes = await boundedFile(
			join(resourceRoot, "javascript-isolation-runtime.exe"),
			128 * 1024 * 1024,
		);
		if (
			sha(runtimeBytes) !== manifest.files["javascript-isolation-runtime.exe"]
		)
			throw new Error("Runtime resource changed while staging");
		await writeFile(join(root, "runtime.exe"), runtimeBytes);
		const encoded = await new Promise<string>((resolveReceipt, reject) => {
			const child = spawn(
				join(resourceRoot, "javascript-isolation-host.exe"),
				[root, String(request.timeoutMs), "run", profileName],
				{
					stdio: ["ignore", "pipe", "ignore"],
					windowsHide: true,
					cwd: resourceRoot,
					env: helperEnvironment,
				},
			);
			let out = Buffer.alloc(0),
				failure: Error | undefined,
				finished = false;
			const stop = (message: string) => {
				failure ??= new Error(message);
				child.kill();
			};
			const abort = () =>
				stop(
					"Isolated execution cancelled; approval is consumed, do not replay",
				);
			signal?.addEventListener("abort", abort, { once: true });
			if (signal?.aborted) abort();
			const timer = setTimeout(
				() => stop("Isolation host deadline exceeded"),
				request.timeoutMs + 20000,
			);
			const finish = (error?: Error) => {
				if (finished) return;
				finished = true;
				clearTimeout(timer);
				signal?.removeEventListener("abort", abort);
				if (error) reject(error);
				else resolveReceipt(out.toString("utf8"));
			};
			child.stdout.on("data", (chunk: Buffer) => {
				if (out.length + chunk.length > 196608)
					stop("Isolation host receipt budget");
				else out = Buffer.concat([out, chunk]);
			});
			child.once("error", (e) => finish(e));
			child.once("close", (code) =>
				finish(
					failure ??
						(code !== 0
							? new Error(isolationHostFailureMessage(out.toString("utf8")))
							: undefined),
				),
			);
		});
		const receipt = Receipt.parse(JSON.parse(encoded));
		const stdout = base64(receipt.stdoutBase64),
			stderr = base64(receipt.stderrBase64);
		const scenario = reconcileProcessScenario(request.scenario, {
			...receipt,
			stdout,
			artifactSha256: approved.targetSha256,
			requestHash: approved.requestHash,
			isolationVerified: true,
		});
		return {
			profile: receipt.profile,
			input: { sha256: approved.targetSha256 },
			requestHash: approved.requestHash,
			isolation: {
				kind: receipt.isolation,
				sid: receipt.sid,
				capabilityCount: 0,
				verifiedBeforeResume: true,
				pid: receipt.pid,
				creationFileTime: receipt.creationFileTime,
			},
			exitCode: receipt.exitCode,
			timedOut: receipt.timedOut,
			overflow: receipt.overflow,
			stdout: { bytes: stdout.length, sha256: sha(stdout) },
			stderr: { bytes: stderr.length, sha256: sha(stderr) },
			scenario,
			verifiedBehavior: scenario.outcome === "supported",
			verificationScope: scenario.scope,
			limitations: [
				"Windows x64 kernel AppContainer, not a VM. No capabilities or network exemptions are provisioned. OS/all-application-package-readable files can remain accessible; not complete host filesystem secrecy.",
				"Standalone staged CommonJS file only; no external dependencies, Electron desktop or automatic target retries. Raw output is not retained.",
			],
		};
	} finally {
		const cleanup = spawnSync(
			join(resourceRoot, "javascript-isolation-host.exe"),
			["--cleanup", profileName],
			{
				stdio: "ignore",
				windowsHide: true,
				timeout: 10000,
				env: helperEnvironment,
			},
		);
		await rm(root, {
			recursive: true,
			force: true,
			maxRetries: 5,
			retryDelay: 100,
		});
		if (cleanup.status !== 0)
			// biome-ignore lint/correctness/noUnsafeFinally: Unconfirmed cleanup must discard even an otherwise successful receipt; never authorize replay.
			throw new Error(
				"AppContainer profile cleanup failed; no successful execution receipt",
			);
	}
}
