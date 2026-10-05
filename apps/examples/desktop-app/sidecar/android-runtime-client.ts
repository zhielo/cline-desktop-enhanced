import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, realpath, link, rm } from "node:fs/promises";
import { isAbsolute, join, relative, resolve } from "node:path";
import { z } from "zod";
import { probeAnalysisSandbox } from "./analysis-sandbox-client";
const Hash = z.string().regex(/^[a-f0-9]{64}$/);
export const AndroidCaptureInput = z
	.object({
		operation: z.literal("android_capture"),
		target: z.string().min(1).max(4096),
		package_name: z
			.string()
			.regex(/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/)
			.max(200),
		capture_dex: z.boolean().default(false),
		capture_native: z.boolean().default(false),
		output_directory: z.string().min(1).max(4096),
		timeout_ms: z.number().int().min(1000).max(120000).default(60000),
		job_nonce: z
			.string()
			.regex(/^[a-f0-9]{32}$/)
			.optional(),
		worker_endpoint: z.string().url().optional(),
		device_serial_sha256: Hash.optional(),
		worker_id: z.string().max(128).optional(),
		worker_key_sha256: Hash.optional(),
	})
	.strict();
export const AndroidReceipt = z
	.object({
		protocol: z.literal("cline-android-capture/v1"),
		workerId: z.string().min(1).max(128),
		nonce: z.string().regex(/^[a-f0-9]{32}$/),
		requestHash: Hash,
		artifactSha256: Hash,
		network: z.literal("disabled"),
		status: z.enum(["completed", "partial", "failed"]),
		engine: z.literal("android-frida"),
		evidence: z
			.object({
				device: z
					.object({
						kind: z.literal("physical"),
						deviceSerialSha256: Hash,
						abi: z.enum(["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]),
						rootProbe: z.literal("uid0-reported"),
						attestation: z.literal("not-proven"),
					})
					.strict()
					.optional(),
				artifacts: z
					.array(
						z
							.object({
								id: Hash,
								sha256: Hash,
								bytes: z.number().int().min(1).max(8388608),
								format: z.enum(["dex", "elf"]),
								source: z.string().max(2048),
							})
							.strict(),
					)
					.max(32),
				registrations: z
					.array(
						z
							.object({
								classDescriptor: z.string().max(512),
								processId: z.number().int().positive().optional(),
								classHandle: z
									.string()
									.regex(/^0x[a-f0-9]+$/)
									.optional(),
								classLoaderIdentity: z
									.string()
									.regex(
										/^(?:unresolved|bootstrap|identity-hash:0x[a-f0-9]{1,8})$/,
									)
									.optional(),
								classLoaderIdentityBasis: z
									.literal("vm-object-identity-hash-not-global-proof")
									.optional(),
								captureSessionNonce: z
									.string()
									.regex(/^[a-f0-9]{32}$/)
									.optional(),
								name: z.string().max(512),
								descriptor: z.string().max(512),
								addressHex: z.string().regex(/^0x[a-f0-9]+$/),
								relativeAddress: z
									.string()
									.regex(/^0x[a-f0-9]+$/)
									.optional(),
								module: z.string().max(2048).optional(),
								moduleSha256: Hash.optional(),
								moduleHashBasis: z
									.literal("captured-disk-file-not-loaded-memory-proof")
									.optional(),
								timestamp: z.number().int().nonnegative(),
								kind: z.literal("worker-observed-registration"),
							})
							.strict(),
					)
					.max(200),
				events: z
					.array(
						z
							.object({
								kind: z.string().max(80),
								source: z.string().max(2048),
								timestamp: z.number().int().nonnegative(),
							})
							.strict(),
					)
					.max(200),
			})
			.strict(),
		limitations: z.array(z.string().max(1000)).max(50),
	})
	.strict();
function config() {
	const endpoint = process.env.CLINE_ANALYSIS_SANDBOX_WORKER?.trim(),
		pem = process.env.CLINE_ANALYSIS_SANDBOX_PUBLIC_KEY?.trim(),
		token = process.env.CLINE_ANDROID_WORKER_TOKEN?.trim();
	if (!endpoint || !pem || !token || token.length < 32)
		throw new Error(
			"Android worker requires configured HTTPS endpoint, pinned key and bearer credential",
		);
	const key = createPublicKey(pem);
	if (key.asymmetricKeyType !== "ed25519") throw new Error("Ed25519 required");
	return {
		endpoint,
		key,
		token,
		keyHash: createHash("sha256")
			.update(key.export({ type: "spki", format: "der" }))
			.digest("hex"),
	};
}
export async function bindAndroidCapture(value: unknown) {
	const input = AndroidCaptureInput.parse(value),
		c = config(),
		health = await probeAnalysisSandbox();
	if (
		!health.ready ||
		!health.manifest?.operations?.includes("android-runtime-capture")
	)
		throw new Error("No ready signed Android capture worker");
	if (
		input.capture_native &&
		!health.manifest.operations?.includes("android-native-capture")
	)
		throw new Error("Worker lacks approved native disk capture capability");
	if (
		health.manifest.targetKind === "physical" &&
		!Hash.safeParse(health.manifest.deviceSerialSha256).success
	)
		throw new Error("Physical worker lacks configured device identity");
	return AndroidCaptureInput.parse({
		...input,
		job_nonce: randomBytes(16).toString("hex"),
		worker_endpoint: c.endpoint,
		worker_id: health.manifest.workerId,
		device_serial_sha256: health.manifest.deviceSerialSha256,
		worker_key_sha256: c.keyHash,
	});
}
async function bounded(response: Response) {
	if (!response.ok)
		throw new Error(
			`Android worker returned HTTP ${response.status}; do not replay execution blindly`,
		);
	const reader = response.body?.getReader();
	if (!reader) throw new Error("Missing worker response");
	let n = 0;
	const chunks: Uint8Array[] = [];
	try {
		for (;;) {
			const r = await reader.read();
			if (r.done) break;
			n += r.value.length;
			if (n > 16777216) throw new Error("Capture response exceeds budget");
			chunks.push(r.value);
		}
	} finally {
		await reader.cancel().catch(() => {});
		reader.releaseLock();
	}
	return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}
export async function verifyAndroidCapture(
	body: unknown,
	input: z.infer<typeof AndroidCaptureInput>,
	requestHash: string,
	artifactSha256: string,
) {
	const c = config(),
		b = body as { receipt?: unknown; signature?: unknown; captures?: unknown };
	if (
		input.worker_endpoint !== c.endpoint ||
		input.worker_key_sha256 !== c.keyHash
	)
		throw new Error("Worker identity changed since approval");
	if (
		typeof b.signature !== "string" ||
		b.signature.length > 128 ||
		!verify(
			null,
			Buffer.from(JSON.stringify(b.receipt)),
			c.key,
			Buffer.from(b.signature, "base64"),
		)
	)
		throw new Error("Invalid Android worker signature");
	const receipt = AndroidReceipt.parse(b.receipt);
	if (
		receipt.workerId !== input.worker_id ||
		receipt.nonce !== input.job_nonce ||
		receipt.requestHash !== requestHash ||
		receipt.artifactSha256 !== artifactSha256
	)
		throw new Error("Android receipt does not bind approved request");
	if (
		receipt.evidence.registrations.some(
			(row) =>
				row.captureSessionNonce && row.captureSessionNonce !== receipt.nonce,
		)
	)
		throw new Error("JNI observation session does not bind signed receipt");
	if (
		receipt.evidence.artifacts.some((a) =>
			a.format === "dex" ? !input.capture_dex : !input.capture_native,
		)
	)
		throw new Error(
			"Worker returned plaintext artifacts without capture consent",
		);
	if (
		input.device_serial_sha256 &&
		(receipt.status !== "failed" || receipt.evidence.artifacts.length > 0) &&
		receipt.evidence.device?.deviceSerialSha256 !== input.device_serial_sha256
	)
		throw new Error(
			"Physical device observation differs from approved identity",
		);
	const captures = z
		.array(
			z.object({ sha256: Hash, base64: z.string().max(11200000) }).strict(),
		)
		.max(32)
		.parse(b.captures ?? []);
	let total = 0;
	const files = captures.map((item) => {
		const bytes = Buffer.from(item.base64, "base64"),
			meta = receipt.evidence.artifacts.find((a) => a.sha256 === item.sha256);
		total += bytes.length;
		if (
			!meta ||
			meta.bytes !== bytes.length ||
			total > 8388608 ||
			createHash("sha256").update(bytes).digest("hex") !== item.sha256
		)
			throw new Error("Captured artifact integrity/budget mismatch");
		return { meta, bytes };
	});
	if (
		files.length !== receipt.evidence.artifacts.length ||
		new Set(receipt.evidence.artifacts.map((x) => x.sha256)).size !==
			receipt.evidence.artifacts.length
	)
		throw new Error("Missing or duplicate signed artifact payload");
	if (new Set(captures.map((x) => x.sha256)).size !== captures.length)
		throw new Error("Duplicate capture payload");
	return { receipt, signature: b.signature, files };
}
async function publish(
	root: string,
	directory: string,
	files: Array<{
		meta: { sha256: string; format: "dex" | "elf" | "receipt" };
		bytes: Buffer;
	}>,
) {
	const workspace = await realpath(root),
		target = resolve(workspace, directory),
		rel = relative(workspace, target);
	if (!rel || isAbsolute(rel) || rel.split(/[\\/]/).includes(".."))
		throw new Error(
			"Capture output must be a dedicated child of this workspace",
		);
	let current = workspace;
	for (const part of rel.split(/[\\/]/)) {
		current = join(current, part);
		await mkdir(current, { mode: 0o700 }).catch((e) => {
			if (e.code !== "EEXIST") throw e;
		});
		if (
			(await lstat(current)).isSymbolicLink() ||
			(await realpath(current)) !== current
		)
			throw new Error("Capture directory must not contain symlinks");
	}
	const ignore = await open(join(target, ".gitignore"), "wx", 0o600).catch(
		(e) => {
			if (e.code !== "EEXIST") throw e;
			return undefined;
		},
	);
	if (ignore) {
		try {
			await ignore.writeFile("*\n");
		} finally {
			await ignore.close();
		}
	}
	const paths: string[] = [];
	for (const { meta, bytes } of files) {
		const path = join(
				target,
				`${meta.sha256}.${meta.format === "dex" ? "dex" : meta.format === "elf" ? "so" : "receipt.json"}`,
			),
			stage = join(target, `.pending-${randomBytes(16).toString("hex")}`);
		const handle = await open(stage, "wx", 0o600);
		try {
			await handle.writeFile(bytes);
			await handle.sync();
		} finally {
			await handle.close();
		}
		try {
			await link(stage, path);
		} catch (e) {
			if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
			const h = await open(
				path,
				constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
			);
			try {
				const st = await h.stat();
				const existing = Buffer.alloc(bytes.length + 1);
				let read = 0;
				while (read < existing.length) {
					const got = await h.read(
						existing,
						read,
						existing.length - read,
						read,
					);
					if (!got.bytesRead) break;
					read += got.bytesRead;
				}
				if (
					!st.isFile() ||
					st.size !== bytes.length ||
					read !== bytes.length ||
					createHash("sha256")
						.update(existing.subarray(0, read))
						.digest("hex") !== meta.sha256
				)
					throw new Error("Existing capture artifact mismatch");
			} finally {
				await h.close();
			}
		} finally {
			await rm(stage, { force: true });
		}
		paths.push(path);
	}
	return paths;
}
export async function runAndroidCapture(
	value: unknown,
	artifact: Buffer | undefined,
	requestHash: string,
	root: string,
	signal?: AbortSignal,
	recover = false,
	expectedArtifactSha256?: string,
) {
	const input = AndroidCaptureInput.parse(value),
		c = config();
	if (!input.job_nonce || !Hash.safeParse(requestHash).success)
		throw new Error("Approved worker-bound job required");
	if (!recover && (!artifact?.length || artifact.length > 16777216))
		throw new Error("APK upload budget exceeded");
	const artifactSha256 = recover
		? Hash.parse(expectedArtifactSha256)
		: createHash("sha256").update(artifact!).digest("hex");
	if (
		input.worker_endpoint !== c.endpoint ||
		input.worker_key_sha256 !== c.keyHash
	)
		throw new Error("Worker identity changed before upload");
	const health = await probeAnalysisSandbox();
	if (
		!health.ready ||
		health.manifest?.workerId !== input.worker_id ||
		!health.manifest?.operations?.includes("android-runtime-capture")
	)
		throw new Error("Worker capability changed before upload");
	if (!recover && (!artifact?.length || artifact.length > 16777216))
		throw new Error("APK upload budget exceeded");
	if (signal?.aborted) throw new Error("Cancelled before Android submission");
	if (
		input.capture_native &&
		!health.manifest.operations?.includes("android-native-capture")
	)
		throw new Error("Worker lacks approved native disk capture capability");
	if (
		(input.device_serial_sha256 &&
			health.manifest.deviceSerialSha256 !== input.device_serial_sha256) ||
		(!recover &&
			health.manifest.targetKind === "physical" &&
			!input.device_serial_sha256)
	)
		throw new Error("Physical device changed or was not bound before upload");
	const controller = new AbortController(),
		abort = () => controller.abort();
	signal?.addEventListener("abort", abort, { once: true });
	const timer = setTimeout(abort, input.timeout_ms + 180000);
	try {
		const response = await fetch(
			new URL(recover ? `/v1/jobs/${input.job_nonce}` : "/v1/jobs", c.endpoint),
			{
				method: recover ? "GET" : "POST",
				redirect: "error",
				signal: controller.signal,
				headers: {
					authorization: `Bearer ${c.token}`,
					"content-type": "application/json",
				},
				...(recover
					? {}
					: {
							body: JSON.stringify({
								protocol: "cline-android-capture/v1",
								nonce: input.job_nonce,
								requestHash,
								artifactSha256,
								network: "disabled",
								operation: "android_capture",
								packageName: input.package_name,
								captureDex: input.capture_dex,
								captureNative: input.capture_native,
								timeoutMs: input.timeout_ms,
								artifactBase64: artifact!.toString("base64"),
							}),
						}),
			},
		);
		const verified = await verifyAndroidCapture(
			await bounded(response),
			input,
			requestHash,
			artifactSha256,
		);
		const receiptBytes = Buffer.from(
			JSON.stringify({
				receipt: verified.receipt,
				signature: verified.signature,
			}),
		);
		if (receiptBytes.length > 1048576)
			throw new Error("Signed receipt exceeds storage budget");
		const receiptHash = createHash("sha256").update(receiptBytes).digest("hex");
		const outputPaths = await publish(root, input.output_directory, [
			...verified.files,
			{ meta: { sha256: receiptHash, format: "receipt" }, bytes: receiptBytes },
		]);
		return { ...verified.receipt, signature: verified.signature, outputPaths };
	} finally {
		clearTimeout(timer);
		signal?.removeEventListener("abort", abort);
	}
}
