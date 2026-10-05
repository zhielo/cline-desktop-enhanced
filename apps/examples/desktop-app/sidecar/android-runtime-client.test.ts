import { generateKeyPairSync, createHash, sign } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	AndroidCaptureInput,
	verifyAndroidCapture,
	runAndroidCapture,
} from "./android-runtime-client";
import { mkdtemp, readFile, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { probeAnalysisSandbox } from "./analysis-sandbox-client";
vi.mock("./analysis-sandbox-client", () => ({ probeAnalysisSandbox: vi.fn() }));
afterEach(() => {
	vi.unstubAllEnvs();
	vi.restoreAllMocks();
});
function fixture() {
	const keys = generateKeyPairSync("ed25519"),
		pem = keys.publicKey.export({ format: "pem", type: "spki" }).toString();
	vi.stubEnv("CLINE_ANALYSIS_SANDBOX_WORKER", "https://worker.example.test/");
	vi.stubEnv("CLINE_ANALYSIS_SANDBOX_PUBLIC_KEY", pem);
	vi.stubEnv("CLINE_ANDROID_WORKER_TOKEN", "x".repeat(40));
	const input = AndroidCaptureInput.parse({
		operation: "android_capture",
		target: "owned.apk",
		package_name: "com.example.owned",
		output_directory: "captures",
		job_nonce: "a".repeat(32),
		worker_endpoint: "https://worker.example.test/",
		worker_id: "worker",
		worker_key_sha256: createHash("sha256")
			.update(keys.publicKey.export({ format: "der", type: "spki" }))
			.digest("hex"),
	});
	const bytes = Buffer.from("owned fixture"),
		hash = createHash("sha256").update(bytes).digest("hex"),
		receipt = {
			protocol: "cline-android-capture/v1",
			workerId: "worker",
			nonce: input.job_nonce,
			requestHash: "b".repeat(64),
			artifactSha256: "c".repeat(64),
			network: "disabled",
			status: "partial",
			engine: "android-frida",
			evidence: {
				artifacts: [
					{
						id: hash,
						sha256: hash,
						bytes: bytes.length,
						format: "dex",
						source: "owned-loader",
					},
				],
				registrations: [],
				events: [],
			},
			limitations: ["Owned transport fixture; not real Android execution"],
		};
	return {
		input,
		receipt,
		body: {
			receipt,
			signature: sign(
				null,
				Buffer.from(JSON.stringify(receipt)),
				keys.privateKey,
			).toString("base64"),
			captures: [{ sha256: hash, base64: bytes.toString("base64") }],
		},
	};
}
describe("signed Android capture boundary", () => {
	it("requires exact package and bounded, reviewed operation fields", () => {
		expect(
			AndroidCaptureInput.safeParse({
				operation: "android_capture",
				target: "apk",
				package_name: "com.x; rm -rf /",
				output_directory: "captures",
			}).success,
		).toBe(false);
		expect(
			AndroidCaptureInput.safeParse({
				operation: "android_capture",
				target: "apk",
				package_name: "com.x",
				output_directory: "captures",
				script: "injection",
			}).success,
		).toBe(false);
	});
	it("verifies signed identities and content bytes, retaining partial coverage", async () => {
		const f = fixture(),
			result = await verifyAndroidCapture(
				f.body,
				f.input,
				"b".repeat(64),
				"c".repeat(64),
			);
		expect(result.receipt.status).toBe("partial");
		expect(result.files).toHaveLength(1);
	});
	it("rejects changed signature, nonce, worker identity or capture bytes", async () => {
		const f = fixture();
		await expect(
			verifyAndroidCapture(
				{ ...f.body, signature: "bad" },
				f.input,
				"b".repeat(64),
				"c".repeat(64),
			),
		).rejects.toThrow("signature");
		await expect(
			verifyAndroidCapture(
				f.body,
				{ ...f.input, job_nonce: "d".repeat(32) },
				"b".repeat(64),
				"c".repeat(64),
			),
		).rejects.toThrow("bind");
		await expect(
			verifyAndroidCapture(
				f.body,
				{ ...f.input, worker_key_sha256: "0".repeat(64) },
				"b".repeat(64),
				"c".repeat(64),
			),
		).rejects.toThrow("identity");
		await expect(
			verifyAndroidCapture(
				{
					...f.body,
					captures: [
						{
							...f.body.captures[0],
							base64: Buffer.from("tampered").toString("base64"),
						},
					],
				},
				f.input,
				"b".repeat(64),
				"c".repeat(64),
			),
		).rejects.toThrow("integrity");
	});
	it("rejects missing or duplicate captured payloads", async () => {
		const f = fixture();
		await expect(
			verifyAndroidCapture(
				{ ...f.body, captures: [] },
				f.input,
				"b".repeat(64),
				"c".repeat(64),
			),
		).rejects.toThrow("Missing");
		await expect(
			verifyAndroidCapture(
				{ ...f.body, captures: [...f.body.captures, ...f.body.captures] },
				f.input,
				"b".repeat(64),
				"c".repeat(64),
			),
		).rejects.toThrow();
	});
});

describe("capture publication and retrieval", () => {
	it("retrieves a prior signed receipt with GET only, persists signature and never reuploads APK", async () => {
		const f = fixture(),
			root = await mkdtemp(join(tmpdir(), "capture-test-"));
		vi.mocked(probeAnalysisSandbox).mockResolvedValue({
			ready: true,
			manifest: { workerId: "worker", operations: ["android-runtime-capture"] },
		} as Awaited<ReturnType<typeof probeAnalysisSandbox>>);
		const fetcher = vi
			.spyOn(globalThis, "fetch")
			.mockImplementation(async () => new Response(JSON.stringify(f.body)));
		try {
			const result = await runAndroidCapture(
				f.input,
				undefined,
				"b".repeat(64),
				root,
				undefined,
				true,
				"c".repeat(64),
			);
			expect(fetcher).toHaveBeenCalledTimes(1);
			expect(fetcher.mock.calls[0][1]).toMatchObject({
				method: "GET",
				redirect: "error",
			});
			expect(fetcher.mock.calls[0][1]?.body).toBeUndefined();
			const receipt = result.outputPaths.find((p) =>
				p.endsWith(".receipt.json"),
			)!;
			expect(JSON.parse(await readFile(receipt, "utf8"))).toEqual({
				receipt: f.receipt,
				signature: f.body.signature,
			});
			expect(await readFile(join(root, "captures", ".gitignore"), "utf8")).toBe(
				"*\n",
			);
			expect(
				(
					await runAndroidCapture(
						f.input,
						undefined,
						"b".repeat(64),
						root,
						undefined,
						true,
						"c".repeat(64),
					)
				).outputPaths,
			).toEqual(result.outputPaths);
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});
	it("refuses changed worker before upload and cancelled approved jobs", async () => {
		const f = fixture(),
			fetcher = vi.spyOn(globalThis, "fetch");
		vi.mocked(probeAnalysisSandbox).mockResolvedValue({
			ready: false,
		} as Awaited<ReturnType<typeof probeAnalysisSandbox>>);
		await expect(
			runAndroidCapture(f.input, Buffer.from("apk"), "b".repeat(64), "/unused"),
		).rejects.toThrow("capability");
		expect(fetcher).not.toHaveBeenCalled();
		vi.mocked(probeAnalysisSandbox).mockResolvedValue({
			ready: true,
			manifest: { workerId: "worker", operations: ["android-runtime-capture"] },
		} as Awaited<ReturnType<typeof probeAnalysisSandbox>>);
		await expect(
			runAndroidCapture(
				f.input,
				Buffer.from("apk"),
				"b".repeat(64),
				"/unused",
				AbortSignal.abort(),
			),
		).rejects.toThrow("Cancelled");
		expect(fetcher).not.toHaveBeenCalled();
	});
	it("refuses symlink output paths without publishing captured plaintext", async () => {
		const f = fixture(),
			root = await mkdtemp(join(tmpdir(), "capture-symlink-")),
			other = await mkdtemp(join(tmpdir(), "capture-other-"));
		vi.mocked(probeAnalysisSandbox).mockResolvedValue({
			ready: true,
			manifest: { workerId: "worker", operations: ["android-runtime-capture"] },
		} as Awaited<ReturnType<typeof probeAnalysisSandbox>>);
		vi.spyOn(globalThis, "fetch").mockImplementation(
			async () => new Response(JSON.stringify(f.body)),
		);
		try {
			await symlink(other, join(root, "captures"), "junction");
			await expect(
				runAndroidCapture(
					f.input,
					undefined,
					"b".repeat(64),
					root,
					undefined,
					true,
					"c".repeat(64),
				),
			).rejects.toThrow("symlinks");
		} finally {
			await rm(root, { recursive: true, force: true });
			await rm(other, { recursive: true, force: true });
		}
	});
});
