import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { AnalysisTaskOrchestrator } from "./analysis-task-orchestrator";
import { digest } from "./incident-artifacts";
import { queryRuntimeJni } from "./runtime-jni-evidence";

vi.mock("./analysis-sandbox-client", () => ({
	assertAnalysisSandboxReady: vi.fn(async () => ({
		workerId: "owned-worker",
		isolation: "owned-protocol-fixture-not-real-device",
	})),
	probeAnalysisSandbox: vi.fn(),
}));
const roots: string[] = [];
afterEach(async () => {
	vi.unstubAllEnvs();
	for (const root of roots.splice(0))
		await rm(root, { recursive: true, force: true });
});
async function fixture(mode = "valid") {
	const root = await mkdtemp(join(tmpdir(), "jni-evidence-"));
	roots.push(root);
	await mkdir(join(root, "captures"));
	await writeFile(
		join(root, "owned.apk"),
		"owned transport fixture, not Android execution",
	);
	const keys = generateKeyPairSync("ed25519");
	vi.stubEnv("CLINE_ANALYSIS_SANDBOX_WORKER", "https://worker.example.test/");
	vi.stubEnv(
		"CLINE_ANALYSIS_SANDBOX_PUBLIC_KEY",
		keys.publicKey.export({ format: "pem", type: "spki" }).toString(),
	);
	vi.stubEnv("CLINE_ANDROID_WORKER_TOKEN", "x".repeat(40));
	const tasks = new AnalysisTaskOrchestrator();
	const plan = await tasks.prepare({
		workspaceRoot: root,
		kind: "dynamic",
		request: {
			operation: "android_capture",
			target: "owned.apk",
			package_name: "com.example.owned",
			capture_dex: false,
			capture_native: false,
			output_directory: "captures",
			timeout_ms: 1000,
			job_nonce: "a".repeat(32),
			worker_endpoint: "https://worker.example.test/",
			worker_id: "owned-worker",
			worker_key_sha256: createHash("sha256")
				.update(keys.publicKey.export({ format: "der", type: "spki" }))
				.digest("hex"),
		},
	});
	const approval = tasks.approve(plan.id, plan.requirements, plan.requestHash);
	await tasks.consume({
		workspaceRoot: root,
		planId: plan.id,
		executionToken: approval.executionToken,
		kind: "dynamic",
		request: plan.request,
	});
	const receipt = {
		protocol: "cline-android-capture/v1",
		workerId: "owned-worker",
		nonce: "a".repeat(32),
		requestHash: plan.requestHash,
		artifactSha256: plan.targetIdentity!.sha256,
		network: "disabled",
		status: "partial",
		engine: "android-frida",
		evidence: {
			artifacts: [],
			registrations: [
				{
					classDescriptor: "Lcom/example/Owned;",
					name: "nativeOwned",
					descriptor: "(I)V",
					addressHex: "0x1234",
					processId: 42,
					classLoaderIdentity: "bootstrap",
					captureSessionNonce: "a".repeat(32),
					timestamp: 1000,
					kind: "worker-observed-registration",
				},
				{
					classDescriptor: "Lcom/example/Owned;",
					name: "nativeOwned",
					descriptor: "(I)V",
					addressHex: "0x1234",
					processId: 43,
					classLoaderIdentity: "identity-hash:0x123",
					captureSessionNonce: "a".repeat(32),
					timestamp: 1001,
					kind: "worker-observed-registration",
				},
			],
			events: [],
		},
		limitations: ["Protocol fixture, not real device execution"],
	};
	if (mode === "wrong-request") receipt.requestHash = "f".repeat(64);
	const envelope = {
		receipt,
		signature: sign(
			null,
			Buffer.from(JSON.stringify(receipt)),
			keys.privateKey,
		).toString("base64"),
	};
	if (mode === "bad-signature")
		envelope.signature = Buffer.alloc(64).toString("base64");
	const bytes = Buffer.from(JSON.stringify(envelope)),
		path = join(root, "captures", `${digest(bytes)}.receipt.json`);
	await writeFile(path, bytes);
	tasks.complete(
		plan.id,
		{ ...receipt, signature: envelope.signature, outputPaths: [path] },
		"isolated-android-worker",
		[path],
	);
	return {
		root,
		tasks,
		plan,
		path,
		receipt,
		keys,
		query: {
			planId: plan.id,
			classDescriptor: "Lcom/example/Owned;",
			name: "nativeOwned",
			descriptor: "(I)V",
		},
	};
}
it("queries verified exact signed registrations without replay and leaves loader/process ambiguity visible", async () => {
	const f = await fixture(),
		r = await queryRuntimeJni(f.root, f.query, f.tasks);
	expect(r.status).toBe("ambiguous-observations");
	expect(r.matches).toHaveLength(2);
	expect(r.matches.every((m) => m.staticBinding === "unresolved")).toBe(true);
	const selected = await queryRuntimeJni(
		f.root,
		{ ...f.query, processId: 42, classLoaderIdentity: "bootstrap" },
		f.tasks,
	);
	expect(selected.status).toBe("unique-observation");
	expect(
		(await queryRuntimeJni(f.root, { ...f.query, descriptor: "()V" }, f.tasks))
			.status,
	).toBe("not-observed");
});
it("rejects modified receipt bytes, unsigned imports and receipt identities from another request", async () => {
	const f = await fixture();
	await writeFile(f.path, '{"receipt":{}}');
	await expect(queryRuntimeJni(f.root, f.query, f.tasks)).rejects.toThrow(
		"filename/hash mismatch",
	);
	await expect(
		queryRuntimeJni(
			f.root,
			{ ...f.query, planId: "00000000-0000-4000-8000-000000000000" },
			f.tasks,
		),
	).rejects.toThrow("approved Android capture");
});

it("rechecks the signature and exact approved request even when the stored envelope hash is valid", async () => {
	for (const mode of ["bad-signature", "wrong-request"]) {
		const f = await fixture(mode);
		await expect(queryRuntimeJni(f.root, f.query, f.tasks)).rejects.toThrow(
			mode === "bad-signature"
				? "Invalid Android worker signature"
				: "does not bind approved request",
		);
	}
});
