import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID, generateKeyPairSync, sign } from "node:crypto";
import { expect, it, vi } from "vitest";
import { EMULATION_PROFILE_SHA256 } from "@cline/core";
import { handleCommand } from "./commands";
import {
	firstPartyStore,
	handleFirstPartyCommand,
	sessionTaskSnapshots,
} from "./first-party-analysis";
import {
	desktopAnalysisTaskOrchestrator,
	type AnalysisTaskPlan,
} from "./analysis-task-orchestrator";
import type { SidecarContext } from "./types";
it("enforces owning Full Access modes, exact artifact approvals, Hybrid basis and cancellation for additive engines", async () => {
	const root = realpathSync(mkdtempSync(join(tmpdir(), "engine-owner-"))),
		id = `session_${randomUUID()}`,
		target = join(root, "owned.elf"),
		bytes = Buffer.alloc(128);
	writeFileSync(target, bytes);
	const live = {
		config: { permissionProfile: "full-access", workspaceRoot: root },
		messages: [],
		promptsInQueue: [],
		busy: false,
	};
	const ctx = {
		activeEnvironmentId: "local",
		localWorkspaceRoot: root,
		liveSessions: new Map([[id, live]]),
		runtimeBindings: new Map([
			[
				"local",
				{
					kind: "local",
					workspaceRoot: root,
					sessionManager: {
						get: async (key: string) =>
							key === id ? { workspaceRoot: root } : undefined,
					},
				},
			],
		]),
	} as unknown as SidecarContext;
	const common = { sessionId: id, environmentId: "local", cwd: root },
		options = { connection: { data: { canApproveTools: true } } } as never;
	const req = {
		operation: "emulate_profile",
		target,
		engine: "qiling",
		architecture: "x86_64",
		scenario: { kind: "entry", expectedExit: 7 },
		instruction_limit: 10000,
		timeout_ms: 1000,
	};
	const prepare = () =>
		handleCommand(
			ctx,
			"prepare_analysis_task",
			{ ...common, kind: "dynamic", request: req },
			options,
		) as Promise<AnalysisTaskPlan>;
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	const signed = (key: string, value: unknown) =>
		new Response(
			JSON.stringify({
				[key]: value,
				signature: sign(
					null,
					Buffer.from(JSON.stringify(value)),
					privateKey,
				).toString("base64"),
			}),
		);
	let posts = 0,
		changeModeDuringProbe = false;
	const transport = vi
		.spyOn(globalThis, "fetch")
		.mockImplementation(async (_url, init) => {
			if (init?.method !== "POST") {
				if (changeModeDuringProbe) firstPartyStore().setMode(id, root, "off");
				return signed("manifest", {
					workerId: "owned-qiling",
					version: "owned",
					protocol: "cline-analysis-worker/v1",
					isolation: "remote-vm",
					ephemeralSnapshots: true,
					networkModes: ["disabled"],
					maxArtifactBytes: 16777216,
					issuedAt: new Date().toISOString(),
					expiresAt: new Date(Date.now() + 60000).toISOString(),
					operations: ["emulate-profile-qiling"],
					engine: "qiling",
					profileSha256: EMULATION_PROFILE_SHA256,
					architectures: ["x86_64", "arm32", "arm64"],
					runtimeSha256: "a".repeat(64),
					isolationClaim: "operator-provisioned-not-hardware-attested",
				});
			}
			posts++;
			const b = JSON.parse(String(init.body));
			return signed("receipt", {
				protocol: b.protocol,
				workerId: "owned-qiling",
				nonce: b.nonce,
				requestHash: b.requestHash,
				artifactSha256: b.artifactSha256,
				network: b.network,
				status: "partial",
				engine: b.engine,
				runtimeSha256: b.runtimeSha256,
				profileSha256: b.profileSha256,
				architecture: b.architecture,
				scenario: b.scenario,
				instructionLimit: b.instructionLimit,
				evidence: { outcome: "unverified", scenarioCheck: "passed" },
				limitations: ["Owned transport fixture; no engine executed"],
			});
		});
	const approve = (p: AnalysisTaskPlan) =>
		handleCommand(
			ctx,
			"approve_analysis_task",
			{
				...common,
				planId: p.id,
				requestHash: p.requestHash,
				requirements: p.requirements,
			},
			options,
		) as Promise<{ executionToken: string }>;
	const run = async (p: AnalysisTaskPlan, token: string) =>
		handleCommand(
			ctx,
			"run_dynamic_analysis",
			{
				...common,
				input: p.request,
				planId: p.id,
				executionToken: token,
				confirmExecution: true,
				confirmArtifactUpload: true,
			},
			options,
		);
	try {
		await expect(
			handleCommand(ctx, "prepare_analysis_task", {
				...common,
				kind: "dynamic",
				request: req,
			}),
		).rejects.toThrow("trusted desktop");
		firstPartyStore().setMode(id, root, "static");
		await expect(prepare()).rejects.toThrow("Runtime/Hybrid");
		firstPartyStore().setMode(id, root, "runtime");
		live.config.permissionProfile = "read-only";
		await expect(prepare()).rejects.toThrow("Full Access");
		live.config.permissionProfile = "full-access";
		await expect(prepare()).rejects.toThrow("independent HTTPS");
		expect(posts).toBe(0);
		process.env.CLINE_EMULATION_QILING_ENDPOINT =
			"https://owned-qiling.invalid";
		process.env.CLINE_EMULATION_QILING_PUBLIC_KEY = publicKey.export({
			type: "spki",
			format: "pem",
		}) as string;
		process.env.CLINE_EMULATION_QILING_TOKEN = "t".repeat(40);
		const p = await prepare();
		expect(p.request).toMatchObject({
			owner_session_id: id,
			analysis_mode: "runtime",
			worker_profile_sha256: EMULATION_PROFILE_SHA256,
		});
		expect(p.requirements).toEqual(
			expect.arrayContaining([
				"artifact-upload",
				"authorized-target-execution",
				"isolated-sandbox",
			]),
		);
		const consent = await approve(p);
		await run(p, consent.executionToken);
		expect(posts).toBe(1);
		expect(sessionTaskSnapshots(id, root).some((s) => s.taskId === p.id)).toBe(
			true,
		);
		await expect(run(p, consent.executionToken)).rejects.toThrow();
		expect(posts).toBe(1);
		const changed = await prepare(),
			changedConsent = await approve(changed);
		writeFileSync(target, Buffer.alloc(128, 1));
		await expect(run(changed, changedConsent.executionToken)).rejects.toThrow(
			"changed",
		);
		expect(posts).toBe(1);
		writeFileSync(target, bytes);
		const switched = await prepare();
		await approve(switched);
		await handleFirstPartyCommand(
			"first_party_analysis_mode",
			{ mode: "off" },
			{ id, workspace: root, busy: false },
			true,
		);
		expect(
			desktopAnalysisTaskOrchestrator
				.list(root)
				.find((p) => p.id === switched.id)?.status,
		).toBe("cancelled");
		firstPartyStore().setMode(id, root, "hybrid");
		await expect(prepare()).rejects.toThrow();
		expect(posts).toBe(1);
		firstPartyStore().setMode(id, root, "runtime");
		const race = await prepare(),
			raceConsent = await approve(race);
		changeModeDuringProbe = true;
		await expect(run(race, raceConsent.executionToken)).rejects.toThrow(
			"Runtime/Hybrid",
		);
		expect(posts).toBe(1);
	} finally {
		transport.mockRestore();
		for (const key of Object.keys(process.env))
			if (key.startsWith("CLINE_EMULATION_QILING_")) delete process.env[key];
		rmSync(root, { recursive: true, force: true });
	}
}, 60000);
