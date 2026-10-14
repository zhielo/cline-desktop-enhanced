import { it, expect } from "vitest";
import { digest } from "@cline/core";
import { mkdtemp, rm, writeFile, realpath } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import {
	bindHybridObservation,
	recheckHybridObservation,
} from "./hybrid-analysis";
const id = "11111111-1111-4111-8111-111111111111",
	proposal = {
		baselineKind: "receipt",
		baselineId: id,
		question: "Does the observed source match?",
	};
it("requires an intact owning static receipt, binds exact file identity and rejects stale/cross-session evidence", async () => {
	const root = await realpath(
			await mkdtemp(join(tmpdir(), "hybrid-basis-owned-")),
		),
		target = join(root, "owned.js"),
		scope = { sessionId: "s", workspace: root };
	try {
		await writeFile(target, "owned");
		const sha = createHash("sha256").update("owned").digest("hex"),
			result = { artifacts: [{ path: "owned.js", sha256: sha }] };
		let receipt = {
			id,
			sessionId: "s",
			workspace: root,
			status: "completed",
			result,
			resultHash: digest(result),
		};
		const ports = { receipt: () => receipt, task: () => undefined };
		const bound = await bindHybridObservation(proposal, scope, ports, target);
		expect(bound.relation).toBe("exact-artifact-hash");
		expect((await bindHybridObservation(proposal, scope, ports)).relation).toBe(
			"investigation-context-only",
		);
		await recheckHybridObservation(bound, scope, ports, target);
		for (const change of [
			{ sessionId: "other" },
			{ workspace: join(root, "other") },
			{ status: "running" },
			{ status: "failed" },
			{ resultHash: "0".repeat(64) },
		]) {
			const old = receipt;
			receipt = { ...receipt, ...change };
			await expect(
				bindHybridObservation(proposal, scope, ports, target),
			).rejects.toThrow();
			receipt = old;
		}
		await writeFile(target, "changed");
		await expect(
			recheckHybridObservation(bound, scope, ports, target),
		).rejects.toThrow("matching static artifact");
		await expect(
			bindHybridObservation({ ...proposal, question: " " }, scope, ports),
		).rejects.toThrow();
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
it("native task basis is integrity checked and never accepts runtime task evidence as static", async () => {
	const root = await realpath(
			await mkdtemp(join(tmpdir(), "hybrid-native-owned-")),
		),
		scope = { sessionId: "s", workspace: root };
	try {
		const body = {
			taskId: id,
			sessionId: "s",
			workspace: root,
			domain: "static",
			result: { evidence: "owned" },
			resultHash: digest({ evidence: "owned" }),
			targetSha256: "a".repeat(64),
		};
		let task = { ...body, snapshotHash: digest(body) };
		const ports = { receipt: () => undefined, task: () => task };
		const p = { ...proposal, baselineKind: "static-task" };
		expect((await bindHybridObservation(p, scope, ports)).evidenceHash).toBe(
			task.snapshotHash,
		);
		task = { ...task, domain: "execution" };
		await expect(bindHybridObservation(p, scope, ports)).rejects.toThrow(
			"static task",
		);
		task = { ...body, snapshotHash: digest(body) };
		const context = await bindHybridObservation(p, scope, ports);
		await expect(
			recheckHybridObservation(
				{ ...context, evidenceHash: "0".repeat(64) },
				scope,
				ports,
			),
		).rejects.toThrow("changed");
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
