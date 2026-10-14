import { it, expect, vi } from "vitest";
import { mkdtemp, rm, realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { digest } from "@cline/core";
import { DesktopBrowserManager } from "./browser-manager";
import { handleAnalysisWorkflow } from "./analysis-workflow";
import { AnalysisWorkflowStore } from "./analysis-workflow-store";
it("Hybrid retains original static basis through explicit start/stop, mode changes and selected export", async () => {
	const root = await realpath(
			await mkdtemp(join(tmpdir(), "hybrid-flow-owned-")),
		),
		scope = { sessionId: "owned", workspace: root };
	const store = new AnalysisWorkflowStore(join(root, "workflow.sqlite"));
	let manager: DesktopBrowserManager;
	const bridges: string[] = [];
	manager = new DesktopBrowserManager({
		onRequest: (r) => {
			bridges.push(r.operation);
			queueMicrotask(() =>
				manager.resolveRequest(
					r.requestId,
					r.operation === "capture_stop"
						? { cleanupVerified: true, events: [], expired: false, dropped: 0 }
						: { ok: true },
				),
			);
		},
	});
	try {
		const browser = JSON.parse(
			await manager.executor({ action: "start" }, {
				sessionId: "owned",
				agentId: "lead",
			} as never),
		);
		const id = "11111111-1111-4111-8111-111111111111",
			result = { artifacts: [], facts: [] },
			receipt = {
				id,
				sessionId: scope.sessionId,
				workspace: root,
				status: "completed",
				result,
				resultHash: digest(result),
			};
		const ports = {
			invoke: vi.fn(),
			taskBundle: vi.fn(),
			staticReceipt: vi.fn(() => receipt),
			capture: (input: Record<string, unknown>) =>
				manager.captureScenario(scope.sessionId, input),
		};
		const proposal = {
			baselineKind: "receipt",
			baselineId: id,
			question: "What metadata event occurs?",
		};
		const req = {
			action: "start",
			browserSessionId: browser.browserSessionId,
			purpose: "Owned question",
			confirmRecord: true,
			hybridProposal: proposal,
		};
		await handleAnalysisWorkflow(
			"capture_browser_scenario",
			req,
			scope,
			{ trusted: true, idle: true, mode: "hybrid" },
			store,
			ports,
		);
		expect(bridges).toEqual(["start", "capture_start"]); // No navigation, replay, launch of an application or automatic actions.
		const saved = (await handleAnalysisWorkflow(
			"capture_browser_scenario",
			{
				...req,
				action: "stop",
				purpose: "changed",
				hybridProposal: { ...proposal, question: "changed" },
			},
			scope,
			{ trusted: true, idle: true, mode: "off" },
			store,
			ports,
		)) as { id: string; capture: { hybrid: unknown } };
		expect(saved.capture.hybrid).toMatchObject({
			...proposal,
			evidenceHash: receipt.resultHash,
			relation: "investigation-context-only",
		});
		const exported = (await handleAnalysisWorkflow(
			"get_evidence_bundle",
			{ receiptIds: [id], scenarioIds: [saved.id] },
			scope,
			{ trusted: false, idle: false, mode: "off" },
			store,
			ports,
		)) as { payload: { records: unknown[] } };
		expect(exported.payload.records).toHaveLength(2);
		expect(bridges).toEqual(["start", "capture_start", "capture_stop"]);
	} finally {
		store.close();
		await manager.stopAll();
		await rm(root, { recursive: true, force: true });
	}
});
