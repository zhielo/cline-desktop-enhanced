import { describe, expect, it } from "vitest";
import {
	type BrowserBridgeRequest,
	DesktopBrowserManager,
} from "./browser-manager";

const context = { sessionId: "session-1", agentId: "lead" } as never;

describe("DesktopBrowserManager", () => {
	it("creates an owner-scoped session and forwards structured operations", async () => {
		let manager: DesktopBrowserManager;
		const requests: BrowserBridgeRequest[] = [];
		manager = new DesktopBrowserManager({
			onRequest: (request) => {
				requests.push(request);
				queueMicrotask(() =>
					manager.resolveRequest(request.requestId, { ok: true }),
				);
			},
		});
		const started = JSON.parse(
			await manager.executor(
				{ action: "start", url: "https://example.com" },
				context,
			),
		);
		expect(started.browserSessionId).toMatch(/^[0-9a-f-]{36}$/);
		const inspected = JSON.parse(
			await manager.executor(
				{
					action: "inspect",
					browser_session_id: started.browserSessionId,
					max_nodes: 10,
				},
				context,
			),
		);
		expect(inspected).toEqual({ ok: true });
		expect(requests.map((request) => request.operation)).toEqual([
			"start",
			"inspect",
		]);
	});

	it("rejects cross-session access", async () => {
		let manager: DesktopBrowserManager;
		manager = new DesktopBrowserManager({
			onRequest: (request) =>
				queueMicrotask(() =>
					manager.resolveRequest(request.requestId, { ok: true }),
				),
		});
		const started = JSON.parse(
			await manager.executor({ action: "start" }, context),
		);
		await expect(
			manager.executor(
				{
					action: "inspect",
					browser_session_id: started.browserSessionId,
					max_nodes: 10,
				},
				{ sessionId: "session-2", agentId: "lead" } as never,
			),
		).rejects.toThrow("ownership mismatch");
	});
});
