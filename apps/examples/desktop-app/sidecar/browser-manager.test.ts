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

it("recording is explicit, owner-scoped, metadata-only and honest about incomplete cleanup", async () => {
	let manager: DesktopBrowserManager;
	manager = new DesktopBrowserManager({
		onRequest: (r) =>
			queueMicrotask(() =>
				manager.resolveRequest(
					r.requestId,
					r.operation === "capture_stop"
						? { cleanupVerified: false, events: [], expired: false, dropped: 0 }
						: { ok: true },
				),
			),
	});
	const { browserSessionId: id } = JSON.parse(
		await manager.executor({ action: "start" }, context),
	);
	expect(
		JSON.parse(
			await manager.executor({ action: "list" }, {
				sessionId: "other",
			} as never),
		).sessions,
	).toEqual([]);
	await expect(
		manager.captureScenario("other", {
			browserSessionId: id,
			action: "start",
			confirmRecord: true,
		}),
	).rejects.toThrow("ownership");
	await expect(
		manager.captureScenario("session-1", {
			browserSessionId: id,
			action: "start",
		}),
	).rejects.toThrow("consent");
	await manager.captureScenario("session-1", {
		browserSessionId: id,
		action: "start",
		confirmRecord: true,
		purpose: "original",
	});
	await expect(
		manager.captureScenario("session-1", {
			browserSessionId: id,
			action: "start",
			confirmRecord: true,
		}),
	).rejects.toThrow("active");
	await manager.executor(
		{
			action: "type",
			browser_session_id: id,
			text: "owned-private-secret",
			ref: "secret-field",
		} as never,
		context,
	);
	const captured = await manager.captureScenario("session-1", {
		browserSessionId: id,
		action: "stop",
		confirmRecord: true,
		purpose: "changed",
	});
	expect(captured).toMatchObject({
		purpose: "original",
		status: "partial",
		actions: [{ action: "type", inputOmitted: true, status: "acknowledged" }],
	});
	expect(JSON.stringify(captured)).not.toContain("owned-private-secret");
	expect(JSON.stringify(captured)).not.toContain("secret-field");
});
