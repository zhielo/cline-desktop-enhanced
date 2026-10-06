import { afterEach, describe, expect, it, vi } from "vitest";

const calls = vi.hoisted(() => ({
	command: vi.fn(async () => ({ ok: true })),
}));
vi.mock("./commands", () => ({ handleCommand: calls.command }));
vi.mock("./context", () => ({
	cancelSidecarToolApprovalsForOwner: vi.fn(),
	encodeSidecarEvent: vi.fn(() => "{}"),
	sendEvent: vi.fn(),
	syncSidecarApprovalReadiness: vi.fn(async () => {}),
}));

import { createFetchHandler, createWebSocketHandler } from "./server";
import type { SidecarContext, SidecarWebSocketClient } from "./types";

const token = "test-sidecar-authentication-token";
afterEach(() => {
	vi.restoreAllMocks();
	calls.command.mockClear();
});
function fixture() {
	const ctx = {
		wsClients: new Set<SidecarWebSocketClient>(),
	} as SidecarContext;
	const server = { port: 3126, upgrade: vi.fn(() => true) };
	return {
		ctx,
		server,
		fetch: createFetchHandler(ctx, undefined, token),
		ws: createWebSocketHandler(ctx),
	};
}
describe("authenticated desktop command boundary", () => {
	it.each([
		undefined,
		"tauri://localhost",
		"http://localhost:3125",
	])("rejects missing token for origin %s", async (origin) => {
		const f = fixture();
		const response = await f.fetch(
			new Request("http://127.0.0.1:3126/transport", {
				headers: origin ? { origin } : {},
			}),
			f.server,
		);
		expect(response?.status).toBe(401);
		expect(f.server.upgrade).not.toHaveBeenCalled();
	});
	it("rejects untrusted origin even with valid token", async () => {
		const f = fixture();
		const response = await f.fetch(
			new Request(`http://127.0.0.1:3126/transport?approval_token=${token}`, {
				headers: { origin: "https://untrusted.example" },
			}),
			f.server,
		);
		expect(response?.status).toBe(403);
		expect(f.server.upgrade).not.toHaveBeenCalled();
	});
	it("authenticates originless integrations without approval authority", async () => {
		const f = fixture();
		await f.fetch(
			new Request("http://127.0.0.1:3126/transport", {
				headers: { authorization: `Bearer ${token}` },
			}),
			f.server,
		);
		expect(f.server.upgrade).toHaveBeenCalledWith(expect.any(Request), {
			data: { authenticated: true, canApproveTools: false },
		});
	});
	it("never registers or dispatches an unauthenticated socket", async () => {
		const f = fixture();
		const ws = {
			data: { canApproveTools: true },
			send: vi.fn(),
			close: vi.fn(),
		};
		f.ws.open(ws);
		expect(f.ctx.wsClients.size).toBe(0);
		expect(ws.close).toHaveBeenCalled();
		await f.ws.message(ws, '{"id":"private","command":"get_settings"}');
		expect(calls.command).not.toHaveBeenCalled();
		expect(ws.send).toHaveBeenCalledWith(
			expect.stringContaining("authentication required"),
		);
	});
	it("dispatches only authenticated registered connections", async () => {
		const f = fixture();
		const ws = {
			data: { authenticated: true, canApproveTools: false },
			send: vi.fn(),
			close: vi.fn(),
		};
		f.ws.open(ws);
		await f.ws.message(ws, '{"id":"ok","command":"get_settings","args":{}}');
		expect(calls.command).toHaveBeenCalledWith(
			f.ctx,
			"get_settings",
			{},
			{ connection: ws },
		);
		calls.command.mockClear();
		f.ctx.wsClients.delete(ws);
		await f.ws.message(ws, '{"id":"stale","command":"get_settings"}');
		expect(calls.command).not.toHaveBeenCalled();
	});
	it.each([
		"/shutdown",
		"/telemetry/error",
	])("denies unauthenticated POST %s", async (path) => {
		const f = fixture();
		const response = await f.fetch(
			new Request("http://127.0.0.1:3126" + path, {
				method: "POST",
				headers: { origin: "tauri://localhost" },
				body: "{}",
			}),
			f.server,
		);
		expect(response?.status).toBe(401);
	});
	it("bounds authenticated telemetry without trusting Content-Length", async () => {
		const f = fixture();
		const response = await f.fetch(
			new Request("http://127.0.0.1:3126/telemetry/error", {
				method: "POST",
				headers: { authorization: `Bearer ${token}` },
				body: '{"operation":"' + "x".repeat(65536) + '"}',
			}),
			f.server,
		);
		expect(response?.status).toBe(400);
	});
	it("keeps health public and permits authorization in trusted preflight", async () => {
		const f = fixture();
		expect(
			(await f.fetch(new Request("http://127.0.0.1:3126/health"), f.server))
				?.status,
		).toBe(200);
		const response = await f.fetch(
			new Request("http://127.0.0.1:3126/telemetry/error", {
				method: "OPTIONS",
				headers: { origin: "tauri://localhost" },
			}),
			f.server,
		);
		expect(response?.headers.get("access-control-allow-headers")).toContain(
			"authorization",
		);
	});
	it("supports authenticated originless shutdown without exiting test process", async () => {
		const exit = vi
			.spyOn(process, "exit")
			.mockImplementation(() => undefined as never);
		const shutdown = vi.fn(async () => {});
		const f = fixture();
		const handler = createFetchHandler(f.ctx, shutdown, token);
		const response = await handler(
			new Request("http://127.0.0.1:3126/shutdown", {
				method: "POST",
				headers: { authorization: `Bearer ${token}` },
			}),
			f.server,
		);
		expect(response?.status).toBe(200);
		await vi.waitFor(() => expect(exit).toHaveBeenCalledWith(0));
		expect(shutdown).toHaveBeenCalledOnce();
	});
});
