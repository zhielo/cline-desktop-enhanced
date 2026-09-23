import { describe, expect, it, vi } from "vitest";
import { createFetchHandler, createWebSocketHandler } from "./server";
import type { SidecarContext, SidecarWebSocketClient } from "./types";

const TEST_TOKEN = "test-sidecar-token";

function testServer() {
	return {
		port: 3126,
		upgrade: vi.fn(() => true),
	};
}

describe("sidecar command authorization", () => {
	it("rejects commands from a websocket without the per-launch secret", async () => {
		const handler = createWebSocketHandler({} as SidecarContext);
		const send = vi.fn();
		const close = vi.fn();
		const client = {
			data: { canApproveTools: false },
			send,
			close,
		} satisfies SidecarWebSocketClient;

		await handler.message(
			client,
			JSON.stringify({
				type: "command",
				id: "unauthorized-command",
				command: "get_process_context",
			}),
		);

		expect(send).toHaveBeenCalledOnce();
		expect(JSON.parse(String(send.mock.calls[0]?.[0]))).toMatchObject({
			type: "response",
			ok: false,
			error: "desktop transport authorization required",
		});
		expect(close).toHaveBeenCalledOnce();
	});

	it("rejects an originless shutdown request without the per-launch secret", async () => {
		const onShutdown = vi.fn();
		const handler = createFetchHandler(
			{} as SidecarContext,
			onShutdown,
			TEST_TOKEN,
		);
		const response = await handler(
			new Request("http://127.0.0.1:3126/shutdown", { method: "POST" }),
			testServer(),
		);

		expect(response?.status).toBe(403);
		expect(onShutdown).not.toHaveBeenCalled();
	});
});
