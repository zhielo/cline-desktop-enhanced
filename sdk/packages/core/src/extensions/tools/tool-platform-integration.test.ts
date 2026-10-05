import { afterEach, describe, expect, it, vi } from "vitest";
import { createDefaultTools, createShellTool } from "./definitions";
import { getCoreBuiltinToolCatalog } from "./runtime";

const context = { agentId: "foundation-test", iteration: 1 };
afterEach(() => vi.useRealTimers());

describe("fresh tool platform integration", () => {
	it("registers the real metadata tool when the host enables it", () => {
		expect(createDefaultTools({ executors: {}, enableToolRegistry: true }).some((tool) => tool.name === "tool_registry")).toBe(true);
		expect(createDefaultTools({ executors: {}, enableToolRegistry: false }).some((tool) => tool.name === "tool_registry")).toBe(false);
	});
	it("makes registry selection visible in the builtin catalog", () => {
		expect(getCoreBuiltinToolCatalog({ mode: "act" }).find((entry) => entry.id === "tool_registry")).toMatchObject({ defaultEnabled: true, headlessToolNames: ["tool_registry"] });
	});
	it("orders production run_commands execution", async () => {
		const events: string[] = [];
		const execute = vi.fn(async (command) => {
			events.push(`start:${command}`);
			await Promise.resolve();
			events.push(`end:${command}`);
			return String(command);
		});
		const result = await createShellTool(execute).execute({ commands: ["one", "two"] }, context);
		expect(events).toEqual(["start:one", "end:one", "start:two", "end:two"]);
		expect(result.every((entry) => entry.success)).toBe(true);
	});
	it("shares the production deadline and does not launch the queued command", async () => {
		vi.useFakeTimers();
		const execute = vi.fn(() => new Promise<string>(() => {}));
		const tool = createShellTool(execute, { bashTimeoutMs: 100 });
		const pending = tool.execute({ commands: ["one", "two"] }, context);
		await vi.advanceTimersByTimeAsync(100);
		const result = await pending;
		expect(execute).toHaveBeenCalledTimes(1);
		expect(result.map((entry) => entry.success)).toEqual([false, false]);
		expect(result[0].cleanupUnverified).toBe(true);
		expect(result[1].cleanupUnverified).toBeUndefined();
		expect(execute.mock.calls[0][2].signal?.aborted).toBe(true);
	});
	it("prevents a pre-cancelled production launch", async () => {
		const controller = new AbortController();
		controller.abort(new Error("stop"));
		const execute = vi.fn(async () => "not run");
		const result = await createShellTool(execute).execute({ commands: ["one"] }, { ...context, signal: controller.signal });
		expect(execute).not.toHaveBeenCalled();
		expect(result[0].success).toBe(false);
	});
});
