import type { AgentToolContext } from "@cline/shared";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createDefaultTools, createShellTool } from "./definitions";
import { resolveToolRoutingConfig } from "./model-tool-routing";
import { getCoreBuiltinToolCatalog } from "./runtime";
import type { ShellExecutor } from "./types";

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
	it("routes explicit registry enable and disable rules", () => {
		expect(resolveToolRoutingConfig("provider", "model", "act", [{ disableTools: ["tool_registry"] }])).toEqual({ enableToolRegistry: false });
		expect(resolveToolRoutingConfig("provider", "model", "act", [{ enableTools: ["tool_registry"] }])).toEqual({ enableToolRegistry: true });
	});
	it("orders production run_commands execution and tool invocations", async () => {
		const events: string[] = [];
		const execute = vi.fn<ShellExecutor>(async (command) => {
			events.push(`start:${command}`);
			await Promise.resolve();
			events.push(`end:${command}`);
			return String(command);
		});
		const tool = createShellTool(execute);
		expect(tool.executionMode).toBe("sequential");
		const result = await tool.execute({ commands: ["one", "two"] }, context);
		expect(events).toEqual(["start:one", "end:one", "start:two", "end:two"]);
		expect(result.every((entry) => entry.success)).toBe(true);
	});
	it("shares the production deadline and does not launch the queued command", async () => {
		vi.useFakeTimers();
		const execute = vi.fn<ShellExecutor>(() => new Promise<string>(() => {}));
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
		const execute = vi.fn<ShellExecutor>(async () => "not run");
		const result = await createShellTool(execute).execute({ commands: ["one"] }, { ...context, signal: controller.signal });
		expect(execute).not.toHaveBeenCalled();
		expect(result[0].success).toBe(false);
	});
	it("ignores an observer failure without falsely failing the command", async () => {
		const execute: ShellExecutor = async (_command, _cwd, commandContext) => {
			commandContext.emitUpdate?.({ chunk: "stdout" });
			return "stdout";
		};
		const result = await createShellTool(execute).execute({ commands: ["one"] }, { ...context, emitUpdate: () => { throw new Error("disconnected observer"); } });
		expect(result[0]).toMatchObject({ success: true, result: "stdout" });
	});
	it("suppresses late progress after timeout", async () => {
		vi.useFakeTimers();
		let commandContext: AgentToolContext | undefined;
		const execute: ShellExecutor = (_command, _cwd, captured) => {
			commandContext = captured;
			return new Promise<string>(() => {});
		};
		const observer = vi.fn();
		const pending = createShellTool(execute, { bashTimeoutMs: 100 }).execute({ commands: ["one"] }, { ...context, emitUpdate: observer });
		await vi.advanceTimersByTimeAsync(100);
		await pending;
		commandContext?.emitUpdate?.({ chunk: "late stdout" });
		expect(observer).not.toHaveBeenCalled();
	});
});
