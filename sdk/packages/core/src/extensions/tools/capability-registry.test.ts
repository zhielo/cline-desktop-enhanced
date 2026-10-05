import { type AgentTool, createTool } from "@cline/shared";
import { describe, expect, it, vi } from "vitest";
import { createToolRegistryTool } from "./capability-registry";

const context = { agentId: "registry-test", iteration: 1 };
function makeTool(name: string): AgentTool {
	return createTool({ name, description: "registered metadata", inputSchema: { type: "object", properties: { token: { type: "string", default: "private-token" } } }, execute: async () => "not executed" });
}

describe("tool registry metadata boundary", () => {
	it("orders and pages actual registrations without optimistic readiness", async () => {
		const registry = createToolRegistryTool(() => [makeTool("zeta"), makeTool("alpha")]);
		const first = await registry.execute({ limit: 1 }, context);
		expect(first.tools.map((entry) => entry.name)).toEqual(["alpha"]);
		expect(first.nextCursor).toBe(1);
		expect(first.tools[0]).toMatchObject({ executable: "not_probed", license: "not_probed", health: "not_probed", permission: "not_evaluated", availability: "not_verified" });
		const second = await registry.execute({ cursor: 1, limit: 1 }, context);
		expect(second.tools.map((entry) => entry.name)).toEqual(["zeta"]);
		expect(second.nextCursor).toBeNull();
	});
	it("does not invoke executors or dynamic descriptions", async () => {
		const tool = makeTool("example");
		const execute = vi.fn();
		const description = vi.fn(() => "dynamic");
		tool.execute = execute;
		Object.defineProperty(tool, "description", { get: description });
		const result = await createToolRegistryTool(() => [tool]).execute({ operation: "describe", tool_name: "example" }, context);
		expect(result.tools[0]).not.toHaveProperty("description");
		expect(execute).not.toHaveBeenCalled();
		expect(description).not.toHaveBeenCalled();
	});
	it("returns field names, not default credential values", async () => {
		const result = await createToolRegistryTool(() => [makeTool("example")]).execute({ operation: "describe", tool_name: "example" }, context);
		expect(result.tools[0].inputFields).toEqual(["token"]);
		expect(JSON.stringify(result)).not.toContain("private-token");
	});
	it("reports unregistered tools as unavailable", async () => {
		const result = await createToolRegistryTool(() => []).execute({ operation: "describe", tool_name: "sandbox_job" }, context);
		expect(result).toMatchObject({ status: "unavailable", reason: "not_registered", tools: [] });
	});
	it("rejects duplicate registrations", async () => {
		await expect(createToolRegistryTool(() => [makeTool("a"), makeTool("a")]).execute({}, context)).rejects.toThrow("Duplicate");
	});
	it("rejects oversized pages and unknown authority inputs", async () => {
		const registry = createToolRegistryTool(() => []);
		await expect(registry.execute({ limit: 51 }, context)).rejects.toThrow();
		await expect(registry.execute({ confirm_write: true } as never, context)).rejects.toThrow();
		await expect(registry.execute({ cursor: -1 }, context)).rejects.toThrow();
	});
	it("does not cross constructor-owned tool lists", async () => {
		const left = createToolRegistryTool(() => [makeTool("left")]);
		const right = createToolRegistryTool(() => [makeTool("right")]);
		expect((await left.execute({}, context)).tools.map((entry) => entry.name)).toEqual(["left"]);
		expect((await right.execute({}, context)).tools.map((entry) => entry.name)).toEqual(["right"]);
	});
	it("requires a name for describe", async () => {
		await expect(createToolRegistryTool(() => []).execute({ operation: "describe" }, context)).rejects.toThrow("tool_name");
	});
});
