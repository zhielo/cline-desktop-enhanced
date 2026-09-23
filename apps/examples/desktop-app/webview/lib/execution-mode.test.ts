import { describe, expect, it } from "vitest";
import { DEFAULT_CHAT_CONFIG } from "@/hooks/chat-session/constants";
import { ChatSessionConfigSchema } from "@/lib/chat-schema";
import {
	applyExecutionMode,
	executionPolicyForMode,
} from "@/lib/execution-mode";

describe("execution mode policy", () => {
	it("defaults new sessions to guarded execution", () => {
		expect(DEFAULT_CHAT_CONFIG.mode).toBe("act");
		expect(DEFAULT_CHAT_CONFIG.autoApproveTools).toBe(false);
	});

	it("defaults omitted schema fields to guarded execution", () => {
		const parsed = ChatSessionConfigSchema.parse({
			executionTarget: "local",
			workspaceRoot: "",
			environmentId: "local",
			provider: "cline",
			model: "test-model",
			apiKey: "",
			enableTools: true,
		});
		expect(parsed.mode).toBe("act");
		expect(parsed.autoApproveTools).toBe(false);
	});

	it.each([
		["plan", false],
		["act", false],
		["yolo", true],
	] as const)("maps %s to auto-approval %s", (mode, autoApproveTools) => {
		expect(executionPolicyForMode(mode)).toEqual({
			mode,
			autoApproveTools,
		});
	});

	it("updates mode and approval authority atomically", () => {
		const fullAccess = applyExecutionMode(DEFAULT_CHAT_CONFIG, "yolo");
		expect(fullAccess).toMatchObject({
			mode: "yolo",
			autoApproveTools: true,
		});
		expect(applyExecutionMode(fullAccess, "act")).toMatchObject({
			mode: "act",
			autoApproveTools: false,
		});
	});
});
