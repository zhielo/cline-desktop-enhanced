import type {
	AgentBeforeToolContext,
	AgentRuntimeStateSnapshot,
	AgentTool,
} from "@cline/shared";
import { describe, expect, it } from "vitest";
import {
	createPermissionProfileExtension,
	PERMISSION_PROFILE_EXTENSION_NAME,
} from "./permission-profile";

function context(
	toolName: string,
	input: unknown = {},
): AgentBeforeToolContext {
	const snapshot = {
		agentId: "agent-1",
		conversationId: "conversation-1",
		runId: "run-1",
		status: "running",
		iteration: 1,
		messages: [],
		pendingToolCalls: [],
		usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 },
	} as unknown as AgentRuntimeStateSnapshot;
	return {
		snapshot,
		tool: { name: toolName } as AgentTool,
		toolCall: {
			type: "tool-call",
			toolCallId: "call-1",
			toolName,
			input,
		},
		input,
	};
}

async function before(
	profile: Parameters<typeof createPermissionProfileExtension>[0],
	toolName: string,
	input?: unknown,
) {
	return createPermissionProfileExtension(profile).hooks?.beforeTool?.(
		context(toolName, input),
	);
}

describe("permission profile guard", () => {
	it("uses a stable extension identity", () => {
		const extension = createPermissionProfileExtension("workspace");
		expect(extension.name).toBe(PERMISSION_PROFILE_EXTENSION_NAME);
		expect(extension.manifest.capabilities).toContain("hooks");
	});

	it("keeps full access behavior unchanged", async () => {
		expect(
			await before("full-access", "third_party_write_tool"),
		).toBeUndefined();
		expect(await before("full-access", "android_device")).toBeUndefined();
		expect(await before("full-access", "computer_use")).toBeUndefined();
	});

	it("allows read-only investigation and blocks writes", async () => {
		expect(await before("read-only", "read_files")).toBeUndefined();
		expect(
			await before("read-only", "run_commands", {
				commands: ["git status", "rg TODO src"],
			}),
		).toBeUndefined();
		expect((await before("read-only", "editor"))?.skip).toBe(true);
		expect(
			(
				await before("read-only", "run_commands", {
					commands: ["echo secret > output.txt"],
				})
			)?.reason,
		).toContain("output redirection");
		expect((await before("read-only", "process_session"))?.skip).toBe(true);
		expect((await before("read-only", "computer_use"))?.skip).toBe(true);
	});

	it("separates workspace and network-enabled profiles", async () => {
		expect(await before("workspace", "editor")).toBeUndefined();
		expect((await before("workspace", "fetch_web_content"))?.skip).toBe(true);
		expect(
			await before("workspace-network", "fetch_web_content"),
		).toBeUndefined();
		expect(
			await before("workspace-network", "browser", { action: "inspect" }),
		).toBeUndefined();
		expect(
			(await before("workspace-network", "browser", { action: "click" }))
				?.reason,
		).toContain("state-changing browser actions");
		expect(
			await before("full-access", "browser", { action: "click" }),
		).toBeUndefined();
	});

	it("separates repository reads, local writes, and network operations", async () => {
		expect(
			await before("read-only", "repository", { action: "status" }),
		).toBeUndefined();
		expect(
			(await before("read-only", "repository", { action: "commit" }))?.reason,
		).toContain("repository writes are disabled");
		expect(
			await before("workspace", "repository", { action: "commit" }),
		).toBeUndefined();
		expect(
			(await before("workspace", "repository", { action: "push" }))?.reason,
		).toContain("repository network access is disabled");
		expect(
			await before("workspace-network", "repository", { action: "push" }),
		).toBeUndefined();
	});

	it("blocks unclassified MCP/plugin tools in restricted profiles", async () => {
		const result = await before("workspace-network", "github_create_issue");
		expect(result?.skip).toBe(true);
		expect(result?.reason).toContain("unclassified plugin or MCP tool");
	});

	it("supports explicit custom allow and deny rules", async () => {
		const profile = {
			kind: "custom" as const,
			name: "reviewer",
			allowFileWrites: false,
			allowCommands: false,
			allowProcessSessions: false,
			allowComputerUse: false,
			allowNetwork: false,
			allowExternalTools: false,
			allowUnknownTools: false,
			allowedToolNames: ["company_lookup"],
			deniedToolNames: ["skills"],
		};
		expect(await before(profile, "company_lookup")).toBeUndefined();
		expect((await before(profile, "skills"))?.skip).toBe(true);
		expect((await before(profile, "run_commands"))?.skip).toBe(true);
	});

	it("preserves coordination tools while enforcing child tool calls", async () => {
		expect(await before("read-only", "spawn_agent")).toBeUndefined();
		expect(await before("read-only", "team_status")).toBeUndefined();
	});
});
