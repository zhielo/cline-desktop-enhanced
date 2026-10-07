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
			(
			await before("read-only", "run_commands", {
				commands: ["git status", "rg TODO src"],
				})
			)?.skip,
		).toBe(true);
		expect((await before("read-only", "editor"))?.skip).toBe(true);
		expect(
			(
				await before("read-only", "run_commands", {
					commands: ["echo secret > output.txt"],
				})
			)?.reason,
		).toContain("command execution is disabled");
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

	it("isolates Notion function sessions to Notion MCP tools", async () => {
		expect(await before("notion-functions", "Notion__search")).toBeUndefined();
		expect(
			await before("notion-functions", "notion__create_page"),
		).toBeUndefined();
		expect(await before("notion-functions", "ask_question")).toBeUndefined();
		expect((await before("notion-functions", "read_files"))?.skip).toBe(true);
		expect((await before("notion-functions", "run_commands"))?.skip).toBe(true);
		expect((await before("notion-functions", "github__search"))?.skip).toBe(
			true,
		);
	});

	it("combines read-only local analysis with official Notion tools", async () => {
		expect(
			await before("project-notion-bridge", "Notion__search_agents"),
		).toBeUndefined();
		expect(
			await before("project-notion-bridge", "notion__spawn_session"),
		).toBeUndefined();
		expect(
			await before("project-notion-bridge", "search_codebase"),
		).toBeUndefined();
		expect(
			await before("project-notion-bridge", "reverse_engineer"),
		).toBeUndefined();
		expect(
			(
				await before("project-notion-bridge", "run_commands", {
					commands: [
						"Set-Content secret.txt value",
						"New-Item -ItemType Directory outputs/notion-analyst",
					],
				})
			)?.skip,
		).toBe(true);
		expect((await before("project-notion-bridge", "editor"))?.skip).toBe(true);
		expect(
			(await before("project-notion-bridge", "github__search"))?.skip,
		).toBe(true);
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

describe("restricted profiles fail closed for arbitrary execution", () => {
	for (const profile of ["read-only", "project-notion-bridge"] as const) {
		it.each([
			{ commands: ["python -c 'print(1)'"] },
			{ commands: ["bash -c 'echo inspection'"] },
			{ commands: ["curl https://example.invalid"] },
			{ commands: [{ command: "node", args: ["-e", "console.log(1)"] }] },
			{ commands: [{ command: "unknown.exe", args: [] }] },
			{},
		])(`${profile} denies shell, interpreter, network, unknown and malformed commands: %j`, async (input) => {
			expect((await before(profile, "run_commands", input))?.skip).toBe(true);
		});
		it("allows only exhaustive structured repository reads", async () => {
			for (const action of ["status", "diff", "log", "branches"]) {
				expect(await before(profile, "repository", { action })).toBeUndefined();
			}
			for (const action of [
				"commit",
				"fetch",
				"pull",
				"push",
				"create_branch",
				"switch_branch",
				"github_status",
				"future_action",
				undefined,
			]) {
				expect((await before(profile, "repository", { action }))?.skip).toBe(
					true,
				);
			}
		});
	}
	it("does not weaken workspace or full-access command execution", async () => {
		for (const profile of [
			"workspace",
			"workspace-network",
			"full-access",
		] as const) {
			expect(
				await before(profile, "run_commands", { commands: ["node --version"] }),
			).toBeUndefined();
		}
	});
});


it.each(["read-only","project-notion-bridge"] as const)("%s blocks native candidate writes and pointer rollback",async profile=>{
 for(const mode of ["preview","candidate","rollback"])expect((await before(profile,"reverse_engineer",{operation:"project_edit",project_edit:{mode}}))?.skip).toBe(true);
});
