/**
 * Host-enforced permission profiles.
 *
 * These profiles constrain the tool surface at the runtime hook boundary.
 * They are deliberately described as capability profiles and not an operating-system sandbox:
 * an allowed command still executes with the host
 * process' OS permissions. Hosts that need containment must combine this
 * guard with native sandboxing.
 */

import type {
	AgentBeforeToolContext,
	AgentBeforeToolResult,
	AgentExtension,
} from "@cline/shared";
import {
	findFileEditingCommand,
	formatPlanModeBlockedCommandError,
} from "./command-guard";
import { normalizeRunCommandsInput } from "./helpers";

export type PermissionProfileName =
	| "read-only"
	| "workspace"
	| "workspace-network"
	| "full-access";

export interface CustomPermissionProfile {
	kind: "custom";
	name: string;
	allowFileWrites: boolean;
	allowCommands: boolean;
	allowProcessSessions: boolean;
	allowComputerUse?: boolean;
	allowNetwork: boolean;
	allowExternalTools: boolean;
	allowUnknownTools: boolean;
	allowedToolNames?: string[];
	deniedToolNames?: string[];
}

export type PermissionProfile = PermissionProfileName | CustomPermissionProfile;

interface ResolvedPermissionProfile {
	name: string;
	allowFileWrites: boolean;
	allowCommands: boolean;
	allowProcessSessions: boolean;
	allowComputerUse: boolean;
	allowNetwork: boolean;
	allowExternalTools: boolean;
	allowUnknownTools: boolean;
	allowedToolNames: ReadonlySet<string>;
	deniedToolNames: ReadonlySet<string>;
}

export const PERMISSION_PROFILE_EXTENSION_NAME =
	"core.permission-profile-guard";

const READ_ONLY_TOOLS = new Set([
	"read_files",
	"search_codebase",
	"skills",
	"ask_question",
	"submit_and_exit",
	"spawn_agent",
]);

const WORKSPACE_TOOLS = new Set([
	...READ_ONLY_TOOLS,
	"run_commands",
	"process_session",
	"editor",
	"apply_patch",
]);

const NETWORK_TOOLS = new Set(["fetch_web_content", "web_search"]);
const EXTERNAL_TOOLS = new Set([
	"android_device",
	"live_debugger",
	"reverse_engineer",
]);
const COMPUTER_TOOLS = new Set(["computer_use"]);

function builtInProfile(
	profile: PermissionProfileName,
): ResolvedPermissionProfile {
	switch (profile) {
		case "read-only":
			return {
				name: profile,
				allowFileWrites: false,
				allowCommands: true,
				allowProcessSessions: false,
				allowComputerUse: false,
				allowNetwork: false,
				allowExternalTools: false,
				allowUnknownTools: false,
				allowedToolNames: new Set(),
				deniedToolNames: new Set(),
			};
		case "workspace":
			return {
				name: profile,
				allowFileWrites: true,
				allowCommands: true,
				allowProcessSessions: true,
				allowComputerUse: false,
				allowNetwork: false,
				allowExternalTools: false,
				allowUnknownTools: false,
				allowedToolNames: new Set(),
				deniedToolNames: new Set(),
			};
		case "workspace-network":
			return {
				name: profile,
				allowFileWrites: true,
				allowCommands: true,
				allowProcessSessions: true,
				allowComputerUse: false,
				allowNetwork: true,
				allowExternalTools: false,
				allowUnknownTools: false,
				allowedToolNames: new Set(),
				deniedToolNames: new Set(),
			};
		case "full-access":
			return {
				name: profile,
				allowFileWrites: true,
				allowCommands: true,
				allowProcessSessions: true,
				allowComputerUse: true,
				allowNetwork: true,
				allowExternalTools: true,
				allowUnknownTools: true,
				allowedToolNames: new Set(),
				deniedToolNames: new Set(),
			};
	}
}

export function resolvePermissionProfile(
	profile: PermissionProfile,
): ResolvedPermissionProfile {
	if (typeof profile === "string") {
		return builtInProfile(profile);
	}
	return {
		name: profile.name.trim() || "custom",
		allowFileWrites: profile.allowFileWrites,
		allowCommands: profile.allowCommands,
		allowProcessSessions: profile.allowProcessSessions,
		allowComputerUse: profile.allowComputerUse === true,
		allowNetwork: profile.allowNetwork,
		allowExternalTools: profile.allowExternalTools,
		allowUnknownTools: profile.allowUnknownTools,
		allowedToolNames: new Set(profile.allowedToolNames ?? []),
		deniedToolNames: new Set(profile.deniedToolNames ?? []),
	};
}

function isCoordinationTool(toolName: string): boolean {
	return toolName.startsWith("team_") || toolName.startsWith("subagent_");
}

function isKnownTool(toolName: string): boolean {
	return (
		READ_ONLY_TOOLS.has(toolName) ||
		WORKSPACE_TOOLS.has(toolName) ||
		NETWORK_TOOLS.has(toolName) ||
		EXTERNAL_TOOLS.has(toolName) ||
		COMPUTER_TOOLS.has(toolName) ||
		isCoordinationTool(toolName)
	);
}

function blockedReason(
	profileName: string,
	detail: string,
): AgentBeforeToolResult {
	return {
		skip: true,
		reason: `Permission profile "${profileName}" blocked this tool call: ${detail}`,
	};
}

function evaluateTool(
	profile: ResolvedPermissionProfile,
	context: AgentBeforeToolContext,
): AgentBeforeToolResult | undefined {
	const toolName = context.tool.name;
	if (profile.deniedToolNames.has(toolName)) {
		return blockedReason(profile.name, `${toolName} is explicitly denied.`);
	}
	const explicitlyAllowed = profile.allowedToolNames.has(toolName);
	if (!isKnownTool(toolName) && !isCoordinationTool(toolName)) {
		if (explicitlyAllowed) {
			return undefined;
		}
		if (!profile.allowUnknownTools) {
			return blockedReason(
				profile.name,
				`${toolName} is an unclassified plugin or MCP tool.`,
			);
		}
		return undefined;
	}

	if (
		!explicitlyAllowed &&
		COMPUTER_TOOLS.has(toolName) &&
		!profile.allowComputerUse
	) {
		return blockedReason(
			profile.name,
			"desktop computer control is disabled for this profile.",
		);
	}
	if (
		!explicitlyAllowed &&
		NETWORK_TOOLS.has(toolName) &&
		!profile.allowNetwork
	) {
		return blockedReason(profile.name, "network tools are disabled.");
	}
	if (
		!explicitlyAllowed &&
		EXTERNAL_TOOLS.has(toolName) &&
		!profile.allowExternalTools
	) {
		return blockedReason(
			profile.name,
			"device, debugger, and reverse-engineering tools are disabled.",
		);
	}
	if (
		!explicitlyAllowed &&
		toolName === "process_session" &&
		!profile.allowProcessSessions
	) {
		return blockedReason(profile.name, "process sessions are disabled.");
	}
	if (
		!explicitlyAllowed &&
		toolName === "run_commands" &&
		!profile.allowCommands
	) {
		return blockedReason(profile.name, "command execution is disabled.");
	}
	if (
		!explicitlyAllowed &&
		!profile.allowFileWrites &&
		(toolName === "editor" || toolName === "apply_patch")
	) {
		return blockedReason(profile.name, "file writes are disabled.");
	}
	if (
		!explicitlyAllowed &&
		!profile.allowFileWrites &&
		toolName === "run_commands"
	) {
		let commands: ReturnType<typeof normalizeRunCommandsInput>;
		try {
			commands = normalizeRunCommandsInput(context.input);
		} catch {
			return undefined;
		}
		for (const command of commands) {
			const blocked = findFileEditingCommand(command);
			if (blocked) {
				return {
					skip: true,
					reason: `${formatPlanModeBlockedCommandError(blocked)} Active permission profile: "${profile.name}".`,
				};
			}
		}
	}
	return undefined;
}

export function createPermissionProfileExtension(
	profileInput: PermissionProfile,
): AgentExtension {
	const profile = resolvePermissionProfile(profileInput);
	return {
		name: PERMISSION_PROFILE_EXTENSION_NAME,
		manifest: { capabilities: ["hooks"] },
		hooks: {
			beforeTool: (context) => evaluateTool(profile, context),
		},
	};
}
