export type EffectiveInstructionSourceKind =
	| "session"
	| "repository"
	| "global"
	| "skill"
	| "mcp"
	| "tool";

export type EffectiveInstructionSource = {
	id: string;
	kind: EffectiveInstructionSourceKind;
	label: string;
	detail?: string;
	content?: string;
};

type InventoryRule = { name?: string; instructions?: string; path?: string };
type InventorySkill = {
	name?: string;
	description?: string;
	instructions?: string;
	path?: string;
	enabled?: boolean;
};
type InventoryTool = {
	id?: string;
	name?: string;
	enabled?: boolean;
	source?: string;
};
type InventoryMcpServer = {
	name?: string;
	disabled?: boolean;
	transportType?: string;
};

export type EffectiveInstructionInventory = {
	workspaceRoot?: string;
	rules?: InventoryRule[];
	skills?: InventorySkill[];
	tools?: InventoryTool[];
	mcp?: { servers?: InventoryMcpServer[] };
};

const SECRET_ASSIGNMENT =
	/\b(api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|passwd)\b(\s*[:=]\s*)([^\s,;]+)/gi;
const BEARER_TOKEN = /\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi;
const PRIVATE_KEY =
	/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/gi;

export function redactInstructionText(value: string): string {
	return value
		.replace(PRIVATE_KEY, "[REDACTED PRIVATE KEY]")
		.replace(BEARER_TOKEN, "Bearer [REDACTED]")
		.replace(
			SECRET_ASSIGNMENT,
			(_match, name: string, separator: string) =>
				`${name}${separator}[REDACTED]`,
		);
}

function normalizedPath(value?: string): string {
	return value?.replaceAll("\\", "/").replace(/\/$/, "") ?? "";
}

function sourceKind(
	path: string | undefined,
	workspaceRoot: string | undefined,
) {
	const normalized = normalizedPath(path);
	const root = normalizedPath(workspaceRoot);
	return root && (normalized === root || normalized.startsWith(`${root}/`))
		? ("repository" as const)
		: ("global" as const);
}

function sourceDetail(
	path: string | undefined,
	workspaceRoot: string | undefined,
) {
	if (!path) return undefined;
	const normalized = normalizedPath(path);
	const root = normalizedPath(workspaceRoot);
	return root && normalized.startsWith(`${root}/`)
		? normalized.slice(root.length + 1)
		: normalized;
}

export function buildEffectiveInstructionSources(options: {
	systemPrompt?: string;
	rules?: string;
	workspaceRoot?: string;
	inventory?: EffectiveInstructionInventory | null;
}): EffectiveInstructionSource[] {
	const sources: EffectiveInstructionSource[] = [];
	const systemPrompt = options.systemPrompt?.trim();
	if (systemPrompt) {
		sources.push({
			id: "session-system-prompt",
			kind: "session",
			label: "Custom system prompt",
			content: redactInstructionText(systemPrompt),
		});
	}
	const sessionRules = options.rules?.trim();
	if (sessionRules) {
		sources.push({
			id: "session-rules",
			kind: "session",
			label: "Session rules",
			content: redactInstructionText(sessionRules),
		});
	}
	const inventory = options.inventory;
	const workspaceRoot = options.workspaceRoot || inventory?.workspaceRoot;
	for (const [index, rule] of (inventory?.rules ?? []).entries()) {
		const path = rule.path?.trim();
		sources.push({
			id: `rule-${path || rule.name || index}`,
			kind: sourceKind(path, workspaceRoot),
			label: rule.name?.trim() || "Rule",
			detail: sourceDetail(path, workspaceRoot),
			...(rule.instructions?.trim()
				? { content: redactInstructionText(rule.instructions.trim()) }
				: {}),
		});
	}
	for (const [index, skill] of (inventory?.skills ?? []).entries()) {
		if (skill.enabled === false) continue;
		const path = skill.path?.trim();
		sources.push({
			id: `skill-${path || skill.name || index}`,
			kind: "skill",
			label: skill.name?.trim() || "Skill",
			detail: skill.description?.trim() || sourceDetail(path, workspaceRoot),
		});
	}
	for (const [index, server] of (inventory?.mcp?.servers ?? []).entries()) {
		if (server.disabled) continue;
		sources.push({
			id: `mcp-${server.name || index}`,
			kind: "mcp",
			label: server.name?.trim() || "MCP server",
			detail: server.transportType,
		});
	}
	for (const [index, tool] of (inventory?.tools ?? []).entries()) {
		if (tool.enabled === false) continue;
		sources.push({
			id: `tool-${tool.id || tool.name || index}`,
			kind: "tool",
			label: tool.name?.trim() || tool.id?.trim() || "Tool",
			detail: tool.source,
		});
	}
	return sources;
}
