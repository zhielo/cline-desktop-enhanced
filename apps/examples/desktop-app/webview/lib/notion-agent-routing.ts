const NOTION_AGENT_TARGET =
	/\bnotion\s+(?:custom\s+)?agent\b|\blocal project analyst\b|\bagent:\/\/[^\s]+/i;
const BRIDGE_ACTION =
	/\b(?:analy[sz]e|review|inspect|audit|send|share|upload|bridge|ask|use)\b/i;
const LOCAL_PROJECT_CONTEXT =
	/\b(?:local\s+(?:project|repo(?:sitory)?|files?)|project|repo(?:sitory)?|codebase|source\s+code|documentation|docs?|reverse[\s-]?engineer(?:ing)?|ida|ghidra|binary|apk|exe|dll)\b/i;

/**
 * Route only explicit user requests that combine a Notion Agent with local
 * project evidence. Ordinary Notion questions and ordinary coding chats keep
 * their existing tool surfaces.
 */
export function requestsProjectNotionBridge(prompt: string): boolean {
	const normalized = prompt.trim();
	if (!normalized) return false;
	return (
		NOTION_AGENT_TARGET.test(normalized) &&
		BRIDGE_ACTION.test(normalized) &&
		LOCAL_PROJECT_CONTEXT.test(normalized)
	);
}
