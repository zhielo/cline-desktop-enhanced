import type { ChatSessionConfig } from "./chat-schema";
import { normalizeProviderId } from "./provider-id";

export type ReasoningSelection = Pick<
	ChatSessionConfig,
	"thinking" | "reasoningEffort"
>;
export const AUTO_REASONING: ReasoningSelection = {
	thinking: true,
	reasoningEffort: undefined,
};
const PREFIX = "cline.reasoning.v1:";
export function parseReasoning(value: unknown): ReasoningSelection | undefined {
	if (!value || typeof value !== "object") return;
	const v = value as Record<string, unknown>;
	if (typeof v.thinking !== "boolean") return;
	if (
		v.reasoningEffort !== undefined &&
		!["low", "medium", "high", "xhigh"].includes(String(v.reasoningEffort))
	)
		return;
	return {
		thinking: v.thinking,
		reasoningEffort: v.thinking
			? (v.reasoningEffort as ReasoningSelection["reasoningEffort"])
			: undefined,
	};
}
function key(
	kind: string,
	environment: string,
	id: string,
	provider = "",
	model = "",
) {
	return (
		PREFIX +
		JSON.stringify([
			kind,
			environment,
			id,
			normalizeProviderId(provider),
			model,
		])
	);
}
function read(k: string): ReasoningSelection | undefined {
	try {
		return parseReasoning(JSON.parse(window.localStorage.getItem(k) ?? "null"));
	} catch {
		return undefined;
	}
}
function write(k: string, value: ReasoningSelection) {
	const parsed = parseReasoning(value);
	if (!parsed) return;
	try {
		window.localStorage.setItem(k, JSON.stringify(parsed));
	} catch {
		/* Keep current selection usable when desktop storage is unavailable. */
	}
}
export const readSessionReasoning = (env: string, id: string) =>
	read(key("session", env, id));
export const writeSessionReasoning = (
	env: string,
	id: string,
	value: ReasoningSelection,
) => write(key("session", env, id), value);
export function readDraftReasoning(
	env: string,
	draft: string,
	provider: string,
	model: string,
) {
	return (
		read(key("draft", env, draft, provider, model)) ??
		read(key("default", env, "", provider, model)) ??
		AUTO_REASONING
	);
}
export function writeDraftReasoning(
	env: string,
	draft: string,
	provider: string,
	model: string,
	value: ReasoningSelection,
) {
	write(key("draft", env, draft, provider, model), value);
	write(key("default", env, "", provider, model), value);
}
