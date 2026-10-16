export type ReasoningEffort = "low" | "medium" | "high" | "xhigh";

export type SessionReasoningPreference = {
	thinking: boolean;
	reasoningEffort?: ReasoningEffort;
};

export type AnalysisMode = "off" | "static" | "runtime" | "hybrid";

export const PENDING_ANALYSIS_MODE_KEY = "cline.chat.pending-analysis-mode.v1";

const SESSION_REASONING_STORAGE_KEY = "cline.chat.session-reasoning.v1";

function isReasoningEffort(value: unknown): value is ReasoningEffort {
	return (
		value === "low" ||
		value === "medium" ||
		value === "high" ||
		value === "xhigh"
	);
}

function parsePreference(value: unknown): SessionReasoningPreference | undefined {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		return undefined;
	}
	const candidate = value as {
		thinking?: unknown;
		reasoningEffort?: unknown;
	};
	if (candidate.thinking === false) {
		return { thinking: false };
	}
	if (
		"reasoningEffort" in candidate &&
		candidate.reasoningEffort !== undefined &&
		!isReasoningEffort(candidate.reasoningEffort)
	) {
		return undefined;
	}
	if (isReasoningEffort(candidate.reasoningEffort)) {
		return { thinking: true, reasoningEffort: candidate.reasoningEffort };
	}
	return candidate.thinking === true ? { thinking: true } : undefined;
}

function readStoredPreferences(): Record<string, SessionReasoningPreference> {
	if (typeof window === "undefined") return {};
	try {
		const parsed = JSON.parse(
			window.localStorage.getItem(SESSION_REASONING_STORAGE_KEY) ?? "{}",
		) as unknown;
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
			return {};
		}
		return Object.fromEntries(
			Object.entries(parsed)
				.map(([sessionId, value]) => [sessionId, parsePreference(value)] as const)
				.filter(
					(entry): entry is readonly [string, SessionReasoningPreference] =>
						entry[1] !== undefined,
				),
		);
	} catch {
		return {};
	}
}

export function readSessionReasoningPreference(
	metadata: unknown,
	sessionId?: string,
): SessionReasoningPreference | undefined {
	if (metadata && typeof metadata === "object" && !Array.isArray(metadata)) {
		const value = (metadata as { chatPreferences?: unknown }).chatPreferences;
		const fromMetadata = parsePreference(
			value && typeof value === "object" && !Array.isArray(value)
				? (value as { reasoning?: unknown }).reasoning ?? value
				: value,
		);
		if (fromMetadata) return fromMetadata;
	}
	return sessionId ? readStoredPreferences()[sessionId] : undefined;
}

export function writeSessionReasoningPreference(
	sessionId: string,
	preference: SessionReasoningPreference,
): void {
	if (typeof window === "undefined" || !sessionId) return;
	try {
		const preferences = readStoredPreferences();
		preferences[sessionId] = preference;
		window.localStorage.setItem(
			SESSION_REASONING_STORAGE_KEY,
			JSON.stringify(preferences),
		);
	} catch {
		// Browser storage is a fallback; session metadata remains authoritative.
	}
}

export function reasoningPreferenceMetadata(
	preference: SessionReasoningPreference,
): { chatPreferences: { reasoning: SessionReasoningPreference } } {
	return { chatPreferences: { reasoning: preference } };
}

export function readPendingAnalysisMode(): AnalysisMode {
	if (typeof window === "undefined") return "off";
	const value = window.localStorage.getItem(PENDING_ANALYSIS_MODE_KEY);
	return value === "static" || value === "runtime" || value === "hybrid"
		? value
		: "off";
}

export function writePendingAnalysisMode(mode: AnalysisMode): void {
	if (typeof window === "undefined") return;
	try {
		window.localStorage.setItem(PENDING_ANALYSIS_MODE_KEY, mode);
	} catch {
		// The backend session mode remains authoritative once a session exists.
	}
}

export function clearPendingAnalysisMode(): void {
	if (typeof window === "undefined") return;
	try {
		window.localStorage.removeItem(PENDING_ANALYSIS_MODE_KEY);
	} catch {
		// Best-effort cleanup only.
	}
}
