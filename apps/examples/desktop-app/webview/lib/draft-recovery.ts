export interface DraftStorage {
	getItem: (key: string) => string | null;
	setItem: (key: string, value: string) => void;
	removeItem: (key: string) => void;
}
const TTL = 7 * 24 * 60 * 60 * 1000;
export function draftRecoveryKey(
	environmentId: string,
	workspace: string,
	sessionId: string,
) {
	return `cline.draft.v1:${JSON.stringify([environmentId, workspace, sessionId])}`;
}
export function readRecoverableDraft(
	storage: DraftStorage,
	key: string,
	now = Date.now(),
): string | null {
	try {
		const raw = storage.getItem(key);
		if (!raw || raw.length > 65536) return null;
		const value = JSON.parse(raw);
		if (
			value.schemaVersion !== 1 ||
			typeof value.text !== "string" ||
			value.text.length > 32000 ||
			!Number.isFinite(value.savedAt) ||
			value.savedAt > now
		)
			return null;
		if (now - value.savedAt > TTL) {
			storage.removeItem(key);
			return null;
		}
		return value.text || null;
	} catch {
		return null;
	}
}
export function saveRecoverableDraft(
	storage: DraftStorage,
	key: string,
	text: string,
	now = Date.now(),
) {
	const old = storage.getItem(key);
	if (old) {
		let version: unknown;
		try {
			version = JSON.parse(old).schemaVersion;
		} catch {}
		if (version !== undefined && version !== 1)
			throw new Error("Unknown draft version; explicit discard is required");
	}
	if (text.length > 32000)
		throw new Error("Draft recovery limit is 32,000 characters");
	if (!text) storage.removeItem(key);
	else
		storage.setItem(
			key,
			JSON.stringify({ schemaVersion: 1, text, savedAt: now }),
		);
}

export function clearAcceptedDraft(
	storage: DraftStorage,
	key: string,
	acceptedText: string,
) {
	const saved = readRecoverableDraft(storage, key);
	if (saved?.trim() === acceptedText.trim()) {
		storage.removeItem(key);
		return true;
	}
	return false;
}
