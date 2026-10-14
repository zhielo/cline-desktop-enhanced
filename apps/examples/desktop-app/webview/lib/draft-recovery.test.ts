import { it, expect } from "vitest";
import {
	clearAcceptedDraft,
	draftRecoveryKey,
	readRecoverableDraft,
	saveRecoverableDraft,
} from "./draft-recovery";
it("drafts are versioned, expiring and isolated by environment/workspace/session", () => {
	const values = new Map<string, string>();
	const storage = {
		getItem: (k: string) => values.get(k) ?? null,
		setItem: (k: string, v: string) => {
			values.set(k, v);
		},
		removeItem: (k: string) => {
			values.delete(k);
		},
	};
	const key = draftRecoveryKey("local", "/owned", "one");
	saveRecoverableDraft(storage, key, "unsent", 1);
	expect(readRecoverableDraft(storage, key, 2)).toBe("unsent");
	expect(
		readRecoverableDraft(
			storage,
			draftRecoveryKey("remote", "/owned", "one"),
			2,
		),
	).toBeNull();
	expect(
		readRecoverableDraft(storage, key, 8 * 24 * 60 * 60 * 1000),
	).toBeNull();
	expect(storage.getItem(key)).toBeNull();
	expect(() => saveRecoverableDraft(storage, key, "x".repeat(32001))).toThrow(
		"32,000",
	);
	storage.setItem(key, '{"schemaVersion":2,"text":"future","savedAt":1}');
	expect(readRecoverableDraft(storage, key, 2)).toBeNull();
	expect(storage.getItem(key)).toContain("future");
	expect(() => saveRecoverableDraft(storage, key, "replacement")).toThrow(
		"Unknown draft version",
	);
	storage.removeItem(key);
	saveRecoverableDraft(storage, key, "");
	expect(storage.getItem(key)).toBeNull();
});

it("accepted sends clear only the matching saved draft", () => {
	const values = new Map<string, string>();
	const storage = {
		getItem: (k: string) => values.get(k) ?? null,
		setItem: (k: string, v: string) => {
			values.set(k, v);
		},
		removeItem: (k: string) => {
			values.delete(k);
		},
	};
	saveRecoverableDraft(storage, "scope", "newer draft");
	expect(clearAcceptedDraft(storage, "scope", "old send")).toBe(false);
	expect(readRecoverableDraft(storage, "scope")).toBe("newer draft");
	expect(clearAcceptedDraft(storage, "scope", "newer draft")).toBe(true);
});
