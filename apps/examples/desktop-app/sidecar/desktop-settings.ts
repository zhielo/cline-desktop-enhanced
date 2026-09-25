import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { resolveClineDataDir } from "@cline/shared/storage";

/** Desktop-only preferences kept separate from strict shared global settings. */
export type DesktopSettings = {
	/** Opt-in gate for cloud sessions while the feature is in preview. */
	cloudSessionsEnabled: boolean;
	/** User-authored instructions appended to every new local AI session. */
	customAiInstructions: string;
};

export const MAX_CUSTOM_AI_INSTRUCTIONS_LENGTH = 50_000;

const DEFAULT_SETTINGS: DesktopSettings = {
	cloudSessionsEnabled: false,
	customAiInstructions: "",
};

export function resolveDesktopSettingsPath(): string {
	return join(resolveClineDataDir(), "settings", "code-settings.json");
}

export function readDesktopSettings(): DesktopSettings {
	let raw: string;
	try {
		raw = readFileSync(resolveDesktopSettingsPath(), "utf8");
	} catch {
		return { ...DEFAULT_SETTINGS };
	}
	try {
		const parsed = JSON.parse(raw) as Record<string, unknown>;
		return {
			cloudSessionsEnabled: parsed.cloudSessionsEnabled === true,
			customAiInstructions:
				typeof parsed.customAiInstructions === "string"
					? parsed.customAiInstructions.slice(
							0,
							MAX_CUSTOM_AI_INSTRUCTIONS_LENGTH,
						)
					: "",
		};
	} catch {
		return { ...DEFAULT_SETTINGS };
	}
}

export function writeDesktopSettings(settings: DesktopSettings): void {
	const filePath = resolveDesktopSettingsPath();
	mkdirSync(dirname(filePath), { recursive: true });
	// Avoid leaving torn settings if the process exits mid-write.
	const tempPath = `${filePath}.${process.pid}.tmp`;
	writeFileSync(tempPath, `${JSON.stringify(settings, null, 2)}\n`, "utf8");
	renameSync(tempPath, filePath);
}

export function setCloudSessionsEnabled(enabled: boolean): DesktopSettings {
	const next = { ...readDesktopSettings(), cloudSessionsEnabled: enabled };
	writeDesktopSettings(next);
	return next;
}

export function setCustomAiInstructions(instructions: string): DesktopSettings {
	if (instructions.length > MAX_CUSTOM_AI_INSTRUCTIONS_LENGTH) {
		throw new Error(
			`custom AI instructions must be ${MAX_CUSTOM_AI_INSTRUCTIONS_LENGTH} characters or fewer`,
		);
	}
	const next = {
		...readDesktopSettings(),
		customAiInstructions: instructions.trim(),
	};
	writeDesktopSettings(next);
	return next;
}

export function mergeDesktopAiInstructions(
	inlineRules?: string,
): string | undefined {
	const permanent = readDesktopSettings().customAiInstructions.trim();
	const sessionRules = inlineRules?.trim() ?? "";
	const merged = [permanent, sessionRules].filter(Boolean).join("\n\n");
	return merged || undefined;
}
