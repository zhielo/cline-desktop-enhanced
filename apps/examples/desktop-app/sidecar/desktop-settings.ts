import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { resolveClineDataDir } from "@cline/shared/storage";

/** Desktop-only preferences kept separate from strict shared global settings. */
export type DesktopSettings = {
	/** Opt-in gate for cloud sessions while the feature is in preview. */
	cloudSessionsEnabled: boolean;
	/** User-authored instructions appended to every new local AI session. */
	customAiInstructions: string;
	/** Explicit opt-in for app-scoped Windows computer control. */
	computerUseEnabled: boolean;
	/** Exact absolute executable paths that computer control may target. */
	computerUseAllowedApplications: string[];
};

export const MAX_CUSTOM_AI_INSTRUCTIONS_LENGTH = 50_000;

const DEFAULT_SETTINGS: DesktopSettings = {
	cloudSessionsEnabled: false,
	customAiInstructions: "",
	computerUseEnabled: false,
	computerUseAllowedApplications: [],
};

export const MAX_COMPUTER_USE_APPLICATIONS = 32;

function normalizeComputerUseApplications(value: unknown): string[] {
	if (!Array.isArray(value)) return [];
	const unique = new Map<string, string>();
	for (const candidate of value) {
		if (typeof candidate !== "string") continue;
		const trimmed = candidate.trim();
		if (
			!trimmed ||
			trimmed.length > 2048 ||
			!(/^[A-Za-z]:[\\/]/.test(trimmed) && /\.exe$/i.test(trimmed))
		) {
			continue;
		}
		const key = trimmed.replaceAll("/", "\\").toLowerCase();
		if (!unique.has(key)) unique.set(key, trimmed);
		if (unique.size >= MAX_COMPUTER_USE_APPLICATIONS) break;
	}
	return [...unique.values()];
}

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
			computerUseEnabled: parsed.computerUseEnabled === true,
			computerUseAllowedApplications: normalizeComputerUseApplications(
				parsed.computerUseAllowedApplications,
			),
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

export function setComputerUseSettings(input: {
	enabled: boolean;
	allowedApplications: string[];
}): DesktopSettings {
	if (input.allowedApplications.length > MAX_COMPUTER_USE_APPLICATIONS) {
		throw new Error(
			`computer-use allowlist supports at most ${MAX_COMPUTER_USE_APPLICATIONS} applications`,
		);
	}
	const allowedApplications = normalizeComputerUseApplications(
		input.allowedApplications,
	);
	if (
		input.allowedApplications.some(
			(value) =>
				typeof value !== "string" ||
				!(/^[A-Za-z]:[\\/]/.test(value.trim()) && /\.exe$/i.test(value.trim())),
		)
	) {
		throw new Error(
			"computer-use applications must be absolute Windows .exe paths",
		);
	}
	if (input.enabled && allowedApplications.length === 0) {
		throw new Error(
			"computer use requires at least one allowlisted application",
		);
	}
	const next = {
		...readDesktopSettings(),
		computerUseEnabled: input.enabled,
		computerUseAllowedApplications: allowedApplications,
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
