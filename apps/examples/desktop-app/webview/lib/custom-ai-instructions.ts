export type CustomAiInstructions = {
	instructions: string;
	rules: string;
};

export const CUSTOM_AI_INSTRUCTIONS_STORAGE_KEY =
	"cline.customAiInstructions.v1";

const EMPTY_CUSTOM_AI_INSTRUCTIONS: CustomAiInstructions = {
	instructions: "",
	rules: "",
};

export function readCustomAiInstructions(): CustomAiInstructions {
	if (typeof window === "undefined") return EMPTY_CUSTOM_AI_INSTRUCTIONS;
	try {
		const parsed = JSON.parse(
			window.localStorage.getItem(CUSTOM_AI_INSTRUCTIONS_STORAGE_KEY) ?? "{}",
		) as Partial<CustomAiInstructions>;
		return {
			instructions:
				typeof parsed.instructions === "string" ? parsed.instructions : "",
			rules: typeof parsed.rules === "string" ? parsed.rules : "",
		};
	} catch {
		return EMPTY_CUSTOM_AI_INSTRUCTIONS;
	}
}

export function saveCustomAiInstructions(
	value: CustomAiInstructions,
): CustomAiInstructions {
	const normalized = {
		instructions: value.instructions.trim(),
		rules: value.rules.trim(),
	};
	if (typeof window !== "undefined") {
		window.localStorage.setItem(
			CUSTOM_AI_INSTRUCTIONS_STORAGE_KEY,
			JSON.stringify(normalized),
		);
	}
	return normalized;
}