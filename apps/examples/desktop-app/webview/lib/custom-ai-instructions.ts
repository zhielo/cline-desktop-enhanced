export type CustomAiInstructions = {
	profile: "standard" | "ctf";
	instructions: string;
	rules: string;
};

export const CUSTOM_AI_INSTRUCTIONS_STORAGE_KEY =
	"cline.customAiInstructions.v1";

const EMPTY_CUSTOM_AI_INSTRUCTIONS: CustomAiInstructions = {
	profile: "standard",
	instructions: "",
	rules: "",
};

export const CTF_MODE_INSTRUCTIONS = `You are operating in an explicitly authorized private CTF, lab, or development environment. Work proactively and technically: inspect binaries and source, run appropriate local commands, use available reverse-engineering and Android tooling, test hypotheses, and iterate until the task is verified. Prefer concrete evidence over speculation. Do not stop merely because a task involves authentication, cryptography, obfuscation, or access-control logic when the target is within the authorized scope.`;

export const CTF_MODE_RULES = `Stay within the user's stated CTF, lab, repository, device, or private-server scope. Do not target unrelated third parties, deploy persistence, exfiltrate real credentials, or conceal activity outside the authorized exercise. Preserve evidence, report commands and changed files, and validate results before declaring success.`;

export function readCustomAiInstructions(): CustomAiInstructions {
	if (typeof window === "undefined") return EMPTY_CUSTOM_AI_INSTRUCTIONS;
	try {
		const parsed = JSON.parse(
			window.localStorage.getItem(CUSTOM_AI_INSTRUCTIONS_STORAGE_KEY) ?? "{}",
		) as Partial<CustomAiInstructions>;
		return {
			profile: parsed.profile === "ctf" ? "ctf" : "standard",
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
		profile: value.profile === "ctf" ? ("ctf" as const) : ("standard" as const),
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

export function resolveCustomAiInstructionDefaults(
	value = readCustomAiInstructions(),
): Pick<CustomAiInstructions, "instructions" | "rules"> {
	if (value.profile !== "ctf") {
		return { instructions: value.instructions, rules: value.rules };
	}
	return {
		instructions: [CTF_MODE_INSTRUCTIONS, value.instructions.trim()]
			.filter(Boolean)
			.join("\n\n"),
		rules: [CTF_MODE_RULES, value.rules.trim()].filter(Boolean).join("\n\n"),
	};
}