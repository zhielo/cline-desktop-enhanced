import { describe, expect, it } from "vitest";
import { CLINE_SYSTEM_PROMPT_ACT_MODE } from "./act";
import { CLINE_SYSTEM_PROMPT_YOLO_MODE } from "./yolo";

const PROMPTS = [CLINE_SYSTEM_PROMPT_ACT_MODE, CLINE_SYSTEM_PROMPT_YOLO_MODE];

describe("authorized CTF behavior", () => {
	it.each(PROMPTS)(
		"treats explicitly scoped application modification as authorized",
		(prompt) => {
			expect(prompt).toContain("AUTHORIZED CTF AND PRIVATE-LAB WORK");
			expect(prompt).toContain(
				"treat reverse engineering and application modification",
			);
			expect(prompt).toContain("Do not refuse solely");
			expect(prompt).toContain("integrity or signature verification");
		},
	);

	it.each(PROMPTS)(
		"keeps authorization bounded to the stated environment",
		(prompt) => {
			expect(prompt).toContain(
				"systems outside the user's stated environment",
			);
			expect(prompt).toContain("credential or data theft");
		},
	);
});
