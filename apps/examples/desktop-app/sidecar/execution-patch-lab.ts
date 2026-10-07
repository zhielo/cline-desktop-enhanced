import { z } from "zod";
import { ownedFile } from "./incident-artifacts";
export async function reviewPatchArtifacts(root: string, value: unknown) {
	const input = z
			.object({
				original: z.string().min(1),
				candidate: z.string().min(1),
				reproduction: z.string().min(1).max(4000),
				regressionChecklist: z
					.array(z.string().min(1).max(1000))
					.min(1)
					.max(30),
			})
			.strict()
			.parse(value),
		a = await ownedFile(root, input.original),
		b = await ownedFile(root, input.candidate);
	let changedBytes = Math.abs(a.bytes.length - b.bytes.length),
		ranges: { offset: number; length: number }[] = [],
		offset = -1,
		length = 0;
	for (let i = 0; i < Math.min(a.bytes.length, b.bytes.length); i++) {
		if (a.bytes[i] !== b.bytes[i]) {
			changedBytes++;
			if (offset < 0) offset = i;
			length++;
		} else if (offset >= 0) {
			if (ranges.length < 1000) ranges.push({ offset, length });
			offset = -1;
			length = 0;
		}
	}
	if (offset >= 0 && ranges.length < 1000) ranges.push({ offset, length });
	return {
		original: { path: a.path, sha256: a.sha256, bytes: a.size },
		candidate: { path: b.path, sha256: b.sha256, bytes: b.size },
		changedBytes,
		changedRanges: ranges,
		rangesMayBeTruncated: ranges.length === 1000,
		reproduction: input.reproduction,
		regressionChecklist: input.regressionChecklist,
		phase: "review-only-no-write-no-install",
		requiredGates: [
			"review minimal intended changes",
			"build/source checks",
			"signature and exact artifact identity",
			"explicit install/execution approval",
			"same reproduction and regression review",
			"separately approved rollback",
		],
		limitations: [
			"Byte differences do not prove semantic equivalence or a correct patch",
			"Code rollback cannot undo app-data/schema migrations",
			"APK signing/install/rollback remains the existing APK incident workflow",
			"No autonomous patch generation or execution",
		],
	};
}
