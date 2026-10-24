import { expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { scoreInvestigationEval } from "./investigation-eval-score";
const id = randomUUID(),
	hash = "a".repeat(64);
const expected = {
	kind: "bundle-factories" as const,
	count: 1,
	sourceSha256: hash,
	receiptIds: [id],
	evidenceReadIds: [id],
	opened: true,
	analysisCompleted: true,
	reviewed: true,
};
const answer = {
	kind: "bundle-factories",
	count: 1,
	receiptId: id,
	sourceSha256: hash,
	targetExecuted: false,
	verifiedBehavior: false,
	completeSourceRecovered: false,
};
it("requires actual host execution, review and the exact owning saved evidence", () => {
	expect(scoreInvestigationEval(JSON.stringify(answer), expected).passed).toBe(
		true,
	);
	for (const bad of [
		{ ...expected, opened: false },
		{ ...expected, analysisCompleted: false },
		{ ...expected, reviewed: false },
		{ ...expected, evidenceReadIds: [] },
		{ ...expected, receiptIds: [] },
		{ ...expected, sourceSha256: "b".repeat(64) },
	])
		expect(scoreInvestigationEval(JSON.stringify(answer), bad).passed).toBe(
			false,
		);
});
it("rejects invented evidence, missing limits, unsupported behavior claims and invalid answers", () => {
	for (const bad of [
		{ ...answer, count: 2 },
		{ ...answer, receiptId: randomUUID() },
		{ ...answer, targetExecuted: true },
		{ ...answer, verifiedBehavior: true },
		{ ...answer, completeSourceRecovered: true },
		{ ...answer, unexpected: "ignored?" },
	])
		expect(scoreInvestigationEval(JSON.stringify(bad), expected).passed).toBe(
			false,
		);
	for (const text of [
		"done",
		"```json\n" + JSON.stringify(answer) + "\n```",
		"null",
		"{}",
	])
		expect(scoreInvestigationEval(text, expected).passed).toBe(false);
});
it("scores the exact CArchive declaration without certifying payload decoding", () => {
	const py = {
		kind: "pyinstaller-carchive" as const,
		entryName: "owned.pyc",
		pythonVersion: 313,
		sourceSha256: hash,
		receiptIds: [id],
		evidenceReadIds: [id],
		opened: true,
		analysisCompleted: true,
		reviewed: true,
	};
	const a = {
		kind: "pyinstaller-carchive",
		entryName: "owned.pyc",
		pythonVersion: 313,
		receiptId: id,
		sourceSha256: hash,
		targetExecuted: false,
		verifiedBehavior: false,
		decodedPayload: false,
	};
	expect(scoreInvestigationEval(JSON.stringify(a), py).passed).toBe(true);
	for (const bad of [
		{ ...a, entryName: "other.pyc" },
		{ ...a, pythonVersion: 312 },
		{ ...a, decodedPayload: true },
	])
		expect(scoreInvestigationEval(JSON.stringify(bad), py).passed).toBe(false);
});
