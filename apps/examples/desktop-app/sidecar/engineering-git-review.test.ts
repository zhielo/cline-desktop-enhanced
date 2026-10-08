import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildEngineeringGitReview } from "./engineering-git-review";

const roots: string[] = [];
afterEach(() => {
	for (const root of roots.splice(0))
		rmSync(root, { recursive: true, force: true });
});
function repository() {
	const root = mkdtempSync(join(tmpdir(), "cline-review-"));
	roots.push(root);
	for (const args of [
		["init", "-b", "main"],
		["config", "user.email", "test@example.invalid"],
		["config", "user.name", "Test"],
	])
		execFileSync("git", ["-C", root, ...args]);
	writeFileSync(
		join(root, "auth.ts"),
		"export function authorize() { return true }\n",
	);
	execFileSync("git", ["-C", root, "add", "."]);
	execFileSync("git", ["-C", root, "commit", "-m", "base"]);
	return root;
}

describe("buildEngineeringGitReview", () => {
	it("produces transparent file, symbol, and risk evidence", () => {
		const root = repository();
		writeFileSync(
			join(root, "auth.ts"),
			"export function authorize() { return false }\nexport function revoke() {}\n",
		);
		const review = buildEngineeringGitReview(root);
		expect(review.files[0]).toMatchObject({
			path: "auth.ts",
			category: "code",
			sensitive: true,
		});
		expect(review.files[0]?.symbols).toContain("revoke");
		expect(review.risk.reasons).toContain("1 sensitive file(s) changed");
	});
	it("rejects an invalid comparison base", () => {
		const root = repository();
		expect(() => buildEngineeringGitReview(root, "--dangerous")).toThrow();
	});
});

it("returns bounded import-impact and non-executing suggested tests", () => {
	const root = repository();
	writeFileSync(
		join(root, "consumer.ts"),
		"import { authorize } from './auth'; export const value = authorize();",
	);
	writeFileSync(join(root, "consumer.test.ts"), "// owned test candidate");
	writeFileSync(
		join(root, "auth.ts"),
		"export function authorize(){return false}",
	);
	const review = buildEngineeringGitReview(root);
	expect(review.impact.affectedFiles).toContain("consumer.ts");
	expect(review.impact.suggestedTestFiles).toContain("consumer.test.ts");
	expect(review.impact.executedTests).toBe(false);
});
