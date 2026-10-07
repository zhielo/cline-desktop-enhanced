import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { parseAndroidDebugEvidence } from "./android-debug-evidence";
import { planEvidenceAnalysis } from "./execution-analysis-planner";
import { reviewPatchArtifacts } from "./execution-patch-lab";

it("does not attribute other packages or call lock waits proven deadlocks", () => {
	const result = parseAndroidDebugEvidence(
		'----- pid 42 -----\nCmd line: com.example.owned\n"main" prio=5 tid=1 Blocked\n - waiting to lock <0x1> held by thread 2\n    at Owned.method(Owned.java:3)\n #00 pc 0000abcd /data/app/libowned.so (foo+4) (BuildId: aabb)\n----- pid 43 -----\nCmd line: com.other.app\n #01 pc 0000ffff /data/app/libother.so',
		"com.example.owned",
	);
	expect(result.nativeFrames).toHaveLength(1);
	expect(result.nativeFrames[0]).toMatchObject({
		pc: "0x0000abcd",
		buildId: "aabb",
	});
	expect(result.threads[0].lockCandidates).toHaveLength(1);
	expect(result.findings.join(" ")).toContain("not proof");
	expect(
		parseAndroidDebugEvidence(
			"Cmd line: com.example.ownedx\n#00 pc abc libwrong.so",
			"com.example.owned",
		).nativeFrames,
	).toHaveLength(0);
});
it("creates evidence-only plans and hash-bound patch reviews without writing artifacts", async () => {
	const root = await mkdtemp(join(tmpdir(), "execution-evidence-"));
	try {
		await writeFile(join(root, "old.so"), Buffer.from([0x7f, 69, 76, 70, 1]));
		await writeFile(join(root, "new.so"), Buffer.from([0x7f, 69, 76, 70, 2]));
		const plan = await planEvidenceAnalysis(root, { target: "old.so" });
		expect(plan.format).toBe("elf");
		expect(plan.stages.map((s) => s.id)).toEqual([
			"identify",
			"native-inventory",
		]);
		const review = await reviewPatchArtifacts(root, {
			original: "old.so",
			candidate: "new.so",
			reproduction: "Owned regression",
			regressionChecklist: ["same repro"],
		});
		expect(review.changedBytes).toBe(1);
		expect(review.phase).toBe("review-only-no-write-no-install");
		expect(review.original.sha256).not.toBe(review.candidate.sha256);
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
