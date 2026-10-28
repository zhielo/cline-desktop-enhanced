import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { it as test } from "vitest";
import {
	fixture,
	head,
	repeatedE2EEvidence,
} from "./__fixtures__/release-gate";
import { RELEASE_GATE_POLICY as p } from "./release-gate-policy";
import {
	type ReleaseGateEvidence,
	sha256,
	verifyReleaseGateEvidence,
} from "./release-gate-verifier";

test("owned complete evidence passes without claiming behavior verification", () => {
	const r = verifyReleaseGateEvidence(133, head, fixture());
	assert.equal(r.status, "passed");
	assert.equal(r.installedStages, 73);
	assert.match(r.limitations.join(" "), /Unsigned/);
});
const cases: Array<[string, (e: ReleaseGateEvidence) => void]> = [
 ["missing installed session inventory proof", (e) => {
  e.installed.stages=e.installed.stages.filter((stage:string)=>stage!=="installed-session-tool-inventory-exact-provider-names-no-extra-request-passed");
 }],
 ["missing installed same-boot recovery refusal proof", (e) => {
  e.installed.stages=e.installed.stages.filter((stage:string)=>stage!=="installed-setup-recovery-real-boot-same-boot-refusal-no-replay-passed");
 }],
	[
		"missing installed Ghidra architecture proof",
		(e) => {
			e.installed.stages = e.installed.stages.filter(
				(s: string) =>
					s !==
					"installed-ghidra-three-owned-architectures-java-no-target-execution-passed",
			);
		},
	],
	[
		"missing installed AI binary triage proof",
		(e) => {
			e.installed.stages = e.installed.stages.filter(
				(s: string) =>
					s !==
					"installed-ai-binary-triage-seven-operations-approval-and-evidence-passed",
			);
		},
	],
	[
		"missing installed acquisition proof",
		(e) => {
			e.installed.stages = e.installed.stages.filter(
				(s: string) =>
					s !==
					"installed-source-acquisition-hash-bound-saved-off-no-execution-passed",
			);
		},
	],
	[
		"moved head",
		(e) => {
			e.pull.head.sha = "e".repeat(40);
		},
	],
	[
		"fork source",
		(e) => {
			e.pull.head.repo.full_name = "other/fork";
		},
	],
	[
		"missing check",
		(e) => {
			e.checks.check_runs.pop();
			e.checks.total_count--;
		},
	],
	[
		"pending check",
		(e) => {
			e.checks.check_runs[0].status = "in_progress";
		},
	],
	[
		"failed check",
		(e) => {
			e.checks.check_runs[0].conclusion = "failure";
		},
	],
	[
		"required skipped",
		(e) => {
			e.checks.check_runs[0].conclusion = "skipped";
		},
	],
	[
		"untrusted app",
		(e) => {
			e.checks.check_runs[0].app.id = 1;
		},
	],
	[
		"duplicate check identity",
		(e) => {
			e.checks.check_runs[1].id = e.checks.check_runs[0].id;
		},
	],
	[
		"spoof Windows check",
		(e) => {
			e.jobs.jobs[0].id = 999;
		},
	],
	[
		"partial pagination",
		(e) => {
			e.checks.total_count++;
		},
	],
	[
		"wrong workflow",
		(e) => {
			e.run.path = "other.yml";
		},
	],
	[
		"old attempt",
		(e) => {
			e.jobs.jobs[0].run_attempt = 2;
		},
	],
	[
		"installer smoke skipped",
		(e) => {
			e.jobs.jobs[0].steps[4].conclusion = "skipped";
		},
	],
	[
		"changed recipe",
		(e) => {
			e.policyFileBytes[Object.keys(p.policyFiles)[0]] = Buffer.from("changed");
		},
	],
	[
		"invalid integration tree identity",
		(e) => {
			e.testedCommit.tree.sha = "not-a-commit-tree";
		},
	],
	[
		"unrelated test merge",
		(e) => {
			e.testedCommit.parents = [];
		},
	],
	[
		"stale receipt run",
		(e) => {
			e.core.executionScope.runId = "9";
		},
	],
	[
		"stale receipt source",
		(e) => {
			e.engines.sourceCommit = "e".repeat(40);
		},
	],
	[
		"duplicate gate name",
		(e) => {
			e.core.results[0] = e.core.results[1];
		},
	],
	[
		"failed core gate",
		(e) => {
			e.core.results[0].exitCode = 1;
		},
	],
	[
		"wrong engine profile",
		(e) => {
			e.engines.engineProfile = "local";
		},
	],
	[
		"missing installed stage",
		(e) => {
			e.installed.stages.splice(2, 1);
		},
	],
	[
		"cleanup not last",
		(e) => {
			e.installed.stages.reverse();
		},
	],
	[
		"installed not passed",
		(e) => {
			e.installed.status = "failed";
		},
	],
	[
		"expired installer",
		(e) => {
			e.artifacts.artifacts[2].expired = true;
		},
	],
	[
		"wrong artifact source",
		(e) => {
			e.artifacts.artifacts[0].workflow_run.head_sha = "e".repeat(40);
		},
	],
	[
		"missing authenticated digest",
		(e) => {
			e.artifacts.artifacts[0].digest = "";
		},
	],
	[
		"wrong installer attempt",
		(e) => {
			e.artifacts.artifacts[2].name = e.artifacts.artifacts[2].name.replace(
				/-1$/,
				"-2",
			);
		},
	],
];
for (const [name, mutate] of cases)
	test(name + " blocks", () => {
		const e = fixture();
		mutate(e);
		assert.throws(() => verifyReleaseGateEvidence(133, head, e));
	});
test("all policy file fingerprints match staged policy", () => {
	for (const [path, hash] of Object.entries(p.policyFiles))
		assert.equal(
			sha256(readFileSync(new URL(`../../../../${path}`, import.meta.url))),
			hash,
		);
});
test("conditional desktop packaging checks must both pass when triggered", () => {
	const e = fixture();
	const template = e.checks.check_runs[0];
	for (const [index, name] of [
		"Test DMG background tooling",
		"Test x86 installer against x64 sidecars",
	].entries())
		e.checks.check_runs.push({
			...template,
			id: 9000 + index,
			name,
			conclusion: "success",
		});
	e.checks.total_count = e.checks.check_runs.length;
	assert.equal(
		verifyReleaseGateEvidence(133, head, e).checks,
		p.requiredChecks.length + 2,
	);
	for (const conclusion of ["failure", "skipped", "cancelled", "timed_out"]) {
		const changed = structuredClone(e);
		changed.checks.check_runs.at(-1)!.conclusion = conclusion;
		assert.throws(() => verifyReleaseGateEvidence(133, head, changed));
	}
	const missing = structuredClone(e);
	missing.checks.check_runs.pop();
	missing.checks.total_count--;
	assert.throws(() => verifyReleaseGateEvidence(133, head, missing));
	const duplicate = structuredClone(e);
	duplicate.checks.check_runs.push({
		...duplicate.checks.check_runs.at(-1)!,
		id: 9002,
	});
	duplicate.checks.total_count++;
	assert.throws(() => verifyReleaseGateEvidence(133, head, duplicate));
	const unknown = fixture();
	unknown.checks.check_runs.push({
		...template,
		id: 9003,
		name: "unknown conditional gate",
	});
	unknown.checks.total_count++;
	assert.throws(() => verifyReleaseGateEvidence(133, head, unknown));
});

for (const platform of ["ubuntu-latest", "windows-latest"]) {
	test(`semantic parity ${platform} is mandatory and cannot be skipped`, () => {
		const name = `semantic-source-validation / Semantic source parity (${platform})`;
		for (const conclusion of ["failure", "skipped", "cancelled", "timed_out"]) {
			const e = fixture();
			const check = e.checks.check_runs.find((c) => c.name === name);
			assert.ok(check, "semantic parity must remain a required policy check");
			check.conclusion = conclusion;
			assert.throws(() => verifyReleaseGateEvidence(133, head, e));
		}
		const missing = fixture();
		missing.checks.check_runs = missing.checks.check_runs.filter(
			(c) => c.name !== name,
		);
		missing.checks.total_count = missing.checks.check_runs.length;
		assert.throws(() => verifyReleaseGateEvidence(133, head, missing));
	});
}
test("semantic workflow recipe remains hash-pinned", () => {
	const e = fixture();
	e.policyFileBytes[".github/workflows/semantic-source-validation.yml"] =
		Buffer.from("changed");
	assert.throws(() => verifyReleaseGateEvidence(133, head, e));
});

for (const os of ["ubuntu-latest", "windows-latest"]) {
	test(`general recovery ${os} is mandatory and cannot be skipped`, () => {
		const evidence = fixture();
		const check = evidence.checks.check_runs.find(
			(c) => c.name === `Pinned general recovery (${os})`,
		);
		assert.ok(check);
		check.conclusion = "skipped";
		assert.throws(
			() => verifyReleaseGateEvidence(133, head, evidence),
			/Required check not successful/,
		);
	});
}

test("rejects evidence built against a stale base even when head is unchanged", () => {
	const e = fixture();
	e.pull.base.sha = "f".repeat(40);
	assert.throws(
		() => verifyReleaseGateEvidence(133, head, e),
		/current base\/head/,
	);
});
test("requires a two-parent current-base integration commit, not a direct head build", () => {
	const e = fixture();
	e.core.sourceCommit = head;
	e.testedCommit.sha = head;
	assert.throws(
		() => verifyReleaseGateEvidence(133, head, e),
		/current base\/head/,
	);
});

test("accepts the current merge tree even when it differs from the head tree", () => {
	const e = fixture();
	e.testedCommit.tree.sha = "f".repeat(40);
	assert.equal(verifyReleaseGateEvidence(133, head, e).tree, "f".repeat(40));
});
test("rejects a superseded synthetic merge identity", () => {
	const e = fixture();
	e.pull.merge_commit_sha = "f".repeat(40);
	assert.throws(
		() => verifyReleaseGateEvidence(133, head, e),
		/current base\/head/,
	);
});

test("verifies every successful repeated ready-for-review E2E check with exact workflow provenance", () => {
	assert.equal(
		verifyReleaseGateEvidence(133, head, repeatedE2EEvidence()).status,
		"passed",
	);
});
for (const [label, change] of [
	[
		"failed repeat",
		(e: ReleaseGateEvidence) => {
			e.checks.check_runs.at(-1)!.conclusion = "failure";
		},
	],
	[
		"pending repeat",
		(e: ReleaseGateEvidence) => {
			e.checks.check_runs.at(-1)!.status = "queued";
		},
	],
	[
		"missing provenance",
		(e: ReleaseGateEvidence) => {
			delete e.workflowRuns;
		},
	],
	[
		"foreign workflow",
		(e: ReleaseGateEvidence) => {
			e.workflowRuns!.workflow_runs[1].path = ".github/workflows/other.yml";
		},
	],
	[
		"wrong head",
		(e: ReleaseGateEvidence) => {
			e.workflowRuns!.workflow_runs[1].head_sha = "f".repeat(40);
		},
	],
	[
		"wrong job",
		(e: ReleaseGateEvidence) => {
			e.checks.check_runs.at(-1)!.details_url =
				"https://github.com/zhielo/cline-desktop-enhanced/actions/runs/802/job/999";
		},
	],
	[
		"failed workflow",
		(e: ReleaseGateEvidence) => {
			e.workflowRuns!.workflow_runs[1].conclusion = "failure";
		},
	],
	[
		"missing required check",
		(e: ReleaseGateEvidence) => {
			e.checks.check_runs = e.checks.check_runs.filter(
				(c) => c.name !== "Owned additive emulation (qiling)",
			);
			e.checks.total_count = e.checks.check_runs.length;
		},
	],
] as const)
	test(`rejects repeated E2E evidence: ${label}`, () => {
		const e = repeatedE2EEvidence();
		change(e);
		assert.throws(() => verifyReleaseGateEvidence(133, head, e));
	});
