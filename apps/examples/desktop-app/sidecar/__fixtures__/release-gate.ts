import { readFileSync } from "node:fs";
import { RELEASE_GATE_POLICY as p } from "../release-gate-policy";
import type { ReleaseGateEvidence } from "../release-gate-verifier";
export const head = "a".repeat(40),
	tested = "b".repeat(40),
	tree = "c".repeat(40),
	runId = 123456;
const repo = `${p.owner}/${p.repo}`;
export function fixture(): ReleaseGateEvidence {
	const checks = p.requiredChecks.map((name, i) => ({
		id: i + 1,
		name,
		head_sha: head,
		status: "completed",
		conclusion: "success",
		app: { id: 15368 },
	}));
	const receipt = (names: readonly string[], engineProfile: string) => ({
		schemaVersion: 1,
		status: "passed",
		sourceCommit: tested,
		executionScope: {
			runId: String(runId),
			runAttempt: "1",
			job: "build-windows-installer",
		},
		engineProfile,
		engineValidation:
			engineProfile === "windows-portable"
				? "requested-see-corpus-results"
				: "not-requested",
		results: names.map((name) => ({ name, status: "passed", exitCode: 0 })),
	});
	const steps = [
		"Run consolidated custom fork validation",
		"Validate portable Windows analysis engines",
		"Build NSIS installer",
		"Collect and verify installer",
		"Smoke-test installer and installed binaries",
		"Installed WebView acceptance journey",
		"Upload installed UI acceptance evidence",
		"Upload verified setup.exe",
	].map((name) => ({ name, status: "completed", conclusion: "success" }));
	return {
		pull: {
			number: 133,
			head: { sha: head, repo: { full_name: repo } },
			base: { repo: { full_name: repo } },
		},
		checks: { total_count: checks.length, check_runs: checks },
		run: {
			id: runId,
			run_attempt: 1,
			head_sha: head,
			status: "completed",
			conclusion: "success",
			path: ".github/workflows/build-custom-windows-installer.yml",
			event: "pull_request",
			repository: { full_name: repo },
		},
		jobs: {
			total_count: 1,
			jobs: [
				{
					id: checks.find(
						(c) => c.name === "Validate and build Windows x64 setup.exe",
					)!.id,
					name: "Validate and build Windows x64 setup.exe",
					run_id: runId,
					run_attempt: 1,
					status: "completed",
					conclusion: "success",
					steps,
				},
			],
		},
		artifacts: {
			total_count: 3,
			artifacts: [
				`consolidated-validation-${runId}`,
				`installed-ui-evidence-${runId}-1`,
				`cline-enhanced-windows-x64-unsigned-0.3.0-${runId}-1`,
			].map((name, i) => ({
				id: i + 1,
				name,
				expired: false,
				digest: `sha256:${"d".repeat(64)}`,
				size_in_bytes: 100,
				workflow_run: { id: runId, head_sha: head },
			})),
		},
		headCommit: { sha: head, tree: { sha: tree } },
		testedCommit: {
			sha: tested,
			tree: { sha: tree },
			parents: [{ sha: head }],
		},
		core: receipt(p.coreGates, "not-requested"),
		engines: receipt(p.engineGates, "windows-portable"),
		installed: {
			status: "passed",
			sourceCommit: tested,
			stages: [...p.installedStages],
		},
		policyFileBytes: Object.fromEntries(
			Object.keys(p.policyFiles).map((path) => [
				path,
				readFileSync(new URL(`../../../../../${path}`, import.meta.url)),
			]),
		),
	};
}
