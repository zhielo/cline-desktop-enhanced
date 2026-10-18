import { createHash } from "node:crypto";
import { RELEASE_GATE_POLICY as policy } from "./release-gate-policy";

export const sha256 = (bytes: Uint8Array | string) =>
	createHash("sha256").update(bytes).digest("hex");
const requireProof: (condition: unknown, message: string) => asserts condition =
	(condition, message) => {
		if (!condition) throw new Error(message);
	};
type Check = {
	name: string;
	head_sha: string;
	status: string;
	conclusion: string | null;
	app: { id: number };
	id: number;
};
export type ReleaseGateEvidence = {
	pull: {
		number: number;
		head: { sha: string; repo: { full_name: string } };
		base: { repo: { full_name: string } };
	};
	checks: { total_count: number; check_runs: Check[] };
	run: {
		id: number;
		run_attempt: number;
		head_sha: string;
		status: string;
		conclusion: string | null;
		path: string;
		event: string;
		repository: { full_name: string };
	};
	jobs: {
		total_count: number;
		jobs: Array<{
			id: number;
			name: string;
			status: string;
			conclusion: string | null;
			run_id: number;
			run_attempt: number;
			steps: Array<{ name: string; status: string; conclusion: string | null }>;
		}>;
	};
	artifacts: {
		total_count: number;
		artifacts: Array<{
			id: number;
			name: string;
			expired: boolean;
			digest: string;
			size_in_bytes: number;
			workflow_run: { id: number; head_sha: string };
		}>;
	};
	headCommit: { sha: string; tree: { sha: string } };
	testedCommit: {
		sha: string;
		tree: { sha: string };
		parents: Array<{ sha: string }>;
	};
	core: any;
	engines: any;
	installed: any;
	policyFileBytes: Record<string, Buffer>;
};
export function verifyReleaseGateEvidence(
	pullNumber: number,
	expectedHead: string,
	e: ReleaseGateEvidence,
) {
	requireProof(
		Number.isSafeInteger(pullNumber) &&
			pullNumber > 0 &&
			/^[a-f0-9]{40}$/.test(expectedHead),
		"Exact PR and 40-hex head required",
	);
	const repo = `${policy.owner}/${policy.repo}`;
	requireProof(
		e.pull.number === pullNumber &&
			e.pull.head.sha === expectedHead &&
			e.pull.head.repo.full_name === repo &&
			e.pull.base.repo.full_name === repo,
		"PR/head/repository mismatch; fork builds are outside this policy",
	);
	requireProof(
		e.checks.total_count === e.checks.check_runs.length &&
			e.checks.total_count <= 100,
		"Incomplete check pagination",
	);
	const remaining: string[] = [...policy.requiredChecks];
	const ids = new Set<number>();
	for (const c of e.checks.check_runs) {
		requireProof(!ids.has(c.id), "Duplicate check identity");
		ids.add(c.id);
		requireProof(
			c.head_sha === expectedHead &&
				c.app.id === 15368 &&
				c.status === "completed",
			"Check identity/head/app/pending mismatch",
		);
		const at = remaining.indexOf(c.name);
		if (at >= 0) {
			requireProof(
				c.conclusion === "success",
				`Required check not successful: ${c.name}`,
			);
			remaining.splice(at, 1);
		} else
			requireProof(
				policy.allowedSkipped.includes(c.name as never) &&
					c.conclusion === "skipped",
				`Unexpected or duplicate check: ${c.name}`,
			);
	}
	requireProof(
		remaining.length === 0,
		`Missing required checks: ${remaining.join(", ")}`,
	);
	const r = e.run;
	requireProof(
		Number.isSafeInteger(r.id) &&
			r.id > 0 &&
			Number.isSafeInteger(r.run_attempt) &&
			r.run_attempt > 0 &&
			r.head_sha === expectedHead &&
			r.status === "completed" &&
			r.conclusion === "success" &&
			r.path === ".github/workflows/build-custom-windows-installer.yml" &&
			r.event === "pull_request" &&
			r.repository.full_name === repo,
		"Exact Windows PR workflow not successful",
	);
	requireProof(
		e.jobs.total_count === e.jobs.jobs.length && e.jobs.total_count <= 100,
		"Incomplete job pagination",
	);
	const builds = e.jobs.jobs.filter(
		(j) => j.name === "Validate and build Windows x64 setup.exe",
	);
	requireProof(builds.length === 1, "Ambiguous Windows installer job");
	const job = builds[0];
	requireProof(
		e.checks.check_runs.some(
			(c) =>
				c.id === job.id &&
				c.name === "Validate and build Windows x64 setup.exe",
		),
		"Windows job does not match the required check identity",
	);
	requireProof(
		job.run_id === r.id &&
			job.run_attempt === r.run_attempt &&
			job.status === "completed" &&
			job.conclusion === "success",
		"Wrong or unsuccessful Windows job attempt",
	);
	for (const name of [
		"Run consolidated custom fork validation",
		"Validate portable Windows analysis engines",
		"Build NSIS installer",
		"Collect and verify installer",
		"Smoke-test installer and installed binaries",
		"Installed WebView acceptance journey",
		"Upload installed UI acceptance evidence",
		"Upload verified setup.exe",
	]) {
		const steps = job.steps.filter((s) => s.name === name);
		requireProof(
			steps.length === 1 &&
				steps[0].status === "completed" &&
				steps[0].conclusion === "success",
			`Required Windows step not successful: ${name}`,
		);
	}
	for (const [path, hash] of Object.entries(policy.policyFiles))
		requireProof(
			e.policyFileBytes[path] && sha256(e.policyFileBytes[path]) === hash,
			`Release verification recipe changed: ${path}`,
		);
	const tested = e.core.sourceCommit;
	requireProof(
		/^[a-f0-9]{40}$/.test(tested) &&
			/^[a-f0-9]{40}$/.test(e.headCommit.tree.sha) &&
			e.headCommit.sha === expectedHead &&
			e.testedCommit.sha === tested &&
			e.testedCommit.tree.sha === e.headCommit.tree.sha,
		"Receipt commit tree does not match exact proposed head",
	);
	requireProof(
		tested === expectedHead ||
			e.testedCommit.parents.some((p) => p.sha === expectedHead),
		"Tested commit is not this head or its PR test merge",
	);
	const validateReceipt = (v: any, names: readonly string[]) => {
		requireProof(
			v.schemaVersion === 1 &&
				v.status === "passed" &&
				v.sourceCommit === tested &&
				v.executionScope?.runId === String(r.id) &&
				v.executionScope?.runAttempt === String(r.run_attempt) &&
				v.executionScope?.job === "build-windows-installer",
			"Unsuccessful or mismatched validation receipt scope",
		);
		requireProof(
			Array.isArray(v.results) &&
				v.results.length === names.length &&
				new Set(v.results.map((x: any) => x.name)).size === names.length,
			"Incomplete or duplicate validation gates",
		);
		for (const name of names)
			requireProof(
				v.results.some(
					(x: any) =>
						x.name === name && x.status === "passed" && x.exitCode === 0,
				),
				`Validation gate failed: ${name}`,
			);
	};
	validateReceipt(e.core, policy.coreGates);
	validateReceipt(e.engines, policy.engineGates);
	requireProof(
		e.engines.engineProfile === "windows-portable" &&
			e.engines.engineValidation === "requested-see-corpus-results",
		"Wrong engine validation profile",
	);
	const installed = e.installed;
	requireProof(
		installed.status === "passed" &&
			installed.sourceCommit === tested &&
			Array.isArray(installed.stages) &&
			installed.stages.length === policy.installedStages.length &&
			new Set(installed.stages).size === policy.installedStages.length &&
			policy.installedStages.every((s) => installed.stages.includes(s)) &&
			installed.stages.at(-1) === "installed-owned-app-cleanup-confirmed",
		"Installed acceptance or final owned-app cleanup incomplete",
	);
	requireProof(
		e.artifacts.total_count === e.artifacts.artifacts.length &&
			e.artifacts.total_count <= 100,
		"Incomplete artifact pagination",
	);
	const artifact = (name: string, prefix = false) => {
		const matches = e.artifacts.artifacts.filter((a) =>
			prefix ? a.name.startsWith(name) : a.name === name,
		);
		requireProof(matches.length === 1, "Missing or ambiguous release artifact");
		const a = matches[0];
		requireProof(
			Number.isSafeInteger(a.id) &&
				a.id > 0 &&
				Number.isSafeInteger(a.size_in_bytes) &&
				!a.expired &&
				a.size_in_bytes > 0 &&
				/^sha256:[a-f0-9]{64}$/.test(a.digest) &&
				a.workflow_run.id === r.id &&
				a.workflow_run.head_sha === expectedHead,
			"Artifact expired or bound to another run/head",
		);
		return a;
	};
	const validation = artifact(`consolidated-validation-${r.id}`),
		ui = artifact(`installed-ui-evidence-${r.id}-${r.run_attempt}`),
		installer = artifact("cline-enhanced-windows-x64-unsigned-", true);
	requireProof(
		installer.name.endsWith(`-${r.id}-${r.run_attempt}`),
		"Installer attempt mismatch",
	);
	return {
		status: "passed" as const,
		policy: policy.version,
		pullNumber,
		expectedHead,
		testedCommit: tested,
		tree: e.headCommit.tree.sha,
		runId: r.id,
		runAttempt: r.run_attempt,
		checks: policy.requiredChecks.length,
		coreGates: policy.coreGates.length,
		engineGates: policy.engineGates.length,
		installedStages: policy.installedStages.length,
		artifacts: [validation, ui, installer].map((a) => ({
			id: a.id,
			name: a.name,
			digest: a.digest,
			bytes: a.size_in_bytes,
		})),
		limitations: [
			"Read-only CI evidence at check time; never merges, reruns CI or executes the installer.",
			"Unsigned installer metadata only; no signature, live-device, target compatibility or complete semantic correctness guarantee.",
			"Finite host-owned policy; changed recipes, extra checks, missing evidence or expired artifacts block verification.",
		],
	};
}
