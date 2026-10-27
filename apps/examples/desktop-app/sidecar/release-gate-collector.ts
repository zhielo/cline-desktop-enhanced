import { archiveMembers, archiveRead } from "./incident-artifacts";
import { RELEASE_GATE_POLICY as policy } from "./release-gate-policy";
import {
	sha256,
	verifyReleaseGateEvidence,
	type ReleaseGateEvidence,
} from "./release-gate-verifier";

const MIB = 1024 * 1024;
const repo = `${policy.owner}/${policy.repo}`;
const apiRoot = `https://api.github.com/repos/${repo}/`;
const check = (value: unknown, message: string) => {
	if (!value) throw new Error(message);
};
/** Fixed public read-only transport: no credentials, arbitrary endpoints or shell. */
export async function collectReleaseGate(
	pullNumber: number,
	expectedHead: string,
	options: {
		signal?: AbortSignal;
		fetch?: typeof fetch;
		assertCurrent?: () => void;
	} = {},
) {
	check(
		Number.isSafeInteger(pullNumber) &&
			pullNumber > 0 &&
			pullNumber <= 1_000_000 &&
			/^[a-f0-9]{40}$/.test(expectedHead),
		"Exact positive PR and 40-hex head required",
	);
	const signal = AbortSignal.any([
		AbortSignal.timeout(90_000),
		...(options.signal ? [options.signal] : []),
	]);
	const request = options.fetch ?? fetch;
	let requests = 0,
		totalBytes = 0;
	const evidenceSources: Array<{
		source: string;
		sha256: string;
		bytes: number;
	}> = [];
	const allowedHost = (u: URL) =>
		(u.protocol === "https:" &&
			!u.username &&
			!u.password &&
			(!u.port || u.port === "443") &&
			["api.github.com", "nightly.link", "github.com"].includes(u.hostname)) ||
		(u.protocol === "https:" &&
			!u.username &&
			!u.password &&
			!u.port &&
			/^productionresultssa\d+\.blob\.core\.windows\.net$/.test(u.hostname));
	const bytes = async (initial: string, limit: number) => {
		let current = new URL(initial);
		for (let redirects = 0; redirects <= 4; redirects++) {
			check(allowedHost(current), "Unapproved release-evidence transport host");
			check(++requests <= 30, "Release-evidence request budget exhausted");
			options.assertCurrent?.();
			signal.throwIfAborted();
			const response = await request(current, {
				signal,
				redirect: "manual",
				credentials: "omit",
				referrerPolicy: "no-referrer",
				headers: {
					"User-Agent": "Cline-ReadOnly-Release-Gate",
					Accept: "application/vnd.github+json",
				},
			});
			if ([301, 302, 303, 307, 308].includes(response.status)) {
				const location = response.headers.get("location");
				await response.body?.cancel();
				check(!!location, "Artifact redirect missing location");
				current = new URL(location!, current);
				continue;
			}
			if (!response.ok) {
				await response.body?.cancel();
				throw new Error(
					`Release evidence HTTP ${response.status}; no automatic retry or credential fallback`,
				);
			}
			const declared = Number(response.headers.get("content-length") ?? 0);
			check(
				!declared ||
					(Number.isSafeInteger(declared) &&
						declared >= 0 &&
						declared <= limit),
				"Evidence response exceeds byte budget",
			);
			const reader = response.body?.getReader();
			check(reader, "Evidence response has no body");
			const parts: Buffer[] = [];
			let size = 0;
			try {
				for (;;) {
					signal.throwIfAborted();
					const item = await reader!.read();
					if (item.done) break;
					size += item.value.byteLength;
					totalBytes += item.value.byteLength;
					check(
						size <= limit && totalBytes <= 18 * MIB,
						"Evidence transfer byte budget exhausted",
					);
					parts.push(Buffer.from(item.value));
				}
			} finally {
				await reader!.cancel().catch(() => {});
			}
			const result = Buffer.concat(parts);
			evidenceSources.push({
				source: initial,
				sha256: sha256(result),
				bytes: result.length,
			});
			return result;
		}
		throw new Error("Artifact redirect budget exhausted");
	};
	const json = async (path: string) =>
		JSON.parse((await bytes(apiRoot + path, 2 * MIB)).toString("utf8"));
	const pull = await json(`pulls/${pullNumber}`);
	check(
		pull.head?.sha === expectedHead &&
			pull.head?.repo?.full_name === repo &&
			pull.base?.repo?.full_name === repo &&
			/^[a-f0-9]{40}$/.test(pull.base?.sha),
		"PR exact head or repository changed",
	);
	const checks = await json(`commits/${expectedHead}/check-runs?per_page=100`);
	const runs = await json(
		`actions/runs?head_sha=${expectedHead}&event=pull_request&per_page=100`,
	);
	check(
		runs.total_count === runs.workflow_runs?.length && runs.total_count <= 100,
		"Incomplete workflow pagination",
	);
	const matches = runs.workflow_runs.filter(
		(r: any) =>
			r.path === ".github/workflows/build-custom-windows-installer.yml",
	);
	check(
		matches.length === 1,
		"Missing or ambiguous exact-head Windows workflow",
	);
	const run = matches[0];
	check(
		run.status === "completed" &&
			run.conclusion === "success" &&
			Number.isSafeInteger(run.id),
		"Windows workflow not successfully completed",
	);
	const jobs = await json(
		`actions/runs/${run.id}/attempts/${run.run_attempt}/jobs?per_page=100`,
	);
	const artifacts = await json(`actions/runs/${run.id}/artifacts?per_page=100`);
	check(
		artifacts.total_count === artifacts.artifacts?.length &&
			artifacts.total_count <= 100,
		"Incomplete artifact pagination",
	);
	const loadArtifact = async (name: string) => {
		const found = artifacts.artifacts.filter((a: any) => a.name === name);
		check(found.length === 1, "Missing or ambiguous evidence artifact");
		const a = found[0];
		check(
			Number.isSafeInteger(a.id) &&
				a.id > 0 &&
				!a.expired &&
				a.size_in_bytes > 0 &&
				a.size_in_bytes <= 4 * MIB &&
				/^sha256:[a-f0-9]{64}$/.test(a.digest) &&
				a.workflow_run?.id === run.id &&
				a.workflow_run?.head_sha === expectedHead,
			"Artifact identity, expiry, digest or size invalid",
		);
		const zip = await bytes(
			`https://nightly.link/${repo}/actions/artifacts/${a.id}.zip`,
			4 * MIB,
		);
		check(
			zip.length === a.size_in_bytes && `sha256:${sha256(zip)}` === a.digest,
			"Artifact bytes do not match authenticated GitHub SHA256 digest",
		);
		const members = archiveMembers(zip);
		check(
			members.length <= 256 &&
				members.every((m) => m.safe) &&
				members.reduce((n, m) => n + m.bytes, 0) <= 16 * MIB,
			"Unsafe or oversized artifact ZIP directory",
		);
		const summaries = members.filter(
			(m) => m.name === "summary.json" || m.name.endsWith("/summary.json"),
		);
		check(
			summaries.length > 0 && summaries.length <= 4,
			"Missing or ambiguous summary receipts",
		);
		return summaries.map((m) =>
			JSON.parse(archiveRead(zip, m.name, 512 * 1024).bytes.toString("utf8")),
		);
	};
	const receipts = await loadArtifact(`consolidated-validation-${run.id}`);
	const coreMatches = receipts.filter(
			(r) => r.engineProfile === "not-requested",
		),
		engineMatches = receipts.filter(
			(r) => r.engineProfile === "windows-portable",
		);
	check(
		coreMatches.length === 1 &&
			engineMatches.length === 1 &&
			receipts.length === 2,
		"Expected exactly core and portable-engine receipts",
	);
	const core = coreMatches[0],
		engines = engineMatches[0];
	const installedReceipts = await loadArtifact(
		`installed-ui-evidence-${run.id}-${run.run_attempt}`,
	);
	check(
		installedReceipts.length === 1,
		"Ambiguous installed acceptance receipt",
	);
	const tested = core.sourceCommit;
	check(
		typeof tested === "string" && /^[a-f0-9]{40}$/.test(tested),
		"Invalid tested commit identity",
	);
	const headCommit = await json(`git/commits/${expectedHead}`),
		testedCommit = await json(`git/commits/${tested}`);
	const policyFileBytes: Record<string, Buffer> = {};
	for (const path of Object.keys(policy.policyFiles)) {
		const f = await json(`contents/${path}?ref=${tested}`);
		check(
			f.type === "file" &&
				f.encoding === "base64" &&
				typeof f.content === "string" &&
				f.size <= 512 * 1024,
			"Unsupported verification recipe file response",
		);
		policyFileBytes[path] = Buffer.from(f.content, "base64");
		check(
			policyFileBytes[path].length === f.size,
			"Recipe file length mismatch",
		);
	}
	const result = verifyReleaseGateEvidence(pullNumber, expectedHead, {
		pull,
		checks,
		workflowRuns: runs,
		run,
		jobs,
		artifacts,
		headCommit,
		testedCommit,
		core,
		engines,
		installed: installedReceipts[0],
		policyFileBytes,
	} as ReleaseGateEvidence);
	// Refresh authorities last; do not certify a stale PR head or an earlier run attempt.
	const finalPull = await json(`pulls/${pullNumber}`),
		finalRun = await json(`actions/runs/${run.id}`),
		finalChecks = await json(`commits/${expectedHead}/check-runs?per_page=100`);
	check(
		finalPull.head?.sha === expectedHead &&
			finalPull.base?.sha === pull.base.sha &&
			finalPull.merge_commit_sha === pull.merge_commit_sha &&
			finalRun.run_attempt === run.run_attempt &&
			finalRun.status === "completed" &&
			finalRun.conclusion === "success",
		"PR head, base or workflow attempt changed during verification",
	);
	verifyReleaseGateEvidence(pullNumber, expectedHead, {
		pull: finalPull,
		checks: finalChecks,
		workflowRuns: runs,
		run: finalRun,
		jobs,
		artifacts,
		headCommit,
		testedCommit,
		core,
		engines,
		installed: installedReceipts[0],
		policyFileBytes,
	} as ReleaseGateEvidence);
	options.assertCurrent?.();
	signal.throwIfAborted();
	return {
		...result,
		checkedAt: new Date().toISOString(),
		requests,
		totalBytes,
		evidenceSources,
	};
}
