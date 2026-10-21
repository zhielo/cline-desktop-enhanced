/** Regression for the exact provenance-line exception; never prints fixture tokens. */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
	mkdtempSync,
	mkdirSync,
	writeFileSync,
	rmSync,
	readFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { resolve, join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const root = mkdtempSync(join(tmpdir(), "cline-secret-scan-"));
const revision = JSON.parse(
	readFileSync(join(repo, "docs/rea-migration/capabilities.json"), "utf8"),
).revision;
assert.match(revision, /^[a-f0-9]{40}$/);
// Deliberately synthetic token material, assembled only in private temporary fixtures.
const synthetic = "sgp_" + "0123456789abcdef".repeat(2) + "01234567";
try {
	for (const path of [
		"docs/rea-migration/capabilities.json",
		"docs/rea-migration/contract-dependencies.json",
	]) {
		const target = join(root, path);
		mkdirSync(dirname(target), { recursive: true });
		for (const [label, contents, expected] of [
			["pinned revision", `  "revision": "${revision}",\nsourcegraph\n`, 0],
			[
				"token beside revision",
				`  "revision": "${revision}",\n"sourcegraph": "${synthetic}"\n`,
				1,
			],
			[
				"same hash outside revision",
				`  "other": "${revision}",\nsourcegraph\n`,
				1,
			],
			[
				"different revision",
				`  "revision": "${revision.split("").reverse().join("")}",\nsourcegraph\n`,
				1,
			],
		]) {
			writeFileSync(target, contents);
			const report = join(root, "report.json");
			const r = spawnSync(
				process.env.GITLEAKS_BIN || "gitleaks",
				[
					"dir",
					".",
					"--redact",
					"--no-banner",
					"--no-color",
					"--config",
					join(repo, ".gitleaks.toml"),
					"--report-format",
					"json",
					"--report-path",
					report,
				],
				{ cwd: root, encoding: "utf8", timeout: 30_000 },
			);
			assert.equal(r.error, undefined, "Scanner must be available");
			assert.equal(r.status, expected, `${path}: ${label}`);
			if (expected)
				assert.ok(
					JSON.parse(readFileSync(report, "utf8")).some(
						(x) => x.RuleID === "sourcegraph-access-token",
					),
					label,
				);
			rmSync(report, { force: true });
		}
		rmSync(target);
	}
	writeFileSync(
		join(root, "other.json"),
		`  "revision": "${revision}",\nsourcegraph\n`,
	);
	const r = spawnSync(
		process.env.GITLEAKS_BIN || "gitleaks",
		[
			"dir",
			".",
			"--redact",
			"--no-banner",
			"--no-color",
			"--config",
			join(repo, ".gitleaks.toml"),
		],
		{ cwd: root, encoding: "utf8", timeout: 30_000 },
	);
	assert.equal(r.status, 1, "The exception must not cover another file");
	console.log(
		"Secret scan scope regression: 9 cases passed; real token patterns remain blocking.",
	);
} finally {
	rmSync(root, { recursive: true, force: true });
}
