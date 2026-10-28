/** Regression for the exact provenance-line exception; never prints fixture tokens. */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
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
	// The historical documentation exception must never suppress future findings.
	const docPath = "workers/managed-emulation/image/README.md";
	const doc = join(root, docPath);
	mkdirSync(dirname(doc), { recursive: true });
	rmSync(join(root, "other.json"));
	const historicalProse = "escaping links,\n  unresolved/cyclic hardlinks";
	const currentDoc = readFileSync(join(repo, docPath), "utf8");
	const generic =
		'api_key = "' +
		createHash("sha256")
			.update("owned scanner negative-control fixture")
			.digest("hex") +
		'"';
	const ignoredHistory = readFileSync(join(repo, ".gitleaksignore"), "utf8");
	const proseFingerprint =
		"13ab96fa588bb8c7ee1f34b850f6a2b6ee9db166:" +
		docPath +
		":generic-api-key:18";
	assert.ok(ignoredHistory.split(/\r?\n/).includes(proseFingerprint));
	for (const [label, contents, expected] of [
		["current image documentation", currentDoc, 0],
		["historical prose in new content", historicalProse, 1],
		["real token beside current prose", currentDoc + "\n" + generic, 1],
		["real token replacing historical prose", generic, 1],
	]) {
		writeFileSync(doc, contents);
		const report = join(root, "report.json");
		const result = spawnSync(
			process.env.GITLEAKS_BIN || "gitleaks",
			[
				"dir",
				".",
				"--redact",
				"--no-banner",
				"--no-color",
				"--config",
				join(repo, ".gitleaks.toml"),
				"--gitleaks-ignore-path",
				join(repo, ".gitleaksignore"),
				"--report-format",
				"json",
				"--report-path",
				report,
			],
			{ cwd: root, encoding: "utf8", timeout: 30_000 },
		);
		assert.equal(result.error, undefined, "Scanner must be available");
		assert.equal(result.status, expected, label);
		if (expected)
			assert.ok(
				JSON.parse(readFileSync(report, "utf8")).some(
					(finding) => finding.RuleID === "generic-api-key",
				),
				label,
			);
		rmSync(report, { force: true });
	}
	console.log(
		"Secret scan scope regression: 13 cases passed; real token patterns remain blocking.",
	);
} finally {
	rmSync(root, { recursive: true, force: true });
}
