import { mkdtemp, writeFile, readFile, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { afterEach, it, expect, vi } from "vitest";
import { candidateHash } from "./candidate-files";
import { exportEvidenceArchive } from "./evidence-archive";
import { isAnalysisWriteOperation } from "../analysis-commands";
const dirs: string[] = [];
afterEach(async () => {
	vi.unstubAllEnvs();
	await Promise.all(
		dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })),
	);
});
async function fixture() {
	const dir = await mkdtemp(join(tmpdir(), "owned-evidence-"));
	dirs.push(dir);
	const source = JSON.stringify({
		engine: "owned-static-fixture",
		engineVersion: "1",
		token: "fixture-private-token",
		detail: "Authorization: Bearer fixture-other-secret",
	});
	const file = join(dir, "receipt.json");
	await writeFile(file, source);
	const manifest = {
		schemaVersion: 1,
		title: "Owned evidence",
		entries: [
			{
				id: "receipt",
				kind: "receipt",
				format: "json",
				path: "receipt.json",
				sha256: candidateHash(source),
			},
		],
	};
	const raw = JSON.stringify(manifest),
		target = join(dir, "manifest.json"),
		output_file = join(dir, "owned.json.gz");
	await writeFile(target, raw);
	return {
		dir,
		file,
		source,
		manifest,
		input: {
			target,
			output_file,
			evidence_archive: { manifest_sha256: candidateHash(raw) },
		},
	};
}
it("publishes a portable gzip container with separate original and redacted hashes", async () => {
	const q = await fixture();
	const r = await exportEvidenceArchive(q.input);
	expect(r.published).toBe(true);
	const bytes = await readFile(q.input.output_file),
		doc = JSON.parse(gunzipSync(bytes).toString("utf8"));
	expect(r.outputSha256).toBe(candidateHash(bytes));
	expect(doc.protocol).toBe("cline-evidence-archive/v1");
	expect(doc.entries[0].sourceSha256).toBe(candidateHash(q.source));
	expect(doc.entries[0].exportedSha256).toBe(
		candidateHash(doc.entries[0].content),
	);
	expect(JSON.parse(doc.entries[0].content).token).toBe("[REDACTED]");
	expect(JSON.stringify(doc)).not.toContain("fixture-private-token");
	expect(JSON.stringify(doc)).not.toContain("fixture-other-secret");
	expect(JSON.stringify(doc)).not.toContain(q.dir);
	expect(await readFile(q.file, "utf8")).toBe(q.source);
	expect(doc.redaction.completeSecretRemovalGuaranteed).toBe(false);
	expect(isAnalysisWriteOperation("export_evidence_bundle")).toBe(true);
});
it("redacts known environment values inside text without executing it", async () => {
	const q = await fixture();
	vi.stubEnv("OWNED_API_KEY", "owned-env-secret-value");
	await writeFile(
		q.file,
		"owned-env-secret-value\nimport os; execute_target()",
	);
	const content = await readFile(q.file);
	q.manifest.entries[0] = {
		...q.manifest.entries[0],
		format: "text",
		sha256: candidateHash(content),
	};
	const raw = JSON.stringify(q.manifest);
	await writeFile(q.input.target, raw);
	q.input.evidence_archive.manifest_sha256 = candidateHash(raw);
	await exportEvidenceArchive(q.input);
	const doc = JSON.parse(
		gunzipSync(await readFile(q.input.output_file)).toString(),
	);
	expect(doc.entries[0].content).toContain("[REDACTED]");
	expect(doc.entries[0].content).toContain("execute_target()");
});
it("rejects changed manifest, changed entries and existing outputs", async () => {
	const q = await fixture();
	await expect(
		exportEvidenceArchive({
			...q.input,
			evidence_archive: { manifest_sha256: "0".repeat(64) },
		}),
	).rejects.toThrow("manifest hash");
	await writeFile(q.file, "changed");
	await expect(exportEvidenceArchive(q.input)).rejects.toThrow("entry hash");
	await writeFile(q.file, q.source);
	await exportEvidenceArchive(q.input);
	await expect(exportEvidenceArchive(q.input)).rejects.toThrow("exists");
});
it("rejects traversal, duplicate IDs, malformed JSON and cancellation", async () => {
	const q = await fixture();
	for (const path of ["../receipt.json", "/absolute.json", "sub\\file.json"]) {
		const raw = JSON.stringify({
			...q.manifest,
			entries: [{ ...q.manifest.entries[0], path }],
		});
		await writeFile(q.input.target, raw);
		await expect(
			exportEvidenceArchive({
				...q.input,
				evidence_archive: { manifest_sha256: candidateHash(raw) },
			}),
		).rejects.toThrow();
	}
	const raw = JSON.stringify({
		...q.manifest,
		entries: [...q.manifest.entries, ...q.manifest.entries],
	});
	await writeFile(q.input.target, raw);
	await expect(
		exportEvidenceArchive({
			...q.input,
			evidence_archive: { manifest_sha256: candidateHash(raw) },
		}),
	).rejects.toThrow("unique");
	const c = new AbortController();
	c.abort();
	await expect(exportEvidenceArchive(q.input, c.signal)).rejects.toThrow();
});
it.skipIf(process.platform === "win32")(
	"rejects symlinked evidence files",
	async () => {
		const q = await fixture();
		await rm(q.file);
		await writeFile(join(q.dir, "other.json"), q.source);
		await symlink(join(q.dir, "other.json"), q.file);
		await expect(exportEvidenceArchive(q.input)).rejects.toThrow(
			"symbolic link",
		);
	},
);
