import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { it, expect, afterEach } from "vitest";
import { candidateHash } from "./candidate-files";
import { resolvedDependencyEvidence } from "./dependency-evidence";
const dirs: string[] = [];
afterEach(async () => {
	await Promise.all(
		dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })),
	);
});
async function files(lock: unknown, snapshot?: unknown) {
	const dir = await mkdtemp(join(tmpdir(), "owned-dependency-"));
	dirs.push(dir);
	const lockfile = join(dir, "package-lock.json");
	await writeFile(lockfile, JSON.stringify(lock));
	if (!snapshot)
		return { lockfile, lockfile_sha256: candidateHash(JSON.stringify(lock)) };
	const raw = JSON.stringify(snapshot),
		path = join(dir, "advisory.json");
	await writeFile(path, raw);
	return {
		lockfile,
		lockfile_sha256: candidateHash(JSON.stringify(lock)),
		advisory_snapshot: { path, sha256: candidateHash(raw) },
	};
}
const lock = {
	lockfileVersion: 3,
	packages: {
		"": { name: "owned" },
		"node_modules/@owned/lib": {
			version: "1.2.3",
			resolved: "https://secret-user:password@registry.invalid/lib",
		},
		"node_modules/parent/node_modules/@owned/lib": { version: "2.0.0" },
		"node_modules/workspace": { link: true },
	},
};
const advisory = {
	schemaVersion: 1,
	source: "OSV",
	retrievedAt: "2026-10-17T00:00:00Z",
	advisories: [
		{
			id: "OWNED-1",
			modified: "2026-10-16T00:00:00Z",
			affected: [
				{
					package: { ecosystem: "npm", name: "@owned/lib" },
					versions: ["1.2.3"],
					ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }],
				},
			],
		},
	],
};
it("retains transitive locations, exact versions and unresolved links without leaking URLs", async () => {
	const r = await resolvedDependencyEvidence(await files(lock));
	expect(r.resolved.map((v) => v.version)).toEqual(["1.2.3", "2.0.0"]);
	expect(r.unresolved).toHaveLength(1);
	expect(JSON.stringify(r)).not.toContain("password");
	expect(r.riskVerdict).toBe("unknown");
});
it("checks exact affected versions and leaves ranges unresolved", async () => {
	const r = await resolvedDependencyEvidence(await files(lock, advisory));
	expect(r.advisoryMatches).toHaveLength(1);
	expect(r.advisoryMatches[0].version).toBe("1.2.3");
	expect(r.unevaluatedRanges).toHaveLength(1);
	expect(r.status).toBe("partial");
	expect(r.advisorySnapshot?.authority).toContain("not publisher identity");
});
it("rejects changed snapshot bytes", async () => {
	const q = await files(lock, advisory);
	await expect(
		resolvedDependencyEvidence({
			...q,
			advisory_snapshot: { ...q.advisory_snapshot, sha256: "0".repeat(64) },
		}),
	).rejects.toThrow("hash mismatch");
});
it("does not match withdrawn or non-npm evidence", async () => {
	const snapshot = structuredClone(advisory);
	snapshot.advisories[0].affected[0].package.ecosystem = "PyPI";
	expect(
		(await resolvedDependencyEvidence(await files(lock, snapshot)))
			.advisoryMatches,
	).toEqual([]);
	const withdrawn = {
		...advisory,
		advisories: advisory.advisories.map((a) => ({
			...a,
			withdrawn: "2026-10-17T00:00:00Z",
		})),
	};
	expect(
		(await resolvedDependencyEvidence(await files(lock, withdrawn)))
			.advisoryMatches,
	).toEqual([]);
});
it("rejects v1 locks, malformed paths and cancellation", async () => {
	await expect(
		resolvedDependencyEvidence(
			await files({ lockfileVersion: 1, packages: {} }),
		),
	).rejects.toThrow();
	await expect(
		resolvedDependencyEvidence(
			await files({
				lockfileVersion: 2,
				packages: { "../bad": { version: "1" } },
			}),
		),
	).rejects.toThrow("path");
	const c = new AbortController();
	c.abort();
	await expect(
		resolvedDependencyEvidence(await files(lock), c.signal),
	).rejects.toThrow();
});
it("rejects duplicate advisory IDs", async () => {
	await expect(
		resolvedDependencyEvidence(
			await files(lock, {
				...advisory,
				advisories: [advisory.advisories[0], advisory.advisories[0]],
			}),
		),
	).rejects.toThrow("Duplicate");
});
