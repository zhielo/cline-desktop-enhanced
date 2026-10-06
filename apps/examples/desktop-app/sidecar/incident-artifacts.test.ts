import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { apk, zip } from "./__fixtures__/incident";
import {
	apkPackage,
	archiveMembers,
	archiveRead,
	inspectArtifactEvidence,
	ownedFile,
	previewArchiveMember,
} from "./incident-artifacts";

const roots: string[] = [];
async function root() {
	const r = await mkdtemp(join(tmpdir(), "incident-archive-"));
	roots.push(r);
	return r;
}
afterEach(async () => {
	await Promise.all(
		roots.splice(0).map((r) => rm(r, { recursive: true, force: true })),
	);
});
describe("incident archive evidence", () => {
	it("reads a binary Android manifest package", () => {
		expect(apkPackage(apk())).toBe("com.example.app");
		expect(() =>
			apkPackage(
				zip([
					{
						name: "AndroidManifest.xml",
						bytes: Buffer.from("<manifest package='fake' />"),
					},
				]),
			),
		).toThrow("Binary Android");
	});
	it("blocks traversal, duplicate aliases, symlinks, encryption and CRC tampering", () => {
		for (const entries of [
			[{ name: "../secret", bytes: Buffer.from("secret") }],
			[
				{ name: "a/b.txt", bytes: Buffer.from("a") },
				{ name: "a\\b.txt", bytes: Buffer.from("b") },
			],
			[{ name: "encrypted.txt", bytes: Buffer.from("x"), flags: 1 }],
		]) {
			const b = zip(entries);
			expect(archiveMembers(b).every((r) => !r.safe)).toBe(true);
			expect(() => archiveRead(b, entries[0].name)).toThrow();
		}
		const b = zip([{ name: "x.txt", bytes: Buffer.from("safe") }]);
		b[35] ^= 1;
		expect(() => archiveRead(b, "x.txt")).toThrow("integrity");
	});
	it("hash binds explicit archive previews and never extracts a binary member", async () => {
		const r = await root();
		await writeFile(
			join(r, "test.zip"),
			zip([
				{ name: "x.md", bytes: Buffer.from("# hello") },
				{ name: "x.so", bytes: Buffer.from("binary") },
			]),
		);
		const info = await inspectArtifactEvidence(r, "test.zip");
		expect(info.classification).toBe("archive-container");
		if (!info.sha256) throw new Error("Fixture archive hash missing");
		expect(
			(await previewArchiveMember(r, "test.zip", "x.md", info.sha256)).content,
		).toBe("# hello");
		expect(
			(await previewArchiveMember(r, "test.zip", "x.so", info.sha256)).content,
		).toBeUndefined();
		await writeFile(join(r, "test.zip"), apk());
		await expect(
			previewArchiveMember(r, "test.zip", "x.md", info.sha256),
		).rejects.toThrow("changed");
	});
	it("blocks outside-workspace files and reports malformed archives honestly", async () => {
		const r = await root(),
			other = await root();
		await writeFile(join(other, "x"), "x");
		await expect(ownedFile(r, join(other, "x"))).rejects.toThrow("workspace");
		if (process.platform !== "win32") {
			await symlink(join(other, "x"), join(r, "link"));
			await expect(ownedFile(r, "link")).rejects.toThrow("workspace");
		}
		await writeFile(join(r, "bad.apk"), "not a zip");
		expect((await inspectArtifactEvidence(r, "bad.apk")).classification).toBe(
			"blocked-archive",
		);
	});
	it("rejects byte budgets and forged local headers", () => {
		const b = zip([{ name: "x.txt", bytes: Buffer.alloc(20) }]);
		expect(() => archiveRead(b, "x.txt", 10)).toThrow("budget");
		b.writeUInt16LE(8, 8);
		expect(() => archiveRead(b, "x.txt")).toThrow("header");
	});
});

it("distinguishes missing paths and remote references from standalone files", async () => {
	const r = await root();
	expect(
		(await inspectArtifactEvidence(r, "xl/worksheets/sheet1.xml"))
			.classification,
	).toBe("missing-file");
	expect(
		(await inspectArtifactEvidence(r, "content://provider/file"))
			.classification,
	).toBe("remote-reference");
});
