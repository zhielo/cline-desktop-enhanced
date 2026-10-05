import { createHash } from "node:crypto";
import {
	chmod,
	mkdir,
	mkdtemp,
	realpath,
	rm,
	symlink,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	managedRizinStatus,
	REVIEWED_RIZIN_PACKS,
	resolveRizinTool,
	safePackPath,
} from "./managed-rizin-packs";

const roots: string[] = [];
const hash = (s: string) => createHash("sha256").update(s).digest("hex");
async function fixture() {
	const root = await realpath(
		await mkdtemp(join(tmpdir(), "owned-managed-unit-")),
	);
	roots.push(root);
	const id =
		process.platform === "win32"
			? "rizin-0.9.1-windows-x64"
			: "rizin-0.9.1-linux-x64";
	const spec = REVIEWED_RIZIN_PACKS[id],
		revision = join(root, "revisions", id),
		payload = join(revision, "payload");
	const entry = join(payload, spec.entry);
	await mkdir(join(entry, ".."), { recursive: true });
	await writeFile(entry, "owned");
	const receipt = {
		schemaVersion: 1,
		packId: id,
		archiveSha256: spec.sha256 as string,
		entry: spec.entry,
		sourceUrl: "https://github.com/rizinorg/rizin",
		health: { version: "0.9.1", ownedStaticBytes: true, targetExecuted: false },
		files: [{ path: spec.entry, bytes: 5, sha256: hash("owned") }],
		licenseNotice: "Synthetic unit fixture; not vendor or execution evidence.",
	};
	async function save() {
		const text = JSON.stringify(receipt);
		await writeFile(join(revision, "receipt.json"), text);
		await writeFile(
			join(root, "active.json"),
			JSON.stringify({
				schemaVersion: 1,
				active: { packId: id, receiptSha256: hash(text) },
				history: [],
			}),
		);
	}
	await save();
	return { root, id, revision, payload, entry, receipt, save };
}
afterEach(async () => {
	vi.unstubAllEnvs();
	for (const root of roots.splice(0))
		await rm(root, { recursive: true, force: true });
});
describe("managed pack read-only integrity boundary", () => {
	it("rejects traversal, devices, aliases and nonportable paths", () => {
		for (const name of [
			"/tmp/out",
			"../out",
			"a/../b",
			"a//b",
			"a\\b",
			"C:/out",
			"a/CON.txt",
			"a/file.",
			"a/file ",
		])
			expect(() => safePackPath(name)).toThrow();
		expect(safePackPath("bin/rizin")).toBe("bin/rizin");
	});
	it("reports an unconfigured root without writing or execution", async () => {
		expect((await managedRizinStatus(undefined)).status).toBe("unconfigured");
	});
	it("verifies synthetic metadata without executing its contents", async () => {
		const f = await fixture();
		const s = await managedRizinStatus(f.root);
		expect(s.status).toBe("verified");
		expect(s.entry).toBe(f.entry);
		expect(s.filesVerified).toBe(1);
		expect(s.healthIsImportTimeOnly).toBe(true);
	});
	it("retains inactive rollback state", async () => {
		const f = await fixture();
		await writeFile(
			join(f.root, "active.json"),
			JSON.stringify({ schemaVersion: 1, active: null, history: [] }),
		);
		expect((await managedRizinStatus(f.root)).status).toBe("inactive");
	});
	it("detects receipt edits", async () => {
		const f = await fixture();
		await writeFile(join(f.revision, "receipt.json"), "{}");
		await expect(managedRizinStatus(f.root)).rejects.toThrow("receipt hash");
	});
	it("detects installed file edits", async () => {
		const f = await fixture();
		await writeFile(f.entry, "other");
		await expect(managedRizinStatus(f.root)).rejects.toThrow("file integrity");
	});
	it("detects untracked installed files", async () => {
		const f = await fixture();
		await writeFile(join(f.payload, "unexpected"), "owned");
		await expect(managedRizinStatus(f.root)).rejects.toThrow("inventory");
	});
	it("rejects unknown active pack IDs", async () => {
		const f = await fixture();
		await writeFile(
			join(f.root, "active.json"),
			JSON.stringify({
				schemaVersion: 1,
				active: { packId: "caller", receiptSha256: "a".repeat(64) },
				history: [],
			}),
		);
		await expect(managedRizinStatus(f.root)).rejects.toThrow();
	});
	it("rejects receipt identity substitution", async () => {
		const f = await fixture();
		f.receipt.archiveSha256 = "b".repeat(64);
		await f.save();
		await expect(managedRizinStatus(f.root)).rejects.toThrow("identity");
	});
	it("rejects empty engine inventory", async () => {
		const f = await fixture();
		f.receipt.files = [];
		await f.save();
		await expect(managedRizinStatus(f.root)).rejects.toThrow();
	});
	it("honors cancellation", async () => {
		const f = await fixture();
		const c = new AbortController();
		c.abort();
		await expect(managedRizinStatus(f.root, c.signal)).rejects.toThrow(
			"cancelled",
		);
	});
	it("keeps explicit external paths separate from managed inventory", async () => {
		vi.stubEnv("CLINE_RE_RIZIN", "owned-external-path");
		vi.stubEnv("CLINE_RE_TOOLPACK_ROOT", "invalid-root");
		expect(await resolveRizinTool()).toBe("owned-external-path");
	});
	it("requires private root permissions", async () => {
		const f = await fixture();
		if (process.platform === "win32") return;
		await chmod(f.root, 0o777);
		await expect(managedRizinStatus(f.root)).rejects.toThrow("Private");
	});
	it("does not follow payload symlinks", async () => {
		const f = await fixture();
		if (process.platform === "win32") return;
		await symlink(f.entry, join(f.payload, "link"));
		await expect(managedRizinStatus(f.root)).rejects.toThrow("links");
	});
});
