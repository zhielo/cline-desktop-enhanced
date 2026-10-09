import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { scanSmali } from "./smali-search";

let root: string;
const base = () => ({
	target: root,
	queries: ["if-lez", "return"],
	contextLines: 1,
	maxResults: 200,
	owner: "owned-test",
});
beforeEach(async () => {
	root = await fs.mkdtemp(join(tmpdir(), "cline-smali-scan-"));
	await fs.writeFile(
		join(root, "Owned.smali"),
		".method public gate()Z\n if-lez v0, :deny\n return v0\n.end method\n",
	);
});
afterEach(async () => {
	vi.useRealTimers();
	await fs.rm(root, { recursive: true, force: true });
});
describe("bounded single-pass Smali scan", () => {
	it("reads each candidate once for multiple literal queries and reports real bytes/methods", async () => {
		const progress: string[] = [];
		const result = await scanSmali({
			...base(),
			onProgress: (p) => progress.push(p),
		});
		expect(result.matches).toHaveLength(2);
		expect(result.scannedFiles).toBe(1);
		expect(result.bytesRead).toBe(
			(await fs.stat(join(root, "Owned.smali"))).size,
		);
		expect(result.matches[0]?.method).toBe("public gate()Z");
		expect(result.coverage).toBe("completed");
		expect(progress[0]).toContain("scanned_files=0");
		expect(progress.at(-1)).toContain("scanned_files=1");
	});
	it("prunes known and explicit directories without inferring absence outside scope", async () => {
		for (const d of ["node_modules", ".git", "skip-me"]) {
			await fs.mkdir(join(root, d));
			await fs.writeFile(join(root, d, "Hidden.smali"), "return");
		}
		const r = await scanSmali({ ...base(), excludeDirs: ["skip-me"] });
		expect(r.scannedFiles).toBe(1);
		expect(r.excludedDirectories).toBe(3);
	});
	it("returns honest partial coverage at byte and result ceilings", async () => {
		expect(await scanSmali({ ...base(), maxBytes: 1 })).toMatchObject({
			coverage: "partial",
			stopReason: "byte_limit",
			scannedFiles: 0,
			bytesRead: 0,
		});
		expect(await scanSmali({ ...base(), maxResults: 1 })).toMatchObject({
			coverage: "partial",
			stopReason: "result_limit",
			scannedFiles: 1,
		});
	});
	it("rejects duplicate active requests and releases admission after completion", async () => {
		let competing: Promise<unknown> | undefined;
		const first = await scanSmali({
			...base(),
			onProgress: () => {
				if (!competing) competing = scanSmali(base()).catch((e) => e);
			},
		});
		expect(first.scannedFiles).toBe(1);
		expect(String(await competing)).toContain("already running");
		expect((await scanSmali(base())).scannedFiles).toBe(1);
	});
	it("honors explicit cancellation without claiming completion", async () => {
		const c = new AbortController();
		await expect(
			scanSmali({
				...base(),
				signal: c.signal,
				onProgress: () => c.abort(new Error("owned cancel")),
			}),
		).rejects.toThrow("owned cancel");
		expect((await scanSmali(base())).coverage).toBe("completed");
	});
	it("enforces a finite deadline instead of automatically replaying", async () => {
		vi.useFakeTimers();
		await expect(
			scanSmali({
				...base(),
				timeoutMs: 10,
				onProgress: () => vi.advanceTimersByTime(11),
			}),
		).rejects.toThrow("lifetime deadline");
	});
	it("caps retained result text for long lines", async () => {
		await fs.writeFile(
			join(root, "Long.smali"),
			("return " + "x".repeat(4096) + "\n").repeat(200),
		);
		const r = await scanSmali({ ...base(), maxResults: 5000 });
		expect(r.stopReason).toBe("output_limit");
		expect(JSON.stringify(r.matches).length).toBeLessThan(205000);
	});
	it("rejects invalid exclusion paths and budgets", async () => {
		await expect(
			scanSmali({ ...base(), excludeDirs: ["../escape"] }),
		).rejects.toThrow("basenames");
		await expect(scanSmali({ ...base(), maxBytes: 0 })).rejects.toThrow(
			"budget",
		);
	});
});
