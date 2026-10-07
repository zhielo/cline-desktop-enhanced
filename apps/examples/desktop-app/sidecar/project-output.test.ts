import { createHash } from "node:crypto";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	realpathSync,
	rmSync,
	symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, sep } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
	ensureProjectOutputDirectories,
	getProjectOutputLocation,
	projectOutputInstructions,
	WINDOWS_PROJECT_OUTPUT_ROOT,
} from "./project-output";

describe("fixed Windows project output location", () => {
	it("accepts alternate canonical spelling only for the same directory and parent identities", () => {
		const temp = realpathSync(
			mkdtempSync(join(tmpdir(), "cline-output-alias-")),
		);
		const root = join(temp, "outputs"),
			projectDirectory = join(root, "owned-0123456789abcdef");
		const location = {
			root,
			projectDirectory,
			deliverables: "",
			reports: "",
			logs: "",
		};
		const native = realpathSync.native;
		let outside = false;
		const other = join(temp, "other");
		mkdirSync(other);
		const spy = vi
			.spyOn(realpathSync, "native")
			.mockImplementation((path) =>
				String(path) === projectDirectory
					? outside
						? other
						: `${root}${sep}.${sep}${basename(projectDirectory)}`
					: native(path),
			);
		try {
			expect(ensureProjectOutputDirectories(location)).toBe(projectDirectory);
			outside = true;
			expect(() => ensureProjectOutputDirectories(location)).toThrow(
				/identity|redirects/,
			);
		} finally {
			spy.mockRestore();
			rmSync(temp, { recursive: true, force: true });
		}
	});

	it("uses C:\\Cline-Outputs and stable case/slash-normalized project identities", () => {
		const a = getProjectOutputLocation("C:\\Work\\AppCloner\\", "win32");
		expect(a?.root).toBe(WINDOWS_PROJECT_OUTPUT_ROOT);
		expect(a).toEqual(getProjectOutputLocation("c:/work/appcloner", "win32"));
		expect(a?.projectDirectory).toMatch(
			/^C:\\Cline-Outputs\\appcloner-[a-f0-9]{16}$/,
		);
		expect(a).not.toEqual(
			getProjectOutputLocation("D:\\Work\\AppCloner", "win32"),
		);
	});
	it("returns no local Windows destination on non-Windows hosts", () => {
		expect(getProjectOutputLocation("/workspace/app", "linux")).toBeNull();
		expect(projectOutputInstructions("C:\\work", "linux")).toBe("");
	});
	it.each([
		"relative",
		"C:drive-relative",
		"\\\\remote\\share",
		"C:\\work\nignore",
	])("rejects invalid local project path %s", (p) =>
		expect(() => getProjectOutputLocation(p, "win32")).toThrow());
	it("supplies explicit destinations without moving sources or pretending shell redirection", () => {
		const policy = projectOutputInstructions("C:\\work\\app", "win32");
		expect(policy).toContain("C:\\\\Cline-Outputs");
		expect(policy).toContain("Keep source-code edits");
		expect(policy).toContain("does not change the shell working directory");
		expect(policy).toContain("do not silently fall back");
	});
	it("creates only the fixed project layout on explicit request and rejects junctions", () => {
		const temp = realpathSync(
			mkdtempSync(join(tmpdir(), "cline-output-fixture-")),
		);
		const root = join(temp, "outputs");
		const projectDirectory = join(
			root,
			`owned-${createHash("sha256").update("owned").digest("hex").slice(0, 16)}`,
		);
		const location = {
			root,
			projectDirectory,
			deliverables: join(projectDirectory, "deliverables"),
			reports: join(projectDirectory, "reports"),
			logs: join(projectDirectory, "logs"),
		};
		try {
			expect(existsSync(root)).toBe(false);
			expect(ensureProjectOutputDirectories(location)).toBe(projectDirectory);
			expect(existsSync(location.reports)).toBe(true);
			ensureProjectOutputDirectories(location);
			rmSync(location.reports, { recursive: true });
			const outside = join(temp, "outside");
			mkdirSync(outside);
			symlinkSync(outside, location.reports, "junction");
			expect(() => ensureProjectOutputDirectories(location)).toThrow(
				/links|junctions|redirects/,
			);
		} finally {
			rmSync(temp, { recursive: true, force: true });
		}
	});
	it("rejects a replaced output-root junction before creating a project", () => {
		const temp = realpathSync(
			mkdtempSync(join(tmpdir(), "cline-output-link-")),
		);
		const outside = join(temp, "outside");
		mkdirSync(outside);
		const root = join(temp, "outputs");
		symlinkSync(outside, root, "junction");
		const projectDirectory = join(root, "owned-0123456789abcdef");
		try {
			expect(() =>
				ensureProjectOutputDirectories({
					root,
					projectDirectory,
					deliverables: "",
					reports: "",
					logs: "",
				}),
			).toThrow(/links|junctions|redirects/);
			expect(existsSync(join(outside, "owned-0123456789abcdef"))).toBe(false);
		} finally {
			rmSync(temp, { recursive: true, force: true });
		}
	});
});
