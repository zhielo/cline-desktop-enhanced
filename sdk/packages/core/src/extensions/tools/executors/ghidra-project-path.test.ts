import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	ghidraAnalysisCacheRoot,
	validateGhidraProjectDirectory,
	validateGhidraProjectPath,
} from "./ghidra-project-path";

const roots: string[] = [];
afterEach(async () => {
	await Promise.all(
		roots.splice(0).map((p) => fs.rm(p, { recursive: true, force: true })),
	);
});

describe("Ghidra project paths", () => {
	it("keeps the default Ghidra cache out of .cline without changing custom roots", () => {
		expect(ghidraAnalysisCacheRoot("/users/owned", undefined)).toBe(
			path.resolve("/users/owned/cline-analysis-cache/reverse-engineering"),
		);
		expect(ghidraAnalysisCacheRoot("/users/owned", "/custom/cache")).toBe(
			path.resolve("/custom/cache"),
		);
	});

	it.each([
		"/users/owned/.cline/reverse-engineering/hash/ghidra",
		"/users/.hidden/cache",
		"C:\\Users\\owned\\.cline\\reverse-engineering\\hash\\ghidra",
		"\\\\server\\share\\.cache\\ghidra",
		"/tmp/.cache/../project",
	])("rejects a dot-prefixed component: %s", (directory) => {
		expect(() => validateGhidraProjectPath(directory)).toThrow("dot-prefixed");
	});

	it.each([
		"/users/owned/cline-analysis-cache/hash/ghidra",
		"/users/owned/cache.v2/a project",
		"C:\\Users\\owned\\AppData\\Local\\Cline\\ghidra",
		"\\\\server\\share\\ghidra",
	])("accepts ordinary components and internal dots: %s", (directory) => {
		expect(() => validateGhidraProjectPath(directory)).not.toThrow();
	});

	it("validates missing descendants without creating them", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-path-"));
		roots.push(root);
		await expect(
			validateGhidraProjectDirectory(path.join(root, "new", "project")),
		).resolves.toBeUndefined();
		expect(await fs.readdir(root)).toEqual([]);
		await expect(
			validateGhidraProjectDirectory(path.join(root, ".hidden", "project")),
		).rejects.toThrow("dot-prefixed");
		expect(await fs.readdir(root)).toEqual([]);
	});

	it("rejects a non-dot alias pointing into a dot-prefixed parent", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-path-"));
		roots.push(root);
		const hidden = path.join(root, ".hidden");
		await fs.mkdir(hidden);
		const alias = path.join(root, "alias");
		await fs.symlink(
			hidden,
			alias,
			process.platform === "win32" ? "junction" : "dir",
		);
		await expect(
			validateGhidraProjectDirectory(path.join(alias, "new", "project")),
		).rejects.toThrow("dot-prefixed");
		expect(await fs.readdir(hidden)).toEqual([]);
	});
});
