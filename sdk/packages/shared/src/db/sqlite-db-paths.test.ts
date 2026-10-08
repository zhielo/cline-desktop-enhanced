import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { beforeEach, expect, it, vi } from "vitest";

const mkdir = vi.hoisted(() => vi.fn());
vi.mock("node:fs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs")>();
	mkdir.mockImplementation(actual.mkdirSync);
	return { ...actual, mkdirSync: mkdir };
});

import { loadSqliteDb } from "./sqlite-db";

beforeEach(() => {
	mkdir.mockClear();
});
it("opens usable in-memory SQLite without any mkdir operation", () => {
	const db = loadSqliteDb(":memory:");
	try {
		db.exec("CREATE TABLE owned (value INTEGER); INSERT INTO owned VALUES (7)");
		expect(db.prepare("SELECT value FROM owned").get()).toEqual({ value: 7 });
		expect(mkdir).not.toHaveBeenCalled();
	} finally {
		db.close?.();
	}
});
it("creates an absolute parent for a relative on-disk database", () => {
	const root = mkdtempSync(join(tmpdir(), "sqlite-path-"));
	const path = join(root, "nested", "owned.db");
	try {
		const db = loadSqliteDb(relative(process.cwd(), path));
		try {
			db.exec("CREATE TABLE owned (value INTEGER)");
			expect(mkdir).toHaveBeenCalledWith(dirname(path), { recursive: true });
		} finally {
			db.close?.();
		}
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});
it("propagates a real disk-directory failure instead of suppressing it", () => {
	mkdir.mockImplementationOnce(() => {
		throw new Error("owned directory failure");
	});
	expect(() => loadSqliteDb("owned.db")).toThrow("owned directory failure");
});
