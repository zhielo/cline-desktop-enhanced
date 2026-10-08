import { expect, test } from "bun:test";
import { loadSqliteDb } from "../src/db/sqlite-db.ts";

test("native Bun SQLite repeatedly opens isolated memory databases without filesystem setup", () => {
	for (let i = 0; i < 5; i++) {
		const db = loadSqliteDb(":memory:");
		try {
			db.exec("CREATE TABLE owned (value INTEGER)");
			db.prepare("INSERT INTO owned VALUES (?)").run(i);
			expect(db.prepare("SELECT value FROM owned").get()).toEqual({ value: i });
		} finally {
			db.close?.();
		}
	}
});
