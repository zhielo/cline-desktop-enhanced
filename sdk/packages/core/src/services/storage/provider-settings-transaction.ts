import { mkdirSync, realpathSync } from "node:fs";
import { dirname, basename, join } from "node:path";
import { loadSqliteDb } from "@cline/shared/db";

const active = new Set<string>();
/** A kernel-released SQLite mutex. Contains no provider settings or credentials.
 * Lock the complete read/modify/replace operation, not only the final rename.
 * A killed process releases its lock; no age-based deletion of another owner.
 */
export function withProviderSettingsTransaction<T>(
	filePath: string,
	operation: () => T,
): T {
	mkdirSync(dirname(filePath), { recursive: true, mode: 0o700 });
	const canonical = join(realpathSync(dirname(filePath)), basename(filePath));
	if (active.has(canonical))
		throw new Error("Reentrant provider settings transaction is not supported");
	const db = loadSqliteDb(`${canonical}.mutation-lock.db`);
	let begun = false;
	active.add(canonical);
	try {
		db.exec("PRAGMA busy_timeout = 2000;");
		db.exec("BEGIN IMMEDIATE;");
		begun = true;
		const result = operation();
		if (result && typeof (result as { then?: unknown }).then === "function") {
			throw new Error("Provider settings transactions must be synchronous");
		}
		db.exec("COMMIT;");
		begun = false;
		return result;
	} finally {
		try {
			if (begun) db.exec("ROLLBACK;");
		} finally {
			active.delete(canonical);
			db.close?.();
		}
	}
}
