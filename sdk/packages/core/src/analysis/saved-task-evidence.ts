import { z } from "zod";
import { digest } from "./contracts";
const Hash = z.string().regex(/^[a-f0-9]{64}$/);
export const SavedTaskSnapshotSchema = z
	.object({
		id: Hash,
		sessionId: z.string().min(1).max(128),
		workspace: z.string().min(1).max(4096),
		taskId: z.string().uuid(),
		domain: z.enum([
			"static",
			"debugger",
			"gui",
			"dynamic",
			"device",
			"execution",
		]),
		operation: z.string().max(120),
		tool: z.string().max(120),
		targetSha256: Hash.optional(),
		resultHash: Hash,
		requestHash: Hash,
		at: z.string().datetime(),
		result: z.unknown(),
		snapshotHash: Hash,
	})
	.strict();

/** Pure bounded ledger validation; hashes are integrity, not producer authentication. */
export function validateSavedTaskSnapshots(
	scope: { sessionId: string; workspace: string },
	values: unknown[],
) {
	if (!values.length || values.length > 10)
		throw new Error("Select one to ten saved task snapshots");
	if (Buffer.byteLength(JSON.stringify(values)) > 12 * 1024 * 1024)
		throw new Error("Saved task input byte budget exceeded");
	const snapshots = values.map((value) => SavedTaskSnapshotSchema.parse(value));
	const seen = new Set<string>();
	for (const snapshot of snapshots) {
		const { snapshotHash, ...raw } = snapshot;
		if (
			snapshot.sessionId !== scope.sessionId ||
			snapshot.workspace !== scope.workspace ||
			digest(raw) !== snapshotHash ||
			digest(snapshot.result) !== snapshot.resultHash ||
			seen.has(snapshot.taskId)
		)
			throw new Error(
				"Runtime snapshot scope, integrity or uniqueness mismatch",
			);
		seen.add(snapshot.taskId);
	}
	return snapshots;
}
