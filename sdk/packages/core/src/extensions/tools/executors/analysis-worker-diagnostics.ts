import { randomUUID } from "node:crypto";
import { mkdir, readdir, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { resolveClineDataDir } from "@cline/shared/storage";

export type WorkerFailureCategory =
	| "launch-failure"
	| "missing-dependency"
	| "timeout"
	| "cancelled"
	| "output-budget"
	| "invalid-output"
	| "abnormal-exit";

export interface WorkerDiagnostics {
	jobId: string;
	action: string;
	interpreter: string;
	pid: number | null;
	exitCode: number | null;
	signal: string | null;
	durationMs: number;
	stderrTail: string;
	stderrTruncated: boolean;
	terminationConfirmed?: boolean;
	cleanup?: string;
	category?: WorkerFailureCategory;
	receiptPath?: string;
	receiptError?: string;
}

/** Only already-redacted metadata is retained; never arguments, input bytes or keys. */
export async function retainWorkerDiagnostics(diagnostics: WorkerDiagnostics) {
	const root = join(resolveClineDataDir(), "analysis", "worker-diagnostics");
	try {
		await mkdir(root, { recursive: true, mode: 0o700 });
		const path = join(root, `${Date.now()}-${randomUUID()}.json`);
		await writeFile(path, `${JSON.stringify(diagnostics, null, 2)}\n`, {
			flag: "wx",
			mode: 0o600,
		});
		diagnostics.receiptPath = path;
		// Bounded best-effort retention. Only files owned by this receipt format.
		const files = (await readdir(root))
			.filter((name) => /^\d+-[0-9a-f-]{36}\.json$/.test(name))
			.sort();
		await Promise.all(
			files
				.slice(0, -32)
				.map((name) => unlink(join(root, name)).catch(() => undefined)),
		);
	} catch {
		// Diagnosis storage failure must not turn a failed analysis into success.
		diagnostics.receiptError = "Unable to retain redacted diagnostic receipt";
	}
}
