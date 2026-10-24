/** Explicit installed-owned-fixture acceptance only; not part of normal startup. */
import { mkdtemp, realpath, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import {
	FirstPartyAnalysisStore,
	byteDigest,
	runFirstPartyAnalysis,
	queryFirstPartyEvidence,
} from "@cline/core";

export async function selfcheckGeneralRecovery() {
	const root = await realpath(
		await mkdtemp(join(tmpdir(), "cline-installed-recovery-")),
	);
	const store = new FirstPartyAnalysisStore(join(root, "fixture.sqlite"));
	const owner = randomUUID();
	try {
		const bytes = Buffer.from(
			"(function(modules){function r(id){var m={exports:{}};modules[id](m,m.exports,r);return m.exports;}return r(0);})({0:function(module,exports,require){var x=require(1);module.exports=x+1;},1:function(module){module.exports=41;}});",
		);
		const file = join(root, "owned.js");
		await writeFile(file, bytes, { flag: "wx" });
		store.setMode(owner, root, "static");
		const result = await runFirstPartyAnalysis(
			owner,
			{
				target: file,
				bundleRecovery: { engine: "wakaru", expectedSha256: byteDigest(bytes) },
			},
			undefined,
			store,
		);
		if (
			result.status !== "partial" ||
			result.result?.bundleRecovery?.engine !== "wakaru/1.14.0" ||
			result.result.bundleRecovery.modules.length !== 2
		)
			throw new Error("Installed native recovery owned fixture failed");
		store.setMode(owner, root, "off");
		const page = queryFirstPartyEvidence(
			owner,
			{ receiptId: result.id, view: "bundle-recovery", limit: 5 },
			store,
		) as {
			available: boolean;
			engine: string;
			items: unknown[];
			providerCalls: number;
			sourceSha256: string;
		};
		if (
			!page.available ||
			page.engine !== "wakaru/1.14.0" ||
			page.items.length !== 2 ||
			page.providerCalls !== 0 ||
			page.sourceSha256 !== byteDigest(bytes) ||
			!(await readFile(file)).equals(bytes)
		)
			throw new Error("Installed native saved-evidence fixture failed");
		return {
			status: "passed",
			profile: "installed-general-recovery/1",
			engine: page.engine,
			modules: page.items.length,
			sourceSha256: page.sourceSha256,
			resultHash: result.resultHash,
			targetExecuted: false,
			verifiedBehavior: false,
		};
	} catch {
		return {
			status: "failed",
			profile: "installed-general-recovery/1",
			error:
				"Installed native recovery or saved-evidence acceptance failed; no fallback",
		};
	} finally {
		// A failed/unconfirmed native reservation must not authorize deletion.
		const unresolved = store
			.summaries(owner)
			.some(
				(r) =>
					typeof r.status !== "string" ||
					["running", "termination-unconfirmed"].includes(r.status),
			);
		store.close();
		if (!unresolved) await rm(root, { recursive: true, force: true });
	}
}
