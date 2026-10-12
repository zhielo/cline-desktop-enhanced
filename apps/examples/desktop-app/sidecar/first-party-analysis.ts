import { realpathSync } from "node:fs";
import { mkdtemp, writeFile, rm, realpath } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
	AnalysisModeSchema,
	FirstPartyAnalysisStore,
	runFirstPartyAnalysis,
	queryFirstPartyEvidence,
	cancelFirstPartyAnalysis,
} from "@cline/core";

let store: FirstPartyAnalysisStore | undefined;
export const firstPartyStore = () => (store ??= new FirstPartyAnalysisStore());
let fixtureReceipt:
	| { status: string; checkedAt: string; profile: string; error?: string }
	| undefined;
export function firstPartyReadiness() {
	return {
		installed: true,
		parser: "TypeScript 5.9.3",
		staticFixture: fixtureReceipt ?? { status: "not-tested" },
		targetSupported:
			"Determined per request; supported JS/TS/package metadata and bounded ASAR only",
		nativeProvider:
			"Use existing engine-specific Setup Center tests; no new parity claim",
		runtimeCapture:
			"Existing approved workbench tools only; JavaScript Inspector capture is not implemented",
		behaviorVerification:
			"Not established by static analysis or a successful build",
	};
}
export async function testFirstPartyFixture() {
	const root = await mkdtemp(join(tmpdir(), "cline-js-owned-")),
		db = new FirstPartyAnalysisStore(join(root, "fixture.sqlite"));
	try {
		await writeFile(
			join(root, "main.js"),
			'import { ipcMain } from "electron"; ipcMain.handle("owned:add", () => 42);',
		);
		await writeFile(
			join(root, "renderer.js"),
			'import { ipcRenderer } from "electron"; ipcRenderer.invoke("owned:add");',
		);
		await writeFile(
			join(root, "never-execute.js"),
			'throw new Error("TARGET_MUST_NOT_EXECUTE");',
		);
		db.setMode("owned-fixture", await realpath(root), "static");
		const receipt = await runFirstPartyAnalysis(
			"owned-fixture",
			{ target: "." },
			undefined,
			db,
		);
		if (
			!receipt.result?.edges.some((e) => e.kind === "ipc-candidate") ||
			receipt.status !== "completed" ||
			receipt.result.parserVersion !== "5.9.3"
		)
			throw new Error(receipt.error ?? "Owned static IPC fixture did not pass");
		fixtureReceipt = {
			status: "passed",
			checkedAt: new Date().toISOString(),
			profile: receipt.profile,
		};
		return fixtureReceipt;
	} catch (e) {
		fixtureReceipt = {
			status: "failed",
			checkedAt: new Date().toISOString(),
			profile: "cline-js-static/1",
			error: e instanceof Error ? e.message : "Fixture failed",
		};
		throw e;
	} finally {
		db.close();
		await rm(root, { recursive: true, force: true });
	}
}
export async function handleFirstPartyCommand(
	command: string,
	args: Record<string, unknown>,
	session: { id: string; workspace: string; busy: boolean },
	trusted: boolean,
) {
	const db = firstPartyStore();
	const bound = db.session(session.id);
	// The store and receipt service use realpathSync. Use the same resolver here:
	// Windows async/sync path spellings must not split one workspace identity.
	if (bound && bound.workspace !== realpathSync(session.workspace))
		throw new Error(
			"Session workspace changed; existing analysis binding cannot be reused",
		);
	if (command === "first_party_analysis_status")
		return {
			mode: db.session(session.id)?.mode ?? "off",
			readiness: firstPartyReadiness(),
			receipts: db.summaries(session.id),
		};
	if (command === "first_party_analysis_evidence")
		return queryFirstPartyEvidence(session.id, args.query, db);
	if (!trusted)
		throw new Error(
			"Analysis changes require a trusted desktop approval connection",
		);
	if (command === "first_party_analysis_mode") {
		if (session.busy)
			throw new Error(
				"Change Analysis mode only while the chat session is idle",
			);
		return db.setMode(
			session.id,
			session.workspace,
			AnalysisModeSchema.parse(args.mode),
		);
	}
	if (command === "first_party_analysis_cancel") {
		cancelFirstPartyAnalysis(String(args.receiptId), session.id);
		return { requested: true, terminationConfirmed: false };
	}
	if (command === "first_party_analysis_run") {
		const receipt = await runFirstPartyAnalysis(
			session.id,
			args.input,
			undefined,
			db,
		);
		return {
			id: receipt.id,
			status: receipt.status,
			error: receipt.error,
			resultHash: receipt.resultHash,
		};
	}
	throw new Error("Unknown first-party analysis command");
}
