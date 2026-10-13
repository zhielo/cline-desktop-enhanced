import {
	bindNativeModuleObservation,
	NativeModuleRequestSchema,
	observeNativeModule,
} from "./native-module-observation";
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
	recoverFirstPartyReservation,
	InspectorRequestSchema,
	observeJavaScriptInspector,
	probeProcessStartTokenAsync,
	UnifiedEvidenceStore,
	unifiedEvidenceView,
	nativeDossiers,
	dossierDisagreements,
} from "@cline/core";

import { desktopAnalysisTaskOrchestrator } from "./analysis-task-orchestrator";

import {
	bindJavaScriptExecution,
	JavaScriptExecutionSchema,
	runIsolatedJavaScript,
} from "./javascript-isolation";

let store: FirstPartyAnalysisStore | undefined;
let taskEvidence: UnifiedEvidenceStore | undefined;
const inspectorSlots = new Map<string, string>();
const taskStore = () => (taskEvidence ??= new UnifiedEvidenceStore());
export function bindFirstPartyTaskEvidence(
	sessionId: string,
	workspace: string,
	plan: unknown,
) {
	const bound = firstPartyStore().session(sessionId);
	if (!bound || bound.mode === "off") return;
	if (bound.workspace !== realpathSync(workspace))
		throw new Error("Task ownership session workspace mismatch");
	taskStore().bind(sessionId, bound.workspace, plan);
}
export function recordFirstPartyTaskEvidence(
	sessionId: string,
	workspace: string,
	plan: unknown,
	result: unknown,
) {
	const bound = firstPartyStore().session(sessionId);
	if (!bound || bound.mode === "off") return;
	if (bound.workspace !== realpathSync(workspace))
		throw new Error("Task evidence session workspace mismatch");
	return taskStore().record(sessionId, bound.workspace, plan, result);
}
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
			"Determined per request; bounded JS/TS/package/source-map/ASAR and managed PE metadata/IL bytes",
		localSemantics:
			"Closed-inventory relative ES bindings/reexports, const scalar object reads and simple pure-return substitutions; no complete program semantics",
		sourceMaps:
			"Basic v3 mapping declarations and embedded hashes only; runtime reconciliation not implemented",
		nativeProvider:
			"Use existing engine-specific Setup Center tests; no new parity claim",
		runtimeCapture:
			"Separately approved exact-process loopback Node Inspector observation; loaded source hash reconciliation. Separately Execute-approved Windows x64 AppContainer standalone scenarios; no unsandboxed fallback.",
		behaviorVerification:
			"Not established by static analysis or a successful build. Active process-interface assertions have exact per-scenario scope, not universal verification.",
		activeExecution:
			"Packaged Windows x64 helper/runtime only. Installation is not readiness: kernel token/job verification is performed before each approved target resume.",
	};
}
export async function testFirstPartyFixture() {
	const root = await mkdtemp(join(tmpdir(), "cline-js-owned-")),
		db = new FirstPartyAnalysisStore(join(root, "fixture.sqlite"));
	try {
		await writeFile(
			join(root, "main.js"),
			'import { ipcMain } from "electron"; ipcMain.handle("owned:add", () => 42); const host="https://owned.invalid"; function route(h){return h+"/fixture";} fetch(route(host));',
		);
		await writeFile(
			join(root, "renderer.js"),
			'import { ipcRenderer } from "electron"; ipcRenderer.invoke("owned:add");',
		);
		await writeFile(
			join(root, "never-execute.js"),
			'throw new Error("TARGET_MUST_NOT_EXECUTE");',
		);
		await writeFile(
			join(root, "main.js.map"),
			JSON.stringify({
				version: 3,
				file: "main.js",
				sources: ["owned.ts"],
				sourcesContent: ["const owned=42;"],
				names: [],
				mappings: "AAAA",
			}),
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
			receipt.result.parserVersion !== "5.9.3" ||
			!receipt.result.facts.some(
				(f) =>
					f.kind === "resolved-endpoint" &&
					f.value === "https://owned.invalid/fixture",
			) ||
			!receipt.result.facts.some((f) => f.kind === "source-map-location")
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
			profile: "cline-js-static/7",
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
			inspectorActive: inspectorSlots.has(session.id),
			readiness: firstPartyReadiness(),
			receipts: db.summaries(session.id),
		};
	if (command === "first_party_analysis_cross_domain") {
		const snapshots = taskStore().list(session.id, session.workspace);
		const receipt =
			typeof args.receiptId === "string" && args.receiptId
				? db.get(session.id, args.receiptId)
				: undefined;
		const dossiers = nativeDossiers(snapshots);
		const view =
			args.view === "dossiers"
				? dossiers
				: args.view === "disagreements"
					? dossierDisagreements(dossiers)
					: unifiedEvidenceView(receipt?.result, snapshots);
		const offset = Number(args.offset ?? 0);
		if (!Number.isInteger(offset) || offset < 0 || offset > 10000)
			throw new Error("Invalid evidence offset");
		const items: unknown[] = [];
		let bytes = 0;
		for (const item of view.slice(offset, offset + 20)) {
			const encoded = JSON.stringify(item);
			let shown: unknown = item;
			if (Buffer.byteLength(encoded) > 65536) {
				const v = item as Record<string, unknown>;
				shown = {
					id: v.id,
					taskId: v.taskId,
					snapshotId: v.snapshotId,
					snapshotHash: v.snapshotHash,
					resultHash: v.resultHash,
					identity: v.identity,
					name: v.name,
					displayOmitted: true,
					note: "Retained evidence exceeds display budget; snapshot integrity does not imply full evidence was displayed.",
				};
			}
			const size = Buffer.byteLength(JSON.stringify(shown));
			if (bytes + size > 196608 && items.length) break;
			items.push(shown);
			bytes += size;
		}
		return {
			items,
			total: view.length,
			nextOffset:
				offset + items.length < view.length ? offset + items.length : null,
		};
	}
	if (command === "first_party_analysis_evidence")
		return queryFirstPartyEvidence(session.id, args.query, db);
	if (!trusted)
		throw new Error(
			"Analysis changes require a trusted desktop approval connection",
		);

	if (command.startsWith("first_party_analysis_native_")) {
		if (
			bound?.mode !== "runtime" ||
			session.busy ||
			inspectorSlots.has(session.id)
		)
			throw new Error(
				"Native memory observation requires an idle Runtime session and independent Debug approval",
			);
		if (command === "first_party_analysis_native_prepare") {
			const request = await bindNativeModuleObservation(args.input);
			const plan = await desktopAnalysisTaskOrchestrator.prepare({
				workspaceRoot: session.workspace,
				kind: "debugger",
				request,
				allowExternalTarget: args.allowExternalTarget === true,
				timeoutMs: 20000,
			});
			bindFirstPartyTaskEvidence(session.id, session.workspace, plan);
			return plan;
		}
		if (command === "first_party_analysis_native_run") {
			if (args.confirmDebug !== true)
				throw new Error(
					"Independent Debug and sensitive memory-read confirmation required",
				);
			if (inspectorSlots.size >= 2)
				throw new Error("Runtime observation slots occupied");
			const request = NativeModuleRequestSchema.parse(args.input),
				planId = String(args.planId ?? "");
			inspectorSlots.set(session.id, planId);
			let consumed = false;
			try {
				const plan = await desktopAnalysisTaskOrchestrator.consume({
					planId,
					executionToken: String(args.executionToken ?? ""),
					workspaceRoot: session.workspace,
					kind: "debugger",
					request,
				});
				consumed = true;
				if (!plan.targetIdentity?.sha256 || !plan.target)
					throw new Error("Exact native artifact required");
				const result = await observeNativeModule(
					{ ...request, target: plan.target },
					plan.targetIdentity.sha256,
					desktopAnalysisTaskOrchestrator.signal(planId),
				);
				const completed = desktopAnalysisTaskOrchestrator.complete(
					planId,
					result,
					"windows-native-module",
				);
				let evidenceWarning: string | undefined;
				try {
					recordFirstPartyTaskEvidence(
						session.id,
						session.workspace,
						completed,
						result,
					);
				} catch {
					evidenceWarning =
						"Observation completed; evidence metadata failed, do not replay";
				}
				return { result, plan: completed, evidenceWarning };
			} catch (e) {
				if (consumed) desktopAnalysisTaskOrchestrator.fail(planId, e);
				throw e;
			} finally {
				if (inspectorSlots.get(session.id) === planId)
					inspectorSlots.delete(session.id);
			}
		}
		throw new Error("Unknown native observation operation");
	}
	if (command.startsWith("first_party_analysis_execute_")) {
		if (
			bound?.mode !== "runtime" ||
			session.busy ||
			inspectorSlots.has(session.id)
		)
			throw new Error(
				"Active execution requires an idle Runtime-enabled session and independent Execute approval",
			);
		if (command === "first_party_analysis_execute_prepare") {
			const request = await bindJavaScriptExecution(args.input);
			const plan = await desktopAnalysisTaskOrchestrator.prepare({
				workspaceRoot: session.workspace,
				kind: "execution",
				request,
				allowExternalTarget: args.allowExternalTarget === true,
				timeoutMs: request.timeoutMs + 25000,
				maxOutputBytes: 262144,
			});
			bindFirstPartyTaskEvidence(session.id, session.workspace, plan);
			return plan;
		}
		if (command === "first_party_analysis_execute_run") {
			if (args.confirmExecution !== true)
				throw new Error("Independent Execute confirmation required");
			if (inspectorSlots.size >= 2)
				throw new Error("Runtime execution slots occupied");
			const request = JavaScriptExecutionSchema.parse(args.input),
				planId = String(args.planId ?? "");
			inspectorSlots.set(session.id, planId);
			let consumed = false;
			try {
				const plan = await desktopAnalysisTaskOrchestrator.consume({
					planId,
					executionToken: String(args.executionToken ?? ""),
					workspaceRoot: session.workspace,
					kind: "execution",
					request,
				});
				consumed = true;
				if (!plan.targetIdentity?.sha256 || !plan.target)
					throw new Error("Exact reviewed standalone file required");
				const result = await runIsolatedJavaScript(
					{ ...request, target: plan.target },
					{
						targetSha256: plan.targetIdentity.sha256,
						requestHash: plan.requestHash,
					},
					desktopAnalysisTaskOrchestrator.signal(planId),
				);
				const completed = desktopAnalysisTaskOrchestrator.complete(
					planId,
					result,
					"windows-appcontainer-js",
				);
				let evidenceWarning: string | undefined;
				try {
					recordFirstPartyTaskEvidence(
						session.id,
						session.workspace,
						completed,
						result,
					);
				} catch {
					evidenceWarning =
						"Execution completed but evidence metadata was not saved; do not replay";
				}
				return { result, plan: completed, evidenceWarning };
			} catch (e) {
				if (consumed) desktopAnalysisTaskOrchestrator.fail(planId, e);
				throw e;
			} finally {
				if (inspectorSlots.get(session.id) === planId)
					inspectorSlots.delete(session.id);
			}
		}
		throw new Error("Unknown active JavaScript operation");
	}
	if (command.startsWith("first_party_analysis_inspector_")) {
		if (
			bound?.mode !== "runtime" ||
			session.busy ||
			inspectorSlots.has(session.id)
		)
			throw new Error(
				"Inspector requires an idle, Runtime-enabled owning session and separate task approval",
			);
		if (command === "first_party_analysis_inspector_prepare") {
			const supplied =
				args.input && typeof args.input === "object"
					? (args.input as Record<string, unknown>)
					: {};
			const pid = Number(supplied.pid);
			if (!Number.isSafeInteger(pid) || pid < 1)
				throw new Error("Exact Inspector PID required");
			const identity = await probeProcessStartTokenAsync(pid);
			if (identity.status !== "found")
				throw new Error("Inspector process birth identity unavailable");
			const request = InspectorRequestSchema.parse({
				...supplied,
				processToken: identity.token,
			});
			const plan = await desktopAnalysisTaskOrchestrator.prepare({
				workspaceRoot: session.workspace,
				kind: "debugger",
				request,
				timeoutMs: 15000,
				maxOutputBytes: 262144,
			});
			bindFirstPartyTaskEvidence(session.id, session.workspace, plan);
			return plan;
		}
		if (command === "first_party_analysis_inspector_run") {
			const input = InspectorRequestSchema.parse(args.input);
			const planId = String(args.planId ?? "");
			if (inspectorSlots.size >= 2)
				throw new Error(
					"Two Inspector observation slots are already reserved; no automatic retry",
				);
			inspectorSlots.set(session.id, planId);
			let consumed = false;
			try {
				const plan = await desktopAnalysisTaskOrchestrator.consume({
					planId,
					executionToken: String(args.executionToken ?? ""),
					workspaceRoot: session.workspace,
					kind: "debugger",
					request: input,
				});
				consumed = true;
				if (!plan.targetIdentity?.sha256)
					throw new Error(
						"Inspector requires an exact approved source file hash",
					);
				const result = await observeJavaScriptInspector(
					{ ...input, target: plan.target },
					desktopAnalysisTaskOrchestrator.signal(planId),
					plan.targetIdentity.sha256,
				);
				const completed = desktopAnalysisTaskOrchestrator.complete(
					planId,
					result,
					"node-inspector-passive",
				);
				let evidenceWarning: string | undefined;
				try {
					recordFirstPartyTaskEvidence(
						session.id,
						session.workspace,
						completed,
						result,
					);
				} catch {
					evidenceWarning =
						"Observation completed but unified metadata was not saved; do not replay to repair metadata.";
				}
				return { result, plan: completed, evidenceWarning };
			} catch (e) {
				if (consumed) desktopAnalysisTaskOrchestrator.fail(planId, e);
				throw e;
			} finally {
				if (inspectorSlots.get(session.id) === planId)
					inspectorSlots.delete(session.id);
			}
		}
		throw new Error(
			"Unknown Inspector operation; active execution scenarios are not exposed",
		);
	}
	if (command === "first_party_analysis_mode") {
		if (session.busy || inspectorSlots.has(session.id))
			throw new Error(
				"Change Analysis mode only while the chat session is idle",
			);
		return db.setMode(
			session.id,
			session.workspace,
			AnalysisModeSchema.parse(args.mode),
		);
	}
	if (command === "first_party_analysis_recover") {
		if (session.busy || args.confirmed !== true)
			throw new Error(
				"Explicit trusted idle-session recovery approval required",
			);
		return recoverFirstPartyReservation(session.id, String(args.receiptId), db);
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
