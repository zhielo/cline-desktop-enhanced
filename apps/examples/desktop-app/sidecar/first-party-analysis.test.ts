import { realpathSync } from "node:fs";
import { mkdtemp, mkdir, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
const { modes, sessions, run, consume, complete, fail, observe, record } =
	vi.hoisted(() => ({
		modes: vi.fn(),
		sessions: vi.fn(),
		run: vi.fn(),
		consume: vi.fn(),
		complete: vi.fn(),
		fail: vi.fn(),
		observe: vi.fn(),
		record: vi.fn(),
	}));
vi.mock("node:fs/promises", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs/promises")>();
	return { ...actual, realpath: vi.fn(actual.realpath) };
});
vi.mock("@cline/core", () => ({
	AnalysisModeSchema: { parse: (v: unknown) => v },
	FirstPartyAnalysisStore: class {
		setMode = modes;
		session = sessions;
		summaries() {
			return [];
		}
	},
	runFirstPartyAnalysis: run,
	queryFirstPartyEvidence: vi.fn(),
	cancelFirstPartyAnalysis: vi.fn(),
	recoverFirstPartyReservation: vi.fn(),
	UnifiedEvidenceStore: class {
		record = record;
		bind() {}
	},
	InspectorRequestSchema: { parse: (v: unknown) => v },
	observeJavaScriptInspector: observe,
	probeProcessStartTokenAsync: vi.fn(),
	unifiedEvidenceView: vi.fn(),
	nativeDossiers: vi.fn(),
	dossierDisagreements: vi.fn(),
}));
vi.mock("./analysis-task-orchestrator", () => ({
	desktopAnalysisTaskOrchestrator: {
		consume,
		complete,
		fail,
		signal: () => new AbortController().signal,
	},
}));
import {
	handleFirstPartyCommand,
	firstPartyReadiness,
} from "./first-party-analysis";
it("requires trusted changes and an idle session", async () => {
	const session = { id: "s", workspace: "/owned", busy: false };
	await expect(
		handleFirstPartyCommand(
			"first_party_analysis_mode",
			{ mode: "static" },
			session,
			false,
		),
	).rejects.toThrow("trusted");
	await expect(
		handleFirstPartyCommand(
			"first_party_analysis_mode",
			{ mode: "static" },
			{ ...session, busy: true },
			true,
		),
	).rejects.toThrow("idle");
	expect(modes).not.toHaveBeenCalled();
	await handleFirstPartyCommand(
		"first_party_analysis_mode",
		{ mode: "static" },
		session,
		true,
	);
	expect(modes).toHaveBeenCalledWith("s", "/owned", "static");
});
it("reports readiness separately without certifying native or runtime capabilities", () => {
	expect(firstPartyReadiness()).toMatchObject({
		installed: true,
		staticFixture: { status: "not-tested" },
	});
	expect(firstPartyReadiness().runtimeCapture).toContain("Separately Execute-approved");
 expect(firstPartyReadiness().runtimeCapture).toContain("no unsandboxed fallback");
});

let ownedRoot: string | undefined;
beforeEach(() => {
	modes.mockReset();
	sessions.mockReset();
	run.mockReset();
	consume.mockReset();
	complete.mockReset();
	fail.mockReset();
	observe.mockReset();
	record.mockReset();
	vi.mocked(realpath)
		.mockReset()
		.mockImplementation(async (path) => realpathSync(String(path)));
});
afterEach(async () => {
	if (ownedRoot) await rm(ownedRoot, { recursive: true, force: true });
	ownedRoot = undefined;
});
it("accepts the store canonical identity even when async realpath spells it differently", async () => {
	ownedRoot = await mkdtemp(join(tmpdir(), "cline-analysis-binding-"));
	const canonical = realpathSync(ownedRoot);
	sessions.mockReturnValue({ workspace: canonical, mode: "static" });
	// Model the Windows extended-path spelling divergence without relaxing identity.
	vi.mocked(realpath).mockResolvedValueOnce(`\\\\?\\${canonical}`);
	await expect(
		handleFirstPartyCommand(
			"first_party_analysis_status",
			{},
			{ id: "s", workspace: ownedRoot, busy: false },
			false,
		),
	).resolves.toMatchObject({ mode: "static" });
	expect(realpath).not.toHaveBeenCalled();
});
it("admits a run only for the same resolved workspace", async () => {
	ownedRoot = await mkdtemp(join(tmpdir(), "cline-analysis-binding-"));
	await mkdir(join(ownedRoot, "child"));
	sessions.mockReturnValue({
		workspace: realpathSync(ownedRoot),
		mode: "static",
	});
	run.mockResolvedValue({ id: "receipt", status: "completed" });
	await expect(
		handleFirstPartyCommand(
			"first_party_analysis_run",
			{ input: { target: "." } },
			{ id: "s", workspace: `${ownedRoot}${sep}child${sep}..`, busy: false },
			true,
		),
	).resolves.toMatchObject({ id: "receipt", status: "completed" });
	expect(run).toHaveBeenCalledTimes(1);
});
it("still rejects a genuinely changed workspace before mode changes or a run", async () => {
	ownedRoot = await mkdtemp(join(tmpdir(), "cline-analysis-binding-"));
	const other = join(ownedRoot, "other");
	await mkdir(other);
	sessions.mockReturnValue({
		workspace: realpathSync(ownedRoot),
		mode: "static",
	});
	for (const command of [
		"first_party_analysis_status",
		"first_party_analysis_mode",
		"first_party_analysis_run",
		"first_party_analysis_evidence",
	]) {
		await expect(
			handleFirstPartyCommand(
				command,
				{ mode: "static", input: { target: "." } },
				{ id: "s", workspace: other, busy: false },
				true,
			),
		).rejects.toThrow("Session workspace changed");
	}
	expect(modes).not.toHaveBeenCalled();
	expect(run).not.toHaveBeenCalled();
});
it("fails closed when a bound workspace no longer resolves", async () => {
	ownedRoot = await mkdtemp(join(tmpdir(), "cline-analysis-binding-"));
	sessions.mockReturnValue({
		workspace: realpathSync(ownedRoot),
		mode: "static",
	});
	await expect(
		handleFirstPartyCommand(
			"first_party_analysis_run",
			{ input: { target: "." } },
			{ id: "s", workspace: join(ownedRoot, "missing"), busy: false },
			true,
		),
	).rejects.toThrow();
	expect(run).not.toHaveBeenCalled();
});

it("recovery and Inspector mutations never inherit authorization from Runtime mode", async () => {
	ownedRoot = await mkdtemp(join(tmpdir(), "cline-analysis-permissions-"));
	sessions.mockReturnValue({
		workspace: realpathSync(ownedRoot),
		mode: "runtime",
	});
	const session = { id: "s", workspace: ownedRoot, busy: false };
	for (const command of [
		"first_party_analysis_recover",
		"first_party_analysis_inspector_prepare",
		"first_party_analysis_inspector_run",
	]) {
		await expect(
			handleFirstPartyCommand(command, { confirmed: true }, session, false),
		).rejects.toThrow("trusted");
		await expect(
			handleFirstPartyCommand(
				command,
				{ confirmed: true },
				{ ...session, busy: true },
				true,
			),
		).rejects.toThrow("idle");
	}
	await expect(
		handleFirstPartyCommand("first_party_analysis_recover", {}, session, true),
	).rejects.toThrow("Explicit");
	sessions.mockReturnValue({
		workspace: realpathSync(ownedRoot),
		mode: "static",
	});
	await expect(
		handleFirstPartyCommand(
			"first_party_analysis_inspector_prepare",
			{},
			session,
			true,
		),
	).rejects.toThrow("Runtime");
});

it("rejected Inspector approval does not fail another pending task or retain an admission slot", async () => {
	ownedRoot = await mkdtemp(join(tmpdir(), "cline-inspector-denial-"));
	sessions.mockReturnValue({
		workspace: realpathSync(ownedRoot),
		mode: "runtime",
	});
	consume.mockRejectedValue(new Error("approval mismatch"));
	const session = { id: "s", workspace: ownedRoot, busy: false };
	await expect(
		handleFirstPartyCommand(
			"first_party_analysis_inspector_run",
			{ planId: "denied", input: {} },
			session,
			true,
		),
	).rejects.toThrow("approval mismatch");
	expect(fail).not.toHaveBeenCalled();
	await expect(
		handleFirstPartyCommand(
			"first_party_analysis_mode",
			{ mode: "off" },
			session,
			true,
		),
	).resolves.toBeUndefined();
});
it("mode changes are blocked while observation is active and released after completion", async () => {
	ownedRoot = await mkdtemp(join(tmpdir(), "cline-inspector-active-"));
	sessions.mockReturnValue({
		workspace: realpathSync(ownedRoot),
		mode: "runtime",
	});
	consume.mockResolvedValue({
		target: join(ownedRoot, "owned.js"),
		targetIdentity: { sha256: "a".repeat(64) },
	});
	complete.mockReturnValue({ status: "completed" });
	let done!: (v: unknown) => void;
	observe.mockImplementation(() => new Promise((resolve) => (done = resolve)));
	const session = { id: "s", workspace: ownedRoot, busy: false };
	const running = handleFirstPartyCommand(
		"first_party_analysis_inspector_run",
		{ planId: "owned", input: {} },
		session,
		true,
	);
	await vi.waitFor(() => expect(observe).toHaveBeenCalled());
	await expect(
		handleFirstPartyCommand(
			"first_party_analysis_mode",
			{ mode: "off" },
			session,
			true,
		),
	).rejects.toThrow("idle");
	done({ verifiedBehavior: false });
	await running;
	await expect(
		handleFirstPartyCommand(
			"first_party_analysis_mode",
			{ mode: "off" },
			session,
			true,
		),
	).resolves.toBeUndefined();
});
