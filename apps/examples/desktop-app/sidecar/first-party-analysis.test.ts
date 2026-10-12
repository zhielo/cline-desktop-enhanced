import { realpathSync } from "node:fs";
import { mkdtemp, mkdir, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
const { modes, sessions, run } = vi.hoisted(() => ({
	modes: vi.fn(),
	sessions: vi.fn(),
	run: vi.fn(),
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
	expect(firstPartyReadiness().runtimeCapture).toContain("not implemented");
});

let ownedRoot: string | undefined;
beforeEach(() => {
	modes.mockReset();
	sessions.mockReset();
	run.mockReset();
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
