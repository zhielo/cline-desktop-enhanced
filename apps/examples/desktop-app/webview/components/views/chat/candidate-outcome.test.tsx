// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { desktopClient } from "@/lib/desktop-client";
import type { CandidateOutcome } from "../../../../shared/candidate-outcome";
import { AnalysisWorkbench } from "./analysis-workbench";
import { CandidateOutcomeCard } from "./candidate-outcome";

let container: HTMLDivElement, root: Root;
beforeEach(() => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	container = document.createElement("div");
	document.body.append(container);
	root = createRoot(container);
});
afterEach(async () => {
	await act(async () => root.unmount());
	container.remove();
	vi.restoreAllMocks();
});
const outcome = (evidence: CandidateOutcome["evidence"]): CandidateOutcome => ({
	version: "candidate-outcome/v1",
	evidence,
	operation: "validate_candidate",
	scope: "typescript",
	inputSha256: "a".repeat(64),
	receiptSha256: "b".repeat(64),
	checks: [
		{
			id: "source-syntax",
			status: evidence === "failed" ? "failed" : "blocked",
		},
	],
	limitations: [
		"Retained metadata only; not current identity, execution proof or approval.",
		"<script>NEVER_EXECUTE</script>",
	],
});
it.each([
	"failed",
	"partial",
	"unavailable",
	"bounded-checks-passed",
] as const)("displays %s without inferring task success or rendering markup", async (evidence) => {
	const invoke = vi.spyOn(desktopClient, "invoke");
	await act(async () =>
		root.render(
			<CandidateOutcomeCard status="completed" outcome={outcome(evidence)} />,
		),
	);
	expect(container.textContent).toContain("Task status: completed");
	expect(container.textContent).toContain(`Evidence outcome: ${evidence}`);
	expect(container.textContent).toContain("not current identity");
	expect(container.querySelector("script")).toBeNull();
	expect(container.textContent).toContain("<script>");
	expect(invoke).not.toHaveBeenCalled();
	expect(container.querySelector("button")).toBeNull();
});
it("does not invent an outcome for legacy records", async () => {
	await act(async () =>
		root.render(<CandidateOutcomeCard status="completed" />),
	);
	expect(container.textContent).toBe("");
});
it("shows retained failed evidence in the ledger and exports only on explicit click", async () => {
	const saved = {
		id: "failed-plan",
		operation: "validate_candidate",
		status: "failed",
		requestHash: "c".repeat(64),
		candidateOutcome: outcome("failed"),
		evidence: {
			tool: "reverse-engineering",
			resultHash: "d".repeat(64),
			outputPaths: [],
		},
	};
	const invoke = vi
		.spyOn(desktopClient, "invoke")
		.mockImplementation(async (command: string) => {
			if (command === "list_analysis_tasks") return [saved];
			if (
				command === "discover_analysis_tools" ||
				command === "get_analysis_diagnostics"
			)
				return {};
			if (command === "export_analysis_evidence")
				return {
					outputPath: "/owned/evidence.json",
					bundleHash: "e".repeat(64),
				};
			throw Error(`Unexpected RPC ${command}`);
		});
	await act(async () => {
		root.render(<AnalysisWorkbench cwd="/owned" environmentId="local" />);
		await Promise.resolve();
	});
	const evidence = [...container.querySelectorAll("button")].find(
		(b) => b.textContent?.trim() === "Evidence",
	);
	expect(evidence).toBeDefined();
	await act(async () => evidence?.click());
	expect(
		container.querySelector('[aria-label="Candidate verification outcome"]')
			?.textContent,
	).toContain("Task status: failed");
	expect(
		invoke.mock.calls.some(([name]) => name === "export_analysis_evidence"),
	).toBe(false);
	const exportButton = [...container.querySelectorAll("button")].find(
		(b) => b.textContent?.trim() === "Export evidence bundle",
	);
	await act(async () => {
		exportButton?.click();
		await Promise.resolve();
	});
	expect(invoke).toHaveBeenCalledWith("export_analysis_evidence", {
		environmentId: "local",
		cwd: "/owned",
		planId: "failed-plan",
	});
	expect(
		invoke.mock.calls.some(([name]) =>
			/prepare|approve|run_static|execute/.test(name),
		),
	).toBe(false);
});
it("shows unsigned build identity without adding verification or execution actions", async () => {
	const invoke = vi.spyOn(desktopClient, "invoke");
	await act(async () =>
		root.render(
			<CandidateOutcomeCard
				status="completed"
				outcome={{
					...outcome("bounded-checks-passed"),
					operation: "build_android_candidate",
					scope: "android-project-build",
					outputSha256: "c".repeat(64),
					publication: "new-unsigned-candidate",
				}}
			/>,
		),
	);
	expect(container.textContent).toContain("Published candidate SHA256");
	expect(container.textContent).toContain("new-unsigned-candidate");
	expect(container.textContent).toContain(
		"signing and device checks remain separate",
	);
	expect(container.querySelector("button")).toBeNull();
	expect(invoke).not.toHaveBeenCalled();
});

it("renders independent Android lifecycle outcomes without automatic RPC or a green aggregate", async () => {
 const { AndroidCandidateLifecycleCard } = await import("./android-candidate-lifecycle");
 const invoke = vi.spyOn(desktopClient, "invoke");
 await act(async () => root.render(<AndroidCandidateLifecycleCard summary={{
  version: "android-candidate-lifecycle/v1", buildPlanId: "owned-build", outputSha256: "a".repeat(64), publication: "new-unsigned-candidate",
  verificationAttempts: [{ planId: "owned-verify", status: "completed", evidence: "failed", structure: "completed", signature: "failed" }],
  totalLinkedAttempts: 1, omittedAttempts: 2, rejectedLinks: 1, signing: "not-attested", device: "not-linked",
  limitations: ["Retained metadata only. <script>untrusted</script>"],
 }} />));
 expect(container.textContent).toContain("APK structure: completed; signature verification: failed");
 expect(container.textContent).toContain("Signing: not-attested; device outcomes: not-linked");
 expect(container.textContent).toContain("not displayed: 2");
 expect(container.textContent).toContain("inconsistent retained links: 1");
 expect(container.querySelector("script")).toBeNull(); expect(container.querySelector("button")).toBeNull(); expect(invoke).not.toHaveBeenCalled();
});
it("shows the host lifecycle in Evidence, not a UI-inferred successful verification", async () => {
 const saved = { id: "build", operation: "build_android_candidate", status: "completed", requestHash: "c".repeat(64),
  evidence: { tool: "synthetic-test", resultHash: "d".repeat(64), outputPaths: [] },
  candidateLifecycle: { version: "android-candidate-lifecycle/v1", buildPlanId: "build", outputSha256: "a".repeat(64), publication: "new-unsigned-candidate", verificationAttempts: [], totalLinkedAttempts: 0, omittedAttempts: 0, rejectedLinks: 0, signing: "not-attested", device: "not-linked", limitations: ["No execution or approval."] },
 };
 const invoke = vi.spyOn(desktopClient, "invoke").mockImplementation(async (command: string) => command === "list_analysis_tasks" ? [saved] : {});
 await act(async () => { root.render(<AnalysisWorkbench cwd="/owned" environmentId="local" />); await Promise.resolve(); });
 const button = [...container.querySelectorAll("button")].find(b => b.textContent?.trim() === "Evidence");
 await act(async () => button?.click());
 expect(container.querySelector('[aria-label="Android candidate lifecycle"]')?.textContent).toContain("No matching retained APK verification attempt");
 expect(invoke.mock.calls.some(([name]) => /prepare|approve|run_static|execute/.test(name))).toBe(false);
});
