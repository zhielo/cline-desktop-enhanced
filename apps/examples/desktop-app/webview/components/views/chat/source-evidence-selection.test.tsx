// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { SourceEvidenceSelection } from "../../../../shared/source-evidence-selection";
import {
	AnalysisProjectSelectionProvider,
	sourceReferenceStorageKey,
	SharedArtifactSelection,
	useAnalysisProjectSelection,
} from "./analysis-project-selection";
import { FirstPartyAnalysisWorkspace } from "./first-party-analysis-workspace";
import { SharedSourceEvidencePanel } from "./source-evidence-selection";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@/lib/desktop-client", () => ({ desktopClient: { invoke } }));
const receiptId = "00000000-0000-4000-8000-000000000001",
	factId = `ev_${"a".repeat(64)}`;
let container: HTMLDivElement, root: Root;
const response = (): SourceEvidenceSelection => ({
	version: "source-evidence-selection/v1",
	receiptId,
	factId,
	sessionId: "owning",
	workspace: "/owned",
	path: "owned.ts",
	expectedSha256: "b".repeat(64),
	requestHash: "c".repeat(64),
	resultHash: "d".repeat(64),
	status: "matched",
	checkedAt: "2026-10-16T00:00:00Z",
	note: "Snapshot only; not approval.",
	location: { line: 2, column: 1 },
	preview: {
		lines: [
			{ line: 2, text: "<script>NEVER_EXECUTE</script>", truncated: false },
		],
		truncated: false,
	},
});
function Controls() {
	const p = useAnalysisProjectSelection()!;
	return (
		<>
			<button
				type="button"
				onClick={() =>
					p.setSourceEvidence({ receiptId, selector: { kind: "fact", factId } })
				}
			>
				Select fact
			</button>
			<button
				type="button"
				onClick={() =>
					p.setSourceEvidence({
						receiptId,
						selector: { kind: "artifact", path: "other.ts" },
					})
				}
			>
				Select other
			</button>
			<button
				type="button"
				onClick={() => {
					p.setRemember(true);
					p.setTarget("remembered.ts");
				}}
			>
				Remember path
			</button>
			<output>Target: {p.target}</output>
		</>
	);
}
async function render(
	scope = "local:owned:owning",
	sessionId = "owning",
	environmentId = "local",
) {
	await act(async () =>
		root.render(
			<AnalysisProjectSelectionProvider scope={scope}>
				<Controls />
				<SharedArtifactSelection />
				<SharedSourceEvidencePanel
					sessionId={sessionId}
					environmentId={environmentId}
				/>
			</AnalysisProjectSelectionProvider>,
		),
	);
}
async function click(label: string) {
	await act(async () => {
		const b = [...container.querySelectorAll("button")].find(
			(b) => b.textContent === label,
		);
		expect(b).toBeTruthy();
		b!.click();
	});
}
beforeEach(() => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	invoke.mockReset();
	invoke.mockResolvedValue(response());
	localStorage.clear();
	container = document.createElement("div");
	document.body.append(container);
	root = createRoot(container);
});
afterEach(async () => {
	await act(async () => root.unmount());
	container.remove();
	localStorage.clear();
});
it("reads only after explicit evidence selection and renders escaped, exact source provenance", async () => {
	await render();
	expect(invoke).not.toHaveBeenCalled();
	await click("Select fact");
	expect(invoke.mock.calls).toEqual([
		[
			"first_party_analysis_select_source",
			{
				sessionId: "owning",
				environmentId: "local",
				input: { receiptId, selector: { kind: "fact", factId } },
			},
		],
	]);
	expect(container.textContent).toContain("Source identity: matched");
	expect(container.textContent).toContain("<script>NEVER_EXECUTE</script>");
	expect(container.querySelector("script")).toBeNull();
	expect(
		container.querySelector('[aria-current="location"]')?.textContent,
	).toContain("2:");
	expect(container.textContent).toContain(response().expectedSha256);
	await click("Use source path in analysis panes");
	expect(container.textContent).toContain("Target: owned.ts");
	expect(
		container.querySelector('[aria-label="Selected source evidence"]'),
	).toBeNull();
	expect(invoke).toHaveBeenCalledTimes(1);
});
it("explicitly rechecks and withholds all source preview for stale evidence", async () => {
	await render();
	await click("Select fact");
	invoke.mockResolvedValue({
		...response(),
		status: "stale",
		note: "Changed bytes",
		preview: response().preview,
	});
	await click("Recheck selected source");
	expect(invoke).toHaveBeenCalledTimes(2);
	expect(container.textContent).toContain("Source identity: stale");
	expect(
		container.querySelector('[aria-label="Bounded source snapshot"]'),
	).toBeNull();
	expect(container.textContent).not.toContain("NEVER_EXECUTE");
	expect(container.textContent).not.toContain("Use source path");
});
it("discards an old pending response after a new selection and clear", async () => {
	let resolve!: (r: SourceEvidenceSelection) => void;
	invoke.mockImplementationOnce(
		() =>
			new Promise<SourceEvidenceSelection>((r) => {
				resolve = r;
			}),
	);
	await render();
	await click("Select fact");
	invoke.mockResolvedValue({
		...response(),
		factId: undefined,
		path: "other.ts",
		preview: undefined,
	});
	await click("Select other");
	await act(async () => resolve(response()));
	expect(container.textContent).toContain("other.ts");
	expect(container.textContent).not.toContain("NEVER_EXECUTE");
	await click("Clear source evidence selection");
	expect(
		container.querySelector('[aria-label="Selected source evidence"]'),
	).toBeNull();
});
it.each([
	"sessionId",
	"receiptId",
	"factId",
])("rejects mismatched response %s", async (key) => {
	invoke.mockResolvedValue({ ...response(), [key]: "other" });
	await render();
	await click("Select fact");
	expect(container.querySelector('[role="alert"]')?.textContent).toContain(
		"did not match",
	);
	expect(
		container.querySelector('[aria-label="Bounded source snapshot"]'),
	).toBeNull();
});
it("does not persist evidence selection with remembered path or across scope/remount", async () => {
	await render();
	await click("Remember path");
	await click("Select fact");
	expect(JSON.parse(localStorage.getItem("local:owned:owning")!)).toEqual({
		version: 1,
		target: "remembered.ts",
	});
	await render("local:other:owning");
	expect(
		container.querySelector('[aria-label="Selected source evidence"]'),
	).toBeNull();
	await render();
	expect(container.textContent).toContain("Target: remembered.ts");
	expect(
		container.querySelector('[aria-label="Selected source evidence"]'),
	).toBeNull();
});
it("never invokes a source read on a remote connection", async () => {
	await render("remote:owned:owning", "owning", "remote");
	await click("Select fact");
	expect(invoke).not.toHaveBeenCalled();
	expect(
		[...container.querySelectorAll("button")].find(
			(b) => b.textContent === "Recheck selected source",
		)?.disabled,
	).toBe(true);
});
it("clears pending selections on scope changes without showing late bytes", async () => {
	let resolve!: (r: SourceEvidenceSelection) => void;
	invoke.mockImplementationOnce(
		() =>
			new Promise<SourceEvidenceSelection>((r) => {
				resolve = r;
			}),
	);
	await render();
	await click("Select fact");
	await render("local:owned:other", "other");
	await act(async () => resolve(response()));
	expect(container.textContent).not.toContain("NEVER_EXECUTE");
	expect(
		container.querySelector('[aria-label="Selected source evidence"]'),
	).toBeNull();
});

it("selects the actual retained artifact and fact rows without preparing or rerunning analysis", async () => {
	invoke.mockImplementation(
		async (command: string, args?: Record<string, unknown>) => {
			if (command === "first_party_analysis_status")
				return {
					mode: "off",
					receipts: [
						{
							id: receiptId,
							status: "completed",
							target: "owned.ts",
							createdAt: "2026-10-16",
						},
					],
					readiness: {},
				};
			if (command === "first_party_analysis_evidence") {
				const query = args?.query as { view: string };
				return {
					items:
						query.view === "artifacts"
							? [{ path: "owned.ts", sha256: response().expectedSha256 }]
							: [
									{
										id: factId,
										kind: "call",
										location: { path: "owned.ts", line: 2, column: 1 },
									},
								],
					nextOffset: null,
					total: 1,
				};
			}
			if (command === "first_party_analysis_select_source") return response();
			throw new Error(`Unexpected command ${command}`);
		},
	);
	await act(async () =>
		root.render(
			<AnalysisProjectSelectionProvider scope="local:owned:owning">
				<SharedSourceEvidencePanel sessionId="owning" environmentId="local" />
				<FirstPartyAnalysisWorkspace sessionId="owning" environmentId="local" />
			</AnalysisProjectSelectionProvider>,
		),
	);
	await act(async () => {
		const select = container.querySelector<HTMLSelectElement>(
			'select[aria-label="Saved analysis receipt"]',
		)!;
		select.value = receiptId;
		select.dispatchEvent(new Event("change", { bubbles: true }));
	});
	await click("artifacts");
	await click("Inspect saved source identity");
	expect(invoke).toHaveBeenCalledWith("first_party_analysis_select_source", {
		sessionId: "owning",
		environmentId: "local",
		input: { receiptId, selector: { kind: "artifact", path: "owned.ts" } },
	});
	await click("findings");
	await click("Inspect saved source identity");
	expect(invoke).toHaveBeenCalledWith("first_party_analysis_select_source", {
		sessionId: "owning",
		environmentId: "local",
		input: { receiptId, selector: { kind: "fact", factId } },
	});
	expect(container.textContent).toContain("Source identity: matched");
	expect(
		invoke.mock.calls.every(([c]) =>
			[
				"first_party_analysis_status",
				"first_party_analysis_evidence",
				"first_party_analysis_select_source",
			].includes(c),
		),
	).toBe(true);
});

async function toggleReference() {
	await act(async () => {
		const label = [...container.querySelectorAll("label")].find((l) =>
			l.textContent?.includes("Remember this evidence reference"),
		);
		expect(label).toBeTruthy();
		label!.querySelector<HTMLInputElement>("input")!.click();
	});
}
it("restores only opted-in selector metadata and performs no read until explicit recheck", async () => {
	await render();
	await click("Select fact");
	await toggleReference();
	const key = sourceReferenceStorageKey("local:owned:owning");
	expect(JSON.parse(localStorage.getItem(key)!)).toEqual({
		version: 1,
		selection: { receiptId, selector: { kind: "fact", factId } },
	});
	expect(localStorage.getItem(key)).not.toContain(response().expectedSha256);
	expect(localStorage.getItem(key)).not.toContain("NEVER_EXECUTE");
	await act(async () => root.render(null));
	invoke.mockClear();
	await render();
	expect(invoke).not.toHaveBeenCalled();
	expect(container.textContent).toContain("recheck required");
	expect(container.textContent).not.toContain("Source identity: matched");
	expect(
		container.querySelector('[aria-label="Bounded source snapshot"]'),
	).toBeNull();
	await click("Recheck selected source");
	expect(invoke).toHaveBeenCalledTimes(1);
	expect(invoke).toHaveBeenCalledWith("first_party_analysis_select_source", {
		sessionId: "owning",
		environmentId: "local",
		input: { receiptId, selector: { kind: "fact", factId } },
	});
	expect(container.textContent).toContain("Source identity: matched");
});
it("keeps remembered references isolated by workspace, environment and chat", async () => {
	await render();
	await click("Select fact");
	await toggleReference();
	invoke.mockClear();
	for (const scope of [
		"local:other:owning",
		"remote:owned:owning",
		"local:owned:other",
	]) {
		await render(scope);
		expect(
			container.querySelector('[aria-label="Selected source evidence"]'),
		).toBeNull();
	}
	await render();
	expect(invoke).not.toHaveBeenCalled();
	expect(container.textContent).toContain("recheck required");
});
it("unchecking forgets the saved reference but keeps the live selection without another read", async () => {
	await render();
	await click("Select fact");
	await toggleReference();
	await toggleReference();
	expect(invoke).toHaveBeenCalledTimes(1);
	expect(
		localStorage.getItem(sourceReferenceStorageKey("local:owned:owning")),
	).toBeNull();
	expect(container.textContent).toContain("Source identity: matched");
	await act(async () => root.render(null));
	await render();
	expect(
		container.querySelector('[aria-label="Selected source evidence"]'),
	).toBeNull();
});
it.each([
	"Clear source evidence selection",
	"Clear shared selection and saved path",
	"Remember path",
])("%s forgets both the pending and saved source selector", async (action) => {
	await render();
	await click("Select fact");
	await toggleReference();
	await click(action);
	expect(
		localStorage.getItem(sourceReferenceStorageKey("local:owned:owning")),
	).toBeNull();
	expect(
		container.querySelector('[aria-label="Selected source evidence"]'),
	).toBeNull();
	await act(async () => root.render(null));
	await render();
	expect(
		container.querySelector('[aria-label="Selected source evidence"]'),
	).toBeNull();
});
it.each([
	"stale",
	"missing",
	"unsupported",
])("rechecks restored %s evidence without a preview or implicit run", async (status) => {
	await render();
	await click("Select fact");
	await toggleReference();
	await act(async () => root.render(null));
	invoke.mockClear();
	invoke.mockResolvedValue({ ...response(), status });
	await render();
	expect(invoke).not.toHaveBeenCalled();
	await click("Recheck selected source");
	expect(invoke).toHaveBeenCalledTimes(1);
	expect(container.textContent).toContain(`Source identity: ${status}`);
	expect(
		container.querySelector('[aria-label="Bounded source snapshot"]'),
	).toBeNull();
	expect(container.textContent).not.toContain(
		"Use source path in analysis panes",
	);
});
it("retains an unavailable restored reference for explicit retry without falling back to a path", async () => {
	await render();
	await click("Select fact");
	await toggleReference();
	await act(async () => root.render(null));
	invoke.mockClear();
	invoke.mockRejectedValueOnce(
		new Error("Receipt removed or belongs to another session"),
	);
	await render();
	await click("Recheck selected source");
	expect(container.querySelector('[role="alert"]')?.textContent).toContain(
		"Receipt removed",
	);
	expect(
		container.querySelector('[aria-label="Bounded source snapshot"]'),
	).toBeNull();
	expect(invoke).toHaveBeenCalledTimes(1);
	await click("Recheck selected source");
	expect(container.textContent).toContain("Source identity: matched");
});
it("never automatically reads a restored reference in remote or detached contexts", async () => {
	const value = {
		version: 1,
		selection: { receiptId, selector: { kind: "fact", factId } },
	};
	for (const [sessionId, environmentId] of [
		["owning", "remote"],
		["", "local"],
	]) {
		await act(async () => root.render(null));
		localStorage.setItem(
			sourceReferenceStorageKey("local:owned:owning"),
			JSON.stringify(value),
		);
		await render("local:owned:owning", sessionId, environmentId);
		await click("Recheck selected source");
		expect(invoke).not.toHaveBeenCalled();
		expect(container.textContent).toContain("recheck required");
	}
});
it("rejects malformed, authority-bearing and oversized saved reference records", async () => {
	const good = { receiptId, selector: { kind: "fact", factId } };
	for (const value of [
		"{",
		"x".repeat(32769),
		JSON.stringify({ version: 2, selection: good }),
		JSON.stringify({ version: 1, selection: good, executionToken: "bad" }),
		JSON.stringify({
			version: 1,
			selection: { ...good, expectedSha256: "a".repeat(64) },
		}),
		JSON.stringify({
			version: 1,
			selection: {
				receiptId,
				selector: { kind: "fact", factId, command: "bad" },
			},
		}),
		JSON.stringify({
			version: 1,
			selection: { receiptId: "bad", selector: good.selector },
		}),
		JSON.stringify({
			version: 1,
			selection: {
				receiptId,
				selector: { kind: "artifact", path: "bad\npath" },
			},
		}),
	]) {
		await act(async () => root.render(null));
		localStorage.setItem(
			sourceReferenceStorageKey("local:owned:owning"),
			value,
		);
		await render();
		expect(invoke).not.toHaveBeenCalled();
		expect(
			container.querySelector('[aria-label="Selected source evidence"]'),
		).toBeNull();
		expect(
			localStorage.getItem(sourceReferenceStorageKey("local:owned:owning")),
		).toBeNull();
	}
});
it("restores an exact artifact selector without inventing fact identity", async () => {
	const selection = {
		receiptId,
		selector: { kind: "artifact", path: "other.ts" },
	};
	localStorage.setItem(
		sourceReferenceStorageKey("local:owned:owning"),
		JSON.stringify({ version: 1, selection }),
	);
	await render();
	expect(invoke).not.toHaveBeenCalled();
	invoke.mockResolvedValue({
		...response(),
		factId: undefined,
		path: "other.ts",
	});
	await click("Recheck selected source");
	expect(invoke.mock.calls[0][1].input).toEqual(selection);
	expect(container.textContent).toContain("Source identity: matched");
});
it("reports failed reference removal while leaving the live selection cleared", async () => {
	await render();
	await click("Select fact");
	await toggleReference();
	const spy = vi
		.spyOn(Storage.prototype, "removeItem")
		.mockImplementation(() => {
			throw new Error("disabled");
		});
	try {
		await click("Clear source evidence selection");
		expect(
			container.querySelector('[aria-label="Selected source evidence"]'),
		).toBeNull();
		expect(container.textContent).toContain(
			"Saved source reference updates or removal could not be confirmed",
		);
	} finally {
		spy.mockRestore();
	}
});

it("does not carry opt-in storage consent to a different selected evidence reference", async () => {
	await render();
	await click("Select fact");
	await toggleReference();
	invoke.mockResolvedValue({
		...response(),
		factId: undefined,
		path: "other.ts",
	});
	await click("Select other");
	expect(
		localStorage.getItem(sourceReferenceStorageKey("local:owned:owning")),
	).toBeNull();
	const label = [...container.querySelectorAll("label")].find((l) =>
		l.textContent?.includes("Remember this evidence reference"),
	)!;
	expect(label.querySelector<HTMLInputElement>("input")!.checked).toBe(false);
	expect(container.textContent).toContain("other.ts");
});
it("never accepts a late source read as fresh evidence after remount", async () => {
	await render();
	await click("Select fact");
	await toggleReference();
	let resolve!: (value: SourceEvidenceSelection) => void;
	invoke.mockImplementationOnce(
		() =>
			new Promise<SourceEvidenceSelection>((r) => {
				resolve = r;
			}),
	);
	await click("Recheck selected source");
	await act(async () => root.render(null));
	invoke.mockClear();
	await render();
	await act(async () => resolve(response()));
	expect(invoke).not.toHaveBeenCalled();
	expect(container.textContent).toContain("recheck required");
	expect(
		container.querySelector('[aria-label="Bounded source snapshot"]'),
	).toBeNull();
	expect(container.textContent).not.toContain("Source identity: matched");
});
