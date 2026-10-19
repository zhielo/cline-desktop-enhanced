// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import {
	AnalysisProjectSelectionProvider,
	SharedArtifactSelection,
	analysisProjectScope,
	useAnalysisProjectTarget,
} from "./analysis-project-selection";
let container: HTMLDivElement, root: Root;
const scope = analysisProjectScope("local", "/owned", "session-one");
function Pane({ name, fallback = "" }: { name: string; fallback?: string }) {
	const [target, setTarget] = useAnalysisProjectTarget(fallback);
	return (
		<input
			aria-label={name}
			value={target}
			onChange={(e) => setTarget(e.target.value)}
		/>
	);
}
async function render(key = scope) {
	await act(async () =>
		root.render(
			<AnalysisProjectSelectionProvider scope={key}>
				<SharedArtifactSelection />
				<Pane name="Android" />
				<Pane name="Source" fallback="." />
			</AnalysisProjectSelectionProvider>,
		),
	);
}
function input(label: string) {
	return container.querySelector<HTMLInputElement>(
		`input[aria-label="${label}"]`,
	)!;
}
async function type(label: string, value: string) {
	await act(async () => {
		Object.getOwnPropertyDescriptor(
			HTMLInputElement.prototype,
			"value",
		)!.set!.call(input(label), value);
		input(label).dispatchEvent(new Event("input", { bubbles: true }));
	});
}
async function remember() {
	await act(async () =>
		container
			.querySelector<HTMLInputElement>('input[type="checkbox"]')!
			.click(),
	);
}
beforeEach(() => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	localStorage.clear();
	container = document.createElement("div");
	document.body.append(container);
	root = createRoot(container);
});
afterEach(async () => {
	await act(async () => root.unmount());
	container.remove();
	localStorage.clear();
	vi.restoreAllMocks();
});
it("shares exact path metadata across panes without silently persisting it", async () => {
	await render();
	expect(input("Source").value).toBe(".");
	await type("Android", "/owned/app.apk");
	expect(input("Source").value).toBe("/owned/app.apk");
	expect(input("Shared artifact path").value).toBe("/owned/app.apk");
	expect(localStorage.getItem(scope)).toBeNull();
	await type("Source", "");
	expect(input("Android").value).toBe("");
	expect(input("Source").value).toBe("");
});
it("restores only explicitly remembered path metadata after remount", async () => {
	await render();
	await type("Android", "/owned/fixture.ts");
	await remember();
	expect(JSON.parse(localStorage.getItem(scope)!)).toEqual({
		version: 1,
		target: "/owned/fixture.ts",
	});
	await act(async () => root.render(null));
	await render();
	expect(input("Source").value).toBe("/owned/fixture.ts");
	expect(container.textContent).toContain("no validated hash");
});
it("resets across every workspace, environment and chat boundary and restores only the exact scope", async () => {
	await render();
	await type("Android", "/owned/one.apk");
	await remember();
	for (const key of [
		analysisProjectScope("remote", "/owned", "session-one"),
		analysisProjectScope("local", "/other", "session-one"),
		analysisProjectScope("local", "/owned", "session-two"),
	]) {
		await render(key);
		expect(input("Android").value).toBe("");
		expect(
			container.querySelector<HTMLInputElement>('input[type="checkbox"]')!
				.checked,
		).toBe(false);
	}
	await render();
	expect(input("Android").value).toBe("/owned/one.apk");
});
it("rejects corrupted, oversized, authority-bearing and invalid remembered values", async () => {
	for (const raw of [
		"{",
		"x".repeat(8193),
		JSON.stringify({ version: 2, target: "owned" }),
		JSON.stringify({ version: 1, target: "owned", executionToken: "never" }),
		JSON.stringify({ version: 1, target: "a\ncommand" }),
		JSON.stringify({ version: 1, target: "x".repeat(4097) }),
	]) {
		await act(async () => root.render(null));
		localStorage.setItem(scope, raw);
		await render();
		expect(input("Android").value).toBe("");
		expect(localStorage.getItem(scope)).toBeNull();
	}
});
it("clears saved metadata without touching files or retaining authority", async () => {
	await render();
	await type("Android", "/owned/app.apk");
	await remember();
	await act(async () =>
		[...container.querySelectorAll("button")]
			.find((b) => b.textContent?.startsWith("Clear shared"))!
			.click(),
	);
	expect(localStorage.getItem(scope)).toBeNull();
	expect(input("Android").value).toBe("");
});
it("works with unavailable device storage", async () => {
	vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
		throw new Error("disabled");
	});
	vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
		throw new Error("full");
	});
	vi.spyOn(Storage.prototype, "removeItem").mockImplementation(() => {
		throw new Error("disabled");
	});
	await render();
	await type("Android", "/owned/still-usable");
	await remember();
	expect(input("Source").value).toBe("/owned/still-usable");
	expect(container.querySelector("output")?.textContent).toContain("saved path updates or removal could not be confirmed");
});
it("scope encoding cannot collide through delimiter injection", () => {
	expect(analysisProjectScope("a\u0000b", "c", "d")).not.toBe(
		analysisProjectScope("a", "b\u0000c", "d"),
	);
});
