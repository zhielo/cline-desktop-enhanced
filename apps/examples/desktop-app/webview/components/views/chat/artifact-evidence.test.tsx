// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { desktopClient } from "@/lib/desktop-client";
import { ArtifactContextMenu } from "./artifact-context-menu";
import { CodeChangePreview } from "./messages/code-change-preview";

// Model menu selection without depending on browser context-menu positioning.
vi.mock("@/components/ui/context-menu", () => ({
	ContextMenu: ({ children }: { children: React.ReactNode }) => (
		<div>{children}</div>
	),
	ContextMenuTrigger: ({ children }: { children: React.ReactNode }) => (
		<div>{children}</div>
	),
	ContextMenuContent: ({ children }: { children: React.ReactNode }) => (
		<div>{children}</div>
	),
	ContextMenuItem: ({
		children,
		onSelect,
	}: {
		children: React.ReactNode;
		onSelect: () => void;
	}) => (
		<button type="button" onClick={onSelect}>
			{children}
		</button>
	),
	ContextMenuSeparator: () => null,
}));
let container: HTMLDivElement, root: Root;
beforeEach(() => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	container = document.createElement("div");
	document.body.appendChild(container);
	root = createRoot(container);
});
afterEach(async () => {
	await act(async () => root.unmount());
	container.remove();
	vi.restoreAllMocks();
});
it("requests an explicit member preview bound to originating workspace and container hash", async () => {
	const hash = "a".repeat(64),
		invoke = vi
			.spyOn(desktopClient, "invoke")
			.mockImplementation(async (command) =>
				command === "inspect_artifact_evidence"
					? ({
							path: "C:\\work\\report.xlsx",
							workspace: "C:\\work",
							sha256: hash,
							size: 12,
							classification: "archive-container",
							members: [
								{ name: "xl/worksheets/sheet1.xml", bytes: 4, safe: true },
							],
						} as never)
					: ({
							path: "C:\\work\\report.xlsx",
							kind: "text",
							size: 4,
							content: "test",
						} as never),
			);
	await act(async () =>
		root.render(
			<ArtifactContextMenu
				cwd={"C:\\work"}
				environmentId="local"
				path="report.xlsx"
				onOpen={() => {}}
			>
				<span>artifact</span>
			</ArtifactContextMenu>,
		),
	);
	await act(async () => {
		Array.from(container.querySelectorAll("button"))
			.find((b) => b.textContent?.includes("Inspect evidence / archive"))
			?.click();
	});
	expect(invoke.mock.calls).toHaveLength(1);
	const select = document.querySelector<HTMLSelectElement>(
		'select[aria-label="Archive member"]',
	)!;
	await act(async () => {
		select.value = "xl/worksheets/sheet1.xml";
		select.dispatchEvent(new Event("change", { bubbles: true }));
	});
	expect(invoke.mock.calls[1]).toEqual([
		"preview_archive_member",
		{
			path: "report.xlsx",
			cwd: "C:\\work",
			environmentId: "local",
			member: "xl/worksheets/sheet1.xml",
			expectedHash: hash,
		},
	]);
	expect(
		invoke.mock.calls.some((c) =>
			["open_artifact", "reveal_artifact_in_folder"].includes(c[0]),
		),
	).toBe(false);
});

it("keeps long Markdown in a focusable bounded scroll region without executing it", async () => {
	const content = Array.from({ length: 240 }, (_, i) => `Owned line ${i}`).join(
		"\n",
	);
	const invoke = vi.spyOn(desktopClient, "invoke").mockResolvedValue({
		path: "C:\\work\\report.md",
		name: "report.md",
		size: 35000,
		kind: "text",
		content,
		modifiedAt: "2026-10-09T00:00:00Z",
	} as never);
	await act(async () =>
		root.render(
			<ArtifactContextMenu
				cwd="C:\\work"
				environmentId="local"
				path="report.md"
				primaryAction="preview"
				onOpen={() => {}}
			>
				<a href="#owned">report.md</a>
			</ArtifactContextMenu>,
		),
	);
	await act(async () => container.querySelector("a")?.click());
	const region = document.querySelector<HTMLElement>(
		'[data-testid="artifact-preview-scroll"]',
	)!;
	expect(region.textContent).toContain("Owned line 239");
	expect(region.tabIndex).toBe(0);
	expect(region.className).toContain("min-h-0");
	expect(region.className).toContain("flex-1");
	expect(region.className).toContain("overflow-auto");
	expect(region.closest('[data-slot="dialog-content"]')?.className).toContain(
		"flex-col",
	);
	region.focus();
	expect(document.activeElement).toBe(region);
	expect(invoke.mock.calls.map((c) => c[0])).toEqual(["read_artifact_preview"]);
});

it("opens recorded code by tap and keyboard without reading/executing a file", async () => {
	const invoke = vi.spyOn(desktopClient, "invoke");
	const code = Array.from(
		{ length: 158 },
		(_, i) => `Owned code line ${i}`,
	).join("\n");
	await act(async () =>
		root.render(
			<CodeChangePreview
				path="Owned.smali"
				newText={code}
				oldText="old fragment"
				fragment
			>
				<span>green code snippet</span>
			</CodeChangePreview>,
		),
	);
	await act(async () =>
		document
			.querySelector<HTMLElement>('[data-testid="recorded-code-trigger"]')
			?.click(),
	);
	const scroll = document.querySelector<HTMLElement>(
		'[data-testid="recorded-code-scroll"]',
	)!;
	expect(scroll.textContent).toContain("Owned code line 157");
	expect(scroll.tabIndex).toBe(0);
	expect(scroll.className).toContain("overflow-auto");
	expect(document.body.textContent).toContain("not the full or current file");
	await act(async () =>
		Array.from(document.querySelectorAll("button"))
			.find((b) => b.textContent === "Before change")
			?.click(),
	);
	expect(scroll.textContent).toBe("old fragment");
	await act(async () =>
		document.querySelector<HTMLElement>('[data-slot="dialog-close"]')?.click(),
	);
	await act(async () =>
		document
			.querySelector<HTMLElement>('[data-testid="recorded-code-trigger"]')
			?.dispatchEvent(
				new KeyboardEvent("keydown", { key: "Enter", bubbles: true }),
			),
	);
	expect(
		document.querySelector('[data-testid="recorded-code-scroll"]')?.textContent,
	).toContain("Owned code line 157");
	expect(invoke).not.toHaveBeenCalled();
});
