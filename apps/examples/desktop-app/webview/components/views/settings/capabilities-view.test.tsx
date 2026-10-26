// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { describe, expect, it } from "vitest";
import { CapabilitiesView } from "./capabilities-view";
import { SETTINGS_SECTIONS } from "./sections";
import { AGENDA_UI_ENABLED } from "@/lib/feature-flags";
import { AGENDA_TODO_ENABLED } from "@cline/shared/browser";

describe("capability inventory", () => {
	it("keeps navigation and agent availability policy aligned", () => {
		expect(SETTINGS_SECTIONS).toContain("Capabilities");
		expect(SETTINGS_SECTIONS).not.toContain("Channels");
		expect(AGENDA_UI_ENABLED).toBe(AGENDA_TODO_ENABLED);
	});
	it("renders all 41 scoped families without presenting inventory as live readiness", async () => {
		Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
		const container = document.createElement("div"),
			root = createRoot(container);
		try {
			await act(async () => {
				root.render(<CapabilitiesView />);
			});
			expect(container.querySelectorAll("article")).toHaveLength(41);
			expect(container.textContent).toContain("not a readiness certificate");
			expect(container.textContent).toContain("No checks or paid requests");
			expect(container.textContent).toContain("Image understanding");
		} finally {
			await act(async () => root.unmount());
		}
	});
});
