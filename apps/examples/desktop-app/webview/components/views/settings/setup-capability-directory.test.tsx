// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { setupCapabilityCatalog } from "@cline/core";
import { SetupCapabilityDirectoryView } from "./setup-capability-directory";

it("shows every registered route and the four real framework scopes without granting readiness", async () => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	const element = document.createElement("div");
	document.body.append(element);
	const root = createRoot(element);
	const fetcher = vi.spyOn(globalThis, "fetch");
	const catalog = setupCapabilityCatalog();
	try {
		await act(async () =>
			root.render(
				<SetupCapabilityDirectoryView
					catalog={catalog}
					frameworks={[
						{
							id: "qiling",
							configuration: "configured-not-tested",
							installation: "not-bundled-or-managed",
							readiness: "not-established",
						},
					]}
				/>,
			),
		);
		for (const id of ["qiling", "unidbg", "rnidbg", "speakeasy"])
			expect(
				element.querySelector(`[aria-label="${id} framework"]`),
			).not.toBeNull();
		for (const row of [
			...catalog.engineRoutes,
			...catalog.specialistRoutes,
			...catalog.additionalRoutes,
			...catalog.binaryTriage,
			catalog.firstParty,
		])
			expect(element.textContent).toContain(row.id);
		expect(element.textContent).toContain("Configured, not tested");
		expect(element.textContent).toContain("Readiness not established");
		expect(element.textContent).toContain("Static Linux x86-64 ELF entry");
		expect(element.textContent).toContain("Android ARM32/64");
		expect(element.textContent).toContain(
			"App-managed Install → Test → Use is not implemented",
		);
		expect(element.textContent).toContain(
			"not proof that a tool is exposed to the current model",
		);
		expect(element.querySelectorAll("button")).toHaveLength(0);
		expect(fetcher).not.toHaveBeenCalled();
	} finally {
		fetcher.mockRestore();
		await act(async () => root.unmount());
		element.remove();
	}
});

it("does not invent readiness or architecture support when the catalog is unavailable", async () => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	const element = document.createElement("div");
	const root = createRoot(element);
	try {
		await act(async () => root.render(<SetupCapabilityDirectoryView />));
		expect(element.textContent).toContain("Backend catalog unavailable");
		expect(element.textContent).toContain("Configuration status unavailable");
		expect(element.textContent).not.toContain("Static Linux x86-64 ELF entry");
	} finally {
		await act(async () => root.unmount());
	}
});
