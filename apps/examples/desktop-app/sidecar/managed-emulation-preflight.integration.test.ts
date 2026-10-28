import { expect, it } from "vitest";
import { readManagedEmulationPreflight } from "./managed-emulation-preflight";
it("collects real Windows scalar OS observations, or explicitly skips the OS query on other hosts", async () => {
	const report = await readManagedEmulationPreflight();
	if (process.platform === "win32") {
		expect(report.platform).toBe("win32");
		expect(report.query).toBe("observed");
		expect(report.osBuild).toMatch(/^\d{4,6}$/);
		expect(report.capacity.totalMemoryGiB).not.toBeNull();
		// Hosted Windows Server may be unsupported; this is not a VM feasibility pass.
	} else {
		expect(report.platform).toBe("unsupported");
		expect(report.query).toBe("not-run");
	}
	expect(report.managedInstallation).toBe("not-implemented");
	expect(report.containment).toBe("not-tested");
	expect(report.engineReadiness).toBe("not-tested");
}, 25_000);
