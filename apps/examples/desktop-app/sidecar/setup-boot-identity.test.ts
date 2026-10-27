import { existsSync } from "node:fs";
import { expect, it } from "vitest";
import {
	readSetupBootIdentity,
	validSetupBootIdentity,
} from "./setup-boot-identity";
it("rejects unknown, malformed and zero boot identities", () => {
	for (const v of [
		null,
		{},
		{
			schemaVersion: 1,
			platform: "linux",
			hostId: "a".repeat(64),
			bootId: "00000000-0000-0000-0000-000000000000",
		},
	])
		expect(validSetupBootIdentity(v)).toBe(false);
});
it("reads stable OS evidence or refuses a host without an OS machine identity", async () => {
	const first = await readSetupBootIdentity();
	if (process.platform === "linux" && !existsSync("/etc/machine-id")) {
		expect(first).toBeNull(); // This container has no host identity; not a successful recovery probe.
		return;
	}
	if (["win32", "linux"].includes(process.platform)) {
		expect(validSetupBootIdentity(first)).toBe(true);
		expect(await readSetupBootIdentity()).toEqual(first);
	} else expect(first).toBeNull();
});
