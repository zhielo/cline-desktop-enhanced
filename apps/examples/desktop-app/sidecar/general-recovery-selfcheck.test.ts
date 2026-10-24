import { afterEach, expect, it } from "vitest";
import { selfcheckGeneralRecovery } from "./general-recovery-selfcheck";
const previousRoot = process.env.CLINE_BUNDLED_ANALYSIS_ROOT;
const previousHost = process.env.CLINE_FIRST_PARTY_ANALYSIS_HOST;
afterEach(() => {
	if (previousRoot === undefined)
		delete process.env.CLINE_BUNDLED_ANALYSIS_ROOT;
	else process.env.CLINE_BUNDLED_ANALYSIS_ROOT = previousRoot;
	if (previousHost === undefined)
		delete process.env.CLINE_FIRST_PARTY_ANALYSIS_HOST;
	else process.env.CLINE_FIRST_PARTY_ANALYSIS_HOST = previousHost;
});
it("installed fixture never reports success when its packaged engine is missing", async () => {
	delete process.env.CLINE_BUNDLED_ANALYSIS_ROOT;
	process.env.CLINE_FIRST_PARTY_ANALYSIS_HOST = JSON.stringify({
		executable: process.execPath,
		args: [],
	});
	expect(await selfcheckGeneralRecovery()).toMatchObject({
		status: "failed",
		profile: "installed-general-recovery/1",
	});
});
it.skipIf(!process.env.CLINE_TEST_WAKARU_ROOT)(
	"installed fixture requires actual pinned recovery and saved results",
	async () => {
		process.env.CLINE_BUNDLED_ANALYSIS_ROOT =
			process.env.CLINE_TEST_WAKARU_ROOT;
		process.env.CLINE_FIRST_PARTY_ANALYSIS_HOST = JSON.stringify({
			executable: process.execPath,
			args: [],
		});
		expect(await selfcheckGeneralRecovery()).toMatchObject({
			status: "passed",
			engine: "wakaru/1.14.0",
			modules: 2,
			targetExecuted: false,
			verifiedBehavior: false,
		});
	},
	30000,
);
