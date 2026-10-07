import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
	resolve: {
		alias: {
			"@": fileURLToPath(new URL("./webview", import.meta.url)),
		},
	},
	test: {
		environment: "node",
		setupFiles: [
			fileURLToPath(new URL("./test/vitest-setup.ts", import.meta.url)),
		],
		// First test in a file pays the @cline/core → llms module-graph import
		// cost, which sits near the 5s default under CI contention.
		testTimeout: 20_000,
		// Bound module-graph memory on the hosted Windows runner. Suites still
		// execute in full; installer/UI fixtures run in separate validator jobs.
		maxWorkers: process.platform === "win32" && process.env.CI ? 2 : undefined,
	},
});
