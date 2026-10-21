import { runAnalysisWorkerEntrypoint } from "../sdk/packages/core/src/analysis/worker";
if (!process.argv.includes("--cline-analysis-worker"))
	throw new Error("Owned worker entry only");
await runAnalysisWorkerEntrypoint();
