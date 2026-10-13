// Exact production data-only worker implementation; no alternate benchmark algorithm.
import { runAnalysisWorkerEntrypoint } from "../sdk/packages/core/src/analysis/worker";
void runAnalysisWorkerEntrypoint().catch((error) => {
	process.stderr.write(String(error) + "\n");
	process.exitCode = 1;
});
