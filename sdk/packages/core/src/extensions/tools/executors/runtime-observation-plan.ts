import { canonical } from "../../../analysis/contracts";
import { assertInspectorOwner } from "../../../analysis/inspector";
import { probeProcessStartTokenAsync } from "../../../runtime/process-start-token";
import { RuntimeObservationPlanSchema } from "../runtime-observation-schema";
import type { ReverseEngineeringInput } from "../schemas";
import { candidateHash, readCandidateFile } from "./candidate-files";

/** No WebSocket, CDP command, target execution, process launch or debugger attachment. */
export async function planRuntimeObservation(input: ReverseEngineeringInput, signal?: AbortSignal) {
 if (!input.target) throw new Error("Exact selected source required");
 if (input.output_file || input.output_directory || input.compare_target || input.candidate || input.android_project_patch || input.candidate_validation || input.candidate_review) throw new Error("Runtime planning accepts no writes, patch or verification recipes");
 const options = RuntimeObservationPlanSchema.parse(input.runtime_observation_plan);
 const url = new URL(options.endpoint);
 if (url.protocol !== "ws:" || url.hostname !== "127.0.0.1" || url.username || url.password || url.search || url.hash || !url.port || !/^\/[a-f0-9-]{36}$/i.test(url.pathname)) throw new Error("Only an exact loopback Node Inspector endpoint is supported");
 const combined = AbortSignal.any([...(signal ? [signal] : []), AbortSignal.timeout(Math.min(input.timeout_ms ?? 20000, 20000))]);
 const check = async () => {
  combined.throwIfAborted();
  const p = await probeProcessStartTokenAsync(options.pid);
  combined.throwIfAborted();
  if (p.status !== "found" || p.token !== options.processToken) throw new Error("Selected process birth identity changed or is unavailable");
  await assertInspectorOwner(options.pid, Number(url.port));
  combined.throwIfAborted();
 };
 const bytes = await readCandidateFile(input.target, 1048576, combined);
 if (candidateHash(bytes) !== options.expected_sha256) throw new Error("Selected source hash changed");
 // The planner checks OS process/listener identity only, not the remote protocol or loaded source.
 await check();
 const nextRequest = { operation: "js_inspector_observe", target: input.target, pid: options.pid,
  processToken: options.processToken, endpoint: options.endpoint,
  durationMs: options.durationMs, captureConsole: options.captureConsole };
 const receipt = {
  protocol: "cline-runtime-observation-plan/v1", operation: input.operation,
  status: "completed", effect: "plan-only", backend: options.backend,
  input: {path: input.target, sha256: options.expected_sha256, bytes: bytes.length},
  identity: {pid: options.pid, processToken: options.processToken, listenerOwnedAtPlanTime: true},
  nextRequest, nextRequestSha256: candidateHash(canonical(nextRequest)),
  approval: {granted: false, reusableExecutionToken: false, requiredMode: ["runtime", "hybrid"], requiredTaskKind: "debugger", requiredHumanReview: ["authorized-target", ...(options.captureConsole ? ["sensitive-console-protocol-capture", "private-evidence-write"] : [])], prepareCommand: "first_party_analysis_inspector_prepare", runCommand: "first_party_analysis_inspector_run", hybridStaticEvidenceRequired: true},
  budgets: {durationMs: options.durationMs, selectedSourceBytes: 1048576, consoleReports: options.captureConsole ? 24 : 0},
  cleanup: {plannerCreatedSession: false, plannerNeedsDetach: false, observation: "Existing bounded observer closes its socket; it must not resume, evaluate, launch or terminate the target."},
  observedExecution: false, attached: false, published: false,
  limitations: [
   "Only a selected live local Node Inspector listener on Linux/Windows. No native/JVM/Android persistent debugger, breakpoints, execution tracing, process-tree or file-activity capture.",
   "OS listener ownership is not Inspector protocol authentication, loaded-source identity, code execution evidence or target safety. Actual observation must recheck identity and source hash.",
   "Plan is not consent or a reusable runtime approval. Runtime/Hybrid mode and fresh human Debug approval are required by the existing runtime workbench; Hybrid additionally requires its static-evidence proposal.",
   "No socket connection, target launch, debugger attachment, evaluation, resume, download, target write or automatic observation occurred. Process identity can change immediately after this read-only plan.",
  ],
 };
 if (candidateHash(await readCandidateFile(input.target, 1048576, combined)) !== options.expected_sha256) throw new Error("Selected source changed during planning");
 await check();
 return {...receipt, receiptSha256: candidateHash(canonical(receipt))};
}
