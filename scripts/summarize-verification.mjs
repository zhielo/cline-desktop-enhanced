import { appendFile, lstat, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const cell = value => String(value ?? "").replace(/[|`<>\r\n\x00-\x1f\x7f]/g, " ").slice(0, 100);
export function validationTimings(report, scope) {
  if (report?.sourceCommit !== scope.sha || !/^[a-f0-9]{40}$/.test(scope.sha ?? "") ||
      ["runId", "runAttempt", "job"].some(k => report.executionScope?.[k] !== scope[k]) ||
      !Array.isArray(report.results) || report.results.length > 100) return [];
  return report.results.filter(r => typeof r.name === "string" && Number.isFinite(r.durationMs) && r.durationMs >= 0)
    .map(r => ({ name: cell(r.name), status: cell(r.status), durationMs: r.durationMs }));
}
export function actionTimings(text) {
  if (Buffer.byteLength(text) > 2 * 1024 * 1024) throw new Error("Action journal exceeds timing budget");
  const active = new Map(), rows = [];
  for (const line of text.split("\n")) {
    if (!line) continue;
    let r; try { r = JSON.parse(line); } catch { continue; }
    if (!Number.isSafeInteger(r.sequence) || r.sequence < 1 || typeof r.phase !== "string" || !/^[a-z0-9_-]{1,100}$/.test(r.phase)) continue;
    const at = Date.parse(r.at);
    if (!Number.isFinite(at)) continue;
    if (r.status === "running" && !active.has(r.sequence)) active.set(r.sequence, { phase: r.phase, at });
    else if (["completed", "failed"].includes(r.status)) {
      const start = active.get(r.sequence);
      if (start?.phase === r.phase && at >= start.at) {
        rows.push({ name: r.phase, status: r.status, durationMs: at - start.at });
        active.delete(r.sequence);
      }
    }
  }
  return rows;
}
export function formatTimings(gates, actions) {
  const table = rows => rows.slice().sort((a,b) => b.durationMs-a.durationMs).slice(0,10)
    .map(r => `| ${cell(r.name)} | ${cell(r.status)} | ${(r.durationMs/1000).toFixed(2)} |`).join("\n");
  return `## Verification bottlenecks (diagnostic only)\n\n### Longest validation gates\n\n| Gate | Outcome | Seconds |\n| --- | --- | ---: |\n${table(gates)}\n\n### Longest journaled installed actions\n\n| Action | Outcome | Seconds |\n| --- | --- | ---: |\n${table(actions)}\n\nThese are observations, not a release certificate or proof of a speed improvement. Concurrent durations are not additive wall time. The action journal covers instrumented actions only, not the entire installed journey. Missing data remains unavailable; required gates are never inferred or skipped. No child logs, paths, requests, credentials or environment values are copied here.\n`;
}
async function boundedRead(file, limit) {
  const s = await lstat(file);
  if (!s.isFile() || s.isSymbolicLink() || s.size > limit) throw new Error("Timing input unavailable or oversized");
  const text = await readFile(file,"utf8");
  if (Buffer.byteLength(text) > limit) throw new Error("Timing input grew beyond budget");
  return text;
}
export async function summarize(root, env = process.env) {
  const gates = [], actions = [];
  const scope = {sha:env.GITHUB_SHA,runId:env.GITHUB_RUN_ID,runAttempt:env.GITHUB_RUN_ATTEMPT,job:env.GITHUB_JOB};
  const dir = path.join(root,".cline-validation");
  let entries = [];
  try { entries = await readdir(dir,{withFileTypes:true}); } catch { /* No validation ran. */ }
  if (entries.length <= 100) for (const e of entries) {
    if (!e.isDirectory() || !/^[0-9]+-[0-9]+$/.test(e.name)) continue;
    try { gates.push(...validationTimings(JSON.parse(await boundedRead(path.join(dir,e.name,"summary.json"),131072)),scope)); } catch { /* Diagnostics never invent absent durations. */ }
  }
  const evidence = path.join(root,"apps/examples/desktop-app/dist/installed-ui-evidence");
  try {
    const summary=JSON.parse(await boundedRead(path.join(evidence,"summary.json"),131072));
    if (/^[a-f0-9]{40}$/.test(scope.sha ?? "") && summary.sourceCommit===scope.sha)
      actions.push(...actionTimings(await boundedRead(path.join(evidence,"action-progress.jsonl"),2*1024*1024)));
  } catch { /* A crash may have no final receipt: do not attribute stale journals. */ }
  return formatTimings(gates,actions);
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) throw new Error("Timing reporter accepts no paths or flags");
  const report = await summarize(fileURLToPath(new URL("../",import.meta.url)));
  if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY,report);
  else console.log(report);
}
