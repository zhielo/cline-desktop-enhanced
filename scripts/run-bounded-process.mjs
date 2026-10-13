import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
export async function runBounded(executable, args, { timeoutMs = 1200000, heartbeatMs = 30000, label = "dependency operation", env = process.env } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 1800000) throw new Error("Invalid process deadline");
  return new Promise((resolveResult, reject) => {
    const child = spawn(executable, args, { shell: false, env, stdio: "inherit", detached: process.platform !== "win32", windowsHide: true });
    const started = Date.now(); let expired = false, settled = false;
    const terminate = () => {
      if (child.exitCode !== null || !child.pid) return;
      if (process.platform === "win32") spawnSync("taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], { timeout: 10000, stdio: "ignore", windowsHide: true });
      else { try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); } }
    };
    const heartbeat = setInterval(() => console.log(`[PROGRESS] ${label}: ${Math.floor((Date.now() - started) / 1000)}s`), heartbeatMs);
    const deadline = setTimeout(() => { expired = true; console.error(`[TIMEOUT] ${label}; terminating owned process tree`); terminate(); }, timeoutMs);
    const cleanup = () => { clearInterval(heartbeat); clearTimeout(deadline); };
    child.once("error", error => { if (!settled) { settled = true; cleanup(); reject(error); } });
    child.once("close", code => { if (!settled) { settled = true; cleanup(); resolveResult({ code: expired ? 124 : code ?? 1, timedOut: expired }); } });
  });
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [timeout, executable, ...args] = process.argv.slice(2);
  if (!executable) throw new Error("Expected timeout and executable");
  const result = await runBounded(executable, args, { timeoutMs: Number(timeout) }); process.exitCode = result.code;
}
