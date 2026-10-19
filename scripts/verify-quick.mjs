import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

// Fixed dependency-free feedback tier, never a release/merge certificate.
export const QUICK_CHECKS = [
  ["node", ["scripts/generate-owned-arm64-fixture.mjs", "--check"]],
  ["node", ["scripts/generate-android-investigation.mjs", "--check"]],
  ["node", ["--test", "scripts/validate-advanced-build.test.mjs", "scripts/verification-speed.test.mjs"]],
  ["bun", ["test", "scripts/windows-hardening.test.mjs"]],
];
export function runQuick(run = spawnSync, root = fileURLToPath(new URL("../", import.meta.url))) {
  for (const [executable, args] of QUICK_CHECKS) {
    const result = run(executable, args, { cwd: root, shell: false, stdio: "inherit", timeout: 120_000, windowsHide: true });
    if (result.error || result.status !== 0 || result.signal) return 1;
  }
  return 0;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) throw new Error("Quick verification accepts no flags; full verification is validate:advanced");
  console.log("Quick feedback only; complete CI, installer and installed acceptance remain required.");
  process.exitCode = runQuick();
}
