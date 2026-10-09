/** Advisory host stream text only; never a process-liveness or completion signal. */
export function latestIdaProgress(output: unknown): string | null {
  if (typeof output !== "string") return null;
  const lines = output.slice(-16384).split("\n");
  for (let i = lines.length - 1; i >= 0; i--) {
    if (lines[i].startsWith("[IDA progress] ")) return lines[i].slice(15, 815).trim();
  }
  return null;
}

export function nativeExecutionFailure(value: unknown): string | null {
  let current = value;
  for (let depth = 0; depth < 3; depth++) {
    if (typeof current === "string") {
      if (current.length > 2_000_000) return null;
      try { current = JSON.parse(current); } catch { return null; }
    }
    if (!current || typeof current !== "object" || Array.isArray(current)) return null;
    const record = current as Record<string, unknown>;
    if (["ida", "ghidra", "jadx"].includes(String(record.engine)) && record.succeeded === false) {
      if (record.outputDrainTimedOut === true) return "Native execution unsuccessful; termination or output drain is unconfirmed. No automatic retry or project-lease release.";
      if (record.timedOut === true) return "Native execution deadline exceeded; no successful decompilation is claimed. Inspect the recorded phase and receipt.";
      if (record.cancelled === true) return "Native execution was cancelled; no successful decompilation is claimed.";
      if (record.artifactVerified === false) return "Native execution did not produce the required verified output.";
      return "Native execution failed; inspect its exit code and diagnostic receipt.";
    }
    current = record.result;
  }
  return null;
}
