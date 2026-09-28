import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { resolveClineDataDir } from "@cline/shared/storage";

export type ComputerUseMetrics = {
  version: 1;
  updatedAt: string;
  sessionsStarted: number;
  sessionsCompleted: number;
  actions: number;
  accessibilityActions: number;
  coordinateActions: number;
  focusLossPauses: number;
  takeovers: number;
  failures: number;
  totalDurationMs: number;
};

const EMPTY_METRICS: ComputerUseMetrics = {
  version: 1,
  updatedAt: new Date(0).toISOString(),
  sessionsStarted: 0,
  sessionsCompleted: 0,
  actions: 0,
  accessibilityActions: 0,
  coordinateActions: 0,
  focusLossPauses: 0,
  takeovers: 0,
  failures: 0,
  totalDurationMs: 0,
};

function metricsPath(): string {
  return join(resolveClineDataDir(), "metrics", "computer-use.json");
}

function finiteCount(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? Math.floor(value)
    : 0;
}

export async function readComputerUseMetrics(): Promise<ComputerUseMetrics> {
  try {
    const parsed = JSON.parse(
      await readFile(metricsPath(), "utf8"),
    ) as Partial<ComputerUseMetrics>;
    return {
      version: 1,
      updatedAt:
        typeof parsed.updatedAt === "string"
          ? parsed.updatedAt
          : EMPTY_METRICS.updatedAt,
      sessionsStarted: finiteCount(parsed.sessionsStarted),
      sessionsCompleted: finiteCount(parsed.sessionsCompleted),
      actions: finiteCount(parsed.actions),
      accessibilityActions: finiteCount(parsed.accessibilityActions),
      coordinateActions: finiteCount(parsed.coordinateActions),
      focusLossPauses: finiteCount(parsed.focusLossPauses),
      takeovers: finiteCount(parsed.takeovers),
      failures: finiteCount(parsed.failures),
      totalDurationMs: finiteCount(parsed.totalDurationMs),
    };
  } catch {
    return { ...EMPTY_METRICS };
  }
}

let updateQueue = Promise.resolve<ComputerUseMetrics>({ ...EMPTY_METRICS });

async function applyComputerUseMetricsUpdate(
  update: Partial<
    Record<keyof Omit<ComputerUseMetrics, "version" | "updatedAt">, number>
  >,
): Promise<ComputerUseMetrics> {
  const current = await readComputerUseMetrics();
  for (const [key, value] of Object.entries(update)) {
    if (typeof value !== "number" || !Number.isFinite(value)) continue;
    const metric = key as keyof Omit<
      ComputerUseMetrics,
      "version" | "updatedAt"
    >;
    current[metric] = Math.max(0, current[metric] + Math.floor(value));
  }
  current.updatedAt = new Date().toISOString();
  const path = metricsPath();
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(current, null, 2)}\n`, {
    mode: 0o600,
  });
  await rename(temporary, path);
  return current;
}

export function updateComputerUseMetrics(
  update: Partial<
    Record<keyof Omit<ComputerUseMetrics, "version" | "updatedAt">, number>
  >,
): Promise<ComputerUseMetrics> {
  const next = updateQueue
    .catch(() => ({ ...EMPTY_METRICS }))
    .then(() => applyComputerUseMetricsUpdate(update));
  updateQueue = next;
  return next;
}
