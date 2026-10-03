import { createHash, randomUUID } from "node:crypto";
import { isAbsolute, relative, resolve, sep } from "node:path";

export type AnalysisTaskKind = "static" | "debugger" | "gui" | "dynamic";
export type AnalysisPermission =
  "Inspect" | "Execute" | "Debug" | "Modify" | "Publish";
export type AnalysisTaskStatus =
  "awaiting-approval" | "approved" | "running" | "completed" | "failed";

export interface AnalysisTaskPlan {
  id: string;
  workspaceRoot: string;
  kind: AnalysisTaskKind;
  operation: string;
  target?: string;
  permission: AnalysisPermission;
  status: AnalysisTaskStatus;
  requirements: string[];
  risk: "low" | "moderate" | "high";
  budget: {
    timeoutMs: number;
    maxOutputBytes: number;
    network: "disabled" | "recorded";
  };
  createdAt: string;
  approvedAt?: string;
  completedAt?: string;
  error?: string;
  evidence?: {
    resultHash: string;
    tool: string;
    outputPaths: string[];
  };
}

export interface PrepareAnalysisTaskInput {
  workspaceRoot: string;
  kind: AnalysisTaskKind;
  operation: string;
  target?: string;
  allowExternalTarget?: boolean;
  timeoutMs?: number;
}

function isWithin(root: string, candidate: string): boolean {
  const child = relative(root, candidate);
  return (
    child === "" ||
    (!child.startsWith(`..${sep}`) && child !== ".." && !isAbsolute(child))
  );
}

function permissionFor(
  kind: AnalysisTaskKind,
  operation: string,
): AnalysisPermission {
  if (kind === "static") return "Inspect";
  if (kind === "gui") return "Execute";
  if (kind === "dynamic") return "Execute";
  if (["launch", "continue", "step"].includes(operation)) return "Execute";
  return "Debug";
}

function requirementsFor(
  kind: AnalysisTaskKind,
  operation: string,
  externalTarget: boolean,
): string[] {
  const requirements = new Set<string>();
  if (externalTarget) requirements.add("external-target");
  if (kind === "debugger") requirements.add("authorized-target");
  if (
    kind === "gui" ||
    kind === "dynamic" ||
    ["launch", "continue", "step"].includes(operation)
  ) {
    requirements.add("execution-control");
  }
  if (kind === "dynamic") requirements.add("isolated-sandbox");
  return [...requirements];
}

function publicPlan(plan: AnalysisTaskPlan): AnalysisTaskPlan {
  return structuredClone(plan);
}

export class AnalysisTaskOrchestrator {
  private readonly plans = new Map<
    string,
    AnalysisTaskPlan & { approvalTokenHash?: string }
  >();

  prepare(input: PrepareAnalysisTaskInput): AnalysisTaskPlan {
    const workspaceRoot = resolve(input.workspaceRoot);
    const target = input.target?.trim()
      ? resolve(
          workspaceRoot,
          isAbsolute(input.target) ? input.target : input.target,
        )
      : undefined;
    const externalTarget = Boolean(target && !isWithin(workspaceRoot, target));
    if (externalTarget && input.allowExternalTarget !== true) {
      throw new Error(
        "Target is outside the workspace. Review it and explicitly allow an external target.",
      );
    }
    if (
      input.kind === "dynamic" &&
      !process.env.CLINE_ANALYSIS_SANDBOX_WORKER?.trim()
    ) {
      throw new Error(
        "Dynamic analysis is disabled on the host. Configure an isolated analysis worker or VM first.",
      );
    }
    const permission = permissionFor(input.kind, input.operation);
    const plan: AnalysisTaskPlan = {
      id: randomUUID(),
      workspaceRoot,
      kind: input.kind,
      operation: input.operation,
      ...(target ? { target } : {}),
      permission,
      status: "awaiting-approval",
      requirements: requirementsFor(
        input.kind,
        input.operation,
        externalTarget,
      ),
      risk:
        input.kind === "dynamic" || permission === "Execute" || externalTarget
          ? "high"
          : permission === "Debug"
            ? "moderate"
            : "low",
      budget: {
        timeoutMs: Math.min(
          Math.max(input.timeoutMs ?? 120_000, 1_000),
          30 * 60_000,
        ),
        maxOutputBytes: 1024 * 1024,
        network: input.kind === "dynamic" ? "recorded" : "disabled",
      },
      createdAt: new Date().toISOString(),
    };
    this.plans.set(plan.id, plan);
    return publicPlan(plan);
  }

  approve(
    planId: string,
    acceptedRequirements: string[],
  ): {
    plan: AnalysisTaskPlan;
    executionToken: string;
  } {
    const plan = this.require(planId);
    if (plan.status !== "awaiting-approval") {
      throw new Error("Only a pending analysis plan can be approved.");
    }
    const accepted = new Set(acceptedRequirements);
    const missing = plan.requirements.filter((item) => !accepted.has(item));
    if (missing.length > 0) {
      throw new Error(`Missing required approvals: ${missing.join(", ")}`);
    }
    const executionToken = randomUUID();
    plan.approvalTokenHash = createHash("sha256")
      .update(executionToken)
      .digest("hex");
    plan.status = "approved";
    plan.approvedAt = new Date().toISOString();
    return { plan: publicPlan(plan), executionToken };
  }

  consume(input: {
    planId: string;
    executionToken: string;
    workspaceRoot: string;
    kind: AnalysisTaskKind;
    operation: string;
    target?: string;
  }): AnalysisTaskPlan {
    const plan = this.require(input.planId);
    const suppliedHash = createHash("sha256")
      .update(input.executionToken)
      .digest("hex");
    const target = input.target?.trim()
      ? resolve(input.workspaceRoot, input.target)
      : undefined;
    if (
      plan.status !== "approved" ||
      plan.approvalTokenHash !== suppliedHash ||
      plan.workspaceRoot !== resolve(input.workspaceRoot) ||
      plan.kind !== input.kind ||
      plan.operation !== input.operation ||
      plan.target !== target
    ) {
      throw new Error(
        "Analysis approval does not match this exact operation and target.",
      );
    }
    plan.approvalTokenHash = undefined;
    plan.status = "running";
    return publicPlan(plan);
  }

  complete(
    planId: string,
    result: unknown,
    tool: string,
    outputPaths: string[] = [],
  ): AnalysisTaskPlan {
    const plan = this.require(planId);
    plan.status = "completed";
    plan.completedAt = new Date().toISOString();
    plan.evidence = {
      resultHash: createHash("sha256")
        .update(JSON.stringify(result))
        .digest("hex"),
      tool,
      outputPaths: outputPaths.slice(0, 50),
    };
    return publicPlan(plan);
  }

  fail(planId: string, error: unknown): AnalysisTaskPlan {
    const plan = this.require(planId);
    plan.status = "failed";
    plan.completedAt = new Date().toISOString();
    plan.error = (error instanceof Error ? error.message : String(error)).slice(
      0,
      1_000,
    );
    return publicPlan(plan);
  }

  list(workspaceRoot: string): AnalysisTaskPlan[] {
    const root = resolve(workspaceRoot);
    return [...this.plans.values()]
      .filter((plan) => plan.workspaceRoot === root)
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
      .slice(0, 100)
      .map(publicPlan);
  }

  diagnostics() {
    return {
      taskApproval: "exact-operation one-time token",
      staticAnalysisDefault: true,
      dynamicAnalysisOnHost: false,
      sandboxWorkerConfigured: Boolean(
        process.env.CLINE_ANALYSIS_SANDBOX_WORKER?.trim(),
      ),
      networkDefault: "disabled",
      evidenceIntegrity: "sha256",
      taskRetention: "in-memory, latest 100 returned",
    };
  }

  private require(planId: string) {
    const plan = this.plans.get(planId);
    if (!plan) throw new Error("Analysis plan was not found or expired.");
    return plan;
  }
}

export const desktopAnalysisTaskOrchestrator = new AnalysisTaskOrchestrator();
