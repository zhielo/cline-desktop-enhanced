import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AnalysisTaskOrchestrator } from "./analysis-task-orchestrator";

const roots: string[] = [];

afterEach(() => {
  delete process.env.CLINE_ANALYSIS_SANDBOX_WORKER;
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function workspace() {
  const root = mkdtempSync(join(tmpdir(), "cline-analysis-plan-"));
  roots.push(root);
  return root;
}

describe("AnalysisTaskOrchestrator", () => {
  it("confines targets to the workspace unless explicitly approved", () => {
    const orchestrator = new AnalysisTaskOrchestrator();
    const root = workspace();
    expect(() =>
      orchestrator.prepare({
        workspaceRoot: root,
        kind: "static",
        operation: "inspect",
        target: join(root, "..", "sample.exe"),
      }),
    ).toThrow("outside the workspace");
  });

  it("requires every approval and consumes the token once", () => {
    const orchestrator = new AnalysisTaskOrchestrator();
    const root = workspace();
    const plan = orchestrator.prepare({
      workspaceRoot: root,
      kind: "debugger",
      operation: "continue",
      target: "sample.exe",
    });
    expect(() => orchestrator.approve(plan.id, ["authorized-target"])).toThrow(
      "execution-control",
    );
    const approved = orchestrator.approve(plan.id, plan.requirements);
    const request = {
      planId: plan.id,
      executionToken: approved.executionToken,
      workspaceRoot: root,
      kind: "debugger" as const,
      operation: "continue",
      target: "sample.exe",
    };
    expect(orchestrator.consume(request).status).toBe("running");
    expect(() => orchestrator.consume(request)).toThrow(
      "does not match this exact operation",
    );
  });

  it("never runs dynamic analysis directly on the host", () => {
    const orchestrator = new AnalysisTaskOrchestrator();
    expect(() =>
      orchestrator.prepare({
        workspaceRoot: workspace(),
        kind: "dynamic",
        operation: "execute",
      }),
    ).toThrow("isolated analysis worker");
  });
});
