import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { prepareNotionAgentBridgePackage } from "./notion-agent-bridge";

const roots: string[] = [];

function fixture(): string {
  const root = mkdtempSync(join(tmpdir(), "notion-agent-bridge-"));
  roots.push(root);
  mkdirSync(join(root, "src"), { recursive: true });
  mkdirSync(join(root, "node_modules", "ignored"), { recursive: true });
  writeFileSync(join(root, "README.md"), "# Example\nArchitecture notes\n");
  writeFileSync(
    join(root, "src", "index.ts"),
    'const apiKey = "sk-abcdefghijklmnopqrstuvwxyz123456";\nexport const ready = true;\n',
  );
  writeFileSync(join(root, ".env"), "PASSWORD=do-not-share\n");
  writeFileSync(join(root, "node_modules", "ignored", "index.js"), "secret");
  writeFileSync(join(root, "asset.bin"), Buffer.from([0, 1, 2, 3]));
  return root;
}

afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { force: true, recursive: true });
});

describe("prepareNotionAgentBridgePackage", () => {
  it("creates a bounded text-only package and redacts likely credentials", () => {
    const result = prepareNotionAgentBridgePackage({
      root: fixture(),
      question: "Review this project",
    });
    expect(result.files.map((file) => file.path)).toEqual([
      "README.md",
      "src/index.ts",
    ]);
    expect(result.files[1]?.content).toContain("[REDACTED:secret]");
    expect(result.files[1]?.content).not.toContain(
      "sk-abcdefghijklmnopqrstuvwxyz",
    );
    expect(result.totalRedactions).toBe(1);
    expect(result.depth).toBe("deep");
    expect(result.manifest).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: "README.md",
          kind: "documentation",
          sharingStatus: "full",
        }),
        expect.objectContaining({
          path: "asset.bin",
          sharingStatus: "metadata-only",
        }),
      ]),
    );
    expect(result.batches).toHaveLength(1);
    expect(result.batches[0]?.evidenceIds).toEqual(
      result.files.map((file) => file.evidenceId),
    );
    expect(result.packageMarkdown).toContain("Review this project");
    expect(result.packageMarkdown).toContain("sha256:");
    expect(result.packageMarkdown).toContain("Transfer protocol");
    expect(result.excluded).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ path: ".env", reason: "sensitive filename" }),
        expect.objectContaining({ path: "asset.bin" }),
      ]),
    );
  });

  it("supports an explicit allowlist and stable hashes for incremental snapshots", () => {
    const root = fixture();
    const first = prepareNotionAgentBridgePackage({
      root,
      paths: ["README.md"],
    });
    const second = prepareNotionAgentBridgePackage({
      root,
      paths: ["README.md"],
    });
    expect(first.files).toHaveLength(1);
    expect(first.files[0]?.hash).toBe(second.files[0]?.hash);
    expect(first.files[0]?.path).toBe("README.md");
  });

  it("rejects absolute paths and traversal outside the workspace", () => {
    const root = fixture();
    expect(() =>
      prepareNotionAgentBridgePackage({ root, paths: ["../secret.txt"] }),
    ).toThrow("escapes the workspace");
    expect(() =>
      prepareNotionAgentBridgePackage({
        root,
        paths: [join(root, "README.md")],
      }),
    ).toThrow("relative paths");
  });

  it("enforces file and byte limits", () => {
    const result = prepareNotionAgentBridgePackage({
      root: fixture(),
      maxFiles: 1,
      maxBytes: 12,
    });
    expect(result.files).toHaveLength(1);
    expect(result.totalSharedBytes).toBeLessThanOrEqual(12);
    expect(result.truncated).toBe(true);
    expect(result.manifest).toHaveLength(4);
    expect(
      result.manifest.some(
        (entry) => entry.reason === "content deferred by package limit",
      ),
    ).toBe(true);
  });

  it("creates stable bounded batches for deep and forensic reviews", () => {
    const root = fixture();
    writeFileSync(
      join(root, "src", "second.ts"),
      `export const second = "${"x".repeat(80)}";\n`,
    );
    const result = prepareNotionAgentBridgePackage({
      root,
      depth: "forensic",
      batchBytes: 60,
      maxBytes: 10_000,
    });
    expect(result.depth).toBe("forensic");
    expect(result.batches.length).toBeGreaterThan(1);
    expect(result.batches.map((batch) => batch.index)).toEqual(
      result.batches.map((_, index) => index + 1),
    );
    expect(result.batches.every((batch) => batch.total === result.batches.length))
      .toBe(true);
  });
});
