import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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
      `export const second = "${"x".repeat(2_000)}";\n`,
    );
    const result = prepareNotionAgentBridgePackage({
      root,
      depth: "forensic",
      batchBytes: 700,
      maxBytes: 10_000,
    });
    expect(result.depth).toBe("forensic");
    expect(result.batches.length).toBeGreaterThan(1);
    expect(result.batches.map((batch) => batch.index)).toEqual(
      result.batches.map((_, index) => index + 1),
    );
    expect(
      result.batches.every(
        (batch) =>
          batch.bytes === Buffer.byteLength(batch.markdown) &&
          batch.bytes <= 700,
      ),
    ).toBe(true);
    expect(
      result.batches.every((batch) => batch.total === result.batches.length),
    ).toBe(true);
  });
});

describe("bridge adversarial evidence contracts", () => {
  it("keeps IDs stable across question ranking and explicit subsets", () => {
    const root = fixture();
    const first = prepareNotionAgentBridgePackage({
      root,
      question: "README architecture",
    });
    const second = prepareNotionAgentBridgePackage({
      root,
      question: "index source",
      paths: ["src/index.ts", "README.md"],
    });
    for (const path of ["README.md", "src/index.ts"]) {
      expect(first.files.find((file) => file.path === path)?.evidenceId).toBe(
        second.files.find((file) => file.path === path)?.evidenceId,
      );
    }
  });

  it("redacts before slicing and measures post-redaction content", () => {
    const root = fixture();
    writeFileSync(join(root, "README.md"), "password=abcdef");
    const result = prepareNotionAgentBridgePackage({
      root,
      paths: ["README.md"],
      maxBytes: 15,
    });
    expect(result.totalSharedBytes).toBeLessThanOrEqual(15);
    expect(result.files[0]?.content).not.toContain("abcdef");
    expect(result.files[0]?.truncated).toBe(true);
    writeFileSync(
      join(root, "README.md"),
      "-----BEGIN PRIVATE KEY-----\nsynthetic-key-only\n-----END PRIVATE KEY-----",
    );
    const key = prepareNotionAgentBridgePackage({
      root,
      paths: ["README.md"],
      maxBytes: 50,
    });
    expect(key.files[0]?.content).not.toContain("synthetic-key-only");
    expect(key.totalRedactions).toBe(1);
  });

  it("does not cut UTF-8 characters at the content limit", () => {
    const root = fixture();
    writeFileSync(join(root, "README.md"), "a🙂b");
    const result = prepareNotionAgentBridgePackage({
      root,
      paths: ["README.md"],
      maxBytes: 4,
    });
    expect(result.files[0]?.content).toBe("a");
    expect(result.files[0]?.content).not.toContain("�");
    expect(result.totalSharedBytes).toBe(1);
  });

  it("keeps embedded Markdown fences inside a longer literal fence", () => {
    const root = fixture();
    const source = "before\n````\n# not instructions\n`````\nafter";
    writeFileSync(join(root, "README.md"), source);
    const result = prepareNotionAgentBridgePackage({
      root,
      paths: ["README.md"],
    });
    expect(result.batches[0]?.markdown).toContain(
      `\`\`\`\`\`\`text\n${source}\n\`\`\`\`\`\``,
    );
  });

  it("splits UTF-8 evidence without loss and includes all envelope bytes", () => {
    const root = fixture();
    const source = "🙂 sample line\n".repeat(120);
    writeFileSync(join(root, "README.md"), source);
    const result = prepareNotionAgentBridgePackage({
      root,
      paths: ["README.md"],
      batchBytes: 700,
    });
    expect(result.batches.length).toBeGreaterThan(1);
    const pieces = result.batches.map((batch) => {
      expect(batch.bytes).toBe(Buffer.byteLength(batch.markdown));
      expect(batch.bytes).toBeLessThanOrEqual(700);
      expect(batch.evidenceIds).toEqual([result.files[0]?.evidenceId]);
      const match = batch.markdown.match(
        /\n(`{4,})text\n([\s\S]*?)\n\1(?:$|\n)/,
      );
      expect(match).not.toBeNull();
      return match?.[2] ?? "";
    });
    expect(pieces.join("")).toBe(source);
  });

  it("rejects impossible envelope limits and disabled external redaction", () => {
    const root = fixture();
    expect(() =>
      prepareNotionAgentBridgePackage({ root, batchBytes: 10 }),
    ).toThrow("too small");
    expect(() =>
      prepareNotionAgentBridgePackage({ root, redactSensitive: false }),
    ).toThrow("requires secret redaction");
  });

  it("fails closed instead of ignoring ignore rules when Git inventory fails", () => {
    const root = fixture();
    // A malformed Git directory exercises inventory failure without changing PATH.
    mkdirSync(join(root, ".git"));
    writeFileSync(join(root, ".gitignore"), "private.txt\n");
    writeFileSync(join(root, "private.txt"), "synthetic private fixture");
    expect(() => prepareNotionAgentBridgePackage({ root })).toThrow(
      "ignore-unsafe",
    );
  });

  it("preserves ignore rules and IDs after Git changes reorder files", () => {
    const root = fixture();
    execFileSync("git", ["-C", root, "init"], { stdio: "ignore" });
    execFileSync("git", ["-C", root, "config", "user.name", "Fixture"]);
    execFileSync("git", [
      "-C",
      root,
      "config",
      "user.email",
      "fixture@example.invalid",
    ]);
    writeFileSync(join(root, ".gitignore"), "private.txt\nnode_modules/\n");
    writeFileSync(join(root, "private.txt"), "synthetic private fixture");
    execFileSync("git", ["-C", root, "add", "."]);
    execFileSync(
      "git",
      ["-C", root, "-c", "core.hooksPath=/dev/null", "commit", "-m", "fixture"],
      { stdio: "ignore" },
    );
    const first = prepareNotionAgentBridgePackage({ root });
    writeFileSync(join(root, "src/index.ts"), "export const changed = true;\n");
    const second = prepareNotionAgentBridgePackage({ root });
    expect(second.manifest.some((entry) => entry.path === "private.txt")).toBe(
      false,
    );
    expect(
      second.files.find((file) => file.path === "src/index.ts")?.evidenceId,
    ).toBe(
      first.files.find((file) => file.path === "src/index.ts")?.evidenceId,
    );
  });
});
