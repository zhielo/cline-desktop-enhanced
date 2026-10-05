import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  type Dirent,
  existsSync,
  lstatSync,
  readdirSync,
  readFileSync,
  realpathSync,
  statSync,
} from "node:fs";
import {
  basename,
  extname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { NOTION_AGENT_DEPTH_LIMITS } from "../shared/notion-agent-depth";

const DEFAULT_MAX_FILES = 50;
const DEFAULT_MAX_BYTES = 500_000;
const DEFAULT_BATCH_BYTES = 100_000;
const MAX_FILE_BYTES = 64_000;
const HARD_MAX_FILES = 200;
const HARD_MAX_BYTES = 2_000_000;
const HARD_MAX_BATCH_BYTES = 250_000;
const IGNORED_DIRECTORIES = new Set([
  ".git",
  ".next",
  ".turbo",
  ".venv",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "target",
  "vendor",
]);
const ALLOWED_HIDDEN_DIRECTORIES = new Set([".github"]);
const TEXT_EXTENSIONS = new Set([
  ".c",
  ".cc",
  ".conf",
  ".cpp",
  ".cs",
  ".css",
  ".go",
  ".h",
  ".hpp",
  ".html",
  ".ini",
  ".java",
  ".js",
  ".json",
  ".jsx",
  ".kt",
  ".kts",
  ".md",
  ".mjs",
  ".mts",
  ".php",
  ".properties",
  ".py",
  ".rb",
  ".rs",
  ".sh",
  ".sql",
  ".svelte",
  ".swift",
  ".toml",
  ".ts",
  ".tsx",
  ".txt",
  ".vue",
  ".xml",
  ".yaml",
  ".yml",
]);
const SAFE_EXTENSIONLESS_NAMES = new Set([
  "dockerfile",
  "license",
  "makefile",
  "readme",
]);
const BLOCKED_BASENAME_PATTERNS = [
  /^\.env(?:\.|$)/i,
  /^id_(?:rsa|dsa|ecdsa|ed25519)(?:\.|$)/i,
  /(?:credential|password|secret|token)s?\.(?:json|txt|ya?ml)$/i,
];
const BLOCKED_EXTENSIONS = new Set([
  ".cer",
  ".crt",
  ".der",
  ".key",
  ".p12",
  ".pem",
  ".pfx",
]);

export type NotionAgentBridgeFile = {
  evidenceId: string;
  path: string;
  hash: string;
  kind: NotionAgentEvidenceKind;
  priority: "critical" | "high" | "normal" | "low";
  lineCount: number;
  selectionReason: string;
  originalBytes: number;
  sharedBytes: number;
  redactions: number;
  truncated: boolean;
  content: string;
};

export type NotionAgentEvidenceKind =
  | "documentation"
  | "source"
  | "configuration"
  | "test"
  | "reverse-engineering"
  | "binary"
  | "other";

export type NotionAgentAnalysisDepth = "quick" | "deep" | "forensic";

export type NotionAgentManifestEntry = {
  evidenceId: string;
  path: string;
  kind: NotionAgentEvidenceKind;
  priority: "critical" | "high" | "normal" | "low";
  bytes: number;
  hash: string | null;
  sharingStatus: "full" | "excerpt" | "metadata-only" | "excluded";
  reason: string;
};

export type NotionAgentEvidenceBatch = {
  id: string;
  index: number;
  total: number;
  bytes: number;
  evidenceIds: string[];
  paths: string[];
  markdown: string;
};

export type NotionAgentBridgePackage = {
  root: string;
  createdAt: string;
  depth: NotionAgentAnalysisDepth;
  manifest: NotionAgentManifestEntry[];
  batches: NotionAgentEvidenceBatch[];
  files: NotionAgentBridgeFile[];
  excluded: Array<{ path: string; reason: string }>;
  totalOriginalBytes: number;
  totalSharedBytes: number;
  totalRedactions: number;
  truncated: boolean;
  packageMarkdown: string;
};

export type PrepareNotionAgentBridgeOptions = {
  root: string;
  paths?: string[];
  maxFiles?: number;
  maxBytes?: number;
  batchBytes?: number;
  depth?: NotionAgentAnalysisDepth;
  redactSensitive?: boolean;
  question?: string;
};

function clampInteger(
  value: number | undefined,
  fallback: number,
  max: number,
): number {
  if (!Number.isFinite(value)) return fallback;
  return Math.min(max, Math.max(1, Math.floor(value ?? fallback)));
}

function isWithinRoot(root: string, candidate: string): boolean {
  const rootPrefix = `${root}${sep}`;
  const left =
    process.platform === "win32" ? rootPrefix.toLowerCase() : rootPrefix;
  const right =
    process.platform === "win32"
      ? `${candidate}${sep}`.toLowerCase()
      : `${candidate}${sep}`;
  return candidate === root || right.startsWith(left);
}

function normalizeSelectedPath(root: string, value: string): string {
  const trimmed = value.trim();
  if (!trimmed || isAbsolute(trimmed))
    throw new Error("Bridge paths must be non-empty relative paths");
  const absolute = resolve(root, trimmed);
  if (!isWithinRoot(root, absolute))
    throw new Error(`Bridge path escapes the workspace: ${trimmed}`);
  return relative(root, absolute).split(sep).join("/");
}

function fallbackWorkspaceFiles(root: string): string[] {
  const files: string[] = [];
  const pending = [root];
  while (pending.length > 0 && files.length < 10_000) {
    const directory = pending.pop();
    if (!directory) break;
    let entries: Dirent[];
    try {
      entries = readdirSync(directory, { withFileTypes: true });
    } catch {
      continue;
    }
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (IGNORED_DIRECTORIES.has(entry.name)) continue;
        if (
          entry.name.startsWith(".") &&
          !ALLOWED_HIDDEN_DIRECTORIES.has(entry.name)
        )
          continue;
        pending.push(join(directory, entry.name));
      } else if (entry.isFile()) {
        files.push(
          relative(root, join(directory, entry.name)).split(sep).join("/"),
        );
      }
    }
  }
  return files;
}

function listGitAwareFiles(root: string): string[] {
  try {
    const output = execFileSync(
      "git",
      ["-C", root, "ls-files", "-co", "--exclude-standard", "-z"],
      {
        encoding: "utf8",
        maxBuffer: 8 * 1024 * 1024,
        stdio: ["ignore", "pipe", "ignore"],
        windowsHide: true,
      },
    );
    return output
      .split("\0")
      .filter(Boolean)
      .sort((a, b) => a.localeCompare(b));
  } catch {
    for (let directory = root; ; directory = resolve(directory, "..")) {
      if (
        existsSync(join(directory, ".git")) ||
        existsSync(join(directory, ".gitignore"))
      )
        throw new Error(
          "Git-aware bridge inventory is unavailable; refusing an ignore-unsafe filesystem fallback",
        );
      if (directory === resolve(directory, "..")) break;
    }
    return fallbackWorkspaceFiles(root).sort((a, b) => a.localeCompare(b));
  }
}

function changedGitPaths(root: string): Set<string> {
  try {
    const output = execFileSync(
      "git",
      ["-C", root, "status", "--porcelain=v1", "-z", "--untracked-files=all"],
      {
        encoding: "utf8",
        maxBuffer: 8 * 1024 * 1024,
        stdio: ["ignore", "pipe", "ignore"],
        windowsHide: true,
      },
    );
    const changed = new Set<string>();
    for (const record of output.split("\0").filter(Boolean)) {
      const value = record.slice(3).replace(/\\/g, "/");
      const renamedTarget = value.includes(" -> ")
        ? value.split(" -> ").at(-1)
        : value;
      if (renamedTarget) changed.add(renamedTarget);
    }
    return changed;
  } catch {
    return new Set();
  }
}

function relevanceOrder(
  paths: string[],
  changed: Set<string>,
  question: string,
): string[] {
  const tokens = [
    ...new Set(
      question
        .toLowerCase()
        .match(/[a-z0-9_-]{3,}/g)
        ?.filter(
          (token) =>
            !["about", "analyze", "project", "review", "this", "with"].includes(
              token,
            ),
        ) ?? [],
    ),
  ].slice(0, 20);
  return [...paths].sort((left, right) => {
    const score = (path: string) =>
      (changed.has(path) ? 100 : 0) +
      tokens.reduce(
        (total, token) => total + (path.toLowerCase().includes(token) ? 10 : 0),
        0,
      );
    return score(right) - score(left) || left.localeCompare(right);
  });
}

function evidenceKind(path: string): NotionAgentEvidenceKind {
  const normalized = path.toLowerCase();
  const extension = extname(normalized);
  if (
    normalized.includes("ghidra") ||
    normalized.includes("ida") ||
    normalized.includes("decompil") ||
    normalized.includes("reverse-engineer") ||
    [".asm", ".dex", ".smali"].includes(extension)
  )
    return "reverse-engineering";
  if (
    normalized.startsWith("docs/") ||
    /(?:^|\/)(?:readme|changelog|architecture|design|security)(?:\.|$)/.test(
      normalized,
    ) ||
    [".md", ".txt"].includes(extension)
  )
    return "documentation";
  if (
    /(?:^|\/)(?:test|tests|__tests__|spec)(?:\/|$)/.test(normalized) ||
    /\.(?:test|spec)\.[^.]+$/.test(normalized)
  )
    return "test";
  if (
    [
      ".json",
      ".toml",
      ".yaml",
      ".yml",
      ".ini",
      ".conf",
      ".properties",
    ].includes(extension) ||
    /(?:^|\/)(?:dockerfile|makefile|package\.json|cargo\.toml)$/.test(
      normalized,
    )
  )
    return "configuration";
  if (
    [
      ".c",
      ".cc",
      ".cpp",
      ".cs",
      ".go",
      ".h",
      ".hpp",
      ".java",
      ".js",
      ".jsx",
      ".kt",
      ".kts",
      ".mjs",
      ".mts",
      ".php",
      ".py",
      ".rb",
      ".rs",
      ".sh",
      ".sql",
      ".svelte",
      ".swift",
      ".ts",
      ".tsx",
      ".vue",
    ].includes(extension)
  )
    return "source";
  if (
    [".apk", ".bin", ".dll", ".dylib", ".exe", ".jar", ".so"].includes(
      extension,
    )
  )
    return "binary";
  return "other";
}

function evidencePriority(
  path: string,
  kind: NotionAgentEvidenceKind,
  changed: Set<string>,
): "critical" | "high" | "normal" | "low" {
  const normalized = path.toLowerCase();
  if (
    /(?:^|\/)(?:readme|architecture|security)(?:\.|$)/.test(normalized) ||
    /(?:auth|credential|crypto|permission|sandbox|entry|main)/.test(normalized)
  )
    return "critical";
  if (
    changed.has(path) ||
    kind === "reverse-engineering" ||
    kind === "configuration"
  )
    return "high";
  if (kind === "documentation" || kind === "source" || kind === "test")
    return "normal";
  return "low";
}

function evidenceId(path: string, kind: NotionAgentEvidenceKind): string {
  const prefix: Record<NotionAgentEvidenceKind, string> = {
    documentation: "DOC",
    source: "SRC",
    configuration: "CFG",
    test: "TEST",
    "reverse-engineering": "RE",
    binary: "BIN",
    other: "EVD",
  };
  // Identity belongs to the path, not its question-dependent ranking.
  return `${prefix[kind]}-${createHash("sha256").update(path).digest("hex")}`;
}

function fileEligibility(path: string): string | null {
  const name = basename(path);
  const extension = extname(name).toLowerCase();
  if (BLOCKED_BASENAME_PATTERNS.some((pattern) => pattern.test(name)))
    return "sensitive filename";
  if (BLOCKED_EXTENSIONS.has(extension))
    return "credential or certificate file";
  if (name.startsWith(".") && !path.startsWith(".github/"))
    return "hidden file";
  if (!extension && !SAFE_EXTENSIONLESS_NAMES.has(name.toLowerCase()))
    return "unsupported extensionless file";
  if (extension && !TEXT_EXTENSIONS.has(extension))
    return "non-text or unsupported file type";
  return null;
}

function redactContent(value: string): { content: string; redactions: number } {
  let content = value;
  let redactions = 0;
  const replace = (pattern: RegExp, replacement: string) => {
    content = content.replace(pattern, (...args) => {
      redactions += 1;
      return typeof args[1] === "string"
        ? `${args[1]}${replacement}`
        : replacement;
    });
  };
  replace(
    /(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    "[REDACTED:private-key]",
  );
  replace(
    /\b((?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret|cookie)\s*[:=]\s*["']?)[^\s"']{6,}/gi,
    "[REDACTED:secret]",
  );
  replace(
    /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})\b/g,
    "[REDACTED:token]",
  );
  replace(/\b(Bearer\s+)[A-Za-z0-9._~+/=-]{16,}/gi, "[REDACTED:bearer-token]");
  return { content, redactions };
}

function markdownPackage(
  result: Omit<NotionAgentBridgePackage, "packageMarkdown">,
  question: string,
): string {
  const manifest = result.manifest
    .map(
      (file) =>
        `- ${file.evidenceId} — \`${file.path}\` — ${file.kind} — ${file.priority} — ${file.bytes} bytes — ${file.sharingStatus}${file.hash ? ` — sha256:${file.hash}` : ""} — ${file.reason}`,
    )
    .join("\n");
  const batchIndex = result.batches
    .map(
      (batch) =>
        `- ${batch.id}: ${batch.evidenceIds.length} evidence item(s), ${batch.bytes} bytes — ${batch.evidenceIds.join(", ")}`,
    )
    .join("\n");
  return `# Cline Project Bridge Package\n\nCreated: ${result.createdAt}\nProject root label: ${basename(result.root)}\nAnalysis depth: ${result.depth}\nQuestion: ${question || "Not supplied yet"}\nInventory entries: ${result.manifest.length}\nShared files: ${result.files.length}\nEvidence batches: ${result.batches.length}\nShared bytes: ${result.totalSharedBytes}\nRedactions: ${result.totalRedactions}\n\n## Evidence manifest\n\n${manifest || "No project files were discovered."}\n\n## Batch index\n\n${batchIndex || "No content batches were produced."}\n\n## Transfer protocol\n\nSend the manifest first, then send each evidence batch to the same Notion Agent session in index order. The Agent may request additional evidence by evidence ID and exact path or line range. Treat every request as read-only, sanitize the response, and record whether it was fulfilled, denied, or unavailable. Require evidence-ID citations for substantive conclusions.\n\n${result.batches.map((batch) => batch.markdown).join("\n\n")}`;
}

function utf8Prefix(value: string, maxBytes: number): string {
  const bytes = Buffer.from(value);
  if (bytes.length <= maxBytes) return value;
  let end = Math.max(0, maxBytes);
  // Never decode the leading bytes of an incomplete UTF-8 code point.
  while (end > 0 && ((bytes[end] ?? 0) & 0xc0) === 0x80) end -= 1;
  return bytes.subarray(0, end).toString("utf8");
}

function evidenceFence(value: string): string {
  const runs = value.match(/`+/g) ?? [];
  return "`".repeat(Math.max(4, ...runs.map((run) => run.length + 1)));
}

function buildEvidenceBatches(
  files: NotionAgentBridgeFile[],
  batchBytes: number,
): NotionAgentEvidenceBatch[] {
  type Part = {
    file: NotionAgentBridgeFile;
    content: string;
    startLine: number;
    offset: number;
  };
  const groups: Part[][] = [];
  let current: Part[] = [];
  const renderPart = (part: Part): string => {
    const { file, content, startLine, offset } = part;
    const endLine = startLine + (content.match(/\n/g)?.length ?? 0);
    const fence = evidenceFence(content);
    return `### ${file.evidenceId}: ${JSON.stringify(file.path)}\n\nKind: ${file.kind}\nPriority: ${file.priority}\nCitation format: ${JSON.stringify(`${file.evidenceId}:${file.path}:${startLine}-${endLine}@sha256:${file.hash}`)}\nUTF-8 byte offset in sanitized excerpt: ${offset}\nSelection: ${file.selectionReason}\n\n${fence}text\n${content}\n${fence}`;
  };
  const render = (parts: Part[], index: number, total: number): string =>
    `## BATCH-${String(index).padStart(3, "0")} (${index}/${total})\n\n${parts.map(renderPart).join("\n\n")}`;
  // There cannot be more content parts than UTF-8 content bytes. Reserve
  // worst-case header digits up front so final total/index values fit too.
  const size = (parts: Part[]) =>
    Buffer.byteLength(render(parts, HARD_MAX_BYTES, HARD_MAX_BYTES));
  for (const file of files) {
    let rest = file.content;
    let startLine = 1;
    let offset = 0;
    do {
      const part = { file, content: rest, startLine, offset };
      if (size([...current, part]) <= batchBytes) {
        current.push(part);
        break;
      }
      if (current.length > 0) {
      groups.push(current);
      current = [];
        continue;
    }
      // Split oversized evidence without dropping content. Binary search is
      // in UTF-8 bytes; the renderer accounts for fences and metadata too.
      let low = 0;
      let high = Buffer.byteLength(rest);
      let accepted = "";
      while (low <= high) {
        const middle = Math.floor((low + high) / 2);
        const content = utf8Prefix(rest, middle);
        if (size([{ ...part, content }]) <= batchBytes) {
          accepted = content;
          low = middle + 1;
        } else high = middle - 1;
      }
      if (!accepted)
        throw new Error(
          "Bridge batch byte limit is too small for evidence metadata and a UTF-8 character",
        );
      // Prefer a complete line when that still makes progress.
      const newline = accepted.lastIndexOf("\n");
      if (newline >= 0) accepted = accepted.slice(0, newline + 1);
      groups.push([{ ...part, content: accepted }]);
      offset += Buffer.byteLength(accepted);
      startLine += accepted.match(/\n/g)?.length ?? 0;
      rest = rest.slice(accepted.length);
    } while (rest.length > 0);
  }
  if (current.length > 0) groups.push(current);
  const total = groups.length;
  return groups.map((parts, index) => {
    const markdown = render(parts, index + 1, total);
    const bytes = Buffer.byteLength(markdown);
    if (bytes > batchBytes)
      throw new Error("Bridge serialized batch exceeded its byte limit");
    return {
      id: `BATCH-${String(index + 1).padStart(3, "0")}`,
      index: index + 1,
      total,
      bytes,
      evidenceIds: [...new Set(parts.map((part) => part.file.evidenceId))],
      paths: [...new Set(parts.map((part) => part.file.path))],
      markdown,
    };
  });
}

export function prepareNotionAgentBridgePackage(
  options: PrepareNotionAgentBridgeOptions,
): NotionAgentBridgePackage {
  if (options.redactSensitive === false)
    throw new Error("External bridge evidence requires secret redaction");
  const root = resolve(options.root);
  if (!existsSync(root) || !statSync(root).isDirectory())
    throw new Error(`Workspace directory not found: ${root}`);
  const realRoot = realpathSync(root);
  const depth = options.depth ?? "deep";
  const depthDefaults = NOTION_AGENT_DEPTH_LIMITS;
  const maxFiles = clampInteger(
    options.maxFiles,
    depthDefaults[depth].files ?? DEFAULT_MAX_FILES,
    HARD_MAX_FILES,
  );
  const maxBytes = clampInteger(
    options.maxBytes,
    depthDefaults[depth].bytes ?? DEFAULT_MAX_BYTES,
    HARD_MAX_BYTES,
  );
  const batchBytes = clampInteger(
    options.batchBytes,
    depthDefaults[depth].batchBytes ?? DEFAULT_BATCH_BYTES,
    HARD_MAX_BATCH_BYTES,
  );
  const selected = options.paths?.length
    ? new Set(options.paths.map((path) => normalizeSelectedPath(root, path)))
    : null;
  const changedPaths = changedGitPaths(root);
  const candidates = relevanceOrder(
    listGitAwareFiles(root).filter((path) => !selected || selected.has(path)),
    changedPaths,
    options.question?.trim() ?? "",
  );
  const manifest: NotionAgentManifestEntry[] = [];
  const files: NotionAgentBridgeFile[] = [];
  const excluded: Array<{ path: string; reason: string }> = [];
  let totalOriginalBytes = 0;
  let totalSharedBytes = 0;
  let totalRedactions = 0;
  let truncated = false;

  for (const path of candidates) {
    const kind = evidenceKind(path);
    const id = evidenceId(path, kind);
    const priority = evidencePriority(path, kind, changedPaths);
    const absolute = resolve(root, path);
    if (!isWithinRoot(root, absolute) || !existsSync(absolute)) continue;
    if (lstatSync(absolute).isSymbolicLink()) {
      excluded.push({ path, reason: "symbolic link" });
      manifest.push({
        evidenceId: id,
        path,
        kind,
        priority,
        bytes: 0,
        hash: null,
        sharingStatus: "excluded",
        reason: "symbolic link",
      });
      continue;
    }
    const realFile = realpathSync(absolute);
    if (!isWithinRoot(realRoot, realFile) || !statSync(realFile).isFile()) {
      excluded.push({ path, reason: "path resolves outside workspace" });
      manifest.push({
        evidenceId: id,
        path,
        kind,
        priority,
        bytes: 0,
        hash: null,
        sharingStatus: "excluded",
        reason: "path resolves outside workspace",
      });
      continue;
    }
    const originalBytes = statSync(realFile).size;
    const reason = fileEligibility(path);
    if (reason) {
      excluded.push({ path, reason });
      manifest.push({
        evidenceId: id,
        path,
        kind,
        priority,
        bytes: originalBytes,
        hash: null,
        sharingStatus:
          kind === "binary" || reason.includes("unsupported")
            ? "metadata-only"
            : "excluded",
        reason,
      });
      continue;
    }
    if (files.length >= maxFiles || totalSharedBytes >= maxBytes) {
      truncated = true;
      manifest.push({
        evidenceId: id,
        path,
        kind,
        priority,
        bytes: originalBytes,
        hash: null,
        sharingStatus: "metadata-only",
        reason: "content deferred by package limit",
      });
      continue;
    }
    const original = readFileSync(realFile);
    if (original.includes(0)) {
      excluded.push({ path, reason: "binary content" });
      manifest.push({
        evidenceId: id,
        path,
        kind: kind === "other" ? "binary" : kind,
        priority,
        bytes: originalBytes,
        hash: createHash("sha256").update(original).digest("hex"),
        sharingStatus: "metadata-only",
        reason: "binary content; bytes were not shared",
      });
      continue;
    }
    const remaining = Math.min(MAX_FILE_BYTES, maxBytes - totalSharedBytes);
    if (remaining <= 0) {
      truncated = true;
      manifest.push({
        evidenceId: id,
        path,
        kind,
        priority,
        bytes: originalBytes,
        hash: null,
        sharingStatus: "metadata-only",
        reason: "content deferred by byte limit",
      });
      continue;
    }
    const originalText = original.toString("utf8");
    const redacted = redactContent(originalText);
    const content = utf8Prefix(redacted.content, remaining);
    const contentTruncated = content.length < redacted.content.length;
    const sharedBytes = Buffer.byteLength(content);
    const hash = createHash("sha256").update(original).digest("hex");
    const file: NotionAgentBridgeFile = {
      evidenceId: id,
      path,
      hash,
      kind,
      priority,
      lineCount: Math.max(1, content.split(/\r?\n/).length),
      selectionReason: selected
        ? "explicit allowlist"
        : changedPaths.has(path)
          ? "recent Git change"
          : "question/path relevance",
      originalBytes,
      sharedBytes,
      redactions: redacted.redactions,
      truncated: contentTruncated,
      content,
    };
    files.push(file);
    manifest.push({
      evidenceId: id,
      path,
      kind,
      priority,
      bytes: originalBytes,
      hash,
      sharingStatus: file.truncated ? "excerpt" : "full",
      reason: file.selectionReason,
    });
    totalOriginalBytes += originalBytes;
    totalSharedBytes += sharedBytes;
    totalRedactions += redacted.redactions;
    if (contentTruncated) truncated = true;
  }
  if (selected) {
    for (const path of selected) {
      if (!candidates.includes(path))
        excluded.push({ path, reason: "not found or ignored by git" });
    }
  }
  const batches = buildEvidenceBatches(files, batchBytes);
  const base = {
    root,
    createdAt: new Date().toISOString(),
    depth,
    manifest,
    batches,
    files,
    excluded,
    totalOriginalBytes,
    totalSharedBytes,
    totalRedactions,
    truncated,
  };
  return {
    ...base,
    packageMarkdown: markdownPackage(base, options.question?.trim() ?? ""),
  };
}
