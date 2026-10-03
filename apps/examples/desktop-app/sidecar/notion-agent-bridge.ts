import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
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

const DEFAULT_MAX_FILES = 50;
const DEFAULT_MAX_BYTES = 500_000;
const MAX_FILE_BYTES = 64_000;
const HARD_MAX_FILES = 200;
const HARD_MAX_BYTES = 2_000_000;
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
  path: string;
  hash: string;
  originalBytes: number;
  sharedBytes: number;
  redactions: number;
  truncated: boolean;
  content: string;
};

export type NotionAgentBridgePackage = {
  root: string;
  createdAt: string;
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
    let entries;
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
    return fallbackWorkspaceFiles(root).sort((a, b) => a.localeCompare(b));
  }
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
  const manifest = result.files
    .map(
      (file) =>
        `- \`${file.path}\` — sha256:${file.hash} — ${file.sharedBytes} shared bytes${file.redactions ? ` — ${file.redactions} redaction(s)` : ""}${file.truncated ? " — truncated" : ""}`,
    )
    .join("\n");
  const fence = "````";
  const excerpts = result.files
    .map(
      (file) =>
        `## ${file.path}\n\nSHA-256: \`${file.hash}\`\n\n${fence}text\n${file.content}\n${fence}`,
    )
    .join("\n\n");
  return `# Cline Project Bridge Package\n\nCreated: ${result.createdAt}\nProject root label: ${basename(result.root)}\nQuestion: ${question || "Not supplied yet"}\nFiles: ${result.files.length}\nShared bytes: ${result.totalSharedBytes}\nRedactions: ${result.totalRedactions}\n\n## Evidence manifest\n\n${manifest || "No eligible files selected."}\n\n${excerpts}`;
}

export function prepareNotionAgentBridgePackage(
  options: PrepareNotionAgentBridgeOptions,
): NotionAgentBridgePackage {
  const root = resolve(options.root);
  if (!existsSync(root) || !statSync(root).isDirectory())
    throw new Error(`Workspace directory not found: ${root}`);
  const realRoot = realpathSync(root);
  const maxFiles = clampInteger(
    options.maxFiles,
    DEFAULT_MAX_FILES,
    HARD_MAX_FILES,
  );
  const maxBytes = clampInteger(
    options.maxBytes,
    DEFAULT_MAX_BYTES,
    HARD_MAX_BYTES,
  );
  const selected = options.paths?.length
    ? new Set(options.paths.map((path) => normalizeSelectedPath(root, path)))
    : null;
  const candidates = listGitAwareFiles(root).filter(
    (path) => !selected || selected.has(path),
  );
  const files: NotionAgentBridgeFile[] = [];
  const excluded: Array<{ path: string; reason: string }> = [];
  let totalOriginalBytes = 0;
  let totalSharedBytes = 0;
  let totalRedactions = 0;
  let truncated = false;

  for (const path of candidates) {
    if (files.length >= maxFiles || totalSharedBytes >= maxBytes) {
      truncated = true;
      break;
    }
    const reason = fileEligibility(path);
    if (reason) {
      excluded.push({ path, reason });
      continue;
    }
    const absolute = resolve(root, path);
    if (!isWithinRoot(root, absolute) || !existsSync(absolute)) continue;
    if (lstatSync(absolute).isSymbolicLink()) {
      excluded.push({ path, reason: "symbolic link" });
      continue;
    }
    const realFile = realpathSync(absolute);
    if (!isWithinRoot(realRoot, realFile) || !statSync(realFile).isFile()) {
      excluded.push({ path, reason: "path resolves outside workspace" });
      continue;
    }
    const original = readFileSync(realFile);
    if (original.includes(0)) {
      excluded.push({ path, reason: "binary content" });
      continue;
    }
    const originalBytes = original.byteLength;
    const remaining = Math.min(MAX_FILE_BYTES, maxBytes - totalSharedBytes);
    if (remaining <= 0) {
      truncated = true;
      break;
    }
    const sliced = original.subarray(0, remaining);
    let content = sliced.toString("utf8");
    const redacted =
      options.redactSensitive === false
        ? { content, redactions: 0 }
        : redactContent(content);
    content = redacted.content;
    const sharedBytes = Buffer.byteLength(content);
    files.push({
      path,
      hash: createHash("sha256").update(original).digest("hex"),
      originalBytes,
      sharedBytes,
      redactions: redacted.redactions,
      truncated: sliced.byteLength < originalBytes,
      content,
    });
    totalOriginalBytes += originalBytes;
    totalSharedBytes += sharedBytes;
    totalRedactions += redacted.redactions;
    if (sliced.byteLength < originalBytes) truncated = true;
  }
  if (selected) {
    for (const path of selected) {
      if (!candidates.includes(path))
        excluded.push({ path, reason: "not found or ignored by git" });
    }
  }
  const base = {
    root,
    createdAt: new Date().toISOString(),
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
