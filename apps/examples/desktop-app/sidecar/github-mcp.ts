import { existsSync, readFileSync } from "node:fs";
import { dirname, join, normalize } from "node:path";
import { updateMcpSettingsFileSync } from "@cline/core";
import { resolveMcpSettingsPath } from "@cline/shared/storage";

const LEGACY_GITHUB_MCP_URL = "https://api.githubcopilot.com/mcp/";
const BUILTIN_SOURCE = "cline-enhanced";
const BUILTIN_PROVIDER = "github-mcp-server";

type JsonRecord = Record<string, unknown>;

type GitHubMcpResolutionOptions = {
  env?: NodeJS.ProcessEnv;
  execPath?: string;
  platform?: NodeJS.Platform;
  arch?: string;
  cwd?: string;
  exists?: (path: string) => boolean;
};

export type BundledGitHubMcpStatus = {
  available: boolean;
  path?: string;
  serverName?: string;
  migrated: boolean;
  reason?: string;
};

function binaryNames(
  platform: NodeJS.Platform,
  arch: string,
): string[] {
  if (platform === "win32") {
    return arch === "arm64"
      ? ["github-mcp-server-arm64.exe", "github-mcp-server.exe"]
      : ["github-mcp-server-x64.exe", "github-mcp-server.exe"];
  }
  if (platform === "darwin") {
    return arch === "arm64"
      ? ["github-mcp-server-arm64", "github-mcp-server"]
      : ["github-mcp-server-x64", "github-mcp-server"];
  }
  return arch === "arm64"
    ? ["github-mcp-server-arm64", "github-mcp-server"]
    : ["github-mcp-server-x64", "github-mcp-server"];
}

function isLegacyRemoteRegistration(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const record = value as JsonRecord;
  const transport =
    record.transport &&
    typeof record.transport === "object" &&
    !Array.isArray(record.transport)
      ? (record.transport as JsonRecord)
      : undefined;
  const url =
    typeof transport?.url === "string"
      ? transport.url
      : typeof record.url === "string"
        ? record.url
        : undefined;
  return url?.replace(/\/$/, "") === LEGACY_GITHUB_MCP_URL.replace(/\/$/, "");
}

function isBuiltInRegistration(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const metadata = (value as JsonRecord).metadata;
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    return false;
  }
  const record = metadata as JsonRecord;
  return (
    record.source === BUILTIN_SOURCE &&
    record.provider === BUILTIN_PROVIDER
  );
}

export function resolveBundledGitHubMcpServerPath(
  options: GitHubMcpResolutionOptions = {},
): string | undefined {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  const arch = options.arch ?? process.arch;
  const execPath = options.execPath ?? process.execPath;
  const cwd = options.cwd ?? process.cwd();
  const exists = options.exists ?? existsSync;
  const names = binaryNames(platform, arch);
  const executableDirectory = dirname(execPath);
  const directories = [
    env.CLINE_GITHUB_MCP_SERVER?.trim(),
    executableDirectory,
    join(executableDirectory, "bin"),
    join(executableDirectory, "..", "Resources"),
    join(executableDirectory, "..", "resources"),
    cwd,
    join(cwd, "bin"),
  ].filter((value): value is string => Boolean(value?.trim()));

  for (const candidate of directories.flatMap((directory) => {
    const normalized = normalize(directory);
    return names.map((name) =>
      directory === env.CLINE_GITHUB_MCP_SERVER?.trim()
        ? normalized
        : join(normalized, name),
    );
  })) {
    if (exists(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

function hasMcpServers(settings: JsonRecord): settings is JsonRecord & {
  mcpServers: JsonRecord;
} {
  return (
    Boolean(settings.mcpServers) &&
    typeof settings.mcpServers === "object" &&
    !Array.isArray(settings.mcpServers)
  );
}

function builtInServerRecord(command: string, disabled = false): JsonRecord {
  return {
    transport: {
      type: "stdio",
      command,
      args: ["stdio"],
    },
    disabled,
    metadata: {
      source: BUILTIN_SOURCE,
      provider: BUILTIN_PROVIDER,
      oauth: "browser",
      version: "2.0.2",
    },
  };
}

/**
 * Install the bundled official GitHub MCP server into the user's MCP settings.
 *
 * The migration deliberately recognizes only GitHub's hosted Copilot MCP URL.
 * Other user-configured servers are left untouched. The official stdio server
 * owns OAuth in the child process, so no bearer token or dynamic-registration
 * state is written to cline_mcp_settings.json.
 */
export function ensureBundledGitHubMcpServer(
  options: GitHubMcpResolutionOptions & { settingsPath?: string } = {},
): BundledGitHubMcpStatus {
  const serverPath = resolveBundledGitHubMcpServerPath(options);
  if (!serverPath) {
    return {
      available: false,
      migrated: false,
      reason: "The bundled GitHub MCP server is not present in this build.",
    };
  }

  const settingsPath = options.settingsPath ?? resolveMcpSettingsPath();
  let migrated = false;
  let serverName = "github";
  updateMcpSettingsFileSync(settingsPath, (settings) => {
    if (!hasMcpServers(settings)) {
      settings.mcpServers = {};
    }
    const servers = settings.mcpServers;
    const existing = servers.github;

    if (existing === undefined || isLegacyRemoteRegistration(existing)) {
      servers.github = builtInServerRecord(
        serverPath,
        existing &&
          typeof existing === "object" &&
          !Array.isArray(existing) &&
          (existing as JsonRecord).disabled === true,
      );
      migrated = existing !== undefined;
      return;
    }

    if (isBuiltInRegistration(existing)) {
      const current = existing as JsonRecord;
      const transport =
        current.transport &&
        typeof current.transport === "object" &&
        !Array.isArray(current.transport)
          ? (current.transport as JsonRecord)
          : undefined;
      if (transport?.command !== serverPath) {
        servers.github = builtInServerRecord(
          serverPath,
          current.disabled === true,
        );
        migrated = true;
      }
      return;
    }

    // Never overwrite an unrelated user-owned server named "github".
    serverName = "github-cline";
    if (servers[serverName] === undefined) {
      servers[serverName] = builtInServerRecord(serverPath);
      migrated = true;
    }
  });

  return {
    available: true,
    path: serverPath,
    serverName,
    migrated,
  };
}

export function readBundledGitHubMcpSettings(
  settingsPath = resolveMcpSettingsPath(),
): JsonRecord | undefined {
  if (!existsSync(settingsPath)) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(readFileSync(settingsPath, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as JsonRecord)
      : undefined;
  } catch {
    return undefined;
  }
}
