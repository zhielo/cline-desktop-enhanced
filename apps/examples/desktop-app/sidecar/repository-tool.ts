import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type {
	AgentToolContext,
	RepositoryExecutor,
	RepositoryInput,
} from "@cline/core";

const execFileAsync = promisify(execFile);
const MAX_OUTPUT_BYTES = 512 * 1024;
const SAFE_REF = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/;
const SAFE_REMOTE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function requireSafeRef(value: string, label: string): string {
	if (
		!SAFE_REF.test(value) ||
		value.includes("..") ||
		value.includes("//") ||
		value.includes("@{") ||
		value.endsWith("/") ||
		value.endsWith(".")
	) {
		throw new Error(`${label} is not a safe Git ref`);
	}
	return value;
}

function requireSafeRemote(value: string): string {
	if (!SAFE_REMOTE.test(value))
		throw new Error("remote is not a safe Git remote name");
	return value;
}

function cleanPath(value: string): string {
	const path = value.trim().replaceAll("\\", "/");
	if (!path || path.startsWith("/") || /^[A-Za-z]:\//.test(path)) {
		throw new Error("repository paths must be relative to the workspace");
	}
	if (path.split("/").some((part) => part === "..")) {
		throw new Error("repository paths cannot escape the workspace");
	}
	return path;
}

function output(value: unknown): string {
	return JSON.stringify(value, null, 2);
}

async function run(
	file: "git" | "gh",
	args: string[],
	cwd: string,
	context: AgentToolContext,
): Promise<string> {
	try {
		const { stdout, stderr } = await execFileAsync(file, args, {
			cwd,
			encoding: "utf8",
			timeout: 60_000,
			maxBuffer: MAX_OUTPUT_BYTES,
			signal: context.signal,
			env: {
				...process.env,
				GH_PROMPT_DISABLED: "1",
				GIT_TERMINAL_PROMPT: "0",
			},
		});
		return `${stdout ?? ""}${stderr ?? ""}`.trim();
	} catch (error) {
		const detail =
			error && typeof error === "object" && "stderr" in error
				? String(error.stderr).trim()
				: error instanceof Error
					? error.message
					: String(error);
		throw new Error(`${file} ${args[0] ?? "command"} failed: ${detail}`);
	}
}

async function repositorySummary(cwd: string, context: AgentToolContext) {
	const [root, branch, status, remote] = await Promise.all([
		run("git", ["rev-parse", "--show-toplevel"], cwd, context),
		run("git", ["branch", "--show-current"], cwd, context),
		run("git", ["status", "--short", "--branch"], cwd, context),
		run("git", ["remote", "get-url", "origin"], cwd, context).catch(() => ""),
	]);
	return { root, branch: branch || null, origin: remote || null, status };
}

export function createRepositoryExecutor(
	workspaceRoot: () => string,
): RepositoryExecutor {
	return async (input: RepositoryInput, context: AgentToolContext) => {
		const cwd = workspaceRoot();
		if (!cwd)
			throw new Error("repository tool requires an active local workspace");
		switch (input.action) {
			case "status":
				return output(await repositorySummary(cwd, context));
			case "diff": {
				const args = ["diff", "--no-ext-diff", "--no-textconv", "--no-color"];
				if (input.staged) args.push("--cached");
				if (input.path) args.push("--", cleanPath(input.path));
				return await run("git", args, cwd, context);
			}
			case "log":
				return await run(
					"git",
					[
						"log",
						`-${input.limit}`,
						"--date=iso-strict",
						"--pretty=format:%h%x09%ad%x09%an%x09%s",
					],
					cwd,
					context,
				);
			case "branches":
				return await run(
					"git",
					[
						"branch",
						"--all",
						"--format=%(refname:short)%09%(upstream:short)%09%(HEAD)",
					],
					cwd,
					context,
				);
			case "create_branch":
				if (!input.confirm_write)
					throw new Error("create_branch requires confirm_write=true");
				await run(
					"git",
					[
						"switch",
						"-c",
						requireSafeRef(input.name, "branch name"),
						...(input.start_point
							? [requireSafeRef(input.start_point, "start point")]
							: []),
					],
					cwd,
					context,
				);
				return output(await repositorySummary(cwd, context));
			case "switch_branch":
				if (!input.confirm_write)
					throw new Error("switch_branch requires confirm_write=true");
				await run(
					"git",
					["switch", requireSafeRef(input.name, "branch name")],
					cwd,
					context,
				);
				return output(await repositorySummary(cwd, context));
			case "commit": {
				if (!input.confirm_write)
					throw new Error("commit requires confirm_write=true");
				const paths = input.paths?.map(cleanPath) ?? [];
				if (paths.length > 0)
					await run("git", ["add", "--", ...paths], cwd, context);
				const commit = await run(
					"git",
					["commit", "-m", input.message],
					cwd,
					context,
				);
				return output({
					commit,
					repository: await repositorySummary(cwd, context),
				});
			}
			case "fetch":
				if (!input.confirm_remote)
					throw new Error("fetch requires confirm_remote=true");
				return await run(
					"git",
					["fetch", requireSafeRemote(input.remote)],
					cwd,
					context,
				);
			case "pull": {
				if (!input.confirm_remote)
					throw new Error("pull requires confirm_remote=true");
				const args = ["pull", "--ff-only", requireSafeRemote(input.remote)];
				if (input.branch) args.push(requireSafeRef(input.branch, "branch"));
				return await run("git", args, cwd, context);
			}
			case "push": {
				if (!input.confirm_remote)
					throw new Error("push requires confirm_remote=true");
				const branch = input.branch
					? requireSafeRef(input.branch, "branch")
					: await run("git", ["branch", "--show-current"], cwd, context);
				if (!branch) throw new Error("cannot push from a detached HEAD");
				const remote = requireSafeRemote(input.remote);
				return await run(
					"git",
					[
						"push",
						...(input.set_upstream ? ["--set-upstream"] : []),
						remote,
						branch,
					],
					cwd,
					context,
				);
			}
			case "github_status": {
				const auth = await run(
					"gh",
					["auth", "status", "--active", "--hostname", "github.com"],
					cwd,
					context,
				);
				const pr = await run(
					"gh",
					["pr", "status", "--json", "currentBranch,createdBy,needsReview"],
					cwd,
					context,
				).catch((error) =>
					error instanceof Error ? error.message : String(error),
				);
				return output({ auth, pullRequests: pr });
			}
		}
	};
}
