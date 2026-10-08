import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { extname, relative, resolve, sep } from "node:path";
import { analyzeChangedImpact } from "./engineering-impact";
import { scoreReviewRisk } from "./engineering-control-plane";

export type EngineeringGitFile = {
	path: string;
	status: string;
	added: number;
	deleted: number;
	category:
		| "code"
		| "test"
		| "dependency"
		| "migration"
		| "workflow"
		| "documentation"
		| "binary"
		| "other";
	sensitive: boolean;
	symbols: string[];
};

function git(root: string, args: string[]): string {
	return execFileSync("git", ["-C", root, ...args], {
		encoding: "utf8",
		timeout: 15_000,
		windowsHide: true,
		stdio: ["ignore", "pipe", "pipe"],
	}).trim();
}

function category(path: string): EngineeringGitFile["category"] {
	const lower = path.toLowerCase();
	if (
		/(^|\/)(package\.json|.*lock.*|cargo\.toml|go\.mod|requirements.*|pyproject\.toml)$/.test(
			lower,
		)
	)
		return "dependency";
	if (/(^|\/)(migrations?|schema)(\/|\.)/.test(lower)) return "migration";
	if (
		lower.startsWith(".github/workflows/") ||
		/(^|\/)(azure-pipelines|gitlab-ci)/.test(lower)
	)
		return "workflow";
	if (
		/\.(test|spec)\.[^.]+$/.test(lower) ||
		/(^|\/)(tests?|__tests__)(\/|$)/.test(lower)
	)
		return "test";
	if (/\.(md|mdx|rst|txt)$/.test(lower)) return "documentation";
	if (/\.(exe|dll|so|dylib|png|jpe?g|gif|zip|7z|pdf|bin|apk)$/.test(lower))
		return "binary";
	if (/\.(c|cc|cpp|cs|go|java|js|jsx|kt|py|rs|swift|ts|tsx)$/.test(lower))
		return "code";
	return "other";
}

function isSensitive(path: string): boolean {
	return (
		/(^|\/)(auth|security|permissions?|credentials?|secrets?|crypto|payments?|billing|migrations?|schema)([./_-]|$)/i.test(
			path,
		) || /(^|\/)(\.github\/workflows|package\.json|.*lock.*)$/i.test(path)
	);
}

function symbols(root: string, path: string): string[] {
	const absolute = resolve(root, path);
	const relativePath = relative(resolve(root), absolute);
	if (
		!relativePath ||
		relativePath.startsWith("..") ||
		relativePath.split(sep).includes("..") ||
		!existsSync(absolute) ||
		!statSync(absolute).isFile() ||
		statSync(absolute).size > 512_000
	)
		return [];
	if (
		![
			".ts",
			".tsx",
			".js",
			".jsx",
			".py",
			".go",
			".rs",
			".java",
			".cs",
			".cpp",
			".c",
		].includes(extname(path).toLowerCase())
	)
		return [];
	const text = readFileSync(absolute, "utf8");
	const names = new Set<string>();
	for (const match of text.matchAll(
		/(?:export\s+)?(?:async\s+)?(?:function|class|interface|type|enum|def|fn|struct)\s+([A-Za-z_$][\w$]*)/g,
	))
		names.add(match[1]);
	return [...names].slice(0, 24);
}

export function buildEngineeringGitReview(
	workspaceRoot: string,
	base = "HEAD",
) {
	const repositoryRoot = realpathSync.native(
		git(workspaceRoot, ["rev-parse", "--show-toplevel"]),
	);
	const normalizedBase = base.trim() || "HEAD";
	if (
		normalizedBase.startsWith("-") ||
		!/^[A-Za-z0-9_./~^{}-]{1,200}$/.test(normalizedBase)
	)
		throw new Error("Invalid Git comparison base");
	git(repositoryRoot, ["rev-parse", "--verify", normalizedBase]);
	const statusLines = git(repositoryRoot, [
		"diff",
		"--name-status",
		normalizedBase,
		"--",
	])
		.split(/\r?\n/)
		.filter(Boolean);
	const numstat = new Map<string, { added: number; deleted: number }>();
	for (const line of git(repositoryRoot, [
		"diff",
		"--numstat",
		normalizedBase,
		"--",
	])
		.split(/\r?\n/)
		.filter(Boolean)) {
		const [added, deleted, path] = line.split("\t");
		if (path)
			numstat.set(path, {
				added: Number(added) || 0,
				deleted: Number(deleted) || 0,
			});
	}
	const files: EngineeringGitFile[] = statusLines.map((line) => {
		const [status, ...pathParts] = line.split("\t");
		const path = pathParts.at(-1) ?? "";
		const counts = numstat.get(path) ?? { added: 0, deleted: 0 };
		return {
			path,
			status,
			...counts,
			category: category(path),
			sensitive: isSensitive(path),
			symbols: symbols(repositoryRoot, path),
		};
	});
	const changedLines = files.reduce(
		(sum, file) => sum + file.added + file.deleted,
		0,
	);
	const risk = scoreReviewRisk({
		changedLines,
		sensitiveFiles: files
			.filter((file) => file.sensitive)
			.map((file) => file.path),
		dependenciesChanged: files.some((file) => file.category === "dependency"),
		migrationsChanged: files.some((file) => file.category === "migration"),
		publicApiChanged: files.some(
			(file) => file.category === "code" && file.symbols.length > 0,
		),
		testsAdded: files.some(
			(file) => file.category === "test" && file.status.startsWith("A"),
		),
		failedChecks: 0,
	});
	return {
		repositoryRoot,
		base: normalizedBase,
		head: git(repositoryRoot, ["rev-parse", "HEAD"]),
		branch: git(repositoryRoot, ["branch", "--show-current"]),
		files,
		summary: {
			filesChanged: files.length,
			changedLines,
			added: files.reduce((sum, file) => sum + file.added, 0),
			deleted: files.reduce((sum, file) => sum + file.deleted, 0),
			sensitiveFiles: files.filter((file) => file.sensitive).length,
		},
		risk,
		impact: analyzeChangedImpact(
			repositoryRoot,
			files.filter((f) => f.category === "code").map((f) => f.path),
		),
		generatedAt: new Date().toISOString(),
	};
}
