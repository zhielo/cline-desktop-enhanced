import { execFileSync } from "node:child_process";
import {
	existsSync,
	lstatSync,
	readFileSync,
	realpathSync,
	statSync,
} from "node:fs";
import { extname, isAbsolute, relative, resolve, sep } from "node:path";
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
	});
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
	if (lstatSync(absolute).isSymbolicLink()) return [];
	const canonicalRelative = relative(
		realpathSync(root),
		realpathSync(absolute),
	);
	if (canonicalRelative.startsWith("..") || isAbsolute(canonicalRelative))
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
		git(workspaceRoot, ["rev-parse", "--show-toplevel"]).trim(),
	);
	const normalizedBase = base.trim() || "HEAD";
	if (
		normalizedBase.startsWith("-") ||
		!/^[A-Za-z0-9_./~^{}-]{1,200}$/.test(normalizedBase)
	)
		throw new Error("Invalid Git comparison base");
	git(repositoryRoot, ["rev-parse", "--verify", normalizedBase]);
	const status = git(repositoryRoot, [
		"diff",
		"--name-status",
		"-z",
		normalizedBase,
		"--",
	]).split("\0");
	const changes: Array<{ status: string; path: string }> = [];
	for (let i = 0; i < status.length && status[i]; ) {
		const code = status[i++];
		let path = status[i++];
		if (/^[RC]/.test(code)) path = status[i++];
		if (path) changes.push({ status: code, path });
	}
	const untracked = git(repositoryRoot, [
		"ls-files",
		"--others",
		"--exclude-standard",
		"-z",
	])
		.split("\0")
		.filter(Boolean);
	for (const path of untracked) changes.push({ status: "?", path });
	if (changes.length > 10_000)
		throw new Error(
			"Git review inventory exceeds 10000 files; narrow the workspace",
		);
	const numstat = new Map<string, { added: number; deleted: number }>();
	const stats = git(repositoryRoot, [
		"diff",
		"--numstat",
		"-z",
		normalizedBase,
		"--",
	]).split("\0");
	for (let i = 0; i < stats.length; i++) {
		const [added, deleted, ...name] = stats[i].split("\t");
		let path = name.join("\t");
		if (name.length && !path) {
			i++;
			path = stats[++i];
		} // rename old/new paths
		if (path)
			numstat.set(path, {
				added: Number(added) || 0,
				deleted: Number(deleted) || 0,
			});
	}
	for (const path of untracked) {
		const absolute = resolve(repositoryRoot, path);
		if (!existsSync(absolute) || lstatSync(absolute).isSymbolicLink()) continue;
		const rel = relative(repositoryRoot, realpathSync(absolute));
		if (
			isAbsolute(rel) ||
			rel.startsWith("..") ||
			!statSync(absolute).isFile() ||
			statSync(absolute).size > 512_000
		)
			continue;
		const bytes = readFileSync(absolute);
		if (!bytes.includes(0)) {
			const text = bytes.toString("utf8");
			numstat.set(path, {
				added: text
					? text.split("\n").length - (text.endsWith("\n") ? 1 : 0)
					: 0,
				deleted: 0,
			});
		}
	}
	const files: EngineeringGitFile[] = changes.map(({ status, path }) => ({
		path,
		status,
		...(numstat.get(path) ?? { added: 0, deleted: 0 }),
		category: category(path),
		sensitive: isSensitive(path),
		symbols: symbols(repositoryRoot, path),
	}));
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
			(file) =>
				file.category === "test" &&
				(file.status.startsWith("A") || file.status === "?"),
		),
		failedChecks: undefined,
	});
	return {
		repositoryRoot,
		base: normalizedBase,
		head: git(repositoryRoot, ["rev-parse", "HEAD"]).trim(),
		branch: git(repositoryRoot, ["branch", "--show-current"]).trim(),
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
