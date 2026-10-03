import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
	existsSync,
	lstatSync,
	readFileSync,
	realpathSync,
	statSync,
} from "node:fs";
import {
	basename,
	extname,
	isAbsolute,
	relative,
	resolve,
	sep,
} from "node:path";

const MAX_PATCH_BYTES = 1_000_000;
const MAX_PATCH_FILES = 50;
const ALLOWED_EXTENSIONS = new Set([
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
const BLOCKED_NAMES = [
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

type PatchFileStatus = "Modified" | "Added" | "Deleted";

export type NotionAgentPatchFile = {
	path: string;
	status: PatchFileStatus;
	originalHash: string | null;
	expectedHash: string | null;
	additions: number;
	deletions: number;
};

export type NotionAgentPatchPreview = {
	previewId: string;
	root: string;
	baseCommit: string;
	baseBranch: string;
	cleanWorkspace: boolean;
	applicable: boolean;
	files: NotionAgentPatchFile[];
	additions: number;
	deletions: number;
	warnings: string[];
	citations: string[];
	patchHash: string;
};

export type PreviewNotionAgentPatchOptions = {
	root: string;
	patch: string;
	approvedHashes?: Record<string, string>;
	allowNewFiles?: boolean;
	response?: string;
};

export type ApplyNotionAgentPatchOptions = PreviewNotionAgentPatchOptions & {
	confirm: boolean;
	branchName?: string;
};

export type AppliedNotionAgentPatch = NotionAgentPatchPreview & {
	branch: string;
	previousBranch: string;
	appliedHashes: Record<string, string | null>;
};

function git(root: string, args: string[], input?: string): string {
	return execFileSync("git", ["-C", root, ...args], {
		encoding: "utf8",
		input,
		maxBuffer: 8 * 1024 * 1024,
		stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
		windowsHide: true,
	}).trim();
}

function isWithinRoot(root: string, candidate: string): boolean {
	const left = process.platform === "win32" ? root.toLowerCase() : root;
	const right =
		process.platform === "win32" ? candidate.toLowerCase() : candidate;
	return right === left || right.startsWith(`${left}${sep}`);
}

function normalizePatchPath(root: string, value: string): string {
	const normalized = value.replace(/\\/g, "/").trim();
	if (!normalized || normalized === "/dev/null" || isAbsolute(normalized)) {
		throw new Error(`Invalid patch path: ${value}`);
	}
	const absolute = resolve(root, normalized);
	if (!isWithinRoot(root, absolute))
		throw new Error(`Patch path escapes the workspace: ${normalized}`);
	const relativePath = relative(root, absolute).split(sep).join("/");
	const name = basename(relativePath);
	const extension = extname(name).toLowerCase();
	if (
		BLOCKED_NAMES.some((pattern) => pattern.test(name)) ||
		BLOCKED_EXTENSIONS.has(extension)
	) {
		throw new Error(`Patch targets a sensitive file: ${relativePath}`);
	}
	if (name.startsWith(".") && !relativePath.startsWith(".github/")) {
		throw new Error(`Patch targets a hidden file: ${relativePath}`);
	}
	if (
		(!extension && !SAFE_EXTENSIONLESS_NAMES.has(name.toLowerCase())) ||
		(extension && !ALLOWED_EXTENSIONS.has(extension))
	) {
		throw new Error(`Patch targets an unsupported file type: ${relativePath}`);
	}
	return relativePath;
}

function hashFile(root: string, path: string): string | null {
	const absolute = resolve(root, path);
	if (!existsSync(absolute)) return null;
	if (lstatSync(absolute).isSymbolicLink())
		throw new Error(`Patch target is a symbolic link: ${path}`);
	const realRoot = realpathSync(root);
	const realFile = realpathSync(absolute);
	if (!isWithinRoot(realRoot, realFile) || !statSync(realFile).isFile()) {
		throw new Error(`Patch target resolves outside the workspace: ${path}`);
	}
	return createHash("sha256").update(readFileSync(realFile)).digest("hex");
}

function parsePatch(
	root: string,
	patch: string,
): Array<{
	path: string;
	status: PatchFileStatus;
	additions: number;
	deletions: number;
}> {
	if (!patch.trim()) throw new Error("Paste a unified Git patch first");
	if (Buffer.byteLength(patch) > MAX_PATCH_BYTES)
		throw new Error("Patch exceeds the 1 MB safety limit");
	if (/GIT binary patch|Binary files .* differ/.test(patch))
		throw new Error("Binary patches are not supported");
	if (
		/^similarity index |^rename (?:from|to) |^copy (?:from|to) /m.test(patch)
	) {
		throw new Error(
			"Rename and copy patches are not supported; request explicit delete/add changes",
		);
	}
	const lines = patch.replace(/\r\n/g, "\n").split("\n");
	const files: Array<{
		path: string;
		status: PatchFileStatus;
		additions: number;
		deletions: number;
	}> = [];
	let current: (typeof files)[number] | undefined;
	for (const line of lines) {
		const match = /^diff --git a\/(.+) b\/(.+)$/.exec(line);
		if (match) {
			const sourcePath = match[1];
			const targetPath = match[2];
			if (!sourcePath || !targetPath)
				throw new Error("Patch contains an empty file path");
			if (sourcePath !== targetPath)
				throw new Error("Patch path changes are not supported");
			current = {
				path: normalizePatchPath(root, targetPath),
				status: "Modified",
				additions: 0,
				deletions: 0,
			};
			files.push(current);
			continue;
		}
		if (!current) continue;
		if (line.startsWith("new file mode ")) current.status = "Added";
		if (line.startsWith("deleted file mode ")) current.status = "Deleted";
		if (line.startsWith("+") && !line.startsWith("+++")) current.additions += 1;
		if (line.startsWith("-") && !line.startsWith("---")) current.deletions += 1;
	}
	if (files.length === 0)
		throw new Error("No diff --git file sections were found");
	if (files.length > MAX_PATCH_FILES)
		throw new Error(
			`Patch changes ${files.length} files; maximum is ${MAX_PATCH_FILES}`,
		);
	if (new Set(files.map((file) => file.path)).size !== files.length)
		throw new Error("Patch contains duplicate file sections");
	return files;
}

function extractCitations(response: string): string[] {
	const matches =
		response.match(
			/(?:^|\s)([\w./-]+:\d+(?:-\d+)?@sha256:[a-f0-9]{8,64})\b/gi,
		) ?? [];
	return [...new Set(matches.map((value) => value.trim()))].slice(0, 100);
}

export function previewNotionAgentPatch(
	options: PreviewNotionAgentPatchOptions,
): NotionAgentPatchPreview {
	const root = resolve(options.root);
	if (!existsSync(root) || !statSync(root).isDirectory())
		throw new Error(`Workspace directory not found: ${root}`);
	const parsed = parsePatch(root, options.patch);
	const approvedHashes = options.approvedHashes ?? {};
	const files: NotionAgentPatchFile[] = parsed.map((file) => {
		const originalHash = hashFile(root, file.path);
		const expectedHash = approvedHashes[file.path] ?? null;
		if (file.status === "Added") {
			if (originalHash !== null)
				throw new Error(
					`New-file patch would overwrite an existing file: ${file.path}`,
				);
			if (!options.allowNewFiles)
				throw new Error(`New file requires explicit approval: ${file.path}`);
		} else {
			if (originalHash === null)
				throw new Error(`Patch target does not exist: ${file.path}`);
			if (!expectedHash)
				throw new Error(
					`Patch target was not in the approved Agent Bridge package: ${file.path}`,
				);
			if (originalHash !== expectedHash)
				throw new Error(
					`Patch target changed after sharing with Notion: ${file.path}`,
				);
		}
		return { ...file, originalHash, expectedHash };
	});
	const baseCommit = git(root, ["rev-parse", "HEAD"]);
	const baseBranch = git(root, ["branch", "--show-current"]) || "DETACHED";
	const cleanWorkspace = git(root, ["status", "--porcelain"]) === "";
	const warnings: string[] = [];
	if (!cleanWorkspace)
		warnings.push(
			"Workspace has uncommitted changes; apply is blocked until it is clean.",
		);
	if (files.some((file) => file.status === "Deleted"))
		warnings.push("Patch deletes one or more approved files.");
	const citations = extractCitations(options.response ?? "");
	if (options.response?.trim() && citations.length === 0)
		warnings.push(
			"Agent response contains no verifiable path:line@sha256 citations.",
		);
	let applicable = false;
	try {
		git(
			root,
			["apply", "--check", "--whitespace=error-all", "-"],
			options.patch,
		);
		applicable = cleanWorkspace;
	} catch (cause) {
		const message = cause instanceof Error ? cause.message : String(cause);
		warnings.push(`Git dry-run failed: ${message.split("\n")[0]}`);
	}
	return {
		previewId: randomUUID(),
		root,
		baseCommit,
		baseBranch,
		cleanWorkspace,
		applicable,
		files,
		additions: files.reduce((sum, file) => sum + file.additions, 0),
		deletions: files.reduce((sum, file) => sum + file.deletions, 0),
		warnings,
		citations,
		patchHash: createHash("sha256").update(options.patch).digest("hex"),
	};
}

function safeBranchName(value?: string): string {
	const suffix = (
		value?.trim() || new Date().toISOString().replace(/[:.]/g, "-")
	)
		.replace(/[^A-Za-z0-9._/-]+/g, "-")
		.replace(/^[-/.]+|[-/.]+$/g, "");
	if (!suffix || suffix.includes("..") || suffix.startsWith("-"))
		throw new Error("Invalid patch branch name");
	return suffix.startsWith("notion-agent/") ? suffix : `notion-agent/${suffix}`;
}

export function applyNotionAgentPatch(
	options: ApplyNotionAgentPatchOptions,
): AppliedNotionAgentPatch {
	if (options.confirm !== true)
		throw new Error("Applying a Notion Agent patch requires confirm=true");
	const preview = previewNotionAgentPatch(options);
	if (!preview.applicable || !preview.cleanWorkspace)
		throw new Error(
			"Patch cannot be applied until the dry-run passes and the workspace is clean",
		);
	const branch = safeBranchName(options.branchName);
	const previousBranch = preview.baseBranch;
	if (previousBranch === "DETACHED")
		throw new Error(
			"Create or switch to a named Git branch before applying a patch",
		);
	if (git(preview.root, ["branch", "--list", branch]))
		throw new Error(`Branch already exists: ${branch}`);
	git(preview.root, ["switch", "-c", branch]);
	try {
		git(preview.root, ["apply", "--whitespace=error-all", "-"], options.patch);
	} catch (cause) {
		git(preview.root, ["switch", previousBranch]);
		git(preview.root, ["branch", "-D", branch]);
		throw cause;
	}
	return {
		...preview,
		branch,
		previousBranch,
		appliedHashes: Object.fromEntries(
			preview.files.map((file) => [
				file.path,
				hashFile(preview.root, file.path),
			]),
		),
	};
}

export function rollbackNotionAgentPatch(options: {
	root: string;
	patch: string;
	branch: string;
	previousBranch: string;
	appliedHashes: Record<string, string | null>;
	confirm: boolean;
}): { rolledBack: true; branchDeleted: string; currentBranch: string } {
	if (options.confirm !== true)
		throw new Error("Rolling back a patch requires confirm=true");
	const root = resolve(options.root);
	const currentBranch = git(root, ["branch", "--show-current"]);
	if (
		currentBranch !== options.branch ||
		!options.branch.startsWith("notion-agent/")
	)
		throw new Error(
			"Rollback is allowed only on the exact generated Notion Agent branch",
		);
	for (const [path, expected] of Object.entries(options.appliedHashes)) {
		if (hashFile(root, normalizePatchPath(root, path)) !== expected)
			throw new Error(
				`File changed after patch application; rollback stopped: ${path}`,
			);
	}
	git(root, ["apply", "--reverse", "--check", "-"], options.patch);
	git(root, ["apply", "--reverse", "-"], options.patch);
	if (git(root, ["status", "--porcelain"]) !== "")
		throw new Error(
			"Rollback did not restore a clean workspace; branch was preserved",
		);
	git(root, ["switch", options.previousBranch]);
	git(root, ["branch", "-D", options.branch]);
	return {
		rolledBack: true,
		branchDeleted: options.branch,
		currentBranch: options.previousBranch,
	};
}
