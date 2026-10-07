import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, realpathSync } from "node:fs";
import { dirname, join, relative, win32 } from "node:path";

export const WINDOWS_PROJECT_OUTPUT_ROOT = "C:\\Cline-Outputs";
export interface ProjectOutputLocation {
	root: string;
	projectDirectory: string;
	deliverables: string;
	reports: string;
	logs: string;
}

/** Read-only resolution: no folder creation during navigation or refresh. */
export function getProjectOutputLocation(
	workspace: string,
	platform = process.platform,
): ProjectOutputLocation | null {
	if (platform !== "win32") return null;
	if (
		workspace.length > 4096 ||
		!/^[A-Za-z]:[\\/]/.test(workspace) ||
		[...workspace].some((character) => character.charCodeAt(0) < 32)
	)
		throw new Error("A local absolute Windows project path is required");
	const canonical = win32
		.normalize(workspace)
		.replace(/[\\/]+$/, "")
		.toLowerCase();
	const name =
		win32
			.basename(canonical)
			.replace(/[^a-z0-9._-]+/g, "-")
			.replace(/^[.-]+|[.-]+$/g, "")
			.slice(0, 48) || "project";
	const key = createHash("sha256").update(canonical).digest("hex").slice(0, 16);
	const projectDirectory = win32.join(
		WINDOWS_PROJECT_OUTPUT_ROOT,
		`${name}-${key}`,
	);
	return {
		root: WINDOWS_PROJECT_OUTPUT_ROOT,
		projectDirectory,
		deliverables: win32.join(projectDirectory, "deliverables"),
		reports: win32.join(projectDirectory, "reports"),
		logs: win32.join(projectDirectory, "logs"),
	};
}

export function projectOutputInstructions(
	workspace: string,
	platform = process.platform,
): string {
	if (platform !== "win32" || !/^[A-Za-z]:[\\/]/.test(workspace)) return "";
	const location = getProjectOutputLocation(workspace, platform);
	if (!location) return "";
	return `\n<desktop_project_output>\nDefault generated project outputs: ${JSON.stringify(location)}\nPut final generated deliverables, reports and logs in the corresponding absolute directories. Create them only when needed, using normal approved file/shell operations. Keep source-code edits in the original workspace. Preserve build-system directories such as dist/build/out; copy a final deliverable only when requested or appropriate, never silently move existing files. Preserve managed private captures and native-engine databases in their existing protected storage. Use unique names for new task outputs and do not overwrite unrelated results. Include the actual absolute output paths in the final response and verify files exist. If C:\\Cline-Outputs cannot be used, report the permission/path error; do not silently fall back to AppData or another directory. This default does not change the shell working directory or redirect commands with explicit output paths.\n</desktop_project_output>`;
}

function assertDirectory(path: string): void {
	const stat = lstatSync(path, { bigint: true });
	if (!stat.isDirectory() || stat.isSymbolicLink())
		throw new Error(
			"Project output directories must not be links or junctions",
		);
	const actual = realpathSync.native(path);
	// Windows native canonical spelling can differ from the requested path.
	// Accept only the same directory object and parent object, not arbitrary
	// redirected names. The entry itself must still be a non-link directory.
	const canonical = lstatSync(actual, { bigint: true });
	const parent = lstatSync(dirname(path), { bigint: true });
	const canonicalParent = lstatSync(dirname(actual), { bigint: true });
	if (
		!canonical.isDirectory() ||
		canonical.isSymbolicLink() ||
		parent.isSymbolicLink() ||
		canonicalParent.isSymbolicLink() ||
		stat.ino === BigInt(0) ||
		parent.ino === BigInt(0) ||
		stat.dev !== canonical.dev ||
		stat.ino !== canonical.ino ||
		parent.dev !== canonicalParent.dev ||
		parent.ino !== canonicalParent.ino
	)
		throw new Error(
			"Project output directory identity redirects outside its fixed location",
		);
}

/** Called only by the explicit folder button, not a passive read. */
export function ensureProjectOutputDirectories(
	location: ProjectOutputLocation,
): string {
	const child = relative(location.root, location.projectDirectory);
	if (
		!child ||
		child.startsWith("..") ||
		/[\\/]/.test(child) ||
		!/^[a-z0-9._-]+-[0-9a-f]{16}$/.test(child)
	)
		throw new Error("Invalid project output identity");
	// No recursive mkdir follows a pre-existing junction. Validate each parent
	// before creating its direct child and revalidate the whole chain afterwards.
	try {
		mkdirSync(location.root);
	} catch (e) {
		if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
	}
	assertDirectory(location.root);
	try {
		mkdirSync(location.projectDirectory);
	} catch (e) {
		if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
	}
	assertDirectory(location.projectDirectory);
	for (const name of ["deliverables", "reports", "logs"]) {
		const target = join(location.projectDirectory, name);
		try {
			mkdirSync(target);
		} catch (e) {
			if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
		}
		assertDirectory(target);
	}
	assertDirectory(location.root);
	assertDirectory(location.projectDirectory);
	return location.projectDirectory;
}
