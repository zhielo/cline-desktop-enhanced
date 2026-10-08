import { readdirSync, readFileSync, lstatSync, realpathSync } from "node:fs";
import { dirname, extname, relative, resolve, sep } from "node:path";
export function analyzeChangedImpact(root: string, changed: string[]) {
	const canonical = realpathSync(root);
	const changedSet = new Set(changed.map((p) => p.replaceAll("\\", "/")));
	const files: string[] = [];
	let scanned = 0;
	let truncated = false;
	let readBytes = 0;
	let readFiles = 0;
	const skip = new Set([
		".git",
		"node_modules",
		"dist",
		"build",
		"target",
		".next",
		"out",
	]);
	function walk(path: string, depth: number) {
		if (depth > 8) {
			truncated = true;
			return;
		}
		for (const entry of readdirSync(path, { withFileTypes: true })) {
			if (scanned++ >= 2000) {
				truncated = true;
				return;
			}
			if (entry.isSymbolicLink()) continue;
			const absolute = resolve(path, entry.name);
			if (entry.isDirectory()) {
				if (!skip.has(entry.name) && !entry.name.startsWith("."))
					walk(absolute, depth + 1);
			} else if (
				/\.[cm]?[jt]sx?$/.test(entry.name) &&
				lstatSync(absolute).size <= 256000
			)
				files.push(absolute);
		}
	}
	walk(canonical, 0);
	const affected = new Set(changedSet);
	const candidates: string[] = [];
	for (const absolute of files) {
		if (
			++readFiles > 250 ||
			readBytes + lstatSync(absolute).size > 8 * 1024 * 1024
		) {
			truncated = true;
			break;
		}
		const contained = relative(canonical, realpathSync(absolute));
		if (contained.startsWith("..") || lstatSync(absolute).isSymbolicLink())
			continue;
		const text = readFileSync(absolute, "utf8");
		readBytes += Buffer.byteLength(text);
		const importer = relative(canonical, absolute).split(sep).join("/");
		for (const match of text.matchAll(
			/(?:from\s*|import\s*(?:\(\s*)?|require\s*\(\s*)["'](\.[^"']{1,300})["']/g,
		)) {
			const imported = relative(canonical, resolve(dirname(absolute), match[1]))
				.split(sep)
				.join("/");
			if (imported.startsWith("../")) continue;
			if (
				[...changedSet].some(
					(p) =>
						p === imported ||
						p.replace(/\.[^.]+$/, "") === imported ||
						p === `${imported}/index.ts`,
				)
			)
				affected.add(importer);
		}
	}
	for (const file of affected) {
		const stem = file.replace(/\.[^.]+$/, "");
		for (const test of files.map((p) =>
			relative(canonical, p).split(sep).join("/"),
		))
			if (
				test === `${stem}.test.ts` ||
				test === `${stem}.test.tsx` ||
				test === `${stem}.spec.ts`
			)
				candidates.push(test);
	}
	return {
		kind: "bounded-static-import-impact",
		affectedFiles: [...affected].slice(0, 200),
		suggestedTestFiles: [...new Set(candidates)].slice(0, 100),
		scannedEntries: Math.min(scanned, 2000),
		readBytes,
		truncated,
		executedTests: false,
		limitations: [
			"Relative JS/TS import candidates only; not complete AST, dynamic import, alias, or semantic/security proof.",
			"Suggested tests are never executed automatically.",
		],
	};
}
