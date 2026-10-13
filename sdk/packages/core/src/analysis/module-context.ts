import ts from "typescript";
import path from "node:path";
import type { SourceArtifact } from "./parser";
/** Only inventory bytes participate. No disk, package search, libraries or network. */
export function closedModuleContext(sources: SourceArtifact[]) {
	const files = new Map(
		sources
			.filter((s) => /\.[cm]?[jt]sx?$/.test(s.path))
			.map((s) => [
				s.path,
				ts.createSourceFile(
					s.path,
					s.source,
					ts.ScriptTarget.Latest,
					true,
					/\.[jt]sx$/.test(s.path)
						? ts.ScriptKind.TSX
						: /\.[cm]?ts$/.test(s.path)
							? ts.ScriptKind.TS
							: ts.ScriptKind.JS,
				),
			]),
	);
	const resolve = (from: string, label: string): string | undefined => {
		if (!label.startsWith(".")) return undefined;
		const base = path.posix.normalize(
			path.posix.join(path.posix.dirname(from), label),
		);
		const matches = [
			base,
			...[
				".js",
				".ts",
				".mjs",
				".cjs",
				".mts",
				".cts",
				".jsx",
				".tsx",
				"/index.js",
				"/index.ts",
			].map((e) => base + e),
		].filter((x) => files.has(x));
		return matches.length === 1 ? matches[0] : undefined;
	};
	const host: ts.CompilerHost = {
		getSourceFile: (n) => files.get(n),
		getDefaultLibFileName: () => "",
		writeFile: () => {},
		getCurrentDirectory: () => "",
		getDirectories: () => [],
		fileExists: (n) => files.has(n),
		readFile: (n) => sources.find((s) => s.path === n)?.source,
		getCanonicalFileName: (n) => n,
		useCaseSensitiveFileNames: () => true,
		getNewLine: () => "\n",
		resolveModuleNames: (names, from) =>
			names.map((label) => {
				const name = resolve(from, label);
				return name ? { resolvedFileName: name } : undefined;
			}),
	};
	const program = ts.createProgram(
		[...files.keys()],
		{
			allowJs: true,
			noLib: true,
			noResolve: false,
			target: ts.ScriptTarget.Latest,
		},
		host,
	);
	return {
		checker: program.getTypeChecker(),
		files: [...files.values()],
		resolve,
	};
}
export type ClosedModuleContext = ReturnType<typeof closedModuleContext>;
