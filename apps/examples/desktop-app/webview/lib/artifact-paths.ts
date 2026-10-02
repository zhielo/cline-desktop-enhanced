const CODE_EXTENSIONS = new Set([
	"c",
	"cc",
	"cpp",
	"cs",
	"css",
	"go",
	"h",
	"hpp",
	"html",
	"java",
	"js",
	"jsx",
	"kt",
	"kts",
	"mjs",
	"php",
	"py",
	"rb",
	"rs",
	"scss",
	"sh",
	"sql",
	"swift",
	"ts",
	"tsx",
	"vue",
]);

const INLINE_PREVIEW_EXTENSIONS = new Set([
	"c",
	"cc",
	"cpp",
	"cs",
	"css",
	"csv",
	"gif",
	"go",
	"h",
	"hpp",
	"html",
	"java",
	"jpeg",
	"jpg",
	"js",
	"json",
	"jsx",
	"kt",
	"log",
	"md",
	"mjs",
	"pdf",
	"php",
	"png",
	"py",
	"rb",
	"rs",
	"scss",
	"sh",
	"sql",
	"svg",
	"swift",
	"toml",
	"ts",
	"tsx",
	"txt",
	"vue",
	"webp",
	"xml",
	"yaml",
	"yml",
]);

export const ARTIFACT_EXTENSION_SOURCE =
	"7z|aab|apk|apks|c|cc|cpp|cs|css|csv|doc|docx|exe|gif|go|h|hpp|html|java|jpeg|jpg|js|json|jsx|kt|kts|log|md|mjs|msi|pdf|php|png|ppt|pptx|py|rar|rb|rs|scss|sh|sql|svg|swift|tar|toml|ts|tsx|txt|vue|webp|xls|xlsx|xml|yaml|yml|zip";

export type ArtifactReference = {
	path: string;
	line?: number;
	column?: number;
};

export function parseArtifactReference(value: string): ArtifactReference {
	const normalized = value.trim().replace(/[),.;!?]+$/, "");
	const match = normalized.match(/^(.*?):(\d+)(?::(\d+))?$/);
	if (!match) return { path: normalized };
	return {
		path: match[1] ?? normalized,
		line: Number(match[2]),
		column: match[3] ? Number(match[3]) : undefined,
	};
}

export function isCodeArtifactPath(path: string): boolean {
	const extension = path
		.replace(/:\d+(?::\d+)?$/, "")
		.match(/\.([A-Za-z0-9]+)$/)?.[1]
		?.toLowerCase();
	return extension ? CODE_EXTENSIONS.has(extension) : false;
}

export function isInlinePreviewArtifactPath(path: string): boolean {
	const extension = path
		.replace(/:\d+(?::\d+)?$/, "")
		.match(/\.([A-Za-z0-9]+)$/)?.[1]
		?.toLowerCase();
	return extension ? INLINE_PREVIEW_EXTENSIONS.has(extension) : false;
}

export function isArtifactReference(value: string): boolean {
	const reference = parseArtifactReference(value);
	return new RegExp(
		`^(?:(?:\\.{0,2}[\\\\/])|(?:[A-Za-z]:[\\\\/])|(?:[\\w@.-]+[\\\\/])).+\\.(?:${ARTIFACT_EXTENSION_SOURCE})$`,
		"i",
	).test(reference.path);
}

export function extractArtifactPaths(content: string): string[] {
	const matches: string[] = [];
	const patterns = [
		new RegExp(
			`[A-Za-z]:[\\\\/][^\\r\\n"<>|?*]+?\\.(?:${ARTIFACT_EXTENSION_SOURCE})(?=(?::\\d+(?::\\d+)?)?(?:[\\s),;.!?]|$))`,
			"gi",
		),
		new RegExp(
			`(?:^|[\\s(])((?:\\.{0,2}[\\\\/]|[\\w@.-]+[\\\\/])[^\\r\\n\\x60"<>|?*]+?\\.(?:${ARTIFACT_EXTENSION_SOURCE}))(?=(?::\\d+(?::\\d+)?)?(?:[\\s),;.!?]|$))`,
			"gim",
		),
	];
	for (const pattern of patterns) {
		for (const match of content.matchAll(pattern)) {
			const candidate = (match[1] ?? match[0]).trim();
			const path = parseArtifactReference(candidate).path;
			if (path && !matches.includes(path)) matches.push(path);
		}
	}
	return matches;
}
