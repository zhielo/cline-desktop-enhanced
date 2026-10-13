import { byteDigest, LIMITS } from "./contracts";
const BASE64 =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/** Source Map v3 basic maps only. Labels are data; never fetch or open sourceRoot/sources. */
export function sourceMapLocations(text: string, limit: number = LIMITS.facts) {
	if (Buffer.byteLength(text) > LIMITS.sourceBytes)
		throw new Error("Source map byte budget exceeded");
	const map = JSON.parse(text) as Record<string, unknown>;
	if (
		map.version !== 3 ||
		map.sections ||
		typeof map.mappings !== "string" ||
		!Array.isArray(map.sources) ||
		map.sources.length > LIMITS.files ||
		map.sources.some((s) => typeof s !== "string" || s.length > 4096) ||
		(map.sourceRoot !== undefined &&
			(typeof map.sourceRoot !== "string" || map.sourceRoot.length > 4096))
	)
		throw new Error("Unsupported source map shape");
	const sources = map.sources as string[],
		contents = map.sourcesContent;
	if (
		contents !== undefined &&
		(!Array.isArray(contents) ||
			contents.length !== sources.length ||
			contents.some(
				(s) =>
					s !== null &&
					(typeof s !== "string" || Buffer.byteLength(s) > LIMITS.sourceBytes),
			))
	)
		throw new Error("Invalid embedded source content");
	const names = map.names ?? [];
	if (
		!Array.isArray(names) ||
		names.length > LIMITS.facts ||
		names.some((n) => typeof n !== "string" || n.length > 1000)
	)
		throw new Error("Invalid map names");
	const locations: Array<{
		generatedLine: number;
		generatedColumn: number;
		generatedFileLabel?: string;
		sourceLabel: string;
		sourceRootLabel?: string;
		originalLine: number;
		originalColumn: number;
		embeddedSha256?: string;
		name?: string;
	}> = [];
	const hashes = sources.map((_, i) =>
		Array.isArray(contents) && typeof contents[i] === "string"
			? byteDigest(Buffer.from(contents[i]))
			: undefined,
	);
	let sourceIndex = 0,
		originalLine = 0,
		originalColumn = 0,
		nameIndex = 0,
		segments = 0;
	for (const [line, row] of map.mappings.split(";").entries()) {
		let generatedColumn = 0;
		for (const segment of row.split(",")) {
			if (!segment) continue;
			if (++segments > LIMITS.nodes || locations.length >= limit)
				return { locations, partial: true };
			const values: number[] = [];
			let number = 0,
				bits = 0,
				continuation = false;
			for (const c of segment) {
				const digit = BASE64.indexOf(c);
				if (digit < 0 || bits > 30) throw new Error("Invalid VLQ mapping");
				number += (digit & 31) * 2 ** bits;
				continuation = !!(digit & 32);
				if (continuation) {
					bits += 5;
					continue;
				}
				values.push(
					number & 1 ? -Math.floor(number / 2) : Math.floor(number / 2),
				);
				number = 0;
				bits = 0;
			}
			if (continuation || ![1, 4, 5].includes(values.length))
				throw new Error("Invalid mapping arity");
			generatedColumn += values[0];
			if (!Number.isSafeInteger(generatedColumn) || generatedColumn < 0)
				throw new Error("Invalid generated position");
			if (values.length === 1) continue;
			sourceIndex += values[1];
			originalLine += values[2];
			originalColumn += values[3];
			if (
				sourceIndex < 0 ||
				sourceIndex >= sources.length ||
				originalLine < 0 ||
				originalColumn < 0 ||
				![sourceIndex, originalLine, originalColumn].every(Number.isSafeInteger)
			)
				throw new Error("Invalid original position");
			let name: string | undefined;
			if (values.length === 5) {
				nameIndex += values[4];
				if (nameIndex < 0 || nameIndex >= names.length)
					throw new Error("Invalid name index");
				name = names[nameIndex];
			}
			const sourceLabel = sources[sourceIndex];
			if (sourceLabel.length > 4096) throw new Error("Map source label budget");
			locations.push({
				generatedFileLabel:
					typeof map.file === "string" && map.file.length <= 4096
						? map.file
						: undefined,
				generatedLine: line + 1,
				generatedColumn: generatedColumn + 1,
				sourceLabel,
				sourceRootLabel:
					typeof map.sourceRoot === "string" ? map.sourceRoot : undefined,
				originalLine: originalLine + 1,
				originalColumn: originalColumn + 1,
				embeddedSha256: hashes[sourceIndex],
				name,
			});
		}
	}
	return { locations, partial: false };
}
