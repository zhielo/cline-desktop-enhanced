import { z } from "zod";
import { createHash } from "node:crypto";

const hash = z.string().regex(/^[a-f0-9]{64}$/);
const relativePath = z
	.string()
	.min(1)
	.max(4096)
	.refine(
		(p) =>
			p === "." ||
			(!p.includes("\\") &&
				!/[\0\r\n]/.test(p) &&
				!p.startsWith("/") &&
				!/^[a-z]:/i.test(p) &&
				p.split("/").every((s) => s !== "" && s !== "." && s !== "..")),
		"Acquisition paths must be confined relative labels",
	);
const origin = z.discriminatedUnion("kind", [
	z.object({ kind: z.literal("file"), path: relativePath }).strict(),
	z
		.object({
			kind: z.literal("asar-member"),
			containerPath: relativePath,
			containerSha256: hash,
			offset: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
		})
		.strict(),
]);
const bodySchema = z
	.object({
		version: z.literal(1),
		selectedPath: relativePath,
		selection: z.literal("explicit-workspace-target"),
		coverage: z.literal("partial"),
		containers: z
			.array(
				z
					.object({
						path: relativePath,
						sha256: hash,
						bytes: z
							.number()
							.int()
							.nonnegative()
							.max(32 * 1024 * 1024),
						kind: z.literal("asar-candidate"),
					})
					.strict(),
			)
			.max(128),
		sources: z
			.array(
				z
					.object({
						path: relativePath,
						sha256: hash,
						bytes: z
							.number()
							.int()
							.nonnegative()
							.max(1024 * 1024),
						origin,
					})
					.strict(),
			)
			.max(128),
		limitations: z.array(z.string().max(1000)).max(84),
	})
	.strict();

export type AcquisitionBody = z.infer<typeof bodySchema>;
const hashBody = (body: AcquisitionBody) =>
	createHash("sha256").update(JSON.stringify(body)).digest("hex");
/** Fixed field order and sorted arrays; this commits observed bytes, not a producer signature. */
export function acquisitionDigest(body: AcquisitionBody) {
	return hashBody(bodySchema.parse(body));
}
export const AcquisitionSchema = bodySchema
	.extend({ manifestSha256: hash })
	.superRefine((report, ctx) => {
		const { manifestSha256, ...body } = report;
		const reject = (message: string) =>
			ctx.addIssue({ code: "custom", message });
		if (hashBody(body) !== manifestSha256)
			reject("Acquisition manifest digest mismatch");
		const containers = new Map(report.containers.map((c) => [c.path, c]));
		if (containers.size !== report.containers.length)
			reject("Duplicate acquisition container");
		if (report.containers.reduce((n, c) => n + c.bytes, 0) > 64 * 1024 * 1024)
			reject("Acquisition container byte budget exceeded");
		if (report.sources.reduce((n, s) => n + s.bytes, 0) > 8 * 1024 * 1024)
			reject("Acquisition source byte budget exceeded");
		const sources = new Set<string>();
		for (const s of report.sources) {
			if (s.path === "." || sources.has(s.path))
				reject("Duplicate or invalid acquisition source");
			sources.add(s.path);
			if (s.origin.kind === "file") {
				if (s.origin.path !== s.path)
					reject("Acquisition file origin mismatch");
			} else {
				const c = containers.get(s.origin.containerPath);
				if (
					!c ||
					c.sha256 !== s.origin.containerSha256 ||
					s.origin.offset + s.bytes > c.bytes ||
					!s.path.startsWith(`${s.origin.containerPath}!/`)
				)
					reject("Acquisition member/container binding mismatch");
			}
		}
	});
export type AcquisitionReport = z.infer<typeof AcquisitionSchema>;
export function buildAcquisitionReport(
	body: AcquisitionBody,
): AcquisitionReport {
	const ordered = bodySchema.parse({
		...body,
		limitations: [...new Set(body.limitations)].sort(),
		containers: [...body.containers].sort((a, b) =>
			a.path < b.path ? -1 : a.path > b.path ? 1 : 0,
		),
		sources: [...body.sources].sort((a, b) =>
			a.path < b.path ? -1 : a.path > b.path ? 1 : 0,
		),
	});
	return AcquisitionSchema.parse({
		...ordered,
		manifestSha256: acquisitionDigest(ordered),
	});
}
