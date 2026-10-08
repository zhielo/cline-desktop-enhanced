import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { resolveClineDataDir } from "@cline/shared/storage";
/** Cross-process project coordination, not an OS sandbox or control of external GUI writers. */
export async function withProjectLease<T>(
	key: string,
	work: () => Promise<T>,
	signal?: AbortSignal,
	options: { root?: string; waitMs?: number; retainLease?: () => boolean } = {},
) {
	const resolved = await realpath(resolve(key)).catch(() => resolve(key)),
		canonical =
			process.platform === "win32" ? resolved.toLowerCase() : resolved;
	const root =
			options.root ?? join(resolveClineDataDir(), "analysis", "project-leases"),
		name = createHash("sha256").update(canonical).digest("hex"),
		lease = join(root, name),
		nonce = randomUUID(),
		until = Date.now() + (options.waitMs ?? 30000);
	await mkdir(root, { recursive: true, mode: 0o700 });
	for (;;) {
		signal?.throwIfAborted();
		try {
			await mkdir(lease, { mode: 0o700 });
			break;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
			if (Date.now() >= until)
				throw new Error(
					"Analysis project is leased; inspect the owner before recovery. Stale leases are never automatically stolen.",
				);
			await new Promise<void>((res, rej) => {
				const timer = setTimeout(() => {
					signal?.removeEventListener("abort", abort);
					res();
				}, 50);
				const abort = () => {
					clearTimeout(timer);
					rej(new Error("Project lease wait cancelled"));
				};
				signal?.addEventListener("abort", abort, { once: true });
				if (signal?.aborted) abort();
			});
		}
	}
	let published = false;
	try {
		await writeFile(
			join(lease, "owner.json"),
			JSON.stringify({
				protocol: 1,
				pid: process.pid,
				nonce,
				createdAt: new Date().toISOString(),
				keySha256: name,
			}),
			{ flag: "wx", mode: 0o600 },
		);
		published = true;
		signal?.throwIfAborted();
		return await work();
	} finally {
		if (!options.retainLease?.() && (
			!published ||
			JSON.parse(await readFile(join(lease, "owner.json"), "utf8")).nonce ===
				nonce
		))
			await rm(lease, { recursive: true });
	}
}
