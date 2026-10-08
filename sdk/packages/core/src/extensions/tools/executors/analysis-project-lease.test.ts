import { mkdtemp, rm, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { withProjectLease } from "./analysis-project-lease";
it("retains a lease when process termination is uncertain", async () => {
	const root = await mkdtemp(join(tmpdir(), "uncertain-lease-"));
	try {
		await withProjectLease(join(root, "project"), async () => {}, undefined, { root, retainLease: () => true });
		expect(await readdir(root)).toHaveLength(1);
		await expect(withProjectLease(join(root, "project"), async () => {}, undefined, { root, waitMs: 1 })).rejects.toThrow("never automatically stolen");
	} finally { await rm(root, { recursive: true, force: true }); }
});

it("serializes independent owners and releases only after work finishes", async () => {
	const root = await mkdtemp(join(tmpdir(), "project-lease-"));
	try {
		const events: string[] = [];
		let release!: () => void;
		const held = withProjectLease(
			join(root, "project"),
			async () => {
				events.push("first");
				await new Promise<void>((r) => {
					release = r;
				});
				events.push("release");
			},
			undefined,
			{ root },
		);
		while (!release) await new Promise((r) => setTimeout(r, 10));
		const second = withProjectLease(
			join(root, "project"),
			async () => {
				events.push("second");
			},
			undefined,
			{ root },
		);
		await new Promise((r) => setTimeout(r, 80));
		expect(events).toEqual(["first"]);
		release();
		await Promise.all([held, second]);
		expect(events).toEqual(["first", "release", "second"]);
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
it("never steals a live lease and cancels bounded waits", async () => {
	const root = await mkdtemp(join(tmpdir(), "project-lease-"));
	let release!: () => void;
	const held = withProjectLease(
		join(root, "project"),
		async () =>
			new Promise<void>((r) => {
				release = r;
			}),
		undefined,
		{ root },
	);
	try {
		while (!release) await new Promise((r) => setTimeout(r, 10));
		await expect(
			withProjectLease(join(root, "project"), async () => {}, undefined, {
				root,
				waitMs: 30,
			}),
		).rejects.toThrow("never automatically stolen");
		const controller = new AbortController(),
			waiting = withProjectLease(
				join(root, "project"),
				async () => {},
				controller.signal,
				{ root },
			);
		setTimeout(() => controller.abort(), 10);
		await expect(waiting).rejects.toThrow();
	} finally {
		release();
		await held;
		await rm(root, { recursive: true, force: true });
	}
});
