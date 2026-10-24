import { mkdtemp, rm, realpath } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { beforeEach, afterEach, expect, it } from "vitest";
import { FirstPartyAnalysisStore } from "./store";
import { ANALYSIS_PROFILE, digest, type AnalysisReceipt } from "./contracts";
import {
	ownershipBinding,
	recoverFirstPartyReservation,
	originalInstanceGone,
	analysisHostIdentity,
} from "./recovery";
import { probeProcessStartTokenAsync } from "../runtime/process-start-token";
let root: string, store: FirstPartyAnalysisStore;
const host = "a".repeat(64),
	token = "linux:00000000-0000-0000-0000-000000000000:123";
beforeEach(async () => {
	root = await realpath(await mkdtemp(join(tmpdir(), "cline-recovery-")));
	store = new FirstPartyAnalysisStore(join(root, "test.sqlite"));
	store.setMode("s", root, "static");
});
afterEach(async () => {
	store.close();
	await rm(root, { recursive: true, force: true });
});
function receipt(): AnalysisReceipt {
	const r: AnalysisReceipt = {
		id: randomUUID(),
		sessionId: "s",
		workspace: root,
		profile: ANALYSIS_PROFILE,
		input: { target: "." },
		requestHash: digest("request"),
		createdAt: new Date().toISOString(),
		status: "running",
		pid: 1234568,
	};
	const p = {
		version: 1 as const,
		host,
		nonce: randomUUID(),
		owner: { pid: 1234567, token },
		worker: { pid: 1234568, token },
	};
	r.ownership = { ...p, binding: ownershipBinding(r, p) };
	store.start(r);
	return r;
}
const gone = {
	host: async () => host,
	probe: async () => ({ status: "missing" as const }),
};
it("releases admission with immutable audit, without changing terminal evidence or replaying", async () => {
	const r = receipt();
	r.status = "termination-unconfirmed";
	store.save(r);
	const before = store.get("s", r.id);
	const audit = await recoverFirstPartyReservation("s", r.id, store, gone);
	expect(audit.bodyHash).toBe(digest(before));
	expect(store.get("s", r.id)).toEqual(before);
	expect(store.summaries("s")[0].reservationReleasedAt).toBe(audit.at);
	expect(() => store.setMode("s", root, "off")).not.toThrow();
	expect(() => store.save({ ...r, status: "completed" })).toThrow("immutable");
	await expect(
		recoverFirstPartyReservation("s", r.id, store, gone),
	).rejects.toThrow("already released");
});
it("blocks when either original instance is alive or permission probing is unavailable", async () => {
	for (const status of ["found", "unavailable"] as const)
		for (const alive of [1234567, 1234568]) {
			const r = receipt();
			await expect(
				recoverFirstPartyReservation("s", r.id, store, {
					host: gone.host,
					probe: async (pid) =>
						pid === alive
							? status === "found"
								? { status, token }
								: { status }
							: { status: "missing" },
				}),
			).rejects.toThrow("cannot be proved gone");
			r.status = "failed";
			store.save(r);
		}
});
it("PID reuse proves original instance gone but does not grant permission to kill replacement", () => {
	expect(
		originalInstanceGone(
			{ pid: 10, token },
			{ status: "found", token: token + "4" },
		),
	).toBe(true);
	expect(
		originalInstanceGone({ pid: 10, token }, { status: "unavailable" }),
	).toBe(false);
});
it("blocks foreign/unknown host and incomplete or tampered proof", async () => {
	const r = receipt();
	for (const h of [undefined, "b".repeat(64)])
		await expect(
			recoverFirstPartyReservation("s", r.id, store, {
				...gone,
				host: async () => h,
			}),
		).rejects.toThrow("host");
	delete r.ownership;
	store.save(r);
	await expect(
		recoverFirstPartyReservation("s", r.id, store, gone),
	).rejects.toThrow("incomplete");
	r.status = "failed";
	store.save(r);
	const bad = receipt();
	bad.ownership!.worker.token = "win32:not-a-birth-token";
	store.save(bad);
	await expect(
		recoverFirstPartyReservation("s", bad.id, store, gone),
	).rejects.toThrow("proof");
});
it("blocks other sessions and late worker writes after release", async () => {
	const r = receipt();
	await expect(
		recoverFirstPartyReservation("other", r.id, store, gone),
	).rejects.toThrow("session");
	await recoverFirstPartyReservation("s", r.id, store, gone);
	expect(() => store.save(r)).toThrow("immutable");
});
it("competing recovery compares exact receipt body inside a transaction", () => {
	const r = receipt(),
		expected = digest(r);
	r.pid = 55;
	store.save(r);
	expect(() => store.releaseReservation(r, expected)).toThrow("changed");
});
it("actual kernel probe identifies the live owner", async () => {
	if (!["linux", "win32"].includes(process.platform)) return;
	const h = await analysisHostIdentity(),
		probe = await probeProcessStartTokenAsync(process.pid);
	expect(h).toMatch(/^[a-f0-9]{64}$/);
	expect(probe.status).toBe("found");
	if (probe.status === "found")
		expect(
			originalInstanceGone({ pid: process.pid, token: probe.token }, probe),
		).toBe(false);
});

it("actual exited owner and worker instances can release a reservation after restart", async () => {
	if (!["linux", "win32"].includes(process.platform)) return;
	const owner = spawn(process.execPath, ["-e", "setInterval(()=>{},1000)"], {
			stdio: "ignore",
		}),
		worker = spawn(process.execPath, ["-e", "setInterval(()=>{},1000)"], {
			stdio: "ignore",
		});
	const stop = async (child: typeof owner) => {
		if (child.exitCode !== null || child.signalCode !== null) return;
		const done = new Promise<void>((resolve) =>
			child.once("exit", () => resolve()),
		);
		child.kill("SIGKILL");
		await done;
	};
	try {
		const h = await analysisHostIdentity(),
			a = await probeProcessStartTokenAsync(owner.pid!),
			b = await probeProcessStartTokenAsync(worker.pid!);
		if (!h || a.status !== "found" || b.status !== "found")
			throw new Error("Owned kernel fixture process proof unavailable");
		const r = receipt(),
			p = {
				version: 1 as const,
				host: h,
				nonce: randomUUID(),
				owner: { pid: owner.pid!, token: a.token },
				worker: { pid: worker.pid!, token: b.token },
			};
		r.pid = worker.pid;
		r.ownership = { ...p, binding: ownershipBinding(r, p) };
		store.save(r);
		await expect(
			recoverFirstPartyReservation("s", r.id, store),
		).rejects.toThrow("cannot be proved gone");
		await stop(owner);
		await stop(worker);
		const before = store.get("s", r.id),
			audit = await recoverFirstPartyReservation("s", r.id, store);
		expect(audit.bodyHash).toBe(digest(before));
		expect(store.get("s", r.id)).toEqual(before);
	} finally {
		await stop(owner);
		await stop(worker);
	}
}, 20000);

it("does not release a proved-dead leader while a bound descendant group may remain", async () => {
	const r = receipt();
	const { binding: _binding, ...proof } = r.ownership!;
	const extended = {
		...proof,
		descendants: { kind: "linux-private-process-group" as const, id: r.pid! },
	};
	r.ownership = { ...extended, binding: ownershipBinding(r, extended) };
	r.status = "termination-unconfirmed";
	store.save(r);
	for (const groupGone of [
		() => false,
		() => {
			throw new Error("unavailable");
		},
	])
		await expect(
			recoverFirstPartyReservation("s", r.id, store, { ...gone, groupGone }),
		).rejects.toThrow();
	expect(store.summaries("s")[0].reservationReleasedAt).toBeNull();
	const audit = await recoverFirstPartyReservation("s", r.id, store, {
		...gone,
		groupGone: () => true,
	});
	expect(audit.bodyHash).toBe(digest(store.get("s", r.id)));
});

it("binds descendant identity to its private group leader rather than an arbitrary PID", async () => {
	const r = receipt();
	const { binding: _binding, ...proof } = r.ownership!;
	const extended = {
		...proof,
		descendants: {
			kind: "linux-private-process-group" as const,
			id: r.pid! + 1,
		},
	};
	r.ownership = { ...extended, binding: ownershipBinding(r, extended) };
	store.save(r);
	await expect(
		recoverFirstPartyReservation("s", r.id, store, {
			...gone,
			groupGone: () => true,
		}),
	).rejects.toThrow("Invalid process-instance");
});
