import { privateProcessGroupGone } from "../runtime/private-process-group";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { hostname } from "node:os";
import { z } from "zod";
import { digest, type AnalysisReceipt } from "./contracts";
import {
	probeProcessStartTokenAsync,
	type ProcessStartTokenProbeResult,
} from "../runtime/process-start-token";
import type { FirstPartyAnalysisStore } from "./store";

const Instance = z
	.object({
		pid: z.number().int().positive(),
		token: z.string().min(1).max(300),
	})
	.strict();
export const OwnershipSchema = z
	.object({
		version: z.literal(1),
		host: z.string().regex(/^[a-f0-9]{64}$/),
		nonce: z.string().uuid(),
		owner: Instance,
		worker: Instance,
		descendants: z
			.object({
				kind: z.literal("linux-private-process-group"),
				id: z.number().int().positive(),
			})
			.strict()
			.optional(),
		binding: z.string().regex(/^[a-f0-9]{64}$/),
	})
	.strict();
export type AnalysisOwnership = z.infer<typeof OwnershipSchema>;
export const ownershipBinding = (
	r: AnalysisReceipt,
	p: Omit<AnalysisOwnership, "binding">,
) =>
	digest({
		id: r.id,
		sessionId: r.sessionId,
		workspace: r.workspace,
		requestHash: r.requestHash,
		profile: r.profile,
		createdAt: r.createdAt,
		ownership: p,
	});
/** Local machine namespace, not a copied ledger UUID. Unknown identity fails closed. */
export async function analysisHostIdentity(): Promise<string | undefined> {
	try {
		let machine: string;
		if (process.platform === "linux") {
			try {
				machine = (await readFile("/etc/machine-id", "utf8")).trim();
			} catch {
				machine = (
					await readFile("/proc/sys/kernel/random/boot_id", "utf8")
				).trim();
			}
		} else if (process.platform === "win32") {
			const root = process.env.SystemRoot;
			if (!root) return undefined;
			const text = await new Promise<string>((resolve, reject) =>
				execFile(
					join(root, "System32", "reg.exe"),
					[
						"query",
						"HKLM\\SOFTWARE\\Microsoft\\Cryptography",
						"/v",
						"MachineGuid",
						"/reg:64",
					],
					{ timeout: 2000, maxBuffer: 4096, windowsHide: true },
					(e, out) => (e ? reject(e) : resolve(out)),
				),
			);
			machine = /MachineGuid\s+REG_SZ\s+([a-f0-9-]+)/i.exec(text)?.[1] ?? "";
		} else return undefined;
		if (!/^[a-f0-9-]{32,36}$/i.test(machine)) return undefined;
		return digest({
			platform: process.platform,
			machine: machine.toLowerCase(),
			host: hostname(),
		});
	} catch {
		return undefined;
	}
}
export function originalInstanceGone(
	instance: { pid: number; token: string },
	probe: ProcessStartTokenProbeResult,
) {
	return (
		probe.status === "missing" ||
		(probe.status === "found" && probe.token !== instance.token)
	);
}
const strong = (token: string) =>
	/^(linux:[a-f0-9-]+:\d+|win32:\d+)$/.test(token);
export async function recoverFirstPartyReservation(
	sessionId: string,
	id: string,
	store: FirstPartyAnalysisStore,
	deps: {
		host: () => Promise<string | undefined>;
		probe: (pid: number) => Promise<ProcessStartTokenProbeResult>;
		groupGone?: (id: number) => boolean;
	} = { host: analysisHostIdentity, probe: probeProcessStartTokenAsync },
) {
	const r = store.get(sessionId, id),
		parsed = OwnershipSchema.safeParse(r.ownership);
	if (!["running", "termination-unconfirmed"].includes(r.status))
		throw new Error("Only unresolved reservations can be recovered");
	if (!parsed.success)
		throw new Error("Legacy or incomplete ownership proof; recovery blocked");
	const p = parsed.data,
		{ binding, ...unstamped } = p;
	if (
		ownershipBinding(r, unstamped) !== binding ||
		r.pid !== p.worker.pid ||
		p.owner.pid === p.worker.pid ||
		(p.descendants && p.descendants.id !== p.worker.pid) ||
		!strong(p.owner.token) ||
		!strong(p.worker.token)
	)
		throw new Error("Invalid process-instance ownership proof");
	const host = await deps.host();
	if (!host || host !== p.host)
		throw new Error("Unknown or foreign host; recovery blocked");
	const [owner, worker] = await Promise.all([
		deps.probe(p.owner.pid),
		deps.probe(p.worker.pid),
	]);
	if (
		!originalInstanceGone(p.owner, owner) ||
		!originalInstanceGone(p.worker, worker)
	)
		throw new Error(
			"Original owner/worker is alive or cannot be proved gone; recovery blocked",
		);
	if (
		p.descendants &&
		!(deps.groupGone ?? privateProcessGroupGone)(p.descendants.id)
	)
		throw new Error(
			"Original descendant group is alive or absence cannot be proved; recovery blocked",
		);
	return store.releaseReservation(r, digest(r));
}
