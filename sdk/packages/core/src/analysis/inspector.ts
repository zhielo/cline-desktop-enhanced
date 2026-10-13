import { readdir, readFile, readlink, open } from "node:fs/promises";
import { realpathSync } from "node:fs";
import { execFile } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import WebSocket from "ws";
import { z } from "zod";
import { byteDigest } from "./contracts";
import { probeProcessStartTokenAsync } from "../runtime/process-start-token";
/** Lexical source-label comparison only; never opens/fetches an Inspector URL. */
export function sameInspectorSourcePath(
	label: string,
	target: string,
	platform: NodeJS.Platform = process.platform,
) {
	if (platform !== "win32") return label === target;
	const normalize = (p: string) =>
		p
			.replace(/^\\\\\?\\UNC\\/i, "\\\\")
			.replace(/^\\\\\?\\/, "")
			.replaceAll("\\", "/")
			.toLowerCase();
	return normalize(label) === normalize(target);
}
export const InspectorRequestSchema = z
	.object({
		operation: z.literal("js_inspector_observe"),
		target: z.string().min(1).max(4096),
		pid: z.number().int().positive(),
		processToken: z.string().min(1).max(300),
		endpoint: z.string().max(2048),
		durationMs: z.number().int().min(200).max(5000).default(1000),
	})
	.strict();
/** Endpoint must be bound to the selected live process, not merely accompanied by a PID. */
export async function assertInspectorOwner(pid: number, port: number) {
	if (process.platform === "linux") {
		const tcp = await readFile("/proc/net/tcp", "utf8"),
			inodes = new Set(
				tcp
					.split("\n")
					.slice(1)
					.map((line) => line.trim().split(/\s+/))
					.filter(
						(c) =>
							c[1] ===
								`0100007F:${port.toString(16).toUpperCase().padStart(4, "0")}` &&
							c[3] === "0A",
					)
					.map((c) => c[9]),
			);
		const fds = await readdir(`/proc/${pid}/fd`);
		if (fds.length > 4096) throw new Error("Inspector descriptor budget");
		for (const fd of fds) {
			let link: string;
			try {
				link = await readlink(`/proc/${pid}/fd/${fd}`);
			} catch {
				continue;
			}
			const inode = /^socket:\[(\d+)\]$/.exec(link)?.[1];
			if (inode && inodes.has(inode)) return;
		}
	} else if (process.platform === "win32") {
		const root = process.env.SystemRoot;
		if (!root) throw new Error("Inspector owner probe unavailable");
		const output = await new Promise<string>((resolve, reject) =>
			execFile(
				join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
				[
					"-NoLogo",
					"-NoProfile",
					"-NonInteractive",
					"-Command",
					`Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort ${port} -State Listen -ErrorAction Stop | Select-Object -ExpandProperty OwningProcess`,
				],
				{ timeout: 2000, maxBuffer: 4096, windowsHide: true },
				(e, out) => (e ? reject(e) : resolve(out)),
			),
		);
		const owners = output.trim().split(/\s+/);
		if (owners.length === 1 && owners[0] === String(pid)) return;
	}
	throw new Error(
		"Inspector listener is not proved owned by this exact selected process",
	);
}
export async function observeJavaScriptInspector(
	value: unknown,
	signal?: AbortSignal,
	approvedTargetHash?: string,
) {
	const input = InspectorRequestSchema.parse(value),
		url = new URL(input.endpoint);
	if (
		url.protocol !== "ws:" ||
		url.hostname !== "127.0.0.1" ||
		url.username ||
		url.password ||
		url.search ||
		url.hash ||
		!url.port ||
		!/^\/[a-f0-9-]{36}$/i.test(url.pathname)
	)
		throw new Error(
			"Only an exact loopback Node Inspector endpoint is supported",
		);
	const port = Number(url.port);
	const identity = async () => {
		const p = await probeProcessStartTokenAsync(input.pid);
		if (p.status !== "found" || p.token !== input.processToken)
			throw new Error(
				"Selected Inspector process birth identity changed or is unavailable",
			);
		await assertInspectorOwner(input.pid, port);
	};
	if (signal?.aborted) throw new Error("Inspector cancelled before connection");
	await identity();
	const target = realpathSync(input.target),
		file = await open(target, "r");
	let bytes: Buffer;
	try {
		const before = await file.stat();
		if (!before.isFile() || before.size > 1048576)
			throw new Error("Inspector selected source byte budget");
		const buffer = Buffer.alloc(before.size + 1);
		let n = 0;
		while (n < buffer.length) {
			const r = await file.read(buffer, n, buffer.length - n, n);
			if (!r.bytesRead) break;
			n += r.bytesRead;
		}
		const after = await file.stat();
		if (
			n !== before.size ||
			after.size !== before.size ||
			after.mtimeMs !== before.mtimeMs
		)
			throw new Error("Inspector source changed during read");
		bytes = buffer.subarray(0, n);
	} finally {
		await file.close();
	}
	const targetHash = byteDigest(bytes);
	if (approvedTargetHash && targetHash !== approvedTargetHash)
		throw new Error("Inspector selected source hash changed after approval");
	const scripts: Array<{
			scriptId: string;
			url: string;
			status: string;
			sha256?: string;
			staticMatch?: boolean;
		}> = [],
		pending = new Map<
			number,
			{
				resolve: (v: Record<string, unknown>) => void;
				reject: (e: Error) => void;
			}
		>();
	let next = 0,
		eventCount = 0,
		closed = false;
	const ws = new WebSocket(url, {
		maxPayload: 1048576,
		handshakeTimeout: 3000,
		followRedirects: false,
	});
	const failure = new Promise<never>((_, reject) => {
		ws.once("error", reject);
		ws.once("close", () => {
			closed = true;
			for (const p of pending.values())
				p.reject(new Error("Inspector connection closed"));
			pending.clear();
		});
	});
	void failure.catch(() => {});
	const send = (method: string, params: Record<string, unknown> = {}) =>
		new Promise<Record<string, unknown>>((resolve, reject) => {
			if (closed || ws.readyState !== WebSocket.OPEN) {
				reject(new Error("Inspector is not open"));
				return;
			}
			const id = ++next;
			pending.set(id, { resolve, reject });
			ws.send(JSON.stringify({ id, method, params }));
		});
	ws.on("message", (data) => {
		try {
			const m = JSON.parse(data.toString());
			if (++eventCount > 2000) {
				ws.terminate();
				return;
			}
			if (Number.isInteger(m.id)) {
				const p = pending.get(m.id);
				if (p) {
					pending.delete(m.id);
					if (m.error) p.reject(new Error("Inspector command rejected"));
					else p.resolve(m.result ?? {});
				}
			} else if (
				m.method === "Debugger.scriptParsed" &&
				scripts.length < 128 &&
				typeof m.params?.scriptId === "string" &&
				m.params.scriptId.length <= 80 &&
				typeof m.params?.url === "string" &&
				m.params.url.length <= 4096
			)
				scripts.push({
					scriptId: m.params.scriptId,
					url: m.params.url.slice(0, 1000),
					status: "loaded",
				});
		} catch {
			ws.terminate();
		}
	});
	let timer: ReturnType<typeof setTimeout> | undefined;
	const deadline = new Promise<never>((_, reject) => {
		timer = setTimeout(() => {
			ws.terminate();
			reject(new Error("Inspector observation deadline exceeded"));
		}, 10000);
	});
	const abort = () => ws.terminate();
	signal?.addEventListener("abort", abort, { once: true });
	try {
		return await Promise.race([
			(async () => {
				await new Promise<void>((resolve, reject) => {
					ws.once("open", resolve);
					ws.once("error", reject);
				});
				await identity();
				await send("Debugger.enable");
				await new Promise((r) => setTimeout(r, input.durationMs));
				for (const s of scripts) {
					let file: string;
					try {
						file = s.url.startsWith("file:") ? fileURLToPath(s.url) : s.url;
					} catch {
						continue;
					}
					if (!sameInspectorSourcePath(file, target)) continue;
					const response = await send("Debugger.getScriptSource", {
						scriptId: s.scriptId,
					});
					if (
						typeof response.scriptSource !== "string" ||
						Buffer.byteLength(response.scriptSource) > 1048576
					) {
						s.status = "unknown";
						continue;
					}
					s.sha256 = byteDigest(Buffer.from(response.scriptSource));
					s.staticMatch = s.sha256 === targetHash;
				}
				await identity();
				await send("Debugger.disable");
				if (signal?.aborted) throw new Error("Inspector observation cancelled");
				return {
					protocol: "cline-js-inspector/1",
					status:
						eventCount >= 2000 || scripts.length >= 128
							? "partial"
							: "completed",
					input: {
						sha256: targetHash,
						bytes: bytes.length,
						format: "javascript",
					},
					pid: input.pid,
					processToken: input.processToken,
					scripts,
					reconciliation: scripts.some((s) => s.staticMatch)
						? "exact-loaded-source-byte-match"
						: scripts.some((s) => s.sha256)
							? "loaded-source-byte-mismatch"
							: "not-observed-in-bounded-window",
					verifiedBehavior: false,
					limitations: [
						"Attaching Debugger can affect a target; explicit Debug authorization is required. No eval, object inspection, resume, breakpoint or target launch command is sent.",
						"ScriptParsed means loaded/parsed, not executed. Not observed is not absence. Source maps and sourceURL may mislabel scripts; source byte equality is not reachability or execution proof.",
					],
				};
			})(),
			failure,
			deadline,
		]);
	} finally {
		if (timer) clearTimeout(timer);
		signal?.removeEventListener("abort", abort);
		ws.terminate();
	}
}
