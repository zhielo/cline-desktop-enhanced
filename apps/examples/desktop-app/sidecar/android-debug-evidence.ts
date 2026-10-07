import { z } from "zod";
import { ownedFile } from "./incident-artifacts";
export function parseAndroidDebugEvidence(text: string, pkg: string) {
	const escaped = pkg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
		marker = new RegExp(
			`(?:>>>\\s*${escaped}(?=[:\\s]|$)|Cmd line:\\s*${escaped}(?=[:\\s]|$)|ANR in\\s+${escaped}(?=[:\\s]|$)|Process:\\s*${escaped}(?=[:,\\s]|$))`,
		);
	const sections = text
		.split(
			/(?=^.*(?:\*\*\* \*\*\* \*\*\*|----- pid |FATAL EXCEPTION:|ANR in ))/m,
		)
		.filter((s) => marker.test(s))
		.slice(0, 10);
	const nativeFrames: {
			pc: string;
			module: string;
			buildId?: string;
			reportedSymbol?: string;
		}[] = [],
		threads: {
			name: string;
			state: string;
			tid?: number;
			lockCandidates: string[];
			frames: string[];
		}[] = [];
	for (const section of sections) {
		for (const line of section.split(/\r?\n/)) {
			const frame = line.match(/#\d+\s+pc\s+([0-9a-fA-F]{1,16})\s+(\S+)(.*)/);
			if (frame && nativeFrames.length < 200)
				nativeFrames.push({
					pc: `0x${frame[1]}`,
					module: frame[2].slice(0, 1000),
					buildId: frame[3]
						.match(/BuildId:\s*([0-9a-fA-F]+)/i)?.[1]
						?.toLowerCase(),
					reportedSymbol: frame[3].match(/\(([^()]*)\)/)?.[1]?.slice(0, 300),
				});
		}
		let thread: (typeof threads)[number] | undefined;
		for (const line of section.split(/\r?\n/)) {
			const match = line.match(/^"([^"]+)".*?(?:tid=(\d+))?.*$/);
			if (match && threads.length < 100) {
				thread = {
					name: match[1],
					tid: Number(line.match(/tid=(\d+)/)?.[1]) || undefined,
					state: /Blocked|BLOCKED/.test(line)
						? "blocked-reported"
						: /Waiting|WAITING/.test(line)
							? "waiting-reported"
							: "unclassified",
					lockCandidates: [],
					frames: [],
				};
				threads.push(thread);
			} else if (thread) {
				if (
					/waiting to lock|held by thread|locked </i.test(line) &&
					thread.lockCandidates.length < 20
				)
					thread.lockCandidates.push(line.trim().slice(0, 500));
				if (/^\s+(?:at |native:|#\d+)/.test(line) && thread.frames.length < 50)
					thread.frames.push(line.trim().slice(0, 500));
			}
		}
	}
	const deaths = text
		.split(/\r?\n/)
		.filter((line) =>
			new RegExp(
				`(?:Killing\\s+\\d+:${escaped}(?=[:/\\s]|$)|Force stopping\\s+${escaped}(?=[:/\\s]|$))`,
			).test(line),
		)
		.slice(0, 50)
		.map((line) => ({
			kind: /Force stopping/.test(line)
				? "force-stop-reported"
				: "process-kill-reported",
			line: line
				.replace(/((?:token|secret|password)\s*[:=])\s*\S+/gi, "$1[REDACTED]")
				.slice(0, 1000),
		}));
	return {
		package: pkg,
		nativeFrames,
		threads,
		deaths,
		scope: "imported-report-not-authenticated-runtime-observation",
		findings: [
			...(nativeFrames.length
				? [
						"Native frames require exact APK/module SHA-256, ABI, build ID and PC interpretation before symbolication",
					]
				: []),
			...(threads.some((t) => t.name === "main" && t.lockCandidates.length)
				? [
						"Main-thread lock-wait candidate; not proof of a deadlock or its root cause",
					]
				: []),
		],
		limitations: [
			"Reported PC may be relative or absolute; do not guess load bias",
			"Process disappearance alone is not an OS kill",
			"No blanket root, device mutation or automatic debugger continue",
			"Missing package markers produce no attributed thread/native evidence",
		],
	};
}
export async function importAndroidDebugEvidence(root: string, value: unknown) {
	const i = z
			.object({
				file: z.string().min(1),
				package: z.string().regex(/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/),
			})
			.strict()
			.parse(value),
		f = await ownedFile(root, i.file, 3 * 1024 * 1024);
	return {
		source: f.path,
		sourceSha256: f.sha256,
		...parseAndroidDebugEvidence(f.bytes.toString("utf8"), i.package),
	};
}
