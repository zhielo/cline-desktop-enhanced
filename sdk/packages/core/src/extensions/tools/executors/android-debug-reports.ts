import { createHash } from "node:crypto";
import { redactSensitiveText } from "./process-environment-policy";
export const ANDROID_DEBUG_PATH =
	/^(?:\/data\/tombstones\/tombstone_\d{2}|\/data\/anr\/anr_[A-Za-z0-9_.-]{1,120})$/;
const MAX = 200000;
type Result = {
	exitCode: number | null;
	stdout: Buffer;
	stderr: string;
	timedOut: boolean;
	cancelled: boolean;
	truncated?: boolean;
};
type Read = (args: string[], limit: number) => Promise<Result>;
export function scopedDebugSections(text: string, pkg: string) {
	const e = pkg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
		marker = new RegExp(
			`(?:>>>\\s*${e}(?=[:\\s]|$)|Cmd line:\\s*${e}(?=[:\\s]|$)|ANR in\\s+${e}(?=[:\\s]|$)|Process:\\s*${e}(?=[:,\\s]|$))`,
		);
	return text
		.split(
			/(?=^.*(?:\*\*\* \*\*\* \*\*\*|----- pid |FATAL EXCEPTION:|ANR in ))/m,
		)
		.filter((s) => marker.test(s))
		.slice(0, 10)
		.join("\n");
}
export async function collectAndroidDebugReports(
	input: {
		package: string;
		deviceSerial: string;
		paths: string[];
		useRoot: boolean;
		confirmSensitive: boolean;
		acknowledgeRoot: boolean;
	},
	read: Read,
) {
	if (
		!/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/.test(input.package) ||
		!/^[A-Za-z0-9_.:-]{1,128}$/.test(input.deviceSerial)
	)
		throw new Error("Explicit package and device serial required");
	if (!input.confirmSensitive)
		throw new Error("Sensitive report-read confirmation required");
	if (input.useRoot && !input.acknowledgeRoot)
		throw new Error(
			"Separate root-read acknowledgement required; KernelSU policy is never changed",
		);
	if (
		input.paths.length < 1 ||
		input.paths.length > 6 ||
		new Set(input.paths).size !== input.paths.length ||
		input.paths.some(
			(p) => !ANDROID_DEBUG_PATH.test(p) || p.split("/").includes(".."),
		)
	)
		throw new Error(
			"Select 1–6 exact allowed report paths; traversal, global bugreports and binary protobufs are not accepted",
		);
	const checked = async (args: string[], limit: number) => {
		const r = await read(args, limit);
		if (r.exitCode !== 0 || r.timedOut || r.cancelled)
			throw new Error(
				"Device report read failed or was interrupted; no root fallback or retry",
			);
		return r;
	};
	const serial = async () => {
		const r = await checked(["get-serialno"], 1024);
		if (r.truncated || r.stdout.toString().trim() !== input.deviceSerial)
			throw new Error("Selected device identity changed");
	};
	await serial();
	const shell = (script: string) => [
		"exec-out",
		`${input.useRoot ? "su" : "sh"} -c '${script}'`,
	];
	const reports: Record<string, unknown>[] = [];
	for (const path of input.paths) {
		const metadata = `test ! -L ${path} && test -f ${path} && stat -c %s:%i:%Y ${path}`;
		const before = await checked(shell(metadata), 4096),
			identity = before.stdout.toString().trim();
		if (before.truncated || !/^\d+:\d+:\d+$/.test(identity))
			throw new Error("Report file identity unavailable or unsupported");
		const raw = await checked(shell(`head -c ${MAX + 1} -- ${path}`), MAX + 1),
			after = await checked(shell(metadata), 4096);
		if (after.truncated || after.stdout.toString().trim() !== identity)
			throw new Error("Report changed during read; evidence rejected");
		const declared = Number(identity.split(":")[0]);
		if (!Number.isSafeInteger(declared))
			throw new Error("Report size outside budget");
		const retained = raw.stdout.subarray(0, MAX),
			sourceComplete =
				!raw.truncated && declared <= MAX && raw.stdout.length === declared;
		const scoped = scopedDebugSections(
			retained.toString("utf8"),
			input.package,
		);
		if (!scoped) {
			reports.push({
				sourcePath: path,
				status: "unattributed-not-retained",
				sourceComplete: false,
				notice:
					"No exact package marker within captured bytes; no report text retained",
			});
			continue;
		}
		const text = redactSensitiveText(scoped);
		reports.push({
			sourcePath: path,
			status: sourceComplete ? "scoped-report-read" : "scoped-prefix-only",
			sourceComplete,
			reportedSize: declared,
			retainedBytes: Buffer.byteLength(text),
			sha256: createHash("sha256").update(text).digest("hex"),
			text,
			identityBasis:
				"adb-file-size-inode-mtime-observation-not-immutable-snapshot",
		});
	}
	await serial();
	return {
		succeeded: true,
		deviceSerialSha256: createHash("sha256")
			.update(input.deviceSerial)
			.digest("hex"),
		package: input.package,
		rootUsed: input.useRoot,
		reports,
		coverage: "explicit-path-package-scoped-adb-observations",
		limitations: [
			"No device hardware attestation; full report reads are bounded at 200000 bytes",
			"Report age is not established; historical evidence is not automatically a new crash",
			"No install, launch, force-stop, log clearing, instrumentation or root-policy change",
			"File metadata checks do not eliminate every filesystem race; unmatched package text is never returned",
		],
	};
}
