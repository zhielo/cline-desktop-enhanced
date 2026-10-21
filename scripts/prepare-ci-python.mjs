/** CI-only interpreter initialization; no installs, fixtures or target code execute. */
import { execFileSync } from "node:child_process";
import { appendFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute } from "node:path";
import { pathToFileURL } from "node:url";

export const PYTHON_PROBE = `import sys
sys.stderr.write("CI_PYTHON_PHASE=entry\\n"); sys.stderr.flush()
import json, hashlib, importlib.util, io, struct, tempfile, unittest, zipfile, zlib
import xml.etree.ElementTree
sys.stderr.write("CI_PYTHON_PHASE=stdlib-ready\\n"); sys.stderr.flush()
print(json.dumps({"protocol":"cline-ci-python/v1","executable":sys.executable,"version":list(sys.version_info[:3])}), flush=True)
`;
export function parsePythonIdentity(stdout) {
	if (typeof stdout !== "string" || Buffer.byteLength(stdout) > 4096)
		throw new Error("Invalid CI Python identity size");
	const value = JSON.parse(stdout);
	if (
		value?.protocol !== "cline-ci-python/v1" ||
		!Array.isArray(value.version) ||
		value.version.length !== 3 ||
		!value.version.every((x) => Number.isInteger(x) && x >= 0) ||
		value.version[0] !== 3 ||
		typeof value.executable !== "string" ||
		!isAbsolute(value.executable) ||
		/[\0\r\n]/.test(value.executable) ||
		!statSync(value.executable).isFile()
	)
		throw new Error("Invalid CI Python identity");
	const executable = realpathSync.native(value.executable);
	if (!isAbsolute(executable) || /[\0\r\n]/.test(executable))
		throw new Error("Invalid canonical CI Python executable");
	return {
		protocol: value.protocol,
		executable,
		version: value.version,
	};
}
export function prepareCiPython(
	python = process.env.CLINE_RE_PYTHON ||
		(process.platform === "win32" ? "python.exe" : "python3"),
) {
	if (/[\0\r\n]/.test(python)) throw new Error("Invalid CI Python executable");
	let stdout;
	try {
		stdout = execFileSync(python, ["-I", "-B", "-c", PYTHON_PROBE], {
			encoding: "utf8",
			timeout: 60_000,
			maxBuffer: 65_536,
			windowsHide: true,
			stdio: ["ignore", "pipe", "pipe"],
		});
	} catch (error) {
		const phases = String(error.stderr ?? "")
			.split(/\r?\n/)
			.filter((s) => /^CI_PYTHON_PHASE=(entry|stdlib-ready)$/.test(s));
		throw new Error(
			`CI Python initialization failed; phase=${phases.at(-1) ?? "not-entered"}; status=${error.status ?? "none"}; signal=${error.signal ?? "none"}. No fixture tests were run or retried.`,
		);
	}
	const identity = parsePythonIdentity(stdout);
	if (process.env.GITHUB_ENV)
		appendFileSync(
			process.env.GITHUB_ENV,
			`CLINE_RE_PYTHON=${identity.executable}\n`,
			"utf8",
		);
	console.log(
		JSON.stringify({
			...identity,
			status: "initialized",
			fixtureDeadlineChanged: false,
		}),
	);
	return identity;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
	prepareCiPython();
