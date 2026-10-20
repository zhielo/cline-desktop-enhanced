// CI-only pinned real-engine fixture dependency; never bundled into the installer.
import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { appendFile, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
const version = "12.1.4",
	digest = "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db";
const root = join(process.env.RUNNER_TEMP ?? tmpdir(), "cline-ghidra-test"),
	zip = join(root, "ghidra.zip");
await mkdir(root, { recursive: true });
try {
	const response = await fetch(
		`https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${version}_build/ghidra_${version}_PUBLIC_20260921.zip`,
		{ signal: AbortSignal.timeout(180000) },
	);
	if (!response.ok || !response.body)
		throw new Error(`Ghidra fixture download HTTP ${response.status}`);
	const hash = createHash("sha256");
	const source = Readable.fromWeb(response.body);
	source.on("data", (chunk) => hash.update(chunk));
	await pipeline(source, createWriteStream(zip, { flags: "wx" }));
	if (hash.digest("hex") !== digest)
		throw new Error("Pinned Ghidra checksum mismatch");
	const extraction =
		process.platform === "win32"
			? spawnSync(
					"powershell.exe",
					[
						"-NoProfile",
						"-NonInteractive",
						"-Command",
						"Expand-Archive -LiteralPath $env:CLINE_GHIDRA_TEST_ZIP -DestinationPath $env:CLINE_GHIDRA_TEST_ROOT -Force",
					],
					{
						stdio: "inherit",
						env: {
							...process.env,
							CLINE_GHIDRA_TEST_ZIP: zip,
							CLINE_GHIDRA_TEST_ROOT: root,
						},
					},
				)
			: spawnSync("unzip", ["-q", zip, "-d", root], { stdio: "inherit" });
	if (extraction.error || extraction.status !== 0)
		throw new Error("Pinned Ghidra extraction failed");
	const home = join(root, `ghidra_${version}_PUBLIC`);
	if (!process.env.GITHUB_ENV) throw new Error("CI GITHUB_ENV required");
	await appendFile(process.env.GITHUB_ENV, `GHIDRA_HOME=${home}\n`);
	console.log(`Verified Ghidra ${version} fixture installed`);
} finally {
	await rm(zip, { force: true });
}
