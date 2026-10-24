/** Build/CI only. Never import into the application or run on startup. */
import { createHash } from "node:crypto";
import {
	chmod,
	copyFile,
	lstat,
	mkdir,
	mkdtemp,
	readFile,
	readdir,
	rm,
	writeFile,
} from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";
import {
	WAKARU_PINS,
	WAKARU_REVISION,
	WAKARU_VERSION,
} from "../sdk/packages/core/src/analysis/general-recovery/contracts";
const platform = process.platform;
if ((platform !== "linux" && platform !== "win32") || process.arch !== "x64")
	throw new Error("Pinned fixture supports Linux/Windows x64 only");
const root = process.argv[2];
if (!root || !path.isAbsolute(root))
	throw new Error("New absolute build destination required");
try {
	await lstat(root);
	throw new Error("Build destination already exists");
} catch (error) {
	if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
}
const pin = WAKARU_PINS[platform];
const scratch = await mkdtemp(path.join(tmpdir(), "cline-wakaru-build-"));
const hash = (bytes: Uint8Array) =>
	createHash("sha256").update(bytes).digest("hex");
let created = false,
	complete = false;
try {
	const asset =
		platform === "win32" ? "wakaru-win32-x64.zip" : "wakaru-linux-x64.tar.gz";
	const response = await fetch(
		`https://github.com/pionxzh/wakaru/releases/download/v${WAKARU_VERSION}/${asset}`,
		{ signal: AbortSignal.timeout(120000) },
	);
	if (!response.ok || !response.body)
		throw new Error("Official pinned archive unavailable");
	const chunks: Uint8Array[] = [];
	let size = 0;
	for await (const chunk of response.body) {
		size += chunk.length;
		if (size > 12 * 1024 * 1024)
			throw new Error("Engine archive byte budget exceeded");
		chunks.push(chunk);
	}
	const encoded = Buffer.concat(chunks);
	if (hash(encoded) !== pin.archiveSha256)
		throw new Error("Official archive SHA256 mismatch");
	const archive = path.join(scratch, asset),
		extracted = path.join(scratch, "extracted");
	await writeFile(archive, encoded, { flag: "wx" });
	await mkdir(extracted);
	const result =
		platform === "win32"
			? spawnSync(
					"powershell.exe",
					[
						"-NoProfile",
						"-NonInteractive",
						"-Command",
						"Expand-Archive -LiteralPath $env:CLINE_ARCHIVE -DestinationPath $env:CLINE_EXTRACTED",
					],
					{
						env: {
							...process.env,
							CLINE_ARCHIVE: archive,
							CLINE_EXTRACTED: extracted,
						},
						stdio: "inherit",
						timeout: 30000,
					},
				)
			: spawnSync("tar", ["-xzf", archive, "-C", extracted], {
					stdio: "inherit",
					timeout: 30000,
				});
	if (result.status !== 0 || result.error)
		throw new Error("Pinned archive extraction failed");
	const names = await readdir(extracted);
	if (names.length !== 1 || names[0] !== pin.file)
		throw new Error("Unexpected pinned archive entries");
	const binary = path.join(extracted, pin.file),
		info = await lstat(binary);
	if (
		!info.isFile() ||
		info.isSymbolicLink() ||
		info.size > 64 * 1024 * 1024 ||
		hash(await readFile(binary)) !== pin.sha256
	)
		throw new Error("Pinned executable SHA256 mismatch");
	const notices = path.resolve(
		import.meta.dir,
		"../sdk/packages/core/src/analysis/general-recovery",
	);
	const license = await readFile(path.join(notices, "WAKARU-LICENSE"));
	if (
		hash(license) !==
		"c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"
	)
		throw new Error("Upstream license mismatch");
	await mkdir(root);
	created = true;
	await copyFile(binary, path.join(root, pin.file));
	if (platform === "linux") await chmod(path.join(root, pin.file), 0o755);
	await writeFile(path.join(root, "LICENSE"), license, { flag: "wx" });
	await writeFile(
		path.join(root, "manifest.json"),
		JSON.stringify(
			{
				protocol: "cline-wakaru-pack/1",
				version: WAKARU_VERSION,
				upstreamRevision: WAKARU_REVISION,
				platform,
				arch: process.arch,
				archiveSha256: pin.archiveSha256,
				executableSha256: pin.sha256,
				licenseSha256: hash(license),
			},
			null,
			2,
		) + "\n",
		{ flag: "wx" },
	);
	complete = true;
	console.log(
		`Prepared pinned ${platform} x64 general recovery engine; not app readiness.`,
	);
} finally {
	await rm(scratch, { recursive: true, force: true });
	if (created && !complete) await rm(root, { recursive: true, force: true });
}
