// Dedicated minimal compiled runtime. No desktop imports, dotenv, Hub, setup, IPC or telemetry.
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
if (process.argv.length !== 3 || !process.argv[2].endsWith("target.cjs"))
	throw new Error("Fixed standalone staged target required");
const target = resolve(process.argv[2]);
try {
	// Contract is standalone CommonJS. Anchor the filesystem loader to the real
	// staged file, not the compiled executable's virtual module directory.
	createRequire(pathToFileURL(target))(target);
} catch (error) {
	process.stderr.write(String(error) + "\n");
	process.exitCode = 1;
}
