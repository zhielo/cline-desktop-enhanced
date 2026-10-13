// Dedicated minimal compiled runtime. No desktop imports, dotenv, Hub, setup, IPC or telemetry.
import { resolve } from "node:path";
if (process.argv.length !== 3 || !process.argv[2].endsWith("target.cjs"))
	throw new Error("Fixed standalone staged target required");
void import(resolve(process.argv[2])).catch((error) => {
	process.stderr.write(String(error) + "\n");
	process.exitCode = 1;
});
