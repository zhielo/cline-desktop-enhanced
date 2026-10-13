// Dedicated minimal compiled runtime. No desktop imports, dotenv, Hub, setup, IPC or telemetry.
import { readFileSync } from "node:fs";
import { createRequire, Module } from "node:module";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Script } from "node:vm";
if (process.argv.length !== 3 || !process.argv[2].endsWith("target.cjs"))
	throw new Error("Fixed standalone staged target required");
const target = resolve(process.argv[2]);
try {
	// Open only the approved staged file. Bun's filesystem module resolver also
	// probes ancestor directories, which AppContainer is deliberately not granted.
	let source = readFileSync(target, "utf8");
	if (source.charCodeAt(0) === 0xfeff) source = source.slice(1);
	source = source.replace(/^#![^\r\n]*/, "");
	const require = createRequire(pathToFileURL(target));
	const module = {
		exports: {},
		filename: target,
		id: target,
		loaded: false,
		require,
	};
	const run = new Script(Module.wrap(source), {
		filename: target,
	}).runInThisContext();
	run.call(
		module.exports,
		module.exports,
		require,
		module,
		target,
		dirname(target),
	);
	module.loaded = true;
	// vm is just the CommonJS compiler here, NOT the security boundary. The
	// controller still requires the exact kernel AppContainer + assigned job.
} catch (error) {
	process.stderr.write(String(error) + "\n");
	process.exitCode = 1;
}
