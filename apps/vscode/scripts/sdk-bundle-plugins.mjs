import { createRequire } from "node:module"

// jsonc-parser's UMD factory forwards `require` through a parameter. Esbuild's
// CommonJS bundler cannot statically rewrite those relative nested requires;
// they otherwise resolve beside extension.js/cline-core.js at runtime and crash
// activation. Resolve only this dependency to its upstream ESM entry, leaving
// all other package conditions and the parser's behavior unchanged.
const coreRequire = createRequire(new URL("../../../sdk/packages/core/package.json", import.meta.url))
export const sdkJsoncParserPlugin = {
	name: "sdk-jsonc-parser-esm",
	setup(build) {
		build.onResolve({ filter: /^jsonc-parser$/ }, () => ({
			path: coreRequire.resolve("jsonc-parser/lib/esm/main.js"),
		}))
	},
}
