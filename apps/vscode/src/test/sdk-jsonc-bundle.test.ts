import { expect, test } from "bun:test"
import { build } from "esbuild"
import { mkdtemp, rm } from "node:fs/promises"
import path from "node:path"
import os from "node:os"
import { spawnSync } from "node:child_process"
// The production plugin is tested, not a second copy of its resolution rule.
// @ts-expect-error Build scripts are plain ESM and intentionally have no declaration emission.
import { sdkJsoncParserPlugin } from "../../scripts/sdk-bundle-plugins.mjs"

test("production CJS bundling retains JSONC parser internals and starts in Node", async () => {
	const root = await mkdtemp(path.join(os.tmpdir(), "cline-jsonc-bundle-"))
	try {
		const output = path.join(root, "owned.cjs")
		const source =
			'import { visit } from "jsonc-parser"; let keys=[]; visit(\'{"packages":[{"name":"owned"}]}\', {onObjectProperty(k){keys.push(k)}}); if(keys.join(",")!=="packages,name") throw new Error("visitor semantics changed"); console.log("owned-jsonc-bundle-passed");'
		await build({
			stdin: {
				contents: source,
				resolveDir: path.resolve(import.meta.dir, "../.."),
				sourcefile: "owned-jsonc.ts",
				loader: "ts",
			},
			platform: "node",
			format: "cjs",
			bundle: true,
			outfile: output,
			plugins: [sdkJsoncParserPlugin],
		})
		const result = spawnSync("node", [output], { encoding: "utf8", timeout: 10000 })
		expect(result.status).toBe(0)
		expect(result.stdout).toContain("owned-jsonc-bundle-passed")
		expect(result.stderr).not.toContain("Cannot find module")
	} finally {
		await rm(root, { recursive: true, force: true })
	}
})
