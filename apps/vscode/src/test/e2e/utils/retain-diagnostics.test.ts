import { expect, test } from "bun:test"
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises"
import path from "node:path"
import os from "node:os"
import { retainE2ELogs } from "./retain-diagnostics"
test("retains only bounded profile logs and redacts credentials", async () => {
	const root = await mkdtemp(path.join(os.tmpdir(), "cline-e2e-log-test-"))
	try {
		const profile = path.join(root, "profile"),
			output = path.join(root, "retained")
		await mkdir(path.join(profile, "logs", "host"), { recursive: true })
		await writeFile(
			path.join(profile, "logs", "host", "extension.log"),
			'activation failed\nAuthorization: Bearer SECRET\napi_key="SECRET2"\n',
		)
		await writeFile(path.join(profile, "logs", "host", "large.log"), "x".repeat(300 * 1024))
		await writeFile(path.join(profile, "logs", "host", "state.json"), '{"private":"ignored"}')
		const result = await retainE2ELogs(profile, output)
		expect(result.files).toBe(2)
		const text = await readFile(path.join(output, "host", "extension.log"), "utf8")
		expect(text).toContain("activation failed")
		expect(text).not.toContain("SECRET")
		expect((await readFile(path.join(output, "host", "large.log"))).length).toBe(256 * 1024)
		expect(await retainE2ELogs(path.join(root, "missing"), output)).toEqual({ files: 0, bytes: 0, entries: 0 })
	} finally {
		await rm(root, { recursive: true, force: true })
	}
})
