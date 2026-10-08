/** Install E2E prerequisites from the locked workspace, with bounded cold-cache time. */
import { createRequire } from "node:module"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { downloadAndUnzipVSCode } from "@vscode/test-electron"
import { execa } from "execa"

const require = createRequire(import.meta.url)
export const LOCKED_PLAYWRIGHT_CLI = join(dirname(require.resolve("playwright/package.json")), "cli.js")
export const INSTALL_TIMEOUT_MS = 6 * 60 * 1000

export async function installVSCode() {
	console.log("Downloading VS Code stable (60s network-idle limit)...")
	const executable = await downloadAndUnzipVSCode({ version: "stable", timeout: 60_000 })
	console.log("VS Code installation completed successfully")
	return executable
}

export async function installChromium(signal) {
	console.log("Installing locked Playwright Chromium (5 minute process limit)...")
	await execa(process.execPath, [LOCKED_PLAYWRIGHT_CLI, "install", "chromium"], {
		stdio: "inherit",
		timeout: 5 * 60 * 1000,
		cancelSignal: signal,
	})
	console.log("Playwright Chromium installation completed successfully")
}

export async function installDependencies({
	vscode = installVSCode,
	chromium = installChromium,
	timeoutMs = INSTALL_TIMEOUT_MS,
} = {}) {
	const controller = new AbortController()
	let timer
	const pending = new Set(["VS Code", "Chromium"])
	const install = async (name, run) => {
		try {
			await run(controller.signal)
			pending.delete(name)
		} catch (error) {
			throw new Error(`${name} installation failed: ${error instanceof Error ? error.message : String(error)}`, {
				cause: error,
			})
		}
	}
	try {
		await Promise.race([
			Promise.all([install("VS Code", vscode), install("Chromium", chromium)]),
			new Promise((_, reject) => {
				timer = setTimeout(() => {
					reject(
						new Error(
							`E2E dependency installation timed out after ${timeoutMs} ms; pending: ${[...pending].join(", ")}`,
						),
					)
				}, timeoutMs)
			}),
		])
	} finally {
		clearTimeout(timer)
		controller.abort()
	}
	console.log("Installation complete.")
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	installDependencies()
		.then(() => process.exit(0))
		.catch((error) => {
			console.error("Failed to install dependencies for E2E test", error)
			process.exit(1)
		})
}
