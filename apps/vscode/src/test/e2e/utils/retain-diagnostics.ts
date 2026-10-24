/** CI/test-only: copy bounded text logs from this test's own profile, not user data. */
import { lstat, mkdir, open, readdir, writeFile } from "node:fs/promises"
import path from "node:path"
export async function retainE2ELogs(profile: string, output: string) {
	let entries = 0,
		total = 0,
		files = 0
	const walk = async (root: string, relative = "", depth = 0): Promise<void> => {
		if (depth > 8 || entries >= 256 || total >= 2 * 1024 * 1024) return
		for (const entry of await readdir(root, { withFileTypes: true })) {
			if (++entries > 256) break
			const source = path.join(root, entry.name),
				name = path.join(relative, entry.name)
			const info = await lstat(source)
			if (info.isSymbolicLink()) continue
			if (info.isDirectory()) await walk(source, name, depth + 1)
			else if (info.isFile() && /\.(log|txt)$/i.test(entry.name)) {
				const length = Math.min(info.size, 256 * 1024, 2 * 1024 * 1024 - total)
				if (length <= 0) continue
				const handle = await open(source, "r")
				let bytes: Buffer
				try {
					bytes = Buffer.alloc(length)
					const read = await handle.read(bytes, 0, length, Math.max(0, info.size - length))
					bytes = bytes.subarray(0, read.bytesRead)
				} finally {
					await handle.close()
				}
				// Mock-provider CI logs only; redact common credential spellings anyway.
				const text = bytes
					.toString("utf8")
					.replace(/(Bearer\s+)[^\s"']+/gi, "$1[REDACTED]")
					.replace(
						/((?:api[_-]?key|access[_-]?token|refresh[_-]?token|authorization)["']?\s*[:=]\s*["']?)[^\s,"'}]+/gi,
						"$1[REDACTED]",
					)
				const destination = path.join(output, name)
				await mkdir(path.dirname(destination), { recursive: true })
				await writeFile(destination, text, { flag: "wx" })
				total += bytes.length
				files++
			}
		}
	}
	try {
		await walk(path.join(profile, "logs"))
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error
	}
	return { files, bytes: total, entries }
}
