import { rename } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const RETRY_DELAYS_MS = [25, 50, 100, 200, 400] as const;
interface PublicationPorts {
	platform: NodeJS.Platform;
	rename: typeof rename;
	wait(ms: number): Promise<void>;
}
/**
 * Called under the discovery mutation lock, after closing/fsyncing the unique
 * same-directory temporary file. Windows readers/scanners can briefly deny
 * replacement. Retry only that atomic metadata operation, never remove the old
 * record, rewrite its bytes in place, restart a daemon, or retry a tool action.
 */
export async function publishDiscoveryFile(
	temporaryPath: string,
	destination: string,
	ports: PublicationPorts = {
		platform: process.platform,
		rename,
		wait: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
	},
): Promise<void> {
	if (
		resolve(temporaryPath) === resolve(destination) ||
		resolve(dirname(temporaryPath)) !== resolve(dirname(destination))
	)
		throw new Error(
			"Discovery publication requires distinct same-directory paths",
		);
	for (let attempt = 0; ; attempt++) {
		try {
			await ports.rename(temporaryPath, destination);
			return;
		} catch (error) {
			const code = (error as NodeJS.ErrnoException | null)?.code;
			const delay = RETRY_DELAYS_MS[attempt];
			if (
				ports.platform !== "win32" ||
				!["EPERM", "EACCES", "EBUSY"].includes(String(code)) ||
				delay === undefined
			)
				throw error;
			await ports.wait(delay);
		}
	}
}
