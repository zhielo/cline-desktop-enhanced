/** Absence-only probe for a host-created Linux private process group.
 * Never kills or adopts a PID. Alive, reused or unqueryable groups fail closed.
 */
export function privateProcessGroupGone(id: number): boolean {
	if (process.platform !== "linux" || !Number.isSafeInteger(id) || id <= 1)
		return false;
	try {
		process.kill(-id, 0);
		return false;
	} catch (error) {
		return (error as NodeJS.ErrnoException).code === "ESRCH";
	}
}
