/** Internal controller policy, never a request/target field.
 * A validated receipt from the verified native host with exit 0 means its
 * finally block already removed the profile and private stage. Re-deleting the
 * profile races Windows' profile teardown. If no such receipt exists, retain
 * the controller-owned cleanup path (including after cancellation/host death).
 * Stage cleanup stays unconditional and any unconfirmed cleanup fails closed.
 */
export async function finalizeIsolationCleanup(
	hostReceiptVerified: boolean,
	cleanupProfile: () => void | Promise<void>,
	cleanupStage: () => void | Promise<void>,
): Promise<void> {
	try {
		if (!hostReceiptVerified) await cleanupProfile();
	} finally {
		await cleanupStage();
	}
}
