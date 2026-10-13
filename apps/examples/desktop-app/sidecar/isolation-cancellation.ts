/** Internal host control, never a target or provider capability. */
export function createBoundedHostCancellation(
	requestCancel: () => void,
	forceTerminate: () => void,
	graceMs = 10000,
) {
	let timer: ReturnType<typeof setTimeout> | undefined;
	let closed = false;
	return {
		stop() {
			if (closed || timer) return;
			// A broken control pipe must still arm forced termination.
			try {
				requestCancel();
			} catch {}
			timer = setTimeout(forceTerminate, graceMs);
		},
		dispose() {
			closed = true;
			if (timer) clearTimeout(timer);
		},
	};
}
