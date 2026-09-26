import { useEffect, useState } from "react";
import { desktopClient } from "@/lib/desktop-client";

/**
 * Device sign-in confirmation code pushed by the sidecar while a provider
 * OAuth login is pending, so the user can match it against the code shown in
 * their browser. Cleared whenever the pending flow ends.
 */
export function useOAuthUserCode(pending: boolean): string | null {
	const [userCode, setUserCode] = useState<string | null>(null);

	// Subscribe for the lifetime of the mounted login surface, not only after
	// `pending` becomes true. The sidecar can obtain and broadcast the device
	// code in the same turn that starts the command, before React commits the
	// pending-state render. A conditional subscription loses that one-shot
	// event and leaves the user waiting in a browser page that asks for a code
	// the desktop never displays.
	useEffect(() => {
		return desktopClient.subscribe("provider_oauth_user_code", (payload) => {
			const code = (payload as { userCode?: unknown } | null)?.userCode;
			if (typeof code === "string" && code) {
				setUserCode(code);
			}
		});
	}, []);

	useEffect(() => {
		if (!pending) {
			setUserCode(null);
		}
	}, [pending]);

	return userCode;
}
