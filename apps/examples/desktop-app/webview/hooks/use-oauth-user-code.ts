import { useEffect, useState } from "react";
import { desktopClient } from "@/lib/desktop-client";

export type OAuthAuthorizationState = {
	userCode: string | null;
	authorizationUrl: string | null;
};

/**
 * Device sign-in details pushed by the sidecar while a provider OAuth login is
 * pending. The URL remains available as a manual fallback when the OS browser
 * launcher fails. Cleared whenever the pending flow ends.
 */
export function useOAuthAuthorization(
	pending: boolean,
): OAuthAuthorizationState {
	const [authorization, setAuthorization] = useState<OAuthAuthorizationState>({
		userCode: null,
		authorizationUrl: null,
	});

	// Subscribe for the lifetime of the mounted login surface, not only after
	// `pending` becomes true. The sidecar can obtain and broadcast the device
	// code in the same turn that starts the command, before React commits the
	// pending-state render. A conditional subscription loses that one-shot
	// event and leaves the user waiting in a browser page that asks for a code
	// the desktop never displays.
	useEffect(() => {
		return desktopClient.subscribe("provider_oauth_user_code", (payload) => {
			const details = payload as {
				userCode?: unknown;
				authorizationUrl?: unknown;
			} | null;
			const code =
				typeof details?.userCode === "string" && details.userCode
					? details.userCode
					: null;
			const url =
				typeof details?.authorizationUrl === "string" &&
				details.authorizationUrl
					? details.authorizationUrl
					: null;
			if (code || url) {
				setAuthorization({
					userCode: code,
					authorizationUrl: url,
				});
			}
		});
	}, []);

	useEffect(() => {
		if (!pending) {
			setAuthorization({ userCode: null, authorizationUrl: null });
		}
	}, [pending]);

	return authorization;
}

/** Compatibility helper for consumers that only need the confirmation code. */
export function useOAuthUserCode(pending: boolean): string | null {
	return useOAuthAuthorization(pending).userCode;
}
