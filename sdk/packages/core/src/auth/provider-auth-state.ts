import type { ProviderSettings } from "../types/provider-settings";

export function authSettingsEqual(
	a: ProviderSettings["auth"] | undefined,
	b: ProviderSettings["auth"] | undefined,
): boolean {
	const aExpiry = (
		a as (ProviderSettings["auth"] & { expiresAt?: number }) | undefined
	)?.expiresAt;
	const bExpiry = (
		b as (ProviderSettings["auth"] & { expiresAt?: number }) | undefined
	)?.expiresAt;
	return (
		a?.accessToken === b?.accessToken &&
		a?.refreshToken === b?.refreshToken &&
		a?.accountId === b?.accountId &&
		aExpiry === bExpiry
	);
}

/** Compare credential and endpoint identity, not unrelated preferences/metadata. */
export function providerAuthContextEqual(
	a: ProviderSettings | undefined,
	b: ProviderSettings | undefined,
): boolean {
	return (
		authSettingsEqual(a?.auth, b?.auth) &&
		a?.apiKey === b?.apiKey &&
		a?.baseUrl === b?.baseUrl &&
		a?.oca?.mode === b?.oca?.mode
	);
}
