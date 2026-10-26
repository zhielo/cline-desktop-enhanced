import {
	authSettingsEqual,
	providerAuthContextEqual,
} from "../../auth/provider-auth-state";
import type { ITelemetryService } from "@cline/shared";
import {
	getProviderAuthHandler,
	getProviderOAuthCredentialsFromSettings,
	saveProviderOAuthCredentials,
} from "../../auth/provider-auth-registry";
import { hashSecret, sdkDebug } from "../../logging/early-logger";
import { ProviderSettingsManager } from "../../services/storage/provider-settings-manager";
import type { ProviderSettings } from "../../types/provider-settings";
import { withOAuthRefreshLock } from "./oauth-refresh-lock";

type ManagedOAuthProviderId = string;

export class OAuthReauthRequiredError extends Error {
	public readonly providerId: ManagedOAuthProviderId;

	constructor(providerId: ManagedOAuthProviderId) {
		super(
			`OAuth credentials for provider "${providerId}" are no longer valid. Re-run authentication for this provider.`,
		);
		this.name = "OAuthReauthRequiredError";
		this.providerId = providerId;
	}
}

export type RuntimeOAuthResolution = {
	apiKey: string;
	accountId?: string;
	refreshed: boolean;
};

export class RuntimeOAuthTokenManager {
	private readonly providerSettingsManager: ProviderSettingsManager;
	private readonly telemetry?: ITelemetryService;
	private readonly refreshInFlight = new Map<
		ManagedOAuthProviderId,
		Promise<RuntimeOAuthResolution | null>
	>();

	constructor(options?: {
		providerSettingsManager?: ProviderSettingsManager;
		telemetry?: ITelemetryService;
	}) {
		this.providerSettingsManager =
			options?.providerSettingsManager ?? new ProviderSettingsManager();
		this.telemetry = options?.telemetry;
	}

	public async resolveProviderApiKey(input: {
		providerId: string;
		forceRefresh?: boolean;
	}): Promise<RuntimeOAuthResolution | null> {
		const handler = getProviderAuthHandler(input.providerId);
		if (!handler) {
			return null;
		}
		return this.resolveWithSingleFlight(
			handler.providerId,
			handler.storageProviderId,
			input.forceRefresh,
		);
	}

	private async resolveWithSingleFlight(
		providerId: ManagedOAuthProviderId,
		storageProviderId: ManagedOAuthProviderId,
		forceRefresh = false,
	): Promise<RuntimeOAuthResolution | null> {
		const currentInFlight = this.refreshInFlight.get(storageProviderId);
		if (currentInFlight) {
			return currentInFlight;
		}
		const initialSettings =
			this.providerSettingsManager.getProviderSettings(storageProviderId);
		if (
			!initialSettings ||
			!getProviderOAuthCredentialsFromSettings(providerId, initialSettings)
		) {
			return null;
		}
		const originalAuth = initialSettings.auth;
		const pending = withOAuthRefreshLock(
			this.providerSettingsManager.getFilePath(),
			storageProviderId,
			() =>
				this.resolveProviderApiKeyInternal(
					providerId,
					storageProviderId,
					// Another holder may already have rotated the token while we
					// waited. Read disk under the lock and reuse that fresh token.
					forceRefresh &&
						authSettingsEqual(
							originalAuth,
							this.providerSettingsManager.getProviderSettings(
								storageProviderId,
							)?.auth,
						),
				),
		).finally(() => {
			this.refreshInFlight.delete(storageProviderId);
		});
		this.refreshInFlight.set(storageProviderId, pending);
		return pending;
	}

	private async resolveProviderApiKeyInternal(
		providerId: ManagedOAuthProviderId,
		storageProviderId: ManagedOAuthProviderId,
		forceRefresh: boolean,
	): Promise<RuntimeOAuthResolution | null> {
		const handler = getProviderAuthHandler(providerId);
		if (!handler) {
			return null;
		}
		const settings =
			this.providerSettingsManager.getProviderSettings(storageProviderId);
		if (!settings) {
			sdkDebug(
				`oauth.resolve providerId=${providerId} storageProviderId=${storageProviderId} outcome=no_settings`,
			);
			return null;
		}

		const currentCredentials = getProviderOAuthCredentialsFromSettings(
			providerId,
			settings,
		);
		if (!currentCredentials) {
			sdkDebug(
				`oauth.resolve providerId=${providerId} storageProviderId=${storageProviderId} outcome=no_credentials`,
			);
			return null;
		}

		sdkDebug(
			`oauth.resolve.start providerId=${providerId} storageProviderId=${storageProviderId} forceRefresh=${forceRefresh} accessTokenHash=${hashSecret(currentCredentials.access)} refreshTokenHash=${hashSecret(currentCredentials.refresh)}`,
		);

		const nextCredentials = await handler.refresh({
			settings,
			credentials: currentCredentials,
			forceRefresh,
			telemetry: this.telemetry,
		});
		// Compare the credentials and merge only under the settings transaction.
		// A check followed by a separate save would still permit sign-out/new-login
		// to race between those operations and resurrect an obsolete credential.
		let resolvedSettings: ProviderSettings | undefined;
		let wasRefreshed = false;
		const saved = this.providerSettingsManager.updateProviderSettings(
			storageProviderId,
			(latestSettings) => {
				if (
					!latestSettings ||
					!providerAuthContextEqual(settings, latestSettings)
				)
					return undefined;
				if (!nextCredentials) throw new OAuthReauthRequiredError(providerId);
				resolvedSettings = saveProviderOAuthCredentials({
					manager: this.providerSettingsManager,
					providerId,
					settings: latestSettings,
					credentials: nextCredentials,
					setLastUsed: false,
					save: false,
				});
				wasRefreshed = !authSettingsEqual(
					latestSettings.auth,
					resolvedSettings.auth,
				);
				return wasRefreshed ? resolvedSettings : undefined;
			},
			{ setLastUsed: false, tokenSource: "oauth" },
		);
		const nextSettings = saved ?? resolvedSettings;
		if (!nextSettings || !nextCredentials) return null;
		sdkDebug(
			`oauth.resolve providerId=${providerId} outcome=${wasRefreshed ? "refreshed" : "not_refreshed"}`,
		);

		return {
			apiKey: handler.getApiKey(nextSettings) ?? nextCredentials.access,
			accountId: nextCredentials.accountId,
			refreshed: wasRefreshed,
		};
	}
}
