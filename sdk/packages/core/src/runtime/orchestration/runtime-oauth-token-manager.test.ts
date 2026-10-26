import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ProviderSettingsManager } from "../../services/storage/provider-settings-manager";
import {
	OAuthReauthRequiredError,
	RuntimeOAuthTokenManager,
} from "./runtime-oauth-token-manager";

const {
	getValidOpenAICodexCredentials,
	getValidClineCredentials,
	getValidOcaCredentials,
} = vi.hoisted(() => ({
	getValidOpenAICodexCredentials: vi.fn(),
	getValidClineCredentials: vi.fn(),
	getValidOcaCredentials: vi.fn(),
}));

vi.mock("../../auth/codex", () => ({
	getValidOpenAICodexCredentials,
}));

vi.mock("../../auth/cline", () => ({
	getValidClineCredentials,
}));

vi.mock("../../auth/oca", () => ({
	getValidOcaCredentials,
}));

// This lightweight unit fixture models the new transactional callback contract.
// Cross-process locking and fresh-disk behavior use real managers in integration tests.
function withTransactionalProviderFixture<
	T extends Pick<
		ProviderSettingsManager,
		"getProviderSettings" | "saveProviderSettings"
	>,
>(manager: T) {
	return {
		...manager,
		updateProviderSettings: (
			providerId: string,
			mutator: Parameters<ProviderSettingsManager["updateProviderSettings"]>[1],
			options: Parameters<
				ProviderSettingsManager["updateProviderSettings"]
			>[2] = {},
		) => {
			const proposed = mutator(manager.getProviderSettings(providerId));
			if (proposed === undefined) return undefined;
			manager.saveProviderSettings(proposed, options);
			return proposed as NonNullable<
				ReturnType<ProviderSettingsManager["getProviderSettings"]>
			>;
		},
	};
}

describe("RuntimeOAuthTokenManager", () => {
	let testDir: string;
	afterEach(() => rmSync(testDir, { recursive: true, force: true }));
	beforeEach(() => {
		vi.resetAllMocks();
		testDir = mkdtempSync(join(tmpdir(), "oauth-manager-test-"));
	});

	it("refreshes and persists OpenAI Codex OAuth credentials", async () => {
		const getProviderSettings = vi.fn().mockReturnValue({
			provider: "openai-codex",
			auth: {
				accessToken: "access-old",
				refreshToken: "refresh-old",
				expiresAt: Date.now() - 1_000,
				accountId: "acct-old",
			},
		});
		const saveProviderSettings = vi.fn();

		getValidOpenAICodexCredentials.mockResolvedValueOnce({
			access: "access-new",
			refresh: "refresh-new",
			expires: 4_000_000_000_000,
			accountId: "acct-new",
		});

		const manager = new RuntimeOAuthTokenManager({
			providerSettingsManager: withTransactionalProviderFixture({
				getFilePath: () => join(testDir, "providers.json"),
				getProviderSettings,
				saveProviderSettings,
			}) as never,
		});

		const result = await manager.resolveProviderApiKey({
			providerId: "openai-codex",
		});

		expect(result).toMatchObject({
			apiKey: "access-new",
			accountId: "acct-new",
			refreshed: true,
		});
		expect(saveProviderSettings).toHaveBeenCalledWith(
			expect.objectContaining({
				auth: expect.objectContaining({
					accessToken: "access-new",
					refreshToken: "refresh-new",
					accountId: "acct-new",
					expiresAt: 4_000_000_000_000,
				}),
			}),
			{ setLastUsed: false, tokenSource: "oauth" },
		);
	});

	it("resolves ClinePass OAuth using Cline storage and WorkOS formatting", async () => {
		const getProviderSettings = vi.fn().mockReturnValue({
			provider: "cline",
			baseUrl: "https://api.cline.test",
			auth: {
				accessToken: "workos:access-old",
				refreshToken: "refresh-old",
				expiresAt: Date.now() - 1_000,
				accountId: "acct-old",
			},
		});
		const saveProviderSettings = vi.fn();

		getValidClineCredentials.mockResolvedValueOnce({
			access: "access-new",
			refresh: "refresh-new",
			expires: 4_000_000_000_000,
			accountId: "acct-new",
		});

		const manager = new RuntimeOAuthTokenManager({
			providerSettingsManager: withTransactionalProviderFixture({
				getFilePath: () => join(testDir, "providers.json"),
				getProviderSettings,
				saveProviderSettings,
			}) as never,
		});

		const result = await manager.resolveProviderApiKey({
			providerId: "cline-pass",
		});

		expect(getProviderSettings).toHaveBeenCalledWith("cline");
		expect(getValidClineCredentials).toHaveBeenCalledWith(
			expect.objectContaining({
				access: "access-old",
				refresh: "refresh-old",
			}),
			expect.objectContaining({ apiBaseUrl: "https://api.cline.test" }),
			{ forceRefresh: false },
		);
		expect(result).toMatchObject({
			apiKey: "workos:access-new",
			accountId: "acct-new",
			refreshed: true,
		});
		expect(saveProviderSettings).toHaveBeenCalledWith(
			expect.objectContaining({
				provider: "cline",
				auth: expect.objectContaining({
					accessToken: "workos:access-new",
					refreshToken: "refresh-new",
					accountId: "acct-new",
					expiresAt: 4_000_000_000_000,
				}),
			}),
			{ setLastUsed: false, tokenSource: "oauth" },
		);
	});

	it("throws re-auth required when refresh returns null", async () => {
		getValidOpenAICodexCredentials.mockResolvedValueOnce(null);
		const manager = new RuntimeOAuthTokenManager({
			providerSettingsManager: withTransactionalProviderFixture({
				getFilePath: () => join(testDir, "providers.json"),
				getProviderSettings: vi.fn().mockReturnValue({
					provider: "openai-codex",
					auth: {
						accessToken: "access-old",
						refreshToken: "refresh-old",
						expiresAt: Date.now() - 1_000,
					},
				}),
				saveProviderSettings: vi.fn(),
			}) as never,
		});

		await expect(
			manager.resolveProviderApiKey({ providerId: "openai-codex" }),
		).rejects.toBeInstanceOf(OAuthReauthRequiredError);
	});

	it("de-duplicates concurrent refresh calls per provider", async () => {
		const refreshBarrier = Promise.resolve().then(() => ({
			access: "access-new",
			refresh: "refresh-new",
			expires: Date.now() + 60_000,
		}));
		getValidOpenAICodexCredentials.mockImplementationOnce(
			async () => refreshBarrier,
		);

		const manager = new RuntimeOAuthTokenManager({
			providerSettingsManager: withTransactionalProviderFixture({
				getFilePath: () => join(testDir, "providers.json"),
				getProviderSettings: vi.fn().mockReturnValue({
					provider: "openai-codex",
					auth: {
						accessToken: "access-old",
						refreshToken: "refresh-old",
						expiresAt: Date.now() - 1_000,
					},
				}),
				saveProviderSettings: vi.fn(),
			}) as never,
		});

		const [first, second] = await Promise.all([
			manager.resolveProviderApiKey({ providerId: "openai-codex" }),
			manager.resolveProviderApiKey({ providerId: "openai-codex" }),
		]);

		expect(first?.apiKey).toBe("access-new");
		expect(second?.apiKey).toBe("access-new");
		expect(getValidOpenAICodexCredentials).toHaveBeenCalledTimes(1);
	});

	it("coordinates independent managers and does not force-refresh a token another manager just rotated", async () => {
		const settings = new ProviderSettingsManager({
			filePath: join(testDir, "providers.json"),
		});
		settings.saveProviderSettings({
			provider: "cline",
			auth: {
				accessToken: "old",
				refreshToken: "single-use",
				expiresAt: 1,
				accountId: "account-a",
			},
		});
		let finish!: () => void;
		getValidClineCredentials.mockImplementation(
			async (credentials, _options, { forceRefresh }) => {
				if (!forceRefresh && credentials.access === "new") return credentials;
				await new Promise<void>((resolve) => {
					finish = resolve;
				});
				return {
					access: "new",
					refresh: "rotated",
					expires: Date.now() + 3_600_000,
					accountId: "account-a",
				};
			},
		);
		const first = new RuntimeOAuthTokenManager({
			providerSettingsManager: settings,
		});
		const second = new RuntimeOAuthTokenManager({
			providerSettingsManager: settings,
		});
		const a = first.resolveProviderApiKey({
			providerId: "cline",
			forceRefresh: true,
		});
		await vi.waitFor(() => expect(finish).toBeTypeOf("function"));
		const b = second.resolveProviderApiKey({
			providerId: "cline-pass",
			forceRefresh: true,
		});
		finish();
		expect((await Promise.all([a, b])).map((result) => result?.apiKey)).toEqual(
			["workos:new", "workos:new"],
		);
		expect(getValidClineCredentials.mock.calls[1][2]).toEqual({
			forceRefresh: false,
		});
	});

	it.each([
		"sign-out",
		"account-switch",
		"endpoint-change",
	] as const)("guards %s at the exact refresh commit boundary", async (change) => {
		const filePath = join(testDir, "providers.json"),
			settings = new ProviderSettingsManager({ filePath }),
			other = new ProviderSettingsManager({ filePath });
		settings.saveProviderSettings({
			provider: "cline",
			model: "original",
			auth: {
				accessToken: "old",
				refreshToken: "single-use",
				expiresAt: 1,
				accountId: "old-account",
			},
		});
		getValidClineCredentials.mockResolvedValueOnce({
			access: "refreshed",
			refresh: "rotated",
			expires: Date.now() + 3600000,
			accountId: "old-account",
		});
		let interleaved = false;
		const inject = () => {
			if (interleaved) return;
			interleaved = true;
			if (change === "sign-out")
				other.updateProviderSettings(
					"cline",
					() => ({ provider: "cline", auth: {} }),
					{ setLastUsed: false },
				);
			else if (change === "account-switch")
				other.saveProviderSettings({
					provider: "cline",
					auth: {
						accessToken: "new-login",
						refreshToken: "new-login-refresh",
						expiresAt: Date.now() + 3600000,
						accountId: "new-account",
					},
				});
			else
				other.updateProviderSettings(
					"cline",
					(current) => ({
						...current,
						provider: "cline",
						baseUrl: "https://new-origin.invalid/v1",
					}),
					{ setLastUsed: false },
				);
		};
		const save = settings.saveProviderSettings.bind(settings),
			update = settings.updateProviderSettings.bind(settings);
		vi.spyOn(settings, "saveProviderSettings").mockImplementation((...args) => {
			inject();
			return save(...args);
		});
		vi.spyOn(settings, "updateProviderSettings").mockImplementation(
			(...args) => {
				inject();
				return update(...args);
			},
		);
		const result = await new RuntimeOAuthTokenManager({
			providerSettingsManager: settings,
		}).resolveProviderApiKey({ providerId: "cline" });
		expect(interleaved).toBe(true);
		expect(result).toBeNull();
		const persisted = other.getProviderSettings("cline");
		expect(persisted?.auth?.accessToken).not.toBe("workos:refreshed");
		if (change === "sign-out")
			expect(persisted?.auth?.accessToken).toBeUndefined();
		if (change === "account-switch")
			expect(persisted?.auth?.accountId).toBe("new-account");
		if (change === "endpoint-change")
			expect(persisted?.baseUrl).toBe("https://new-origin.invalid/v1");
	});
	it("retains a concurrent preference and auth metadata edit when refreshing credentials", async () => {
		const filePath = join(testDir, "providers.json"),
			settings = new ProviderSettingsManager({ filePath }),
			other = new ProviderSettingsManager({ filePath });
		settings.saveProviderSettings({
			provider: "cline",
			model: "old-model",
			auth: {
				accessToken: "old",
				refreshToken: "single-use",
				expiresAt: 1,
				accountId: "account-a",
			},
		});
		getValidClineCredentials.mockResolvedValueOnce({
			access: "new",
			refresh: "rotated",
			expires: Date.now() + 3600000,
			accountId: "account-a",
		});
		let interleaved = false;
		const inject = () => {
			if (interleaved) return;
			interleaved = true;
			other.updateProviderSettings(
				"cline",
				(current) => ({
					...current,
					provider: "cline",
					model: "fresh-model",
					auth: { ...current?.auth, metadata: { retained: "fresh" } },
				}),
				{ setLastUsed: false },
			);
		};
		const save = settings.saveProviderSettings.bind(settings),
			update = settings.updateProviderSettings.bind(settings);
		vi.spyOn(settings, "saveProviderSettings").mockImplementation((...args) => {
			inject();
			return save(...args);
		});
		vi.spyOn(settings, "updateProviderSettings").mockImplementation(
			(...args) => {
				inject();
				return update(...args);
			},
		);
		const result = await new RuntimeOAuthTokenManager({
			providerSettingsManager: settings,
		}).resolveProviderApiKey({ providerId: "cline" });
		expect(interleaved).toBe(true);
		expect(result?.apiKey).toBe("workos:new");
		expect(other.getProviderSettings("cline")).toMatchObject({
			model: "fresh-model",
			auth: { accessToken: "workos:new", metadata: { retained: "fresh" } },
		});
	});

	it("does not restore credentials when the user signs out during refresh", async () => {
		const settings = new ProviderSettingsManager({
			filePath: join(testDir, "providers.json"),
		});
		settings.saveProviderSettings({
			provider: "cline",
			auth: {
				accessToken: "old",
				refreshToken: "single-use",
				expiresAt: 1,
				accountId: "account-a",
			},
		});
		let finish!: () => void;
		getValidClineCredentials.mockImplementation(async () => {
			await new Promise<void>((resolve) => {
				finish = resolve;
			});
			return {
				access: "new",
				refresh: "rotated",
				expires: Date.now() + 3_600_000,
				accountId: "account-a",
			};
		});
		const manager = new RuntimeOAuthTokenManager({
			providerSettingsManager: settings,
		});
		const result = manager.resolveProviderApiKey({ providerId: "cline" });
		await vi.waitFor(() => expect(finish).toBeTypeOf("function"));
		settings.saveProviderSettings({ provider: "cline", auth: {} });
		finish();
		expect(await result).toBeNull();
		expect(
			settings.getProviderSettings("cline")?.auth?.accessToken,
		).toBeUndefined();
	});
});
