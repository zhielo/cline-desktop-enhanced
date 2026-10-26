import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ProviderSettingsManager } from "../services/storage/provider-settings-manager";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
	formatProviderOAuthApiKey,
	getPersistedProviderApiKey,
	getProviderAuthHandler,
	getProviderAuthStorageId,
	getProviderOAuthCredentialsFromSettings,
	isOAuthProvider,
	loginAndSaveProviderOAuthCredentials,
	resolveProviderApiKeyFromSettings,
} from "./provider-auth-registry";

const { loginClineOAuth } = vi.hoisted(() => ({
	loginClineOAuth: vi.fn(),
}));

vi.mock("./cline", () => ({
	getValidClineCredentials: vi.fn(),
	loginClineOAuth,
}));

vi.mock("./oca", () => ({
	getValidOcaCredentials: vi.fn(),
	loginOcaOAuth: vi.fn(),
}));

vi.mock("./codex", () => ({
	getValidOpenAICodexCredentials: vi.fn(),
	loginOpenAICodex: vi.fn(),
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

describe("provider auth registry", () => {
	beforeEach(() => {
		vi.clearAllMocks();
	});

	it("returns handlers for managed OAuth providers only", () => {
		expect(getProviderAuthHandler("cline")?.providerId).toBe("cline");
		expect(getProviderAuthHandler("cline-pass")?.providerId).toBe("cline-pass");
		expect(getProviderAuthHandler("oca")?.providerId).toBe("oca");
		expect(getProviderAuthHandler("openai-codex")?.providerId).toBe(
			"openai-codex",
		);
		expect(getProviderAuthHandler("openai-codex-cli")).toBeUndefined();
		expect(isOAuthProvider("openai-codex-cli")).toBe(false);
	});

	it("returns storage provider IDs from handlers", () => {
		expect(getProviderAuthStorageId("cline")).toBe("cline");
		expect(getProviderAuthStorageId("cline-pass")).toBe("cline");
		expect(getProviderAuthStorageId("oca")).toBe("oca");
		expect(getProviderAuthStorageId("openai-codex")).toBe("openai-codex");
		expect(getProviderAuthStorageId("openai-codex-cli")).toBeUndefined();
	});

	it("formats Cline WorkOS tokens without double-prefixing", () => {
		expect(formatProviderOAuthApiKey("cline", { access: "abc" })).toBe(
			"workos:abc",
		);
		expect(formatProviderOAuthApiKey("cline-pass", { access: "abc" })).toBe(
			"workos:abc",
		);
		expect(formatProviderOAuthApiKey("cline", { access: "workos:abc" })).toBe(
			"workos:abc",
		);
		expect(
			getPersistedProviderApiKey("cline-pass", {
				provider: "cline",
				auth: { accessToken: "abc" },
			}),
		).toBe("workos:abc");
	});

	it("login/save for ClinePass stores credentials under Cline storage", async () => {
		loginClineOAuth.mockResolvedValueOnce({
			access: "new-access",
			refresh: "new-refresh",
			expires: 4_000_000_000_000,
			accountId: "acct-new",
			metadata: { sessionStartedAtMs: 1_700_000_000_000 },
		});
		const getProviderSettings = vi.fn().mockReturnValue({
			provider: "cline",
			apiKey: "manual-key",
		});
		const saveProviderSettings = vi.fn();
		const manager = withTransactionalProviderFixture({
			getProviderSettings,
			saveProviderSettings,
		}) as never;

		const saved = await loginAndSaveProviderOAuthCredentials(
			manager,
			"cline-pass",
			{
				callbacks: {
					onAuth: vi.fn(),
					onPrompt: vi.fn(async () => ""),
				},
			},
		);

		expect(getProviderSettings).toHaveBeenCalledWith("cline");
		expect(saved).toMatchObject({
			provider: "cline",
			apiKey: "manual-key",
			auth: {
				accessToken: "workos:new-access",
				refreshToken: "new-refresh",
				accountId: "acct-new",
				expiresAt: 4_000_000_000_000,
				metadata: { sessionStartedAtMs: 1_700_000_000_000 },
			},
		});
		expect(saveProviderSettings).toHaveBeenCalledWith(
			expect.objectContaining({ provider: "cline" }),
			{ tokenSource: "oauth" },
		);
	});

	it("ClinePass resolves API keys from Cline storage", () => {
		const getProviderSettings = vi.fn().mockReturnValue({
			provider: "cline",
			auth: { accessToken: "abc" },
		});
		const manager = { getProviderSettings } as never;

		expect(resolveProviderApiKeyFromSettings(manager, "cline-pass")).toBe(
			"workos:abc",
		);
		expect(getProviderSettings).toHaveBeenCalledWith("cline");
	});

	it("login/save stores credentials under handler storageProviderId", async () => {
		loginClineOAuth.mockResolvedValueOnce({
			access: "new-access",
			refresh: "new-refresh",
			expires: 4_000_000_000_000,
			accountId: "acct-new",
			metadata: { sessionStartedAtMs: 1_700_000_000_001 },
		});
		const getProviderSettings = vi.fn().mockReturnValue({
			provider: "cline",
			apiKey: "manual-key",
		});
		const saveProviderSettings = vi.fn();
		const manager = withTransactionalProviderFixture({
			getProviderSettings,
			saveProviderSettings,
		}) as never;

		const saved = await loginAndSaveProviderOAuthCredentials(manager, "cline", {
			callbacks: {
				onAuth: vi.fn(),
				onPrompt: vi.fn(async () => ""),
			},
		});

		expect(getProviderSettings).toHaveBeenCalledWith("cline");
		expect(saved).toMatchObject({
			provider: "cline",
			apiKey: "manual-key",
			auth: {
				accessToken: "workos:new-access",
				refreshToken: "new-refresh",
				accountId: "acct-new",
				expiresAt: 4_000_000_000_000,
				metadata: { sessionStartedAtMs: 1_700_000_000_001 },
			},
		});
		expect(saveProviderSettings).toHaveBeenCalledWith(
			expect.objectContaining({ provider: "cline" }),
			{ tokenSource: "oauth" },
		);
	});

	it("login/save preserves existing auth metadata when incoming metadata is missing", async () => {
		loginClineOAuth.mockResolvedValueOnce({
			access: "new-access",
			refresh: "new-refresh",
			expires: 4_000_000_000_000,
			accountId: "acct-new",
		});
		const getProviderSettings = vi.fn().mockReturnValue({
			provider: "cline",
			auth: {
				accessToken: "workos:old-access",
				refreshToken: "old-refresh",
				accountId: "acct-old",
				metadata: {
					provider: "workos",
					sessionStartedAtMs: 1_700_000_000_003,
				},
			},
		});
		const saveProviderSettings = vi.fn();
		const manager = withTransactionalProviderFixture({
			getProviderSettings,
			saveProviderSettings,
		}) as never;

		const saved = await loginAndSaveProviderOAuthCredentials(manager, "cline", {
			callbacks: {
				onAuth: vi.fn(),
				onPrompt: vi.fn(async () => ""),
			},
		});

		expect(saved).toMatchObject({
			auth: {
				accessToken: "workos:new-access",
				metadata: {
					provider: "workos",
					sessionStartedAtMs: 1_700_000_000_003,
				},
			},
		});
	});

	it("login/save does not let undefined incoming metadata erase existing metadata", async () => {
		loginClineOAuth.mockResolvedValueOnce({
			access: "new-access",
			refresh: "new-refresh",
			expires: 4_000_000_000_000,
			accountId: "acct-new",
			metadata: { provider: undefined, tokenType: "Bearer" },
		});
		const getProviderSettings = vi.fn().mockReturnValue({
			provider: "cline",
			auth: {
				accessToken: "workos:old-access",
				refreshToken: "old-refresh",
				accountId: "acct-old",
				metadata: {
					provider: "workos",
					sessionStartedAtMs: 1_700_000_000_004,
				},
			},
		});
		const saveProviderSettings = vi.fn();
		const manager = withTransactionalProviderFixture({
			getProviderSettings,
			saveProviderSettings,
		}) as never;

		const saved = await loginAndSaveProviderOAuthCredentials(manager, "cline", {
			callbacks: {
				onAuth: vi.fn(),
				onPrompt: vi.fn(async () => ""),
			},
		});

		expect(saved).toMatchObject({
			auth: {
				accessToken: "workos:new-access",
				metadata: {
					provider: "workos",
					sessionStartedAtMs: 1_700_000_000_004,
					tokenType: "Bearer",
				},
			},
		});
	});

	it("reads persisted auth metadata back into OAuth credentials", () => {
		const handler = getProviderAuthHandler("cline");
		const credentials =
			handler &&
			getProviderOAuthCredentialsFromSettings("cline", {
				provider: "cline",
				auth: {
					accessToken: "workos:stored-access",
					refreshToken: "stored-refresh",
					expiresAt: 4_000_000_000_000,
					accountId: "acct-stored",
					metadata: { sessionStartedAtMs: 1_700_000_000_002 },
				},
			});

		expect(credentials).toMatchObject({
			access: "stored-access",
			refresh: "stored-refresh",
			accountId: "acct-stored",
			metadata: { sessionStartedAtMs: 1_700_000_000_002 },
		});
	});
});

describe("sign-in transactional persistence", () => {
	it("rejects a delayed sign-in after a newer account replaces its auth context", async () => {
		const root = mkdtempSync(join(tmpdir(), "cline-sign-in-race-"));
		try {
			const manager = new ProviderSettingsManager({
				filePath: join(root, "providers.json"),
			});
			manager.saveProviderSettings({
				provider: "cline",
				auth: {
					accessToken: "old",
					refreshToken: "old-refresh",
					accountId: "old-account",
					expiresAt: 1,
				},
			});
			let finish!: () => void;
			loginClineOAuth.mockImplementationOnce(async () => {
				await new Promise<void>((resolve) => {
					finish = resolve;
				});
				return {
					access: "stale-login",
					refresh: "stale-refresh",
					expires: 4000000000000,
					accountId: "old-account",
				};
			});
			const pending = loginAndSaveProviderOAuthCredentials(manager, "cline", {
				callbacks: { onAuth: vi.fn(), onPrompt: vi.fn(async () => "") },
			});
			await vi.waitFor(() => expect(finish).toBeTypeOf("function"));
			manager.saveProviderSettings({
				provider: "cline",
				auth: {
					accessToken: "new-login",
					refreshToken: "new-refresh",
					accountId: "new-account",
					expiresAt: 4000000000000,
				},
			});
			const rejected = expect(pending).rejects.toThrow(
				/authentication changed/,
			);
			finish();
			await rejected;
			expect(manager.getProviderSettings("cline")?.auth?.accessToken).toBe(
				"new-login",
			);
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	});
	it("preserves preferences edited while the sign-in network request is pending", async () => {
		const root = mkdtempSync(join(tmpdir(), "cline-sign-in-preferences-"));
		try {
			const manager = new ProviderSettingsManager({
				filePath: join(root, "providers.json"),
			});
			manager.saveProviderSettings({ provider: "cline", model: "old-model" });
			let finish!: () => void;
			loginClineOAuth.mockImplementationOnce(async () => {
				await new Promise<void>((resolve) => {
					finish = resolve;
				});
				return {
					access: "login",
					refresh: "refresh",
					expires: 4000000000000,
					accountId: "account",
				};
			});
			const pending = loginAndSaveProviderOAuthCredentials(manager, "cline", {
				callbacks: { onAuth: vi.fn(), onPrompt: vi.fn(async () => "") },
			});
			await vi.waitFor(() => expect(finish).toBeTypeOf("function"));
			manager.updateProviderSettings(
				"cline",
				(current) => ({ ...current, provider: "cline", model: "fresh-model" }),
				{ setLastUsed: false },
			);
			finish();
			expect(await pending).toMatchObject({
				model: "fresh-model",
				auth: { accessToken: "workos:login" },
			});
			expect(manager.getProviderSettings("cline")?.model).toBe("fresh-model");
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	});
});
