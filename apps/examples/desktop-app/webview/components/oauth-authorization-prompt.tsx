"use client";

import { Check, Copy, ExternalLink } from "lucide-react";
import { useState } from "react";
import type { OAuthAuthorizationState } from "@/hooks/use-oauth-user-code";
import { openExternalUrl } from "@/lib/desktop-client";

export function OAuthAuthorizationPrompt({
	authorization,
	className = "",
}: {
	authorization: OAuthAuthorizationState;
	className?: string;
}) {
	const [copied, setCopied] = useState(false);
	const { userCode, authorizationUrl } = authorization;

	if (!userCode && !authorizationUrl) {
		return null;
	}

	const copyUrl = async () => {
		if (!authorizationUrl || !navigator.clipboard?.writeText) return;
		await navigator.clipboard.writeText(authorizationUrl);
		setCopied(true);
		window.setTimeout(() => setCopied(false), 2_000);
	};

	return (
		<div className={className}>
			{userCode ? (
				<p className="text-sm text-muted-foreground">
					Confirm this code in your browser:{" "}
					<span className="font-mono font-semibold text-foreground">
						{userCode}
					</span>
				</p>
			) : null}
			{authorizationUrl ? (
				<div className="mt-2 space-y-2">
					<p className="text-xs text-muted-foreground">
						If no browser opened, open or copy this sign-in link:
					</p>
					<input
						aria-label="Cline sign-in URL"
						className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs text-foreground"
						onFocus={(event) => event.currentTarget.select()}
						readOnly
						value={authorizationUrl}
					/>
					<div className="flex flex-wrap gap-2">
						<button
							className="inline-flex items-center gap-1.5 rounded-md border border-border px-2.5 py-1.5 text-xs font-medium text-foreground hover:bg-surface-hover"
							onClick={() => void openExternalUrl(authorizationUrl)}
							type="button"
						>
							<ExternalLink className="size-3.5" />
							Open sign-in page
						</button>
						<button
							className="inline-flex items-center gap-1.5 rounded-md border border-border px-2.5 py-1.5 text-xs font-medium text-foreground hover:bg-surface-hover"
							onClick={() => void copyUrl()}
							type="button"
						>
							{copied ? (
								<Check className="size-3.5" />
							) : (
								<Copy className="size-3.5" />
							)}
							{copied ? "Copied" : "Copy sign-in link"}
						</button>
					</div>
				</div>
			) : null}
		</div>
	);
}
