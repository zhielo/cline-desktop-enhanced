"use client";

import { GitHubIcon } from "@cline/ui";
import { Loader2, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
	findGitHubIntegration,
	listClineGitHubRepositories,
	listClineIntegrations,
	type ClineGitHubRepository,
} from "@/lib/cline-integrations";

type GitHubIntegrationCardProps = {
	onConnect: () => void;
	isConnecting: boolean;
};

export function GitHubIntegrationCard({
	onConnect,
	isConnecting,
}: GitHubIntegrationCardProps) {
	const [loading, setLoading] = useState(true);
	const [connected, setConnected] = useState(false);
	const [repositories, setRepositories] = useState<ClineGitHubRepository[]>([]);
	const [error, setError] = useState<string | null>(null);

	const refresh = useCallback(async () => {
		setLoading(true);
		setError(null);
		try {
			const result = await listClineIntegrations();
			if (
				result.status === "not-authenticated" ||
				!findGitHubIntegration(result.integrations)
			) {
				setConnected(false);
				setRepositories([]);
				return;
			}
			setConnected(true);
			setRepositories(await listClineGitHubRepositories());
		} catch (cause) {
			setError(
				cause instanceof Error
					? cause.message
					: "Could not load the GitHub connection.",
			);
		} finally {
			setLoading(false);
		}
	}, []);

	useEffect(() => {
		void refresh();
		const onFocus = () => void refresh();
		window.addEventListener("focus", onFocus);
		return () => window.removeEventListener("focus", onFocus);
	}, [refresh]);

	return (
		<section
			aria-label="GitHub integration"
			className="mb-4 rounded-lg border border-border bg-background px-4 py-3"
		>
			<div className="flex flex-wrap items-center justify-between gap-3">
				<div className="flex min-w-0 items-center gap-3">
					<span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-secondary text-foreground">
						<GitHubIcon className="size-4" />
					</span>
					<div className="min-w-0">
						<div className="flex flex-wrap items-center gap-2">
							<p className="text-sm font-semibold text-foreground">
								GitHub integration
						</p>
							{loading ? (
								<Badge variant="secondary">Checking...</Badge>
						) : connected ? (
								<Badge className="bg-primary/15 text-primary" variant="secondary">
									Connected
								</Badge>
						) : (
								<Badge variant="secondary">Not connected</Badge>
							)}
						</div>
						<p className="text-xs text-muted-foreground">
							Cloud integration for repository, issue, and pull request tools.
						</p>
					</div>
				</div>
				<div className="flex shrink-0 items-center gap-2">
					{connected ? (
						<Button
							aria-label="Refresh GitHub repositories"
							disabled={loading}
							onClick={() => void refresh()}
								size="icon-sm"
								variant="outline"
							title="Refresh GitHub repositories"
						>
							<RefreshCw className={loading ? "size-4 animate-spin" : "size-4"} />
						</Button>
					) : (
						<Button
							disabled={isConnecting}
							onClick={onConnect}
							size="sm"
							type="button"
						>
							{isConnecting ? "Opening GitHub..." : "Connect GitHub"}
						</Button>
					)}
				</div>
			</div>

			{error ? (
				<p className="mt-3 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
					{error}
				</p>
			) : null}

			{connected ? (
				<div className="mt-3 border-t border-border pt-3">
					<p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
						Accessible repositories ({repositories.length})
					</p>
					{loading ? (
						<p className="mt-2 inline-flex items-center gap-2 text-sm text-muted-foreground">
							<Loader2 className="size-4 animate-spin" />
							Loading repositories...
						</p>
					) : repositories.length > 0 ? (
						<ul className="mt-2 grid max-h-32 grid-cols-1 gap-1 overflow-y-auto pr-1 text-sm text-foreground sm:grid-cols-2">
							{repositories.map((repository) => (
								<li
									className="truncate rounded px-2 py-1 hover:bg-muted"
									key={repository.id ?? repository.full_name ?? repository.name}
									title={repository.full_name ?? repository.name}
								>
									{repository.full_name ?? repository.name}
								</li>
							))}
						</ul>
					) : (
						<p className="mt-2 text-sm text-muted-foreground">
							No repositories are currently available to the Cline GitHub App.
						</p>
					)}
				</div>
			) : null}
		</section>
	);
}
