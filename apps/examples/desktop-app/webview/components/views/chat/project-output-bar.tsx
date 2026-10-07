"use client";
import { useEffect, useRef, useState } from "react";
import { desktopClient } from "@/lib/desktop-client";

type Location = { root: string; projectDirectory: string };
export function ProjectOutputBar({
	cwd,
	environmentId,
}: {
	cwd?: string;
	environmentId: string;
}) {
	const key = `${environmentId}:${cwd ?? ""}`;
	const current = useRef(key);
	current.current = key;
	const [result, setResult] = useState<{
		key: string;
		location: Location | null;
	} | null>(null);
	const [error, setError] = useState<{ key: string; text: string } | null>(
		null,
	);
	const [busy, setBusy] = useState<string | null>(null);
	const supported = environmentId === "local" && !!cwd;
	useEffect(() => {
		if (!supported) return;
		let cancelled = false;
		desktopClient
			.invoke<Location | null>("get_project_output_location", {
				cwd,
				environmentId,
			})
			.then((location) => {
				if (!cancelled) setResult({ key, location });
			})
			.catch((cause) => {
				if (!cancelled)
					setError({
						key,
						text:
							cause instanceof Error
								? cause.message
								: "Could not read project output location",
					});
			});
		return () => {
			cancelled = true;
		};
	}, [key, cwd, environmentId, supported]);
	if (!supported) return null;
	const location = result?.key === key ? result.location : null;
	const problem = error?.key === key ? error.text : null;
	if (!location && !problem) return null;
	async function open() {
		const requestKey = key;
		setBusy(requestKey);
		setError(null);
		try {
			await desktopClient.invoke("open_project_output_folder", {
				cwd,
				environmentId,
			});
		} catch (cause) {
			if (current.current === requestKey)
				setError({
					key: requestKey,
					text:
						cause instanceof Error
							? cause.message
							: "Could not open project outputs",
				});
		} finally {
			if (current.current === requestKey) setBusy(null);
		}
	}
	async function copy() {
		if (!location) return;
		try {
			await navigator.clipboard.writeText(location.projectDirectory);
		} catch {
			setError({ key, text: "Could not copy output path" });
		}
	}
	return (
		<div className="border-t border-border/40 px-4 py-1.5 text-xs text-muted-foreground">
			{location ? (
				<div className="flex items-center gap-2">
					<span>Outputs:</span>
					<code
						className="min-w-0 flex-1 truncate"
						title={location.projectDirectory}
					>
						{location.projectDirectory}
					</code>
					<button type="button" onClick={() => void copy()}>
						Copy path
					</button>
					<button
						type="button"
						disabled={busy === key}
						onClick={() => void open()}
					>
						{busy === key ? "Opening…" : "Open outputs"}
					</button>
				</div>
			) : null}
			{problem ? <div role="alert">{problem}</div> : null}
		</div>
	);
}
