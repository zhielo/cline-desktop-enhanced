"use client";
import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import {
	draftRecoveryKey,
	readRecoverableDraft,
	saveRecoverableDraft,
} from "@/lib/draft-recovery";
export function DraftRecoveryControl({
	environmentId,
	workspace,
	sessionId,
	value,
	onRestore,
}: {
	environmentId: string;
	workspace: string;
	sessionId?: string;
	value: string;
	onRestore: (text: string) => void;
}) {
	const key = sessionId
		? draftRecoveryKey(environmentId, workspace, sessionId)
		: null;
	const initial = useRef({ key, text: value });
	const latestValue = useRef(value);
	latestValue.current = value;
	const [loadedKey, setLoadedKey] = useState<string | null>(null);
	const [enabled, setEnabled] = useState(false),
		[saved, setSaved] = useState<string | null>(null),
		[error, setError] = useState("");
	useEffect(() => {
		initial.current = { key, text: latestValue.current };
		setLoadedKey(null);
		setEnabled(false);
		setSaved(null);
		setError("");
		if (!key) return;
		try {
			setEnabled(localStorage.getItem(`${key}:enabled`) === "true");
			setSaved(readRecoverableDraft(localStorage, key));
			setLoadedKey(key);
		} catch {
			setError("Local draft storage is unavailable");
		}
	}, [key]);
	useEffect(() => {
		if (
			!enabled ||
			!key ||
			loadedKey !== key ||
			!value ||
			value === initial.current.text
		)
			return;
		const save = () => {
			try {
				saveRecoverableDraft(localStorage, key, value);
				setError("");
			} catch {
				setError(
					"Draft recovery could not save; keep this window open or copy your text",
				);
			}
		};
		const timer = setTimeout(save, 500);
		window.addEventListener("pagehide", save);
		return () => {
			clearTimeout(timer);
			window.removeEventListener("pagehide", save);
		};
	}, [enabled, key, loadedKey, value]);
	if (!key) return null;
	return (
		<section
			className="flex flex-wrap items-center gap-2 px-4 text-xs"
			aria-label="Unsent draft recovery"
		>
			<label>
				<input
					type="checkbox"
					checked={enabled && loadedKey === key}
					onChange={(e) => {
						const next = e.target.checked;
						if (
							next &&
							!window.confirm(
								"Keep unsent text in device-local plaintext storage with seven-day recovery eligibility (expired text is removed on next access)? Do not enable this for sensitive prompts. Attachments and credentials are not backed up; recovered text is never sent automatically.",
							)
						)
							return;
						try {
							localStorage.setItem(`${key}:enabled`, String(next));
							if (!next) {
								localStorage.removeItem(key);
								setSaved(null);
							}
							if (next && value) saveRecoverableDraft(localStorage, key, value);
							setEnabled(next);
							setLoadedKey(key);
						} catch {
							setError("Local draft storage is unavailable");
						}
					}}
				/>{" "}
				Keep unsent draft locally
			</label>
			{saved && loadedKey === key && (
				<>
					<Button
						variant="outline"
						size="sm"
						onClick={() => {
							if (
								value &&
								!window.confirm(
									"Replace the current unsent text with the saved draft?",
								)
							)
								return;
							onRestore(saved);
							setSaved(null);
						}}
					>
						Recover saved draft
					</Button>
					<Button
						variant="ghost"
						size="sm"
						onClick={() => {
							try {
								localStorage.removeItem(key);
								setSaved(null);
							} catch {
								setError("Could not discard saved draft");
							}
						}}
					>
						Discard saved draft
					</Button>
				</>
			)}
			{error && <span role="alert">{error}</span>}
		</section>
	);
}
