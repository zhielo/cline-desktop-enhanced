"use client";
import {
	createContext,
	useContext,
	useEffect,
	useId,
	useState,
	type ReactNode,
} from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

import type { SourceEvidenceSelector } from "../../../../shared/source-evidence-selection";

type Selection = { target?: string; remember: boolean };
type ProjectSelection = Selection & {
	storageNotice: string;
	sourceEvidence?: SourceEvidenceSelector;
	setSourceEvidence: (selection?: SourceEvidenceSelector) => void;
	setTarget: (target: string) => void;
	setRemember: (remember: boolean) => void;
	clear: () => void;
};
const Context = createContext<ProjectSelection | null>(null);
const validTarget = (target: unknown): target is string =>
	typeof target === "string" &&
	target.length <= 4096 &&
	!["\0", "\r", "\n"].some((character) => target.includes(character));
/** Scoped metadata only. A restored path is not file identity, readiness or authority. */
export function analysisProjectScope(
	environmentId: string,
	cwd?: string,
	sessionId?: string,
) {
	return `cline.analysis-selection.v1:${JSON.stringify([environmentId, cwd ?? "", sessionId ?? ""])}`;
}
function restore(key: string): Selection {
	try {
		const raw = localStorage.getItem(key);
		if (!raw || raw.length > 8192) return { remember: false };
		const value = JSON.parse(raw);
		if (
			value &&
			!Array.isArray(value) &&
			value.version === 1 &&
			validTarget(value.target) &&
			Object.keys(value).every((k) => ["version", "target"].includes(k))
		)
			return { target: value.target, remember: true };
	} catch {
		/* Storage is optional and untrusted. Never block analysis on it. */
	}
	return { remember: false };
}
export function AnalysisProjectSelectionProvider({
	scope,
	children,
}: {
	scope: string;
	children: ReactNode;
}) {
	return (
		<ScopedSelection key={scope} scope={scope}>
			{children}
		</ScopedSelection>
	);
}
function ScopedSelection({
	scope,
	children,
}: {
	scope: string;
	children: ReactNode;
}) {
	const [selection, setSelection] = useState<Selection>(() => restore(scope));
	const [storageNotice, setStorageNotice] = useState("");
	const [sourceEvidence, setSourceEvidence] =
		useState<SourceEvidenceSelector>();
	useEffect(() => {
		try {
			if (selection.remember && selection.target !== undefined)
				localStorage.setItem(
					scope,
					JSON.stringify({ version: 1, target: selection.target }),
				);
			else localStorage.removeItem(scope);
			setStorageNotice("");
		} catch {
			setStorageNotice(
				"Device storage unavailable. The current path is in memory only; saved path updates or removal could not be confirmed.",
			);
		}
	}, [scope, selection]);
	const value: ProjectSelection = {
		...selection,
		storageNotice,
		sourceEvidence,
		setSourceEvidence,
		setTarget: (target) => {
			if (validTarget(target)) {
				setSelection((s) => ({ ...s, target }));
				setSourceEvidence(undefined);
			}
		},
		setRemember: (remember) => setSelection((s) => ({ ...s, remember })),
		clear: () => {
			setSourceEvidence(undefined);
			try {
				localStorage.removeItem(scope);
			} catch {}
			setSelection({ remember: false });
		},
	};
	return <Context.Provider value={value}>{children}</Context.Provider>;
}
/** Standalone panes keep their old local behavior; a workbench shares the target. */
export function useAnalysisProjectTarget(
	fallback = "",
): [string, (target: string) => void] {
	const project = useContext(Context),
		[local, setLocal] = useState(fallback);
	return project
		? [project.target ?? fallback, project.setTarget]
		: [local, setLocal];
}
export function useAnalysisProjectSelection() {
	return useContext(Context);
}
export function SharedArtifactSelection() {
	const project = useContext(Context),
		id = useId();
	if (!project) return null;
	return (
		<section
			aria-label="Shared analysis artifact"
			className="space-y-2 border-b border-border px-3 py-2 text-xs"
		>
			<label htmlFor={id}>Shared artifact path</label>
			<Input
				id={id}
				aria-label="Shared artifact path"
				value={project.target ?? ""}
				maxLength={4096}
				placeholder="Select an artifact path for this workspace and chat"
				onChange={(e) => project.setTarget(e.target.value)}
			/>
			<label className="flex items-center gap-2">
				<input
					type="checkbox"
					checked={project.remember}
					onChange={(e) => project.setRemember(e.target.checked)}
				/>
				Remember this path on this device
			</label>
			<Button variant="outline" size="sm" onClick={project.clear}>
				Clear shared selection and saved path
			</Button>
			{project.storageNotice && <output>{project.storageNotice}</output>}
			<p>
				Shared by Start here, Analyze, Android tools and App analysis. AI
				command JSON changes only when explicitly requested. Path metadata only:
				no validated hash, tool readiness, execution or approval. Remembering
				stores this path locally for this exact workspace, environment and chat;
				clearing does not delete evidence or files.
			</p>
		</section>
	);
}
