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
	rememberSourceEvidence: boolean;
	sourceEvidenceNeedsRecheck: boolean;
	sourceStorageNotice: string;
	setRememberSourceEvidence: (remember: boolean) => void;
	recheckSourceEvidence: () => void;
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
type SourceReference = {
	selection?: SourceEvidenceSelector;
	remember: boolean;
	needsRecheck: boolean;
};
const emptyReference = (): SourceReference => ({
	remember: false,
	needsRecheck: false,
});
export const sourceReferenceStorageKey = (scope: string) =>
	`${scope}:source-reference.v1`;
/** Untrusted device data selects a receipt only, never supplies identity or authority. */
export function parseSourceReference(
	value: unknown,
): SourceEvidenceSelector | undefined {
	if (!value || typeof value !== "object" || Array.isArray(value)) return;
	const v = value as Record<string, unknown>;
	if (
		Object.keys(v).sort().join(",") !== "receiptId,selector" ||
		typeof v.receiptId !== "string" ||
		!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(
			v.receiptId,
		)
	)
		return;
	if (
		!v.selector ||
		typeof v.selector !== "object" ||
		Array.isArray(v.selector)
	)
		return;
	const selector = v.selector as Record<string, unknown>;
	if (
		selector.kind === "fact" &&
		Object.keys(selector).sort().join(",") === "factId,kind" &&
		typeof selector.factId === "string" &&
		/^ev_[a-f0-9]{64}$/.test(selector.factId)
	)
		return {
			receiptId: v.receiptId,
			selector: { kind: "fact", factId: selector.factId },
		};
	if (
		selector.kind === "artifact" &&
		Object.keys(selector).sort().join(",") === "kind,path" &&
		validTarget(selector.path) &&
		selector.path.length > 0
	)
		return {
			receiptId: v.receiptId,
			selector: { kind: "artifact", path: selector.path },
		};
}
function restoreSourceReference(scope: string): SourceReference {
	try {
		const raw = localStorage.getItem(sourceReferenceStorageKey(scope));
		if (!raw || raw.length > 32768) return emptyReference();
		const value = JSON.parse(raw);
		if (
			!value ||
			Array.isArray(value) ||
			value.version !== 1 ||
			Object.keys(value).sort().join(",") !== "selection,version"
		)
			return emptyReference();
		const selection = parseSourceReference(value.selection);
		if (selection) return { selection, remember: true, needsRecheck: true };
	} catch {
		/* Optional storage must not block in-memory analysis. */
	}
	return emptyReference();
}
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
	const [sourceReference, setSourceReference] = useState<SourceReference>(() =>
		restoreSourceReference(scope),
	);
	const [sourceStorageNotice, setSourceStorageNotice] = useState("");
	useEffect(() => {
		try {
			const key = sourceReferenceStorageKey(scope);
			if (sourceReference.remember && sourceReference.selection)
				localStorage.setItem(
					key,
					JSON.stringify({ version: 1, selection: sourceReference.selection }),
				);
			else localStorage.removeItem(key);
			setSourceStorageNotice("");
		} catch {
			setSourceStorageNotice(
				"Device storage unavailable. Saved source reference updates or removal could not be confirmed; no source preview or approval is stored.",
			);
		}
	}, [scope, sourceReference]);
	const clearSourceReference = () => setSourceReference(emptyReference());
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
		sourceEvidence: sourceReference.selection,
		rememberSourceEvidence: sourceReference.remember,
		sourceEvidenceNeedsRecheck: sourceReference.needsRecheck,
		sourceStorageNotice,
		setSourceEvidence: (value) => {
			const selection = parseSourceReference(value);
			setSourceReference((old) =>
				selection
					? {
							selection,
							remember:
								old.remember &&
								JSON.stringify(old.selection) === JSON.stringify(selection),
							needsRecheck: false,
						}
					: emptyReference(),
			);
		},
		setRememberSourceEvidence: (remember) =>
			setSourceReference((old) => ({ ...old, remember })),
		recheckSourceEvidence: () =>
			setSourceReference((old) => ({ ...old, needsRecheck: false })),
		setTarget: (target) => {
			if (validTarget(target)) {
				setSelection((s) => ({ ...s, target }));
				clearSourceReference();
			}
		},
		setRemember: (remember) => setSelection((s) => ({ ...s, remember })),
		clear: () => {
			clearSourceReference();
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
			{project.sourceStorageNotice && (
				<output>{project.sourceStorageNotice}</output>
			)}
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
