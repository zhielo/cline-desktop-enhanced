"use client";

import { createContext, type ReactNode, useContext, useMemo } from "react";

type ArtifactWorkspace = { cwd?: string; environmentId?: string };
const ArtifactWorkspaceContext = createContext<ArtifactWorkspace>({});

/** Bind nested Markdown actions to their transcript, not the active app directory. */
export function ArtifactWorkspaceProvider({
	children,
	cwd,
	environmentId,
}: ArtifactWorkspace & { children: ReactNode }) {
	const value = useMemo(
		() => ({
			cwd: cwd?.trim() || undefined,
			environmentId: environmentId?.trim() || undefined,
		}),
		[cwd, environmentId],
	);
	return (
		<ArtifactWorkspaceContext.Provider value={value}>
			{children}
		</ArtifactWorkspaceContext.Provider>
	);
}

export function useArtifactWorkspace() {
	return useContext(ArtifactWorkspaceContext);
}
