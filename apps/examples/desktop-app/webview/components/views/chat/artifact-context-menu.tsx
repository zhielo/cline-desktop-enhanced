"use client";

import { Copy, ExternalLink, FolderOpen } from "lucide-react";
import type { ReactElement } from "react";
import {
	ContextMenu,
	ContextMenuContent,
	ContextMenuItem,
	ContextMenuSeparator,
	ContextMenuTrigger,
} from "@/components/ui/context-menu";
import { toast } from "@/hooks/use-toast";
import { desktopClient } from "@/lib/desktop-client";

export function ArtifactContextMenu({
	children,
	cwd,
	environmentId,
	onOpen,
	path,
}: {
	children: ReactElement;
	cwd?: string;
	environmentId?: string;
	onOpen: () => void | Promise<void>;
	path: string;
}) {
	const reveal = async () => {
		try {
			await desktopClient.invoke("reveal_artifact_in_folder", {
				path,
				...(environmentId ? { environmentId } : {}),
				...(cwd?.trim() ? { cwd } : {}),
			});
		} catch (error) {
			toast({
				variant: "destructive",
				title: "Could not open file location",
				description:
					error instanceof Error
						? error.message
						: "The artifact location could not be opened.",
			});
		}
	};

	const copyPath = async () => {
		await navigator.clipboard.writeText(path);
		toast({ title: "Artifact path copied" });
	};

	return (
		<ContextMenu>
			<ContextMenuTrigger asChild>{children}</ContextMenuTrigger>
			<ContextMenuContent className="w-52">
				<ContextMenuItem onSelect={() => void onOpen()}>
					<ExternalLink />
					Open artifact
				</ContextMenuItem>
				<ContextMenuItem onSelect={() => void reveal()}>
					<FolderOpen />
					Show in folder
				</ContextMenuItem>
				<ContextMenuSeparator />
				<ContextMenuItem onSelect={() => void copyPath()}>
					<Copy />
					Copy path
				</ContextMenuItem>
			</ContextMenuContent>
		</ContextMenu>
	);
}
