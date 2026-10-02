"use client";

import { Copy, ExternalLink, Eye, FolderOpen, Loader2 } from "lucide-react";
import { type ReactElement, useState } from "react";
import {
	ContextMenu,
	ContextMenuContent,
	ContextMenuItem,
	ContextMenuSeparator,
	ContextMenuTrigger,
} from "@/components/ui/context-menu";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogHeader,
	DialogTitle,
} from "@/components/ui/dialog";
import { toast } from "@/hooks/use-toast";
import { desktopClient } from "@/lib/desktop-client";

type ArtifactPreview = {
	path: string;
	name: string;
	size: number;
	modifiedAt: string;
	kind: "text" | "image" | "pdf" | "metadata" | "directory";
	mime?: string;
	content?: string;
	reason?: string;
};

function formatBytes(value: number) {
	if (value < 1024) return `${value} B`;
	if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
	return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

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
	const [previewOpen, setPreviewOpen] = useState(false);
	const [previewLoading, setPreviewLoading] = useState(false);
	const [preview, setPreview] = useState<ArtifactPreview | null>(null);
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

	const showPreview = async () => {
		setPreviewOpen(true);
		setPreviewLoading(true);
		try {
			setPreview(
				await desktopClient.invoke<ArtifactPreview>("read_artifact_preview", {
					path,
					...(environmentId ? { environmentId } : {}),
					...(cwd?.trim() ? { cwd } : {}),
				}),
			);
		} catch (error) {
			setPreview(null);
			toast({
				variant: "destructive",
				title: "Could not preview artifact",
				description:
					error instanceof Error
						? error.message
						: "The artifact preview could not be loaded.",
			});
			setPreviewOpen(false);
		} finally {
			setPreviewLoading(false);
		}
	};

	return (
		<>
			<ContextMenu>
				<ContextMenuTrigger asChild>{children}</ContextMenuTrigger>
				<ContextMenuContent className="w-52">
					<ContextMenuItem onSelect={() => void showPreview()}>
						<Eye />
						Preview
					</ContextMenuItem>
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
			<Dialog onOpenChange={setPreviewOpen} open={previewOpen}>
				<DialogContent className="max-h-[85vh] gap-3 overflow-hidden sm:max-w-3xl">
					<DialogHeader>
						<DialogTitle className="pr-8 font-mono text-sm">
							{preview?.name ?? path}
						</DialogTitle>
						<DialogDescription>
							{preview
								? `${formatBytes(preview.size)} · Modified ${new Date(preview.modifiedAt).toLocaleString()}`
								: "Loading artifact preview…"}
						</DialogDescription>
					</DialogHeader>
					<div className="min-h-48 overflow-auto rounded-lg border border-border/70 bg-muted/20">
						{previewLoading ? (
							<div className="grid min-h-48 place-items-center">
								<Loader2 className="size-5 animate-spin text-muted-foreground" />
							</div>
						) : preview?.kind === "text" ? (
							<pre className="whitespace-pre-wrap break-words p-4 font-mono text-xs leading-5">
								{preview.content}
							</pre>
						) : preview?.kind === "image" && preview.content && preview.mime ? (
							// biome-ignore lint/performance/noImgElement: runtime artifact data cannot use Next Image.
							<img
								alt={preview.name}
								className="mx-auto max-h-[65vh] max-w-full object-contain"
								src={`data:${preview.mime};base64,${preview.content}`}
							/>
						) : preview?.kind === "pdf" && preview.content && preview.mime ? (
							<iframe
								className="h-[65vh] w-full"
								src={`data:${preview.mime};base64,${preview.content}`}
								title={preview.name}
							/>
						) : (
							<div className="grid min-h-48 place-items-center px-6 text-center text-sm text-muted-foreground">
								{preview?.reason ??
									"Preview is not available for this artifact type."}
							</div>
						)}
					</div>
				</DialogContent>
			</Dialog>
		</>
	);
}
