"use client";

import { Copy, ExternalLink, Eye, FolderOpen, Loader2 } from "lucide-react";
import {
	cloneElement,
	type ReactElement,
	type MouseEvent as ReactMouseEvent,
	useEffect,
	useRef,
	useState,
} from "react";
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
import { useArtifactWorkspace } from "@/lib/artifact-workspace";
import { desktopClient } from "@/lib/desktop-client";

type ArtifactEvidence = {
	path: string;
	workspace: string;
	sha256?: string;
	size: number;
	classification: string;
	blockedReason?: string;
	members?: { name: string; bytes: number; safe: boolean }[];
	membersTruncated?: boolean;
};

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
	cwd: suppliedCwd,
	environmentId: suppliedEnvironmentId,
	onOpen,
	path,
	primaryAction = "open",
}: {
	children: ReactElement;
	cwd?: string;
	environmentId?: string;
	onOpen: () => void | Promise<void>;
	path: string;
	primaryAction?: "open" | "preview";
}) {
	const workspace = useArtifactWorkspace();
	const cwd = suppliedCwd?.trim() || workspace.cwd;
	const environmentId =
		suppliedEnvironmentId?.trim() || workspace.environmentId;
	const [evidence, setEvidence] = useState<ArtifactEvidence | null>(null);
	const epoch = useRef(0);
	useEffect(() => {
		epoch.current++;
		setEvidence(null);
		setPreview(null);
		setPreviewOpen(false);
		return () => {
			epoch.current++;
		};
	}, []);
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

	const inspectEvidence = async () => {
		const at = epoch.current;
		setPreviewOpen(true);
		setPreviewLoading(true);
		setPreview(null);
		setEvidence(null);
		try {
			const value = await desktopClient.invoke<ArtifactEvidence>(
				"inspect_artifact_evidence",
				{ path, cwd, environmentId },
			);
			if (at === epoch.current) setEvidence(value);
		} catch (error) {
			if (at === epoch.current)
				toast({
					variant: "destructive",
					title: "Evidence unavailable",
					description: String(error),
				});
		} finally {
			if (at === epoch.current) setPreviewLoading(false);
		}
	};
	const memberPreview = async (member: string) => {
		if (!evidence?.sha256) return;
		const at = epoch.current;
		setPreviewLoading(true);
		try {
			const value = await desktopClient.invoke<ArtifactPreview>(
				"preview_archive_member",
				{ path, cwd, environmentId, member, expectedHash: evidence.sha256 },
			);
			if (at === epoch.current)
				setPreview({ ...value, name: member, modifiedAt: "" });
		} catch (error) {
			if (at === epoch.current)
				toast({
					variant: "destructive",
					title: "Archive preview blocked",
					description: String(error),
				});
		} finally {
			if (at === epoch.current) setPreviewLoading(false);
		}
	};
	const showPreview = async () => {
		const at = epoch.current;
		setEvidence(null);
		setPreviewOpen(true);
		setPreviewLoading(true);
		try {
			const value = await desktopClient.invoke<ArtifactPreview>(
				"read_artifact_preview",
				{
					path,
					...(environmentId ? { environmentId } : {}),
					...(cwd?.trim() ? { cwd } : {}),
				},
			);
			if (at === epoch.current) setPreview(value);
		} catch (error) {
			if (at !== epoch.current) return;
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
			if (at === epoch.current) setPreviewLoading(false);
		}
	};
	const trigger =
		primaryAction === "preview"
			? cloneElement(
					children as ReactElement<{
						onClick?: (event: ReactMouseEvent<HTMLElement>) => void;
					}>,
					{
						onClick: (event: ReactMouseEvent<HTMLElement>) => {
							event.preventDefault();
							event.stopPropagation();
							void showPreview();
						},
					},
				)
			: children;

	return (
		<>
			<ContextMenu>
				<ContextMenuTrigger asChild>{trigger}</ContextMenuTrigger>
				<ContextMenuContent className="w-52">
					<ContextMenuItem onSelect={() => void showPreview()}>
						<Eye />
						Preview
					</ContextMenuItem>
					<ContextMenuItem onSelect={() => void onOpen()}>
						<ExternalLink />
						Open with default app
					</ContextMenuItem>
					<ContextMenuItem onSelect={() => void reveal()}>
						<FolderOpen />
						Show in folder
					</ContextMenuItem>
					<ContextMenuItem onSelect={() => void inspectEvidence()}>
						<Eye />
						Inspect evidence / archive
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
							{evidence
								? `${evidence.classification} · ${formatBytes(evidence.size)}`
								: preview
									? `${formatBytes(preview.size)} · Modified ${new Date(preview.modifiedAt).toLocaleString()}`
									: "Loading artifact preview…"}
						</DialogDescription>
					</DialogHeader>
					{evidence && (
						<div className="space-y-2 text-xs break-all">
							<p>Origin: {evidence.workspace}</p>
							<p>SHA-256: {evidence.sha256}</p>
							<p>
								Archive members are not standalone files. No automatic
								extraction or execution.
							</p>
							{evidence.blockedReason && <p>{evidence.blockedReason}</p>}
							{evidence.members && (
								<select
									aria-label="Archive member"
									className="w-full border rounded bg-background p-2"
									defaultValue=""
									onChange={(e) => {
										if (e.target.value) void memberPreview(e.target.value);
									}}
								>
									<option value="">Choose a member for bounded preview</option>
									{evidence.members.map((member, i) => (
										<option
											key={`${i}:${member.name}`}
											value={member.name}
											disabled={!member.safe}
										>
											{member.name} · {formatBytes(member.bytes)}
											{member.safe ? "" : " · blocked"}
										</option>
									))}
								</select>
							)}
							{evidence.membersTruncated && (
								<p>
									Listing capped at 200 members; no claim of full archive
									coverage.
								</p>
							)}
						</div>
					)}
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
