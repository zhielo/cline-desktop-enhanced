import {
	agentMarkdownControls,
	markdownCodeHighlighter,
} from "@cline/ui/components/markdown";
import { cjk } from "@streamdown/cjk";
import type { ComponentProps, MouseEvent, ReactNode } from "react";
import { isValidElement, memo, useState } from "react";
import {
	type Components,
	type ExtraProps,
	type LinkSafetyModalProps,
	Streamdown,
} from "streamdown";
import { toast } from "@/hooks/use-toast";
import { desktopClient, openExternalUrl } from "@/lib/desktop-client";
import { cn } from "@/lib/utils";
import {
	AlertDialog,
	AlertDialogAction,
	AlertDialogCancel,
	AlertDialogContent,
	AlertDialogDescription,
	AlertDialogFooter,
	AlertDialogHeader,
	AlertDialogTitle,
} from "./alert-dialog";

const CLINE_FILE_ROUTE = "./__cline_file__";
const INLINE_FILE_REFERENCE =
	/(?<!\[)`((?:(?:\.{1,2}[\\/])|(?:[A-Za-z]:[\\/])|(?:[\w@.-]+[\\/]))[\w@ .()\-\\/]+\.(?:c|cc|cpp|cs|css|go|h|hpp|html|java|js|json|jsx|kt|kts|md|mjs|php|py|rb|rs|scss|sh|sql|swift|toml|ts|tsx|vue|xml|yaml|yml)(?::\d+(?::\d+)?)?)`/g;

type WorkspaceFileReference = { path: string; line?: number; column?: number };

function parseFileLocation(value: string): WorkspaceFileReference {
	const match = value.match(/^(.*?):(\d+)(?::(\d+))?$/);
	if (!match) return { path: value };
	return {
		path: match[1] ?? value,
		line: Number(match[2]),
		column: match[3] ? Number(match[3]) : undefined,
	};
}

function fileReferenceHref(reference: WorkspaceFileReference): string {
	const params = new URLSearchParams({ path: reference.path });
	if (reference.line) params.set("line", String(reference.line));
	if (reference.column) params.set("column", String(reference.column));
	return `${CLINE_FILE_ROUTE}?${params.toString()}`;
}

export function linkifyWorkspaceFileReferences(content: string): string {
	let fenced = false;
	return content
		.split("\n")
		.map((line) => {
			if (/^\s*(?:```|~~~)/.test(line)) {
				fenced = !fenced;
				return line;
			}
			if (fenced) return line;
			return line.replace(INLINE_FILE_REFERENCE, (_match, value: string) => {
				const reference = parseFileLocation(value);
				return `[\`${value}\`](${fileReferenceHref(reference)})`;
			});
		})
		.join("\n");
}

function parseClineFileHref(url: string): WorkspaceFileReference | null {
	if (!url.includes("__cline_file__")) return null;
	try {
		const parsed = new URL(url, "https://cline.local/");
		if (!parsed.pathname.endsWith("/__cline_file__")) return null;
		const path = parsed.searchParams.get("path")?.trim();
		if (!path) return null;
		const line = Number(parsed.searchParams.get("line"));
		const column = Number(parsed.searchParams.get("column"));
		return {
			path,
			line: Number.isInteger(line) && line > 0 ? line : undefined,
			column: Number.isInteger(column) && column > 0 ? column : undefined,
		};
	} catch {
		return null;
	}
}

const streamdownPlugins = { cjk, code: markdownCodeHighlighter };

export function MarkdownLinkSafetyModal({
	isOpen,
	onClose,
	onConfirm,
	url,
}: LinkSafetyModalProps) {
	return (
		<AlertDialog
			onOpenChange={(open) => {
				if (!open) onClose();
			}}
			open={isOpen}
		>
			<AlertDialogContent>
				<AlertDialogHeader>
					<AlertDialogTitle>Open external link?</AlertDialogTitle>
					<AlertDialogDescription>
						You are about to leave Cline and visit this address.
					</AlertDialogDescription>
				</AlertDialogHeader>
				<div className="max-h-32 overflow-y-auto wrap-break-word rounded-md bg-muted p-3 font-mono text-sm">
					{url}
				</div>
				<AlertDialogFooter>
					<AlertDialogCancel>Cancel</AlertDialogCancel>
					<AlertDialogAction onClick={onConfirm}>Open link</AlertDialogAction>
				</AlertDialogFooter>
			</AlertDialogContent>
		</AlertDialog>
	);
}

type MarkdownLinkProps = ComponentProps<"a"> & ExtraProps;

function extractLinkText(children: ReactNode): string {
	if (typeof children === "string" || typeof children === "number") {
		return String(children);
	}
	if (Array.isArray(children)) {
		return children.map(extractLinkText).join("");
	}
	// Inline formatting (**bold**, `code`, …) nests the label text inside
	// elements; recurse so styled hostnames can't dodge the deception check.
	if (isValidElement(children)) {
		return extractLinkText(
			(children.props as { children?: ReactNode }).children,
		);
	}
	return "";
}

// Tolerates one trailing dot after the TLD ("github.com." resolves the same
// as "github.com" in browsers) and a protocol-relative "//" prefix, so those
// label spellings can't slip past the deception check.
const urlLikeTextPattern =
	/^(?:https?:\/\/|\/\/)?(?:[\w-]+\.)+[a-z]{2,}\.?(?:[/:?#]\S*)?$/i;

type LinkParts = {
	protocol: string;
	hostname: string;
	port: string;
	explicitScheme: boolean;
};

function parseLinkParts(value: string): LinkParts | null {
	const explicitScheme = /^[a-z][a-z\d+.-]*:/i.test(value);
	const withScheme = explicitScheme
		? value
		: value.startsWith("//")
			? `https:${value}`
			: `https://${value}`;
	try {
		const parsed = new URL(withScheme);
		const hostname = parsed.hostname
			.toLowerCase()
			.replace(/\.+$/, "")
			.replace(/^www\./, "");
		if (!hostname) return null;
		return {
			explicitScheme,
			hostname,
			port: parsed.port,
			protocol: parsed.protocol,
		};
	} catch {
		return null;
	}
}

/**
 * A link is deceptive when its visible text reads as a URL that does not
 * match the real destination — the one shape where a click genuinely
 * surprises the user. Only those links get the confirmation dialog;
 * ordinary external links open directly. The label and destination must
 * agree on hostname and port, and on scheme when the label states one.
 */
function isDeceptiveLink(children: ReactNode, url: string): boolean {
	const text = extractLinkText(children).trim();
	if (!text || !urlLikeTextPattern.test(text)) return false;
	const textParts = parseLinkParts(text);
	if (!textParts) return false;
	const urlParts = parseLinkParts(url);
	if (!urlParts) return true;
	return (
		textParts.hostname !== urlParts.hostname ||
		textParts.port !== urlParts.port ||
		(textParts.explicitScheme && textParts.protocol !== urlParts.protocol)
	);
}

function SafeMarkdownLink({
	children,
	className,
	href,
	node: _node,
	rel: _rel,
	target: _target,
	title,
	...props
}: MarkdownLinkProps) {
	const [isOpen, setIsOpen] = useState(false);
	const isIncomplete = href === "streamdown:incomplete-link";
	const url = isIncomplete ? undefined : href;

	if (!url) {
		return (
			<span
				className={className}
				data-incomplete={isIncomplete}
				data-streamdown="link"
			>
				{children}
			</span>
		);
	}

	const fileReference = parseClineFileHref(url);
	if (fileReference) {
		const openFile = (event: MouseEvent<HTMLAnchorElement>) => {
			event.preventDefault();
			void desktopClient
				.invoke("open_file_in_editor", {
					path: fileReference.path,
					...(fileReference.line ? { line: fileReference.line } : {}),
					...(fileReference.column ? { column: fileReference.column } : {}),
				})
				.catch((error) => {
					toast({
						variant: "destructive",
						title: "Could not open file",
						description:
							error instanceof Error
								? error.message
								: "The file could not be opened.",
					});
				});
		};
		return (
			<a
				{...props}
				className={`inline-flex cursor-pointer items-center rounded bg-muted/70 px-1 py-0.5 font-mono text-[0.92em] text-primary no-underline hover:bg-primary/10 ${className ?? ""}`}
				data-cline-file-reference={fileReference.path}
				data-streamdown="link"
				href={url}
				onClick={openFile}
				title={`Open ${fileReference.path}${fileReference.line ? `:${fileReference.line}` : ""}`}
			>
				{children}
			</a>
		);
	}

	const isAppLink =
		url.startsWith("#") ||
		(url.startsWith("/") && !url.startsWith("//")) ||
		url.startsWith("./") ||
		url.startsWith("../") ||
		(!/^[a-z][a-z\d+.-]*:/i.test(url) && !url.startsWith("//"));

	if (isAppLink) {
		return (
			<a
				{...props}
				className={`wrap-anywhere font-medium text-primary underline ${className ?? ""}`}
				data-streamdown="link"
				href={url}
				title={title}
			>
				{children}
			</a>
		);
	}

	// Streamdown's harden step only lets http(s), mailto, tel, and
	// protocol-relative URLs reach this component, matching the sidecar's
	// open_external_url allowlist. Protocol-relative URLs fail the sidecar's
	// `new URL()` parse, so pin them to https before handing them off.
	const externalUrl = url.startsWith("//") ? `https:${url}` : url;
	const openExternally = () => void openExternalUrl(externalUrl);

	if (!isDeceptiveLink(children, externalUrl)) {
		const openDirectly = (event: MouseEvent<HTMLAnchorElement>) => {
			event.preventDefault();
			openExternally();
		};
		return (
			<a
				{...props}
				className={`wrap-anywhere font-medium text-primary underline ${className ?? ""}`}
				data-streamdown="link"
				href={externalUrl}
				onAuxClick={(event) => {
					if (event.button === 1) openDirectly(event);
				}}
				onClick={openDirectly}
				rel="noreferrer"
				title={title ?? externalUrl}
			>
				{children}
			</a>
		);
	}

	const openConfirmation = (event: MouseEvent<HTMLAnchorElement>) => {
		event.preventDefault();
		setIsOpen(true);
	};
	const confirmMiddleClick = (event: MouseEvent<HTMLAnchorElement>) => {
		if (event.button === 1) openConfirmation(event);
	};

	return (
		<>
			{/* biome-ignore lint/a11y/useValidAnchor: External Markdown retains native link semantics while confirmation withholds the live destination. */}
			<a
				{...props}
				aria-haspopup="dialog"
				className={`wrap-anywhere font-medium text-primary underline ${className ?? ""}`}
				data-streamdown="link"
				href="#confirm-external-link"
				onAuxClick={confirmMiddleClick}
				onClick={openConfirmation}
				title={title ?? externalUrl}
			>
				{children}
			</a>
			<MarkdownLinkSafetyModal
				isOpen={isOpen}
				onClose={() => setIsOpen(false)}
				onConfirm={openExternally}
				url={externalUrl}
			/>
		</>
	);
}

type MarkdownImageProps =
	| (ComponentProps<"img"> & ExtraProps)
	| (Record<string, unknown> & ExtraProps);

const remoteImagePattern = /^(?:https?:)?[\\/]{2}/i;

function isSafeMarkdownImageSource(source: string): boolean {
	const normalized = source.trim();
	if (!normalized || remoteImagePattern.test(normalized)) return false;

	// Streamdown's hardened URL policy accepts app-root paths. Keeping the rule
	// this narrow prevents model-authored Markdown from making hidden requests.
	return normalized.startsWith("/");
}

function MarkdownImage({ alt, height, src, title, width }: MarkdownImageProps) {
	const label = typeof alt === "string" ? alt.trim() : "";
	const source = typeof src === "string" ? src.trim() : "";

	if (source && isSafeMarkdownImageSource(source)) {
		return (
			// biome-ignore lint/performance/noImgElement: Markdown can reference runtime app assets that Next Image cannot statically optimize.
			<img
				alt={label}
				className="my-4 max-w-full rounded-lg"
				data-streamdown="image"
				height={typeof height === "number" ? height : undefined}
				loading="lazy"
				src={source}
				title={typeof title === "string" ? title : undefined}
				width={typeof width === "number" ? width : undefined}
			/>
		);
	}

	return (
		<span data-streamdown="blocked-image" role="note">
			External image blocked for privacy{label ? `: ${label}` : ""}
		</span>
	);
}

const markdownComponents = {
	a: SafeMarkdownLink,
	img: MarkdownImage,
} satisfies Components;

export const MemoizedMarkdown = memo(
	({
		content,
		classNames,
		streaming = false,
	}: {
		content: string;
		streaming?: boolean;
		classNames?: string;
	}) => (
		<Streamdown
			className={cn("cline-markdown", classNames)}
			components={markdownComponents}
			controls={agentMarkdownControls}
			dir="auto"
			isAnimating={streaming}
			lineNumbers={false}
			mode={streaming ? "streaming" : "static"}
			normalizeHtmlIndentation
			parseIncompleteMarkdown={streaming}
			plugins={streamdownPlugins}
		>
			{linkifyWorkspaceFileReferences(content)}
		</Streamdown>
	),
);

MemoizedMarkdown.displayName = "MemoizedMarkdown";
