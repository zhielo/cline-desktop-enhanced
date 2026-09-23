import { validateImageMedia } from "@cline/shared/browser";
import type { ChatMessageImage } from "@/lib/chat-schema";
import { desktopClient } from "@/lib/desktop-client";
import { imageAttachmentMediaType } from "@/lib/image-attachments";
import type { SerializedAttachmentFile, SerializedAttachments } from "./types";

const FALLBACK_ATTACHMENT_CHUNK_BYTES = 512 * 1024;

async function readFileAsDataUrl(file: File): Promise<string> {
	return await new Promise((resolve, reject) => {
		const reader = new FileReader();
		reader.onload = () => {
			const value = typeof reader.result === "string" ? reader.result : "";
			resolve(value);
		};
		reader.onerror = () => {
			reject(reader.error ?? new Error("failed reading file"));
		};
		reader.readAsDataURL(file);
	});
}

function bytesToBase64(bytes: Uint8Array): string {
	let binary = "";
	for (let offset = 0; offset < bytes.length; offset += 0x8000) {
		binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
	}
	return btoa(binary);
}

async function uploadFile(file: File): Promise<SerializedAttachmentFile> {
	const started = await desktopClient.invoke<{
		uploadId: string;
		maxChunkBytes: number;
	}>("begin_attachment_upload", {
		name: file.name,
		size: file.size,
	});
	const maxChunkBytes =
		Number.isSafeInteger(started.maxChunkBytes) && started.maxChunkBytes > 0
			? started.maxChunkBytes
			: FALLBACK_ATTACHMENT_CHUNK_BYTES;
	try {
		for (let offset = 0; offset < file.size; offset += maxChunkBytes) {
			const bytes = new Uint8Array(
				await file.slice(offset, offset + maxChunkBytes).arrayBuffer(),
			);
			await desktopClient.invoke("append_attachment_upload", {
				uploadId: started.uploadId,
				offset,
				contentBase64: bytesToBase64(bytes),
			});
		}
		await desktopClient.invoke("finish_attachment_upload", {
			uploadId: started.uploadId,
		});
		return { name: file.name, uploadId: started.uploadId };
	} catch (error) {
		void desktopClient
			.invoke("discard_attachment_uploads", {
				uploadIds: [started.uploadId],
			})
			.catch(() => {});
		throw error;
	}
}

export async function serializeAttachments(
	files: File[],
): Promise<SerializedAttachments> {
	const userImages: string[] = [];
	const userFiles: SerializedAttachmentFile[] = [];

	try {
		for (const file of files) {
			const mediaType = imageAttachmentMediaType(file);
			if (mediaType) {
				const dataUrl = await readFileAsDataUrl(
					new File([file], file.name, { type: mediaType }),
				);
				if (dataUrl) {
					userImages.push(dataUrl);
				}
				continue;
			}

			userFiles.push(await uploadFile(file));
		}
	} catch (error) {
		if (userFiles.length > 0) {
			void desktopClient
				.invoke("discard_attachment_uploads", {
					uploadIds: userFiles.map((file) => file.uploadId),
				})
				.catch(() => {});
		}
		throw error;
	}

	return { userImages, userFiles };
}

export function toChatMessageImages(
	userImages: string[],
	idPrefix: string,
): ChatMessageImage[] {
	const images: ChatMessageImage[] = [];
	for (const [index, value] of userImages.entries()) {
		const validation = validateImageMedia(undefined, value);
		if (!validation.ok) {
			continue;
		}
		images.push({
			id: `${idPrefix}_image_${index}`,
			mediaType: validation.mediaType,
			data: validation.base64,
		});
	}
	return images;
}
