import { randomUUID } from "node:crypto";
import {
	appendFileSync,
	existsSync,
	mkdirSync,
	readdirSync,
	renameSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { sharedSessionDataDir } from "./paths";

export const ATTACHMENT_UPLOAD_CHUNK_BYTES = 512 * 1024;
export const MAX_ATTACHMENT_FILE_BYTES = 1024 * 1024 * 1024;

const UPLOAD_TTL_MS = 24 * 60 * 60 * 1000;
const uploads = new Map<
	string,
	{
		path: string;
		expectedSize: number;
		receivedSize: number;
		complete: boolean;
	}
>();
let lastCleanupAt = 0;

function uploadDir(): string {
	return join(sharedSessionDataDir(), "_attachment-uploads");
}

function cleanupExpiredUploads(): void {
	const now = Date.now();
	if (now - lastCleanupAt < 60 * 60 * 1000) return;
	lastCleanupAt = now;
	const dir = uploadDir();
	if (!existsSync(dir)) return;
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		if (!entry.isFile() || !entry.name.endsWith(".upload")) continue;
		const path = join(dir, entry.name);
		try {
			if (now - statSync(path).mtimeMs > UPLOAD_TTL_MS) {
				rmSync(path, { force: true });
			}
		} catch {
			// Best-effort cleanup. A concurrent consumer may have moved the file.
		}
	}
}

export function beginAttachmentUpload(size: number): {
	uploadId: string;
	maxChunkBytes: number;
} {
	if (!Number.isSafeInteger(size) || size < 0) {
		throw new Error("Attachment size must be a non-negative integer");
	}
	if (size > MAX_ATTACHMENT_FILE_BYTES) {
		throw new Error(
			`Attachment is too large (maximum ${MAX_ATTACHMENT_FILE_BYTES} bytes)`,
		);
	}
	cleanupExpiredUploads();
	const dir = uploadDir();
	mkdirSync(dir, { recursive: true });
	const uploadId = randomUUID();
	const path = join(dir, `${uploadId}.upload`);
	writeFileSync(path, Buffer.alloc(0), { flag: "wx" });
	uploads.set(uploadId, {
		path,
		expectedSize: size,
		receivedSize: 0,
		complete: size === 0,
	});
	return { uploadId, maxChunkBytes: ATTACHMENT_UPLOAD_CHUNK_BYTES };
}

export function appendAttachmentUpload(
	uploadId: string,
	offset: number,
	contentBase64: string,
): { receivedSize: number } {
	const upload = uploads.get(uploadId);
	if (!upload) throw new Error("Attachment upload was not found or expired");
	if (upload.complete) throw new Error("Attachment upload is already complete");
	if (!Number.isSafeInteger(offset) || offset !== upload.receivedSize) {
		throw new Error(
			`Attachment chunk offset mismatch (expected ${upload.receivedSize})`,
		);
	}
	if (
		typeof contentBase64 !== "string" ||
		!/^[A-Za-z0-9+/]*={0,2}$/.test(contentBase64) ||
		contentBase64.length % 4 !== 0
	) {
		throw new Error("Attachment chunk is not valid base64");
	}
	const chunk = Buffer.from(contentBase64, "base64");
	if (chunk.length === 0 || chunk.length > ATTACHMENT_UPLOAD_CHUNK_BYTES) {
		throw new Error("Attachment chunk has an invalid size");
	}
	if (upload.receivedSize + chunk.length > upload.expectedSize) {
		throw new Error("Attachment upload exceeds its declared size");
	}
	appendFileSync(upload.path, chunk);
	upload.receivedSize += chunk.length;
	if (upload.receivedSize === upload.expectedSize) upload.complete = true;
	return { receivedSize: upload.receivedSize };
}

export function finishAttachmentUpload(uploadId: string): {
	uploadId: string;
	size: number;
} {
	const upload = uploads.get(uploadId);
	if (!upload) throw new Error("Attachment upload was not found or expired");
	if (upload.receivedSize !== upload.expectedSize) {
		throw new Error(
			`Attachment upload is incomplete (${upload.receivedSize}/${upload.expectedSize} bytes)`,
		);
	}
	upload.complete = true;
	return { uploadId, size: upload.receivedSize };
}

export function consumeAttachmentUpload(
	uploadId: string,
	destinationPath: string,
): void {
	const upload = uploads.get(uploadId);
	if (!upload || !upload.complete) {
		throw new Error("Attachment upload was not completed or has expired");
	}
	renameSync(upload.path, destinationPath);
	uploads.delete(uploadId);
}

export function discardAttachmentUploads(uploadIds: string[]): void {
	for (const uploadId of uploadIds) {
		const upload = uploads.get(uploadId);
		if (!upload) continue;
		uploads.delete(uploadId);
		try {
			rmSync(upload.path, { force: true });
		} catch {
			// Idempotent, best-effort cleanup.
		}
	}
}