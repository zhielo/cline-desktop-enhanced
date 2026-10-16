/** CI-only downloads: retries never bypass the pinned digest or enable runtime installs. */
import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";

export async function downloadPinnedAndroidAsset(url, digest, name, directory, options = {}) {
 const fetchAsset = options.fetch ?? fetch;
 const pause = options.pause ?? (ms => new Promise(resolve => setTimeout(resolve, ms)));
 const file = path.join(directory, name);
 const valid = bytes => createHash("sha256").update(bytes).digest("hex") === digest;
 let cached;
 try { cached = await readFile(file); } catch {}
 if (cached && valid(cached)) return file;
 let response;
 for (let attempt = 1; attempt <= 4; attempt++) {
  let bytes;
  try {
   response = await fetchAsset(url, { signal: AbortSignal.timeout(180000) });
   if (response.ok) bytes = Buffer.from(await response.arrayBuffer());
  } catch (error) {
   if (attempt === 4) throw new Error(`Download failed after 4 attempts: ${name}`, { cause: error });
   await pause(1000 * 2 ** (attempt - 1));
   continue;
  }
  if (response.ok) {
   if (!valid(bytes)) throw new Error(`Pinned digest mismatch: ${name}`);
   await mkdir(directory, { recursive: true });
   await writeFile(file, bytes);
   return file;
  }
  const retryable = [404, 408, 429].includes(response.status) || response.status >= 500;
  await response.body?.cancel();
  if (!retryable || attempt === 4) throw new Error(`Download failed: ${name} (${response.status}; attempt ${attempt})`);
  await pause(1000 * 2 ** (attempt - 1));
 }
 throw new Error(`Download failed: ${name}`);
}
