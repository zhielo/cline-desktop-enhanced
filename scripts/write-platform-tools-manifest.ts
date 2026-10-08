import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
if (!process.argv[2])
  throw new Error("Trusted platform-tools directory required");
const root = resolve(process.argv[2]),
  files: Record<string, string> = {};
for (const name of [
  "adb.exe",
  "AdbWinApi.dll",
  "AdbWinUsbApi.dll",
  "libwinpthread-1.dll",
  "NOTICE.txt",
  "source.properties",
])
  files[name] = createHash("sha256")
    .update(await readFile(join(root, name)))
    .digest("hex");
await writeFile(
  join(root, "runtime-manifest.json"),
  JSON.stringify(
    {
      schemaVersion: 1,
      runtimeId: "android-platform-tools-37.0.1-windows-x64-v1",
      pythonVersion: "not-a-python-runtime",
      fixtureVersion: "adb-version/v1",
      files,
      source:
        "https://dl.google.com/android/repository/platform-tools_r37.0.1-win.zip",
      archiveSha256:
        "45f4d63113e895ebde0c90f194099a4676b6ac653bd28d54314a9e022bbc1a99",
    },
    null,
    2,
  ),
);
