# Android Analysis & Rebuild Pack

Open Analysis workbench → **Android tools**, or Start here → **Analyze / rebuild an owned Android app**. Every target operation prepares an exact request for separate review and approval. Opening the panel checks resource integrity only; it never launches Java, downloads software, generates a key, or installs an app.

## Pack and provenance

The private Windows installer includes Temurin Java 21.0.12.1+1, Apktool 3.0.3, maintained Google Smali/Baksmali 3.0.10, JADX 1.5.6, Bundletool 1.18.3 and official Android Build Tools 36.0.0. `scripts/android-toolchain.lock.json` pins every downloaded archive/JAR and upstream license text by SHA256. Maven runtime dependencies are explicit; there is no installed-time resolution. JRE legal files, SDK notices, dependency JAR notices and upstream licenses remain in the pack. Review applicable upstream redistribution/use terms before distributing beyond private testing.

The installer packages an integrity manifest. Resource checks reject tracked-file changes, untracked classpath files, traversal and links; hashes detect corruption, not producer attestation. The pack invokes Java directly through a fixed-entry ASCII/Base64 argument bridge rather than Windows batch interpolation. The bridge decodes UTF-8 inside the JVM, preserving Unicode paths even when the Windows Java launcher uses an ANSI code page; relative classpaths run from the verified pack directory. Compilation uses checksum-pinned Eclipse ECJ 3.43.0 during packaging, not on the installed machine; the compiler is not shipped. A parallel Windows preflight catches Unicode/native fixture failures before the expensive installer stages, and the installer job independently tests the pack it ships. Child environments preserve non-secret Windows architecture fields required by Apktool, but exclude Java injection variables and signing credentials except for the one approved signer process. Native helpers run from the verified pack directory rather than a target workspace. Static tools parse untrusted data; this is not an OS sandbox.

External installations remain discoverable on hosts without a pack. A present invalid pack does not silently fall back to PATH. Signing requires the verified bundled signer. No automatic software updates or network downloads occur during a target operation.

## Recommended journey

1. Inspect and hash the original. Preserve it unchanged.
2. Decode ordinary `.apk`, or disassemble standalone `.dex`.
3. Search Smali; read the exact file/method; use a single JADX class for a secondary semantic view.
4. Review proposed source changes using normal Files/Changes. Editing is not implicitly approved by this guide.
5. Assemble to a **new DEX**, or rebuild a **new unsigned APK**, from a private source snapshot. Existing destinations are rejected, including publication races. Directory hashing has explicit depth/entry/byte budgets. Output checks are bounded DEX header/digest or ZIP/manifest checks, not a full bytecode or ART verifier.
6. Compare original and candidate. Decode cache reuse binds source hash, tool/runtime/configuration/API identity and current decoded-tree digest; edited output is not silently overwritten or returned as unchanged cached analysis.
7. Align to a new APK using 16 KiB page alignment; sign only after separate approval; verify certificate and signature schemes.
8. Use APK incidents for separately approved dedicated-device validation/rollback. No static step installs, launches, roots, instruments or uploads an app.

AAB uses Bundletool **validate** only. APKS/APKM/XAPK expose bounded APK-member inventory; explicitly select/extract authorized base/split artifacts. Container inspection does not prove split consistency, device suitability, universal APK support or valid AAB reconstruction. No automatic split merging or Bundletool-generated signing identity is used.

## Signing configuration

Only configure a test keystore you own or are authorized to use. Supply these through a protected **host environment**, not chat, model tool arguments, source files or evidence exports:

- `CLINE_ANDROID_TEST_KEYSTORE`: absolute local keystore path
- `CLINE_ANDROID_TEST_KEY_ALIAS`: authorized test alias
- `CLINE_ANDROID_TEST_STORE_PASSWORD`
- `CLINE_ANDROID_TEST_KEY_PASSWORD`

Restart the backend after configuring its environment. `sign_apk` additionally requires `confirm_test_signing=true`, a new `.apk` destination and exact-request approval. Passwords enter the signer through child-only environment references. Signing results omit private signer diagnostics and key paths; verification reports contain public certificate information. This is a test-key workflow, not a production HSM/key-management service. Rebuilding cannot preserve the original signature; matching package names do not imply upgrade compatibility. No production key or default shared signing key is shipped.

## Verification and limits

**Test owned Android fixtures** explicitly executes a fixed static corpus: Smali assembly/header digests, Baksmali exact-method retrieval, APK resources and multidex decode/rebuild, JADX class retrieval, Bundletool launch/invalid-AAB rejection, ephemeral-key signature verification, and Windows alignment/aapt2/dexdump checks. Disposable fixture secrets are child-only, never stored in host signing configuration or exported. Readiness is bound to the exact pack manifest and does not replay on refresh/restart.

Windows CI must pass these real-engine fixtures before building the installer. Installed WebView acceptance must execute the installed pack and navigate its Android controls. Local Linux testing cannot validate Windows native tools. A valid-AAB corpus, arbitrary obfuscated apps, custom OEM framework compatibility, full DEX verification, ART execution and physical-device behavior are not certified. Unexpected/new DEX output formats fail closed rather than being rewritten or silently downgraded.

Frida/Objection/ADB runtime work remains a separate authorized isolated device workflow. Existing Python Androguard/APKID and native triage tools remain complementary; they are not replacements for the Java toolchain.

DEX validation accepts bounded classic DEX 035–040 headers with verified digests. Newer container/header formats (including DEX 041) fail closed; requested API levels are not silently downgraded. Decode caches also require unchanged source bytes after execution and an unchanged decoded tree before reuse.
