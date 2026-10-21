---
name: investigate-android
description: "Inspect owned APK/DEX/Smali and guide separately approved Android candidate, assembly and rebuild steps using Cline’s existing Android pack. Use for classes, methods, resources, JNI candidates and scoped changes; not automatic signing, device installation or guaranteed runtime correctness."
license: Apache-2.0
compatibility: Requires Cline Desktop integrated investigation tools; no REA installation.
metadata:
  version: "1"
---

# Investigate an owned Android artifact

## Inspect before proposing changes

Use the advertised Android catalog and exact input identity. Distinguish ordinary APK, DEX, Smali directory, AAB and split-container workflows. Do not feed an AAB or split set to an ordinary APK decoder. Tool-pack presence is not readiness; run owned fixtures only through the existing explicit readiness action when needed, not automatically for each question.

Use supported bounded inventory, `index_multidex`, `read_android_method_code`, `inspect_elf` and `map_jni_bindings` as appropriate. Preserve class descriptors, exact method signatures, DEX/member origins, source hashes and unresolved or overloaded matches. JNI-name candidates do not prove observed dynamic registration. Resource/XML and manifest callbacks are declared evidence, not a runtime execution trace.

## A separately reviewed candidate

- Read the original Smali file and hash, select one exact class/method, and prepare `preview_smali_patch` with the current schema’s expected hash, exact expected method, replacement and distinct new destination.
- Review the returned before/after text and previewSha256. Apply only through a separately approved `patch_smali_method`/advertised alias bound to that preview. Preserve the original. Stale hashes, ambiguous methods, existing outputs and links must fail rather than be worked around.
- Assembly, project integration, rebuild, align, authorized test signing, verification and device install are different operations. Use existing reviewed tools for each requested effect. An unsigned APK is not a preserved original signature. Do not reuse a production key, install to a device, bypass signatures or execute the app without the separate requested scope and authorization.

## State the limits

A candidate file is not a complete project patch. Parser-checked Smali is not an ART verifier. Owned resource/multidex/JADX/Smali fixtures do not establish OEM framework, real-device or production signing compatibility. Preserve failed/partial receipts; never replay a failed write batch blindly. If engine/layout support is missing, report the exact blocker rather than installing REA or inventing a tool route.

Return artifact/member identity, exact method/resource scope, observed versus inferred findings, preview/apply receipts where requested, completed and unperformed build/sign/device stages, original preservation and required follow-up validation. Never describe an untested rebuild as working on a device.
