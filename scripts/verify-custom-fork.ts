import { existsSync, readFileSync } from "node:fs";

const requiredMarkers: Array<{
	path: string;
	markers: string[];
}> = [
 {path:"workers/managed-emulation/engines/selftest.py",markers:["def owned_jvm_crash_evidence(", "'-XX:ErrorFile='+str(root/'hotspot-crash.log')", "'-XX:-CreateCoredumpOnCrash'", "CLINE_MANAGED_OWNED_JVM_CRASH_V1", "before.st_nlink != 1", "result.stdout[:4096]", "min(before.st_size, 12288)"]},
 {path:".github/workflows/managed-emulation-engines.yml",markers:["pull_request: {}", "Required exact-head release checks"]},
 {path:".github/workflows/managed-emulation-image.yml",markers:["pull_request: {}", "Required exact-head release checks"]},
 {path:".github/workflows/managed-emulation-transport.yml",markers:["pull_request: {}", "Required exact-head release checks"]},
 {path:"apps/examples/desktop-app/sidecar/release-gate-policy.ts",markers:["cline-desktop-release-gate/v5", "managedCheckWorkflows", "Actual owned guest engine (speakeasy)", "Managed inert transport contracts (windows-latest)", ".github/workflows/managed-emulation-image.yml"]},
 {path:"apps/examples/desktop-app/sidecar/release-gate-verifier.ts",markers:["Managed checks require complete authoritative workflow provenance", "Missing or repeated managed check", "Managed check lacks exact job/workflow binding", "Object.entries(policy.managedCheckWorkflows)"]},
 {path:"workers/managed-emulation/engines/python_inputs.py",markers:["cpython-3.13-linux-x86_64-glibc-2.36", "Duplicate private Python input field", "digest.hexdigest() != entry['sha256']", "output.mkdir(mode=0o700)", "partial.open('xb')", "files.pythonhosted.org", "Private Python requirement lock differs", "class NoRedirect", "build_opener(NoRedirect())"]},
 {path:"workers/managed-emulation/engines/prepare.py",markers:["python_inputs.fetch(components, profiles, engine, archives)", "'--require-hashes'", "'--no-build-isolation'", "'--ignore-installed'", "'/build/private-python-tools'", "'--no-cache-dir'"]},
 {path:".github/workflows/managed-emulation-engines.yml",markers:["python3 -B workers/managed-emulation/engines/test_python_inputs.py"]},
 {path:"workers/managed-emulation/image/engine_entry.py",markers:["os.setgroups([])", "os.setresgid(ENGINE_UID, ENGINE_UID, ENGINE_UID)", "os.setresuid(ENGINE_UID, ENGINE_UID, ENGINE_UID)", "PR_SET_NO_NEW_PRIVS = 38", "except PermissionError", "os.execve(PYTHON", "resource.RLIMIT_CORE", "b'CapInh',b'CapPrm',b'CapEff',b'CapAmb'", "no_capabilities()"]},
 {path:"workers/managed-emulation/image/build_image.py",markers:["mode=1777 tmpfs /tmp", "/opt/cline/engine_entry.py || fail"]},
 {path:"workers/managed-emulation/image/smoke_boot.py",markers:["uid-gid-65534/no-supplementary-groups/no-new-privileges"]},

 {path:"apps/examples/desktop-app/sidecar/managed-emulation-pack.mjs",markers:["selectEmulationEngines", "const reused = []", "await releaseLease(", "parent === path", "info = await lstat(path)", "const needed = []", "await verifyEngine(", "ERR_MANAGED_PACK_INTEGRITY", "corresponding-source.tar.zst", "signal?.throwIfAborted()", "output.sync()", "await transfer(", "install.lock", "Retained pack installation budget", "await rename(temporary", 'activation: "not-implemented"', 'engineReadiness: "not-tested"']},
 {path:"apps/examples/desktop-app/sidecar/managed-emulation-catalog.ts",markers:["managedEmulationCatalog: ManagedPackCatalog | null = null"]},
 {path:"apps/examples/desktop-app/sidecar/commands.ts",markers:["setup_center_emulation_install", "setup_center_emulation_verify_files", "installManagedEmulationPack(args.engines, phase)", "verifyManagedEmulationPack(args.engines, phase)"]},
 {path:"apps/examples/desktop-app/webview/components/views/settings/managed-emulation-install.tsx",markers:["Install all four", "Install selected engines (", "Verify selected files", "Installed files are not runtime readiness"]},
 {path:".github/workflows/managed-emulation-transport.yml",markers:["node --test scripts/managed-emulation-pack-install.test.mjs"]},
 {path:"workers/managed-emulation/host/src/windows_service.rs",markers:["fn process_exit(process: HANDLE)", "GetExitCodeProcess(process, &mut code)", "clean_exit(process.as_raw_handle() as HANDLE)", "process_exit(refused_handle) != Ok(2)", "Owned service process has not exited", "Owned service process exited unsuccessfully"]},
 {path:"workers/managed-emulation/host/src/windows_service.rs",markers:["ERROR_SERVICE_EXISTS", "ERROR_SHARING_VIOLATION as i32"]},
 {path:"workers/managed-emulation/host/src/windows_service.rs",markers:["StartServiceCtrlDispatcherW", "RegisterServiceCtrlHandlerExW", "SERVICE_STOP_PENDING", "state.cancel.signal()", "roots.open_job(job_id)?", "job.owned_service_file(false)?", "LOAD_LIBRARY_SEARCH_SYSTEM32", "No service command-line arguments allowed", "SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE", "Never OpenService/adopt an existing entry", "WaitForSingleObject(process.as_raw_handle() as HANDLE, 5000)", "ERROR_SERVICE_DOES_NOT_EXIST", "join(\"owned-local-service-fixture.exe\")"]},
 {path:"workers/managed-emulation/host/src/windows_ipc.rs",markers:["WaitForMultipleObjects", "IPC operation cancelled", "DisconnectNamedPipe", "explicit_cancellation_drains_connect_without_waiting_for_deadline", "pre_cancelled_exchange_opens_no_new_operation"]},
 {path:"workers/managed-emulation/host/src/windows_roots.rs",markers:["validate_system_regular(file, allow_empty, 16384)", "Exclusive owned service binary required", "64 * 1024 * 1024"]},
 {path:"workers/managed-emulation/host/src/bin/owned-local-service-fixture.rs",markers:["Duration::from_secs(120)", "std::process::exit(124)", "windows_service::dispatch()"]},
 {path: ".github/workflows/managed-emulation-transport.yml",markers:["--bin owned-system-roots-fixture --bin owned-local-service-fixture"]},
 {path:"workers/managed-emulation/host/src/windows_ipc.rs",markers:["PIPE_REJECT_REMOTE_CLIENTS", "FILE_FLAG_FIRST_PIPE_INSTANCE", "SECURITY_SQOS_PRESENT | qos", "SECURITY_IDENTIFICATION", "ImpersonateNamedPipeClient(pipe)", "revert.finish()?", "IPC client scope mismatch", "TokenStatistics", "TokenSessionId", "CancelIoEx", "IPC server owner mismatch", "fn anonymous_client_is_denied_without_identity_fallback", "fn connected_silent_client_cancels_read_before_buffer_is_freed", "fn public_server_requires_real_system_without_escalation"]},
 {path:"workers/managed-emulation/host/src/bin/owned-system-roots-fixture.rs",markers:["windows_ipc::owned_system_acceptance()"]},
 {path:"workers/emulation/unidbg/src/main/java/ClineRunner.java",markers:["backend.emu_stop();", "code.compareAndSet(0,reason)", "if(!guard.failed && guard.code.get()!=0)", "finally {emulator.close();}", "CLINE_UNIDBG_GUARD_V1 "]},
 {path:"workers/emulation/unidbg/src/test/java/ClineGuardTest.java",markers:["Proxy.newProxyInstance", "new int[]{75,76}", "Repeated failed stop admitted", "!guard.failed"]},
 {path:"workers/managed-emulation/engines/prepare.py",markers:["'ClineGuardTest'"]},
 {path:"workers/managed-emulation/engines/test_bundle.py",markers:["test_unidbg_native_callback_uses_stop_not_jvm_exit"]},
 {path:".github/workflows/managed-emulation-engines.yml",markers:["Require ALL three fresh cold boots", "for repetition in 2 3", "engine-$repetition-receipt.json", "--uefi --owned-engine unidbg"]},
 {path:"workers/managed-emulation/engines/selftest.py",markers:["result_path.exists() or result_path.is_symlink()"]},

 {path:"workers/managed-emulation/engines/selftest.py",markers:["def validate_jni_refusal", "CLINE_MANAGED_JNI_REFUSAL_DIAGNOSTIC_V1", "'denied': (76, b'CLINE_UNIDBG_GUARD_V1 76'", "'budget': (75, b'CLINE_UNIDBG_GUARD_V1 75'", "java.lang.IllegalArgumentException: Exact static JNI export required", "-signal.SIGABRT", "result.stderr[-4096:]"]},
 {path:"workers/managed-emulation/engines/test_bundle.py",markers:["test_owned_jni_refusals_require_exact_reason_and_exit_without_result", "test_owned_jni_diagnostics_are_bounded_and_unknown_profiles_never_pass", "OutOfMemoryError", "unexpected result"]},
 {path:"docs/MANAGED_EMULATION_RESEARCH.md",markers:["DefineSystem", "PIPE_REJECT_REMOTE_CLIENTS", "Missing evidence must retain state", "Do not ship Microsoft rootfs assets", "Merge only after"]},

 {path:"workers/managed-emulation/host/src/windows_boot.rs",markers:["SYSTEM_BOOT_ENVIRONMENT_INFORMATION: u32 = 90", "NtQuerySystemInformation", "native_boot_observation_is_stable_and_exact", "no fallback", "guid[..4].reverse()", "OS boot changed; explicit VM recovery required"]},
 {path:"workers/managed-emulation/host/src/windows_identity.rs",markers:["let host_boot = crate::windows_boot::HostBoot::observe()?", "require_forward_boot(&event, record.host_boot)?", "forward_work_requires_native_original_boot_without_authorizing_recovery", "pub fn require_original_boot"]},

 {path:"workers/managed-emulation/host/src/windows_identity.rs",markers:["pub const OWNERSHIP_FILE", "fn ownership_mac", "pub fn reserve_vm", "pub fn open_vm", "VM reservation authentication failed", "reservations_bind_all_claims_and_reject_ambiguous_schema", "record: Option<RecordBinding<'installation>>"]},
 {path:"workers/managed-emulation/host/src/bin/owned-system-roots-fixture.rs",markers:["reservation_acceptance(&roots)?", "record.create_store()", "record.open_store()", "VM reservation authentication failed", ".reserve_vm(&job, &\"35\".repeat(32))"]},

 {path:"workers/managed-emulation/image/build_image.py",markers:["Owned acceptance source replaced", "Duplicate engine manifest field", "generatedInitSha256"]},
 {path:"workers/managed-emulation/engines/selftest.py",markers:["verify_bundle()", "CLINE_MANAGED_ENGINE_OWNED_V1", "Owned runtime changed", "unsupported-syscall", "GetTickCount", "-Djna.tmpdir="]},
 {path:"workers/managed-emulation/engines/prepare.py",markers:["Exact JNI dependency closure required", "Engine runtime byte budget", "--compress=2", "strip", "development-owned-guest-tests-only"]},
 {path:".github/workflows/managed-emulation-engines.yml",markers:["engine: [qiling, unidbg, rnidbg, speakeasy]", "Actual offline UEFI guest owned engine execution and refusal cases", "never execute fixture in builder"]},
 {path:"workers/managed-emulation/host/src/boot_media.rs",markers:["getrandom::fill", "create_new(true)", "file.sync_all()", "Zeroizing", "BOOT.JSON;1", "Boot material expired or clock changed"]},
 {path:"workers/managed-emulation/host/tests/boot_media.rs",markers:["os_generated_media_and_private_probe_input_share_exact_boot_identity", "native_fixture_cli_writes_no_keys_or_raw_paths_and_never_overwrites"]},
 {path:".github/workflows/managed-emulation-image.yml",markers:["Native private boot media provisions inside the actual UEFI guest", "--credential-case native"]},
 {path:"workers/managed-emulation/host/src/store.rs",markers:["SnapshotWrittenBeforeCommit", "Recovery anchor changed; stale writer fenced", "PRAGMA synchronous=FULL", "Recovery store fenced; reopen and inspect", "SQLITE_OPEN_NOFOLLOW"]},
 {path:"workers/managed-emulation/host/tests/store_crash.rs",markers:["child.kill()", "COMMIT_BOUNDARY_REACHED", "reopen must never replay create"]},
 {path:"workers/managed-emulation/image/smoke_boot.py",markers:["validate_boot_log", "Duplicate guest receipt field", "Guest receipt scope mismatch", '"-nic", "none"', "hardware containment"]},
 {path:"workers/managed-emulation/image/build_image.py",markers:["Pinned package integrity", "Special archive member forbidden", "Linked/non-directory CPIO parent", "CONFIG_HYPERV_VSOCKETS=m", '"installable": False']},
 {path:"workers/managed-emulation/image/init",markers:["CLINE_MANAGED_CREDENTIAL_ABSENT_V1", "modprobe vsock", "timeout -s KILL 45", "poweroff -f"]},
 {path:"workers/managed-emulation/image/provision_boot.py",markers:["os.O_EXCL | os.O_NOFOLLOW", "read_boot_config()", "1025"]},
 {path:".github/workflows/managed-emulation-image.yml",markers:["BIOS cold boot", "UEFI cold boot", "no image binary published", "docker create --network none --read-only"]},
 {path:"workers/managed-emulation/host/src/main.rs",markers:["managed-inert-deadline", "Duration::from_secs(15)", "terminate_probe_on_deadline", "_exit(124)", "TerminateProcess(GetCurrentProcess(), 124)", "No readiness, cleanup or VM-termination receipt"]},
 {path:"workers/managed-emulation/host/tests/process_boundary.rs",markers:["missing_stdin_eof_is_bounded_by_the_real_whole_process_watchdog", "Some(124)", "blocked_diagnostic_delivery_cannot_defeat_the_watchdog"]},
 {path:"workers/managed-emulation/host/src/lifecycle.rs",markers:["cline-managed-lifecycle/v1", "Journal checkpoint mismatch", "Explicit recovery required; no automatic replay", "Reservation must be first", "MAX_EVENTS: usize = 128", "verify_response(response.as_bytes(), challenge)?"]},
 {path:"workers/managed-emulation/host/tests/lifecycle.rs",markers:["reopened_work_is_fenced_even_when_previous_stop_was_recorded", "independent_checkpoint_detects_valid_prefix_rollback_and_tail_deletion", "every_event_rejects_unknown_fields_including_empty_struct_variants"]},
 {path:"workers/managed-emulation/guest_probe.py",markers:["_open_private_boot_record", "dir_fd=descriptor", "Protected root-owned boot directory required", "info.st_nlink != 1", "Boot record changed"]},
 {path:"workers/managed-emulation/probe_protocol.py",markers:["cline-managed-inert-probe/v1", "hmac.compare_digest", "Only the inert owned probe is implemented", '"vmIsolation": "not-attested"']},
 {path:"workers/managed-emulation/guest_probe.py",markers:["socket.AF_VSOCK", "socket.VMADDR_CID_HOST", "serve_one(connection", "Private root-owned boot record required"]},
 {path:"workers/managed-emulation/host/src/lib.rs",markers:["verify_slice", "Concrete child VM identity required", "not-attested", "not-tested"]},
 {path:"workers/managed-emulation/host/src/main.rs",markers:["Domain::from(34)", "Duration::from_secs(10)", "bytes.zeroize()", "Arguments forbidden"]},
 {path:"apps/examples/desktop-app/sidecar/managed-emulation-preflight.ts",markers:["projectManagedEmulationPreflight", "Get-CimInstance -ClassName Win32_OperatingSystem", "managedInstallation: \"not-implemented\"", "engineReadiness: \"not-tested\"", "timeout: 15_000"]},
 {path:"apps/examples/desktop-app/sidecar/commands.ts",markers:["setup_center_emulation_host_preflight", "readManagedEmulationPreflight"]},
 {path:"apps/examples/desktop-app/webview/components/views/settings/managed-emulation-preflight.tsx",markers:["Check local emulation prerequisites", "No installation or readiness is inferred", "not reserved resources", "confirmed: true"]},
 {path:"apps/vscode/scripts/desktop-installed-acceptance.ts",markers:["installed-managed-emulation-readonly-host-preflight-no-readiness-passed", "vmFeasibilityTested: false", "enginesInstalledOrTested: false"]},
 {path:"apps/examples/desktop-app/sidecar/release-gate-collector.ts",markers:["`consolidated-validation-${run.id}-${run.run_attempt}`"]},
 {path:"apps/examples/desktop-app/sidecar/release-gate-verifier.ts",markers:["`consolidated-validation-${r.id}-${r.run_attempt}`"]},
 {path:"apps/vscode/scripts/owned-triage-model.ts",markers:["const declaredTools = request.tools ?? []", "lastToolNames = declaredTools.map"]},
 {path:"sdk/packages/agents/src/agent-runtime.ts",markers:["getModelToolExposure", "modelToolExposure: this.getModelToolExposure()", "toolCount: request.tools.length"]},
 {path:"sdk/packages/core/src/runtime/orchestration/session-runtime-orchestrator.ts",markers:["lastToolExposure", "exposureRevision++", "activeExposureConfig"]},
 {path:"apps/examples/desktop-app/sidecar/commands.ts",markers:["session_tool_inventory_sessions", "Owning session changed; inspect again", "includeToolExposure: true"]},
 {path:"apps/examples/desktop-app/webview/components/views/settings/session-tool-inventory.tsx",markers:["Refresh attached sessions", "Inspect last request", "Stale", "inventory.authorization", "htmlFor={sessionSelectId}", "id={sessionSelectId}"]},
 {path:"apps/vscode/scripts/desktop-installed-acceptance.ts",markers:["installed-session-tool-inventory-exact-provider-names-no-extra-request-passed", "triageModel.providerRequests !== requestsBeforeInventory"]},

 {path:"apps/vscode/scripts/desktop-installed-acceptance.ts",markers:["installed-setup-recovery-real-boot-same-boot-refusal-no-replay-passed", "actualRebootTested: false", "Same-boot inspection changed admission"]},



 {path:"apps/examples/desktop-app/sidecar/setup-boot-identity.ts",markers:["NtQuerySystemInformation(90", "readSetupBootIdentity", "No client arguments", "boot_id"]},
 {path:"apps/examples/desktop-app/sidecar/setup-jobs.ts",markers:["recoverSetupAfterReboot", "Same OS boot", "Setup boot records disagree", "persist(job); // Keep the lease", "setup-recovery.json"]},
 {path:"apps/examples/desktop-app/sidecar/commands.ts",markers:["setup_center_recovery_status", "setup_center_recover_after_reboot"]},
 {path:"apps/examples/desktop-app/webview/components/views/settings/setup-center-view.tsx",markers:["Check reboot recovery", "Close interrupted setup after reboot", "No installation is replayed"]},
 {path:"scripts/validate-advanced-build.mjs",markers:["setup-boot-identity.test.ts"]},
 {path:"sdk/packages/core/scripts/android-investigation-worker.test.py",markers:["class FixtureTimingResult", "ANDROID_FIXTURE_CASE", "resultclass=FixtureTimingResult"]},
 {path:"sdk/packages/core/src/extensions/tools/executors/android-investigation.test.ts",markers:["finished.map", "18_000"]},
 {path:"apps/examples/desktop-app/sidecar/release-gate-verifier.ts",markers:["Repeated checks require complete authoritative workflow provenance", "Repeated check lacks exact job/workflow binding", "Distinct required detection workflows missing"]},
 {path:"apps/examples/desktop-app/sidecar/ghidra-fixtures.ts",markers:["GHIDRA_ACCEPTANCE_ARCHITECTURES", "ARM:LE:32:", "AARCH64:LE:64:"]},
 {path:"apps/examples/desktop-app/sidecar/setup-center.ts",markers:["testAllGhidraIntegrations", "getGhidraReadiness", "profileIdentity", "languageId", "ghidra-receipt-${architecture}.json"]},
 {path:"apps/examples/desktop-app/webview/components/views/settings/setup-center-view.tsx",markers:["Ghidra acceptance architecture", "Test all Ghidra profiles", "cline.setup.ghidra-processor"]},
 {path:"sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts",markers:["readGhidraAcceptance", "ghidraOwnedAcceptance"]},
 {path:"apps/vscode/scripts/desktop-installed-acceptance.ts",markers:["installed-ghidra-three-owned-architectures-java-no-target-execution-passed", "ghidra-profile-readiness.json"]},
	{path:"apps/vscode/scripts/desktop-installed-acceptance.ts",markers:["export async function recordInstalledRpc<T>","recordInstalledRpc<T>(\n\t\t\tcommand,\n\t\t\tacceptanceAction,","return record(`rpc-${command}`, async () => send(await discover()))"]},
	{path:"apps/vscode/scripts/desktop-installed-acceptance.ts",markers:["[\"qiling\", \"x86_64\"],\n\t\t\t\t[\"qiling\", \"arm32\"],\n\t\t\t\t[\"qiling\", \"arm64\"],\n\t\t\t\t[\"unidbg\", \"arm32\"],\n\t\t\t\t[\"unidbg\", \"arm64\"],\n\t\t\t\t[\"rnidbg\", \"arm64\"]","planned.result.nextRequest.architecture !== architecture"]},
	{path:"workers/emulation/profiles.json",markers:['"qiling-linux-static-v2"','"architectures":["x86_64","arm32","arm64"]']},
	{path:"workers/emulation/qiling_runner.py",markers:["'arm32':{'write':4,'exit':1,'exit_group':248}","'arm64':{'write':64,'exit':93,'exit_group':94}","Qiling architecture differs from admitted ELF","if number not in calls.values()"]},
	{path:"workers/emulation/server.py",markers:["Owned startup fixtures must cover every advertised architecture","Startup fixture is not sealed","Owned startup stdout check failed"]},
	{path:"workers/emulation/runtime_inventory.py",markers:["for arch in PROFILES[engine]['architectures']","Every advertised architecture requires its owned startup fixture"]},
	{path:"sdk/packages/core/src/extensions/tools/emulation-schema.ts",markers:["EMULATION_PROFILE_ARCHITECTURES","supportsEmulationArchitecture"]},
	{path:"apps/examples/desktop-app/sidecar/emulation-client.ts",markers:["expectedArchitectures.some","new Set(m.architectures).size"]},
	{path:"workers/emulation/build-fixtures.sh",markers:["owned-linux-$arch","denied-linux-$arch","--target=\"$target\""]},

	{ path: "scripts/test-setup-ghidra.ts", markers: ["testGhidraIntegration(architecture)", "currentGhidraAcceptance(receipt, home, architecture)", "outside OS temp", "ghidra-receipt-${architecture}.json"] },
	{ path: ".github/workflows/build-custom-windows-installer.yml", markers: ["bun scripts/test-setup-ghidra.ts"] },
	{ path: "apps/examples/desktop-app/sidecar/setup-fixture-directory.ts", markers: ["createSetupFixtureDirectory", "realpath(tmpdir())", "cline-owned-${engine}-", "Setup fixture escaped"] },
	{ path: "apps/examples/desktop-app/sidecar/setup-center.ts", markers: ['createSetupFixtureDirectory("ida")', 'createSetupFixtureDirectory("ghidra")', "optionalFrameworks:", 'readiness: "not-established"'] },
	{ path: "apps/examples/desktop-app/sidecar/setup-fixture-directory.test.ts", markers: ["uses the real executor output policy", 'expect(result.outputScope).toBe("managed")'] },
	{ path: "apps/examples/desktop-app/sidecar/emulation-client.ts", markers: ["emulationConfigurationStatus", "Never project endpoint, key, token", 'return "configured-not-tested"'] },
	{ path: "apps/examples/desktop-app/sidecar/analysis-sandbox-client.ts", markers: ["analysisSandboxConfigurationStatus", "Does not contact or certify a Speakeasy worker"] },
	{ path: "apps/examples/desktop-app/webview/components/views/settings/setup-capability-directory.tsx", markers: ["Registered routes are not proof", "App-managed Install → Test → Use", "implemented in this build", "Readiness not established"] },
	{ path: "scripts/validate-advanced-build.mjs", markers: ["setup-fixture-directory.test.ts", "framework-configuration.test.ts", "setup-capability-directory.test.tsx"] },

 { path: "sdk/packages/core/src/services/session-artifacts.ts", markers: ["isOwnedArtifactPath", "removeSessionMessages", "no junction aliases"] },
	{
		path: "apps/examples/desktop-app/sidecar/session-cleanup.ts",
		markers: [
			"assertSessionCleanupId",
			"Session cleanup refuses links",
			"Stored messagesPath is NOT authority",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/session-data/discovery.ts",
		markers: ["Discovery is read-only"],
	},
	{
		path: "apps/examples/desktop-app/sidecar/attachments.ts",
		markers: ["Originals remain staged", "copyAttachmentUpload"],
	},
	{
		path: "sdk/packages/core/src/runtime/turn-queue/pending-prompt-service.ts",
		markers: ["submissionId", "Steering is text-only today"],
	},
	{
		path: "sdk/packages/llms/src/providers/ai-sdk.ts",
		markers: ["Image delivery blocked", "inputCapabilitiesStatus"],
	},
	{
		path: "apps/examples/desktop-app/sidecar/release-gate-verifier.ts",
		markers: ["current base/head PR merge", "merge_commit_sha", "baseCommit"],
	},
	{
		path: "apps/examples/desktop-app/sidecar/engineering-control-plane.ts",
		markers: [
			"CI checks unknown; merge readiness not established",
			"checksStatus",
		],
	},
 {path:"scripts/validate-advanced-build.mjs",markers:["probeValidationBun", "spawn(validationExecutable(step, bun.executable), step.args", 'supervisorRuntime: "node"', "timeoutMs: 20 * 60 * 1000"]},
 {path:"scripts/validate-advanced-build.test.mjs",markers:["isolated bounded probes", "without leaking child errors"]},
 {path:"sdk/packages/core/src/analysis/profile.ts",markers:['export const ANALYSIS_PROFILE = "cline-js-static/7";']},
 {path:"sdk/packages/core/src/analysis/contracts-profile.test.ts",markers:["the same runtime-neutral receipt profile", "malformed fuse evidence"]},
 {path:"scripts/validate-advanced-build.test.mjs",markers:["selfcheck>=0 && bootstrap>=0 && selfcheck<bootstrap", "verifyInstalledInvestigationCatalog(await readSkills(), false, installedSkillRoot)"]},
 {path:"sdk/packages/core/src/analysis/file-handle-chunks-compat.test.ts",markers:["without moving its cursor", "beyond Number.MAX_SAFE_INTEGER without coercion", "expect(this).toBe(owner)"]},
 {path:"sdk/packages/core/src/analysis/acquisition.ts",markers:["AcquisitionSchema", "Acquisition manifest digest mismatch", "Acquisition member/container binding mismatch", 'coverage: z.literal("partial")']},
 {path:"sdk/packages/core/src/analysis/worker.ts",markers:["buildAcquisitionReport", "archiveBytesRead", "Admission is atomic per parsed archive", "named.dev !== after.dev"]},
 {path:"apps/vscode/scripts/desktop-installed-acceptance.ts",markers:["installed-source-acquisition-hash-bound-saved-off-no-execution-passed", "Installed acquisition byte identity mismatch"]},
 {path:"sdk/packages/core/src/analysis/electron-fuses.ts",markers:["readElectronFuseImage", "resources.close()", 'status: "partial"', "electronFuseReportSchema.parse"]},
 {path:"sdk/packages/core/src/analysis/service.ts",markers:["!!input.electronFuses !== !!parsedResult.electronFuses", "Fuse receipt projection mismatch"]},
 {path:"sdk/packages/core/src/analysis/electron-fuses.test.ts",markers:["chunk-boundary sentinels", "fails closed when the owned child", "unknown wire versions"]},
 {path:"sdk/packages/core/src/analysis/semantic-engine/electron-fuses-parity.test.ts",markers:["CLINE_SEMANTIC_REFERENCE_ROOT", "universalFuseImage", "original.readElectronFuseImage"]},
 {path:"apps/vscode/scripts/desktop-installed-acceptance.ts",markers:["installed-electron-fuses-explicit-read-only-hash-bound-saved-off-passed", "Installed fuse inspection modified the original"]},

	{path:"apps/examples/desktop-app/sidecar/investigation-skills.ts",markers:["verifyInvestigationSkillPack", "resolveDisabledAgentPluginNames", "loaded.mcpServers.length", "targetExecuted: false", "installedPresent"]},
	{path:"apps/examples/desktop-app/sidecar/chat-session.ts",markers:["localInvestigationSkills", "agentPluginPaths: inspectInvestigationSkillPack(true).paths", 'binding.kind === "local"']},
	{path:"apps/examples/desktop-app/sidecar/commands.ts",markers:["bundledInvestigationSkills: bundled.pack", 'agentPluginPaths: inspectInvestigationSkillPack(ctx.activeEnvironmentId === "local").paths']},
	{path:"apps/examples/desktop-app/sidecar/index.ts",markers:["--cline-investigation-skills-selfcheck", "selfcheckInvestigationSkills"]},
	{path:"apps/examples/desktop-app/sidecar/investigation-skills.test.ts",markers:["before creating a profile, Hub or listener", "hard-linked instruction bytes", "does not use a clean development fallback"]},
	{path:"apps/examples/desktop-app/src-tauri/tauri.conf.json",markers:["investigation-skills/**/*"]},
	{path:"apps/examples/desktop-app/src-tauri/tauri.analysis-runtime.conf.json",markers:["investigation-skills/**/*"]},
	{path:"apps/vscode/scripts/desktop-installed-acceptance.ts",markers:["installed-bundled-investigation-skills-instruction-only-namespace-disable-passed", "installed-bundled-investigation-skills-disable-persisted-restart-passed", "verifyInstalledInvestigationCatalog"]},
	{
		path: "apps/vscode/scripts/desktop-installed-acceptance.ts",
		markers: [
			'await sourceWorkspace.getByRole("button", { name: "application-nodes", exact: true }).click()\n\t\tawait sourceWorkspace.getByLabel("Filter analysis evidence", { exact: true }).fill("ipc-channel")',
		],
	},
	{
		path: "scripts/prepare-ci-python.mjs",
		markers: [
			"cline-ci-python/v1",
			"CI_PYTHON_PHASE=entry",
			"timeout: 60_000",
			"fixtureDeadlineChanged: false",
			"CLINE_RE_PYTHON=${identity.executable}",
		],
	},
	{
		path: "scripts/test-secret-scan-fixtures.mjs",
		markers: [
			"token beside revision",
			"same hash outside revision",
			"different revision",
			"historical prose in new content",
			"real token beside current prose",
			"--gitleaks-ignore-path",
			"exception must not cover another file",
		],
	},
	{
		path: "scripts/summarize-semantic-tests.py",
		markers: [
			"Semantic regression failure",
			"JUnit report contains no test cases",
			"<!DOCTYPE",
			"problems[:15]",
		],
	},
	{
		path: ".gitleaks.toml",
		markers: [
			'id = "sourcegraph-access-token"',
			"[[rules.allowlists]]",
			'condition = "AND"',
			'regexTarget = "line"',
		],
	},
	{
		path: "sdk/packages/core/src/analysis/application-bindings.ts",
		markers: [
			"assertAdmittedApplicationManifest",
			"source inventory count",
			"duplicate inventory",
			"admitted source identities",
		],
	},
	{
		path: "sdk/packages/core/src/analysis/semantic-engine/application.ts",
		markers: [
			"cline-application/1",
			"Admitted source set only",
			"Application source hash or byte count mismatch",
			"...full.coverage",
		],
	},
	{
		path: "sdk/packages/core/src/analysis/application-query.ts",
		markers: [
			"compareJavaScriptApplicationVersions",
			"compareJavaScriptExportShapes",
			"compareSourceToBundle",
			"providerCalls: 0",
			"verifiedBehavior: false",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/application-evidence-workflows.tsx",
		markers: [
			"Saved application workflows",
			"Run saved application query",
			"Next saved application page",
		],
	},
	{
		path: "docs/rea-migration/capabilities.json",
		markers: [
			"cline-rea-capability-inventory/1",
			"partial-source-port",
			"not-source-ported-or-audited",
		],
	},
	{
		path: "sdk/packages/core/src/analysis/semantic-engine/engine.ts",
		markers: [
			"cline-semantic/1",
			"file-local-semantics",
			"Semantic source hash mismatch",
		],
	},
	{
		path: "sdk/packages/core/src/analysis/evidence-query.ts",
		markers: [
			"semantic-trace",
			"displayOmitted",
			"Semantic trace request exceeds byte budget",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/release-gate-policy.ts",
		markers: [
			"semantic-source-validation / Semantic source parity (ubuntu-latest)",
			"semantic-source-validation / Semantic source parity (windows-latest)",
			".github/workflows/semantic-source-validation.yml",
		],
	},
	{
		path: "scripts/verify-semantic-port.mjs",
		markers: ["Source digest mismatch", "Missing attribution"],
	},
	{
		path: ".github/workflows/build-custom-windows-installer.yml",
		markers: [
			"semantic-source-validation",
			"needs: [ghidra-owned-fixtures, android-toolchain-preflight, semantic-source-validation]",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/advanced-candidates.ts",
		markers: [
			"matching preview_sha256",
			"No-op byte patch",
			"bounded-structure-only",
			"reconstructed-constant-Int32-body",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/candidate-files.ts",
		markers: [
			"fs.link(temp, output)",
			"Source changed before publication",
			"cleanupWarning",
			"no overwrite permitted",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/candidate-batch.ts",
		markers: [
			"Batch outputs may not replace inputs/manifest",
			"batch_preview_sha256",
			"NOT an all-or-nothing transaction",
			"manifestHash",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/evidence-trace.ts",
		markers: [
			"declared-data-flow-edges-only",
			"observedExecution: false",
			"untrusted-imported-report",
			"Trace seed/coverage exceeds output byte budget",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/model-investigation.ts",
		markers: [
			"capture_network_metadata",
			"independentRecordingConsent: true",
			"analysis_workflow_hybrid_prepare",
		],
	},
	{
		path: "apps/vscode/scripts/desktop-installed-acceptance.ts",
		markers: [
			"installed-preview-approved-binary-ast-batch-originals-preserved",
			"installed-multiedit-audit-source-sink-originals-preserved",
			"installed-integrated-source-hypothesis-notebook-coverage-passed",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/analysis-commands.ts",
		markers: [
			"ANALYSIS_COMMAND_ALIASES",
			"isAnalysisWriteOperation",
			"planInvestigation",
			"notebook_run",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/smali-patch.ts",
		markers: [
			"preview_sha256",
			"fs.link(temporary, output)",
			"expected_sha256",
			"MAX_SOURCE_BYTES",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/advanced-command-workspace.tsx",
		markers: [
			"Advanced AI commands",
			"Prepare advanced command for review",
			"Not available in this command pack",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/lib/session-reasoning.ts",
		markers: [
			"cline.reasoning.v1:",
			"writeSessionReasoning",
			"readDraftReasoning",
			"normalizeProviderId",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/hooks/use-chat-session.ts",
		markers: [
			"hydrationPendingRef",
			"updateReasoning",
			"boundConfig.analysisMode",
			"readSessionReasoning",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/analysis-mode-control.tsx",
		markers: [
			"onDraftModeChange",
			"Runtime mode does not grant execution permission",
		],
	},
	{
		path: "apps/vscode/scripts/desktop-installed-acceptance.ts",
		markers: ["installed-fresh-draft-analysis-visible-before-first-task"],
	},

	{
		path: "scripts/pinned-android-download.mjs",
		markers: ["Pinned digest mismatch", "attempt <= 4", "404, 408, 429"],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/android-toolchain.ts",
		markers: [
			"verifyAndroidToolchain",
			"JAVA_TOOL_OPTIONS",
			"Untracked Android pack resource",
			"ClineAndroidLauncher",
			"PROCESSOR_ARCHITEW6432",
			"Explicit reads avoid Bun/Windows",
			"handle.close()",
			"runBundledAndroidNative",
			"constants.COPYFILE_EXCL",
		],
	},
	{
		path: "scripts/package-android-toolchain.mjs",
		markers: [
			"downloadPinnedAndroidAsset",
			"tools.lock.json",
			"ClineAndroidLauncher.java",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/android-toolchain-workspace.tsx",
		markers: [
			"Prepare exact Android step for review",
			"confirm_test_signing",
			"No automatic install",
		],
	},
	{
		path: ".github/workflows/build-custom-windows-installer.yml",
		markers: ["test-android-toolchain.ts", "package-android-toolchain.mjs"],
	},
	{
		path: "apps/examples/desktop-app/sidecar/binary-triage-worker.ts",
		markers: ["r2pipe.open([target]", "one literal path"],
	},
	{
		path: "scripts/test-embedded-binary-triage.ps1",
		markers: [
			"76f238f606250c87c6beac75dccd35ee99070a13490555936abb6cb64ecce3d0",
			"python313._pth",
			"test-binary-triage-pack.ts",
			"cline triage pack with spaces",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/settings/binary-triage-readiness.tsx",
		markers: ["ownedTriageDiagnostic", "no operation is automatically retried"],
	},
	{
		path: "scripts/install-pinned-gitleaks.ps1",
		markers: ["SHA256", "version self-check failed", "$attempt -le 3"],
	},
	{
		path: "scripts/write-dependency-inventory.ts",
		markers: [
			"CycloneDX",
			"not complete installed distribution",
			"bun-lock-sha256",
		],
	},
    {
        path:"apps/examples/desktop-app/sidecar/model-binary-triage.ts",
        markers:["BinaryTriageCallSchema.parse", "independentStaticAnalysisApproval", "expected: approval", "triageEvidencePage"],
    },
    {
        path:"sdk/packages/core/src/extensions/tools/binary-triage-schema.ts",
        markers:["BinaryTriageCallSchema", "get_function_disassembly", "receipt_id"],
    },
    {
        path:"apps/vscode/scripts/owned-triage-model.ts",
        markers:["OWNED_TRIAGE_SEQUENCE", "independentStaticAnalysisApproval", "independent.size !== 7"],
    },
	{
		path: "apps/examples/desktop-app/sidecar/binary-triage.ts",
		markers: [
			"verifyTriagePack",
			"termination-unconfirmed",
			"no automatic replay",
			"targetSha256",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/guided-investigation.tsx",
		markers: [
			"Start with a question",
			"binary_triage_run",
			"Export selected evidence report",
		],
	},
	{
		path: "scripts/package-binary-triage.ps1",
		markers: [
			"SHA256",
			"test-binary-triage-pack.ts",
			"License digest mismatch",
		],
	},
	{
		path: "sdk/packages/core/src/analysis/recovery.ts",
		markers: ["ownershipBinding", "originalInstanceGone", "recovery blocked"],
	},
	{
		path: "sdk/packages/core/src/analysis/inspector.ts",
		markers: [
			"assertInspectorOwner",
			"Debugger.getScriptSource",
			"exact-loaded-source-byte-match",
		],
	},
	{
		path: "sdk/packages/core/src/analysis/contracts.ts",
		markers: [
			'import { ANALYSIS_PROFILE } from "./profile";',
			'export { ANALYSIS_PROFILE } from "./profile";',
			"profile: z.literal(ANALYSIS_PROFILE)",
			"shipped-artifact",
			"termination-unconfirmed",
		],
	},
	{
		path: "sdk/packages/core/src/analysis/service.ts",
		markers: [
			"--cline-analysis-worker",
			"SIGKILL",
			"reservation retained",
			"do not replay",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/analysis-mode-control.tsx",
		markers: [
			"Session Analysis mode",
			"Runtime mode does not grant",
			"first_party_analysis_mode",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/analysis-parser-notices.ts",
		markers: ["Apache License", "Microsoft"],
	},
	{
		path: "apps/examples/desktop-app/webview/components/ui/preview-scroll-region.tsx",
		markers: [
			"min-h-0 flex-1 overflow-auto",
			"tabIndex={0}",
			"keyboard scrolling",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/artifact-context-menu.tsx",
		markers: [
			"artifact-preview-scroll",
			"flex max-h-[85vh] flex-col",
			"PreviewScrollRegion",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/messages/code-change-preview.tsx",
		markers: [
			"recorded-code-scroll",
			"Before change",
			"not the full or current file",
			"Recorded tool data only",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/smali-search.ts",
		markers: [
			"activeScans",
			"bytesRead",
			"output_limit",
			"byte_limit",
			"yieldTurn",
			"no automatic retry",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/process-session-manager.ts",
		markers: ["scheduleDeadline", "deadlineAtMs", "termination unconfirmed"],
	},
	{
		path: "apps/vscode/scripts/desktop-installed-acceptance.ts",
		markers: [
			"installed-guided-entry-navigation-passed",
			"owned-markdown-preview-wheel-keyboard-scroll-passed",
			"artifact-preview-scroll",
		],
	},
	{
		path: "apps/cli/src/tests/headless/headless.test.ts",
		markers: [
			'CLINE_VCR: "playback"',
			'CLINE_VCR_FILTER: ""',
			"headless-unauthorized.json",
			"expectExitCode(terminal, EXIT_CODE_FAIL)",
		],
	},
	{
		path: "apps/cli/src/tests/fixtures/headless-unauthorized.json",
		markers: [
			'"status": 401',
			'"message": "Unauthorized"',
			'"contentType": "application/json"',
		],
	},
	{
		path: "sdk/packages/core/src/hub/discovery/index.ts",
		markers: [
			"hubLockQueues",
			"reclaimDeadHubLock",
			"current?.nonce === ownership.nonce",
			"Unknown/permission errors are not evidence of death",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/ida-analysis-workspace.ts",
		markers: [
			"idaDatabaseKey",
			"prepareIdaAttempt",
			"publishIdaDatabase",
			"COPYFILE_EXCL",
			"cline-ida-database.json",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts",
		markers: [
			"ensureIdaAnalysisScript",
			"workspaceDirectory: workspaceDir",
			"scriptPhasesExpected:",
			"database-saving",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/setup-jobs.ts",
		markers: [
			"startSetupJob",
			"setup-admission.json",
			"interrupted",
			"redactSensitiveText",
			"files.slice(32)",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/settings/setup-center-view.tsx",
		markers: [
			"setup_center_job_status",
			"Save IDA installation",
			"Test IDA integration (optional)",
			"cline.setup.ida-processor",
			"Setup operation status",
		],
	},
	{
		path: "docs/IDA_AND_SETUP_JOB_RELIABILITY.md",
		markers: ["Operator-confirmed", "does not consult", "eleven"],
	},
	{
		path: "sdk/packages/core/src/hub/client/index.ts",
		markers: [
			"onStartupError",
			"Managed Hub startup failed:",
			"no task command was replayed",
		],
	},
	{
		path: "sdk/packages/core/src/hub/daemon/index.ts",
		markers: [
			'trace("spawn-requested"',
			'trace("spawn-returned"',
			'trace("child-exit"',
		],
	},
	{
		path: "apps/vscode/scripts/desktop-installed-acceptance.ts",
		markers: [
			"owned-hub-daemon-tail.log",
			"hubStartupDiagnostic = tail.slice(-1600)",
		],
	},
	{
		path: "scripts/report-installed-acceptance.mjs",
		markers: ["owned Hub startup tail:", "hubStartupDiagnostic.slice(-1600)"],
	},
	{
		path: "sdk/packages/core/src/hub/client/index.ts",
		markers: ["rememberRecoverableLocalHubUrl(ensured.url, ensured.authToken)"],
	},
	{
		path: "sdk/packages/core/src/hub/client/index.test.ts",
		markers: [
			"cline-hub-auth.replacement-token",
			"ensureDetachedHubServerMock).toHaveBeenCalledTimes(2)",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/command-evidence.ts",
		markers: [
			"CommandExecutionReceipt",
			"inspectCommandArtifacts",
			"non-linked regular file",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/definitions.ts",
		markers: [
			"expected_output_files",
			"command_execution_receipt",
			"side-effecting commands automatically",
		],
	},
	{
		path: "scripts/benchmark-command-execution.mjs",
		markers: [
			"owned-shared-executor-ready/v2",
			"environmentId",
			"not installed UI startup",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/setup-center.ts",
		markers: ["installed_not_tested", "stale", "lastCheckedAt"],
	},
	{
		path: "apps/examples/desktop-app/sidecar/engineering-control-plane.ts",
		markers: ["manualModelId", "no silent fallback", "Model routing mode"],
	},
	{
		path: "sdk/packages/core/src/hub/daemon/index.ts",
		markers: [
			"restartCompatible?: boolean",
			"options.restartCompatible === true",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/settings/setup-center-view.tsx",
		markers: ["Apply setup to idle backend"],
	},
	{
		path: "apps/examples/desktop-app/sidecar/setup-center.ts",
		markers: [
			"FULL_ENGINE_IDS",
			"fullReceiptPassed",
			"executionVerified === true",
			"-----BEGIN PUBLIC KEY-----",
			"deviceSerialSha256",
			"testLicensedIda",
			"owned-arm64-elf.json",
			"currentIdaAcceptance",
			"CLINE_IDA_SELECTED_HOME",
			"executableSha256",
			"platformToolsNotices",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/settings/setup-center-view.tsx",
		markers: [
			"Install all supported components",
			"acceptedPlatformToolsLicense: true",
			"Roll back to core",
			"Package presence alone is not execution proof",
		],
	},
	{
		path: "sdk/packages/core/scripts/full-analysis-readiness.test.py",
		markers: ["executionVerified", "angr", "full"],
	},
	{
		path: "scripts/package-android-platform-tools.ps1",
		markers: [
			"45f4d63113e895ebde0c90f194099a4676b6ac653bd28d54314a9e022bbc1a99",
			"adb.exe",
			"NOTICE.txt",
		],
	},

	{
		path: "apps/examples/desktop-app/webview/lib/run-error.ts",
		markers: ["HUB_RECOVERY_GUIDANCE", "normalizedFailureDetail(description)"],
	},
	{
		path: "scripts/package-analysis-runtime.ps1",
		markers: [
			"76f238f606250c87c6beac75dccd35ee99070a13490555936abb6cb64ecce3d0",
			"python313._pth",
			"Bundled execution corpus failed",
			"Freeze the shipped inventory",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/bundled-analysis-runtime.ts",
		markers: [
			"verifyRuntime",
			"repairBundledAnalysisRuntime",
			"manifest changed",
			"coding remains available",
			"preferBundled",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/resource-governor.ts",
		markers: [
			"class ResourceGovernor",
			"Resource admission timed out",
			"hardMemoryEnforcement: false",
		],
	},
	{
		path: "docs/INTEGRATED_ENHANCEMENT_DELIVERY.md",
		markers: [
			"baseline-required",
			"Machine-wide",
			"Downloads and activation remain disabled",
		],
	},
	{
		path: "apps/vscode/scripts/desktop-installed-acceptance.ts",
		markers: [
			"waitForInstalledBackendEndpoint",
			"verifyRecoveredHubSession",
			"get_desktop_settings",
			"hub-restart-saved-session-reattached-without-prompt-replay",
			"bundled",
		],
	},
	{
		path: "apps/vscode/src/test/e2e/utils/build.mjs",
		markers: [
			'require.resolve("playwright/package.json")',
			"cancelSignal: signal",
			"clearTimeout(timer)",
			"pending:",
		],
	},
	{
		path: "scripts/e2e-dependency-install.test.mjs",
		markers: [
			"requires both installations",
			"cancels the child signal",
			"cannot become successful acceptance",
		],
	},
	{
		path: "apps/vscode/scripts/desktop-installed-acceptance.ts",
		markers: [
			"verifyRestartInstructions",
			"trial: true",
			"Installed backend setting did not survive restart",
			"Date.parse(p.createdAt) >= Date.parse(parent.createdAt)",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/windows-job-launcher.test.ts",
		markers: ["runNativeFixture", "timeout: 60000", "killed: failure.killed"],
	},
	{
		path: "sdk/packages/core/src/hub/daemon/__fixtures__/singleton-daemon.ts",
		markers: [
			"listSessions: async () => []",
			"sessionSearchOptions:",
			"startup failed:",
		],
	},
	{
		path: "apps/examples/desktop-app/src-tauri/src/installed_webview_launch.rs",
		markers: [
			'enabled != Some("1")',
			"--remote-debugging-address=127.0.0.1",
			"data_directory.is_absolute()",
			"normal_launch_does_not_apply_debugging_options",
		],
	},
	{
		path: "apps/examples/desktop-app/src-tauri/src/main.rs",
		markers: [
			'std::env::var("CLINE_INSTALLED_ACCEPTANCE")',
			"window.additional_browser_args = Some",
			"window.data_directory = Some",
			".build(context)",
		],
	},
	{
		path: ".github/workflows/build-custom-windows-installer.yml",
		markers: [
			"Validate opt-in native WebView launch settings",
			"rustc --edition=2021 --test",
			"Native WebView launch option fixtures failed",
		],
	},
	{
		path: "scripts/validate-advanced-build.mjs",
		markers: [
			"Test real Hub singleton crash recovery",
			"Test native Node installed process harness",
			"Test native Bun SQLite memory startup",
			"Test SQLite database path boundaries",
		],
	},
	{
		path: "sdk/packages/shared/src/db/sqlite-db.ts",
		markers: ['filePath !== ":memory:"', "dirname(resolve(filePath))"],
	},
	{
		path: "sdk/packages/shared/src/db/sqlite-db-paths.test.ts",
		markers: [
			"without any mkdir operation",
			"absolute parent",
			"propagates a real disk-directory failure",
		],
	},
	{
		path: "sdk/packages/shared/scripts/sqlite-memory.bun.test.mjs",
		markers: ["native Bun SQLite", 'loadSqliteDb(":memory:")'],
	},
	{
		path: "apps/vscode/scripts/desktop-installed-acceptance.ts",
		markers: [
			"startAcceptanceProcess",
			"debuggingArgumentObserved",
			"descendantProbeExitCode",
			"redactedLaunchText",
			"shell: false",
		],
	},
	{
		path: "scripts/installed-node-process.test.mjs",
		markers: [
			"exact per-process WebView2 environment",
			"launch failure is observed",
			"output retention is bounded",
		],
	},
	{
		path: "scripts/install-pinned-windows-tool.ps1",
		markers: [
			"$attempt -le 3",
			'"--version=$Version"',
			"failed after 3 attempts",
			"$PSNativeCommandUseErrorActionPreference = $false",
		],
	},
	{
		path: "scripts/install-pinned-windows-tool.test.ps1",
		markers: [
			"ExpectedFailure $true",
			"ExpectedDelays @(5, 10)",
			"no installs",
		],
	},
	{
		path: ".github/workflows/build-custom-windows-installer.yml",
		markers: [
			'"CLINE_TEST_INSTALLED_APP=$($appExe.FullName)" >> $env:GITHUB_ENV',
			"IsPathFullyQualified",
			"Test-Path -LiteralPath $path -PathType Leaf",
			"scripts/install-pinned-windows-tool.test.ps1",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/advanced-analysis-worker.ts",
		markers: [
			"def apply_transform_steps(data,steps,max_bytes=None):",
			"if max_bytes is None: max_bytes=MAX_BYTES",
		],
	},
	{
		path: "sdk/packages/core/scripts/advanced-analysis-worker.test.py",
		markers: [
			"--engine-profile",
			"windows-portable",
			"owned-native-elf.json",
			"test_expansion_exact_and_explicit_budgets",
			"Missing optional engine: triton",
			"Missing optional engine: qbindiff",
		],
	},
	{
		path: "scripts/validate-advanced-build.mjs",
		markers: [
			"engineCorpusArgs",
			'platform === "win32" ? "windows-portable" : "full"',
			"engineProfile:",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/android-investigation-index.ts",
		markers: [
			"diagnostics: _diagnostics",
			"digest(indexedResult)",
			"result: indexedResult",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/android-investigation-index.test.ts",
		markers: [
			"keeps host execution diagnostics outside immutable evidence and identity",
			'not.toHaveProperty("diagnostics")',
		],
	},
	{
		path: ".github/workflows/ext-jb-test-integration.yml",
		markers: [
			"github.repository == 'cline/cline'",
			"vars.CLINE_JETBRAINS_APP_ID != ''",
			"curl --fail-with-body",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/advanced-analysis.ts",
		markers: [
			"createStreamingSecretRedactor",
			"retainWorkerDiagnostics",
			'"abnormal-exit"',
			'"invalid-output"',
			"terminationConfirmed",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/analysis-worker-diagnostics.ts",
		markers: ["slice(0, -32)", "mode: 0o600", "never arguments"],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/ida-job-diagnostics.ts",
		markers: [
			"runObservedIda",
			"phase-deadline-exceeded",
			"phaseTimeoutMs",
			"DEFAULT_IDA_PHASE_TIMEOUT_MS",
			"formatIdaProgress",
			"termination-unconfirmed",
			"No script phase observed",
			"auto-analysis-waiting",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/analysis-project-lease.ts",
		markers: ["retainLease", "never automatically stolen"],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/settings/analysis-environment-view.tsx",
		markers: [
			"Check analysis readiness",
			"Refresh IDA jobs",
			"Open Setup Center",
			"Live read-only IDA job refresh",
			"Configuration / acceptance required",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/analysis-environment.ts",
		markers: ["checkAnalysisEnvironment", "active = undefined"],
	},
	{
		path: "scripts/setup-analysis-environment.ps1",
		markers: ["if (-not $Apply)", "CLINE_RE_PYTHON was not changed", "-I -c"],
	},
	{
		path: "apps/vscode/scripts/desktop-installed-acceptance.ts",
		markers: [
			"CLINE_TEST_INSTALLED_APP",
			"get_desktop_backend_endpoint",
			"restart-setting-and-session-persistence-passed",
			"owned-offline-fixture",
		],
	},
	{
		path: ".github/workflows/build-custom-windows-installer.yml",
		markers: [
			"pull_request:",
			"Restore exact Windows engine wheel cache",
			"Select unsigned private installer",
			"validate:advanced --engines",
			"steps.ui_acceptance.outcome == 'success'",
		],
	},
	{
		path: ".github/workflows/custom-desktop-validation.yml",
		markers: [
			"Consolidated blocking regression gates",
			"run: bun run validate:advanced",
		],
	},
	{
		path: "docs/ANALYSIS_RUNTIME_HARDENING.md",
		markers: [
			"not progress evidence",
			"synthetic merge",
			"does not silently alter administrator branch protection",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/chat-session.ts",
		markers: ["return prompt + projectOutputInstructions"],
	},
	{
		path: "apps/examples/desktop-app/sidecar/commands.ts",
		markers: [
			"get_project_output_location",
			"open_project_output_folder",
			"ensureProjectOutputDirectories(location)",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/app/page.tsx",
		markers: ["ProjectOutputBar", "config.workspaceRoot || config.cwd"],
	},
	{
		path: "apps/examples/desktop-app/sidecar/project-output.ts",
		markers: [
			"WINDOWS_PROJECT_OUTPUT_ROOT",
			String.raw`C:\\Cline-Outputs`,
			"do not silently fall back",
			"links or junctions",
			"bigint: true",
			"parent.ino !== canonicalParent.ino",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/project-output-bar.tsx",
		markers: [
			"get_project_output_location",
			"open_project_output_folder",
			"Open outputs",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/hooks/chat-session/helpers.ts",
		markers: [
			"Assistant narration and completed tool calls are not turn-completion",
			"mapHistoryStatusToChatStatus(fallback)",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/hooks/use-chat-session.ts",
		markers: [
			"hydrationOwnsStatus",
			"hydrationStatusRevision",
			"hydrationTurnEpoch",
		],
	},
	{
		path: "docs/SESSION_NAVIGATION_STATUS.md",
		markers: ["not a completion receipt", "does not replay"],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/native-project-candidates.ts",
		markers: [
			"runNativeProjectCandidate",
			"Persisted candidate read-back mismatch",
			"Candidate head changed since review",
			"pointerOnly: true",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/native-project-edit-scripts.ts",
		markers: [
			"currentProgram.endTransaction(tx,commit)",
			"actual.equals_to(tif)",
			"save_database(DATABASE,0)",
		],
	},
	{
		path: "docs/NATIVE_PROJECT_CANDIDATES.md",
		markers: [
			"no native undo guarantee",
			"separate engine process",
			"not signatures",
			"physical KSUN-device",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/managed-engine-pool.ts",
		markers: [
			"class ManagedEnginePool",
			"Worker termination unconfirmed; project lease retained",
			"Managed engine request binding mismatch",
			"Managed engine pool capacity reached",
			"guardManagedBatchArguments",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/managed-engine-scripts.ts",
		markers: [
			"MANAGED_GHIDRA_SCRIPT",
			"managedIdaScript",
			"Ambiguous exact function name",
			"finally: idc.qexit(0)",
		],
	},
	{
		path: "docs/MANAGED_ENGINE_WORKERS.md",
		markers: [
			"90-second idle",
			"not an OS sandbox",
			"Transactional annotation/prototype editing is not implemented",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/android-debug-reports.ts",
		markers: [
			"collectAndroidDebugReports",
			"Separate root-read acknowledgement",
			"no root fallback or retry",
			"unattributed-not-retained",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/runtime-jni-evidence.ts",
		markers: [
			"verifyAndroidObservationReceipt",
			"Completed approved Android capture plan required",
			"ambiguous-observations",
			"executeAutomatically: false",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/runtime-jni-workspace.tsx",
		markers: [
			"query_runtime_jni",
			"Refresh completed JNI captures",
			"Verify and query signed registrations",
		],
	},
	{
		path: "docs/DEVICE_DEBUG_JNI_EVIDENCE.md",
		markers: [
			"Root is off by default",
			"existing signed",
			"not hardware attestation",
			"Persistent IDA/Ghidra",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/windows-job-launcher.test.ts",
		markers: [
			"processLimitProbe",
			"const permitted = await run(2)",
			"const blocked = await run(1)",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/execution-control-service.ts",
		markers: [
			"ExecutionControlService",
			"Execution receipt integrity mismatch",
			"Termination requested but exit was not confirmed",
			"Reconciliation is read-only",
		],
	},
	{
		path: "sdk/packages/core/src/runtime/windows-job-launcher.ts",
		markers: [
			"CreateProcess suspended",
			"AssignProcessToJobObject",
			"no silent hard-limit fallback",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/execution-workspace.tsx",
		markers: [
			"Prepare exact task",
			"Approve and start once",
			"Reconcile without replay",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/analysis-project-lease.ts",
		markers: [
			"withProjectLease",
			"Stale leases are never automatically stolen",
		],
	},
	{
		path: "docs/EXECUTION_EVIDENCE_LAB.md",
		markers: [
			"uncertain",
			"not a security boundary",
			"No physical KSUN device",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/apk-incident-service.ts",
		markers: [
			"class ApkIncidentService",
			"No new matching failure observed",
			"candidate-installed",
			"controlUnavailable",
			"pull_apk_bounded",
			"const base = await realpath(cacheRoot)",
			"Diagnostic incident directory link not permitted",
			"if (path !== expected)",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/apk-incident-service.test.ts",
		markers: [
			"rejects a diagnostic incident directory junction even when report bytes match",
			"rejects modified and oversized private diagnostic reports",
			'symlink(moved, directory, "junction")',
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/incident-correlation.ts",
		markers: [
			"module SHA-256/ABI/build-ID mismatch",
			"candidate-match",
			"symbol-range-match",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/incident-artifacts.ts",
		markers: [
			"Archive changed since inspection",
			"Archive member integrity mismatch",
			"blocked-archive",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/apk-incident-workspace.tsx",
		markers: [
			"Approve and start once",
			"Prepare separately approved rollback",
			"prepare_apk_incident",
		],
	},
	{
		path: "docs/APK_INCIDENT_WORKFLOW.md",
		markers: [
			"No physical KSUN device",
			"fixed",
			"explicit bounded member preview",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/lib/artifact-workspace.tsx",
		markers: [
			"ArtifactWorkspaceProvider",
			"ArtifactWorkspaceContext.Provider",
			"useArtifactWorkspace",
			"useMemo",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/ui/markdown.tsx",
		markers: [
			"useArtifactWorkspace()",
			"workspace.cwd",
			"workspace.environmentId",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/chat-messages.tsx",
		markers: [
			"<ArtifactWorkspaceProvider",
			"cwd={props.cwd}",
			"environmentId={props.environmentId",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/artifact-context-menu.tsx",
		markers: ["suppliedCwd", "suppliedEnvironmentId", "useArtifactWorkspace()"],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/chat-messages.test.tsx",
		markers: [
			"transcript artifact workspace context",
			"right-click %s",
			"unchanged",
			"originating SSH environment",
		],
	},

	{
		path: "apps/examples/desktop-app/sidecar/analysis-task-orchestrator.ts",
		markers: [
			"private readonly consuming",
			"this.prune(this.maxPlans - 1)",
			"finish or cancel pending work first",
			"Hashing yields to cancellation",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/analysis-task-orchestrator.test.ts",
		markers: [
			"exactly once under concurrent requests",
			"does not resurrect a cancelled approval",
			"retains running task control",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/android-runtime-client.ts",
		markers: [
			"prepareCaptureDirectory",
			"regular managed ignore-all file",
			"health.manifest.maxArtifactBytes",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/android-runtime-client.test.ts",
		markers: ["capture output privacy preflight", "signed worker upload limit"],
	},
	{
		path: "workers/android-capture/server.py",
		markers: [
			"def build_result",
			"Capture/result validation failed",
			"Persist a small, signed terminal failure",
		],
	},
	{
		path: "workers/android-capture/server.test.py",
		markers: [
			"test_invalid_collector_observations_become_terminal_signed_failures",
			"Invalid collector must not replay",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/process-session-manager.test.ts",
		markers: ["preserves UTF-8 and exact omitted-byte accounting"],
	},

	{
		path: "sdk/packages/core/src/extensions/tools/executors/supervised-process.test.ts",
		markers: [
			"tool with spaces.exe",
			"fs.copyFile(process.execPath",
			"fixture.args",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/team/writer-worktree.test.ts",
		markers: ["sourceRepo: realpathSync.native(repo)"],
	},
	{
		path: "scripts/validate-advanced-build.mjs",
		markers: [
			"supervised-process.test.ts",
			"writer-worktree.test.ts",
			"formatValidationHeartbeat",
			"formatValidationNotice",
			"recordValidationProgress",
			"progress.jsonl",
			"clearInterval(heartbeat)",
		],
	},
	{
		path: "apps/examples/desktop-app/vitest.config.mts",
		markers: [
			'maxWorkers: process.platform === "win32" && process.env.CI ? 2 : undefined',
		],
	},

	{
		path: "workers/android-capture/capture_support.py",
		markers: [
			"physical_preflight",
			"Root probe denied",
			"uid0-reported",
			"attestation",
		],
	},
	{
		path: "workers/android-capture/capture_support.py",
        markers: ["def instrumentation_preflight", "device.enumerate_processes()", "device.query_system_parameters()", "serverVersion"],
    },
    {
        path: "workers/android-capture/capture.py",
		markers: [
			"Refusing to replace an existing app",
			"support.instrumentation_preflight",
			"support.physical_preflight",
			"'exec-out','su','-c'",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/android-runtime-client.ts",
		markers: [
			"device_serial_sha256",
			"Physical device changed",
			"Physical device observation differs",
		],
	},

	{
		path: "workers/android-capture/capture_support.py",
		markers: [
			"authorized_module_path",
			"MAX_MODULE=2*1024*1024",
			"captured-disk-file-not-loaded-memory-proof",
			"len(attempted)>=4",
		],
	},
	{
		path: "workers/android-capture/server.py",
		markers: [
			"sweep_retention",
			"PRAGMA secure_delete=ON",
			"def do_DELETE",
			"physicalErasure",
			"confirmPlaintextRemoval",
		],
	},
	{
		path: "workers/android-capture/setup-controller.py",
		markers: [
			"ALREADY isolated Linux controller",
			"--apply",
			"os.O_EXCL",
			"No server, VM or target was started",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/android-runtime-client.ts",
		markers: [
			"capture_native",
			"without capture consent",
			"observation session",
			"android-native-capture",
		],
	},
	{
		path: ".github/workflows/build-custom-windows-installer.yml",
		markers: [
			"capture_support.test.py",
			"setup-controller.test.py",
			"not VM provisioning evidence",
		],
	},

	{
		path: "workers/android-capture/server.py",
		markers: [
			"@contextmanager",
			"with connection:yield connection",
			"finally:connection.close()",
		],
	},
	{
		path: "workers/android-capture/server.test.py",
		markers: [
			"test_database_connections_close_after_success",
			"test_database_connections_close_and_rollback_after_failure",
		],
	},
	{
		path: "sdk/packages/core/src/hub/daemon/shutdown.e2e.test.ts",
		markers: [
			"probeBunRuntimeVersion",
			"daemon.runtimeVersion",
			"forced exit:",
			"toBeLessThan(5_000)",
		],
	},
	{
		path: "scripts/validate-advanced-build.mjs",
		markers: [
			"Test real Hub shutdown runtime identity",
			"vitest.e2e.config.ts",
		],
	},

	{
		path: "sdk/packages/core/src/extensions/tools/executors/process-session-manager.ts",
		markers: ["ConPTY can deliver trailing data", "setTimeout(resolve, 250)"],
	},

	{
		path: "apps/examples/desktop-app/sidecar/android-runtime-client.ts",
		markers: [
			"verifyAndroidCapture",
			"receipt.json",
			"Worker capability changed before upload",
			"Capture directory must not contain symlinks",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/analysis-investigation-store.ts",
		markers: [
			"BEGIN IMMEDIATE",
			"Investigation changed; reload before writing",
			"metadataCoverage",
			"equivalent-under-expression-model-only",
			"forked-with-inherited-evidence",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/investigation-workspace.tsx",
		markers: [
			"Fork without replay",
			"correlateEvidence",
			"ambiguous-static-descriptor-matches",
			"unresolved-module-hash",
		],
	},
	{
		path: "workers/android-capture/server.py",
		markers: [
			"Nonce identity conflict",
			"expired",
			"bounded_collect",
			"get_all('Authorization'",
			"operator-enforced-disposable-android-and-denied-egress",
		],
	},
	{
		path: "workers/android-capture/hooks.js",
		markers: ["RegisterNatives", "InMemoryDexClassLoader", "rpc.exports"],
	},
	{
		path: "workers/android-capture/README.md",
		markers: [
			"NOT hardware attestation",
			"GET-only",
			"No such live-device result",
		],
	},
	{
		path: "docs/ADVANCED_INVESTIGATION_INTEGRATION.md",
		markers: [
			"No original binary is rewritten",
			"Exact-head",
			"not a token-refresh implementation",
		],
	},
	{
		path: "scripts/validate-advanced-build.mjs",
		markers: [
			"analysis-investigation-store.test.ts",
			"android-runtime-client.test.ts",
			"investigation-workspace.test.tsx",
		],
	},
	{
		path: ".github/workflows/build-custom-windows-installer.yml",
		markers: [
			"server.test.py",
			"Build pinned Android instrumentation bundle",
			"bun install --frozen-lockfile",
		],
	},

	{
		path: "sdk/packages/core/package.json",
		markers: [
			"bun tsc -p tsconfig.smoke.json --noEmit && bun tsc -p tsconfig.bun-smoke.json --noEmit",
		],
	},

	{ path: "package.json", markers: ["bun --sequential -F '*' typecheck"] },
	{
		path: "sdk/packages/core/tsconfig.bun-smoke.json",
		markers: ['"types": ["node", "bun"]'],
	},
	{
		path: ".github/workflows/sdk-test.yml",
		markers: [
			"bun-version: ${{ steps.toolchain.outputs.version }}",
			"bun install --frozen-lockfile",
			"bun run types",
			"run: bun run lint",
			"scripts/prepare-ci-python*.mjs",
			"node scripts/prepare-ci-python.mjs",
			"node --test scripts/prepare-ci-python.test.mjs",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/settings/functions-view.tsx",
		markers: ["const controlPrefix = useId()", "htmlFor={", "field-21"],
	},

	{
		path: "scripts/build-windows.ps1",
		markers: [
			"Build from a clean committed checkout",
			"validate:advanced",
			"advanced-windows-engine-smoke.test.ts",
			"NOT RUN",
			"Expected exactly one fresh installer",
		],
	},

	{
		path: "sdk/packages/core/src/extensions/tools/executors/targeted-decompiler-scripts.ts",
		markers: ["getFunctionAt", "Ambiguous", "ida_hexrays"],
	},
	{
		path: "docs/COMBINED_ANDROID_TOOLING.md",
		markers: [
			"analysis_readiness",
			"native_function",
			"Runtime requirements",
			"not Windows installer evidence",
		],
	},
	{
		path: ".github/workflows/build-custom-windows-installer.yml",
		markers: [
			"Remove-Item 'src-tauri/target/release/bundle/nsis'",
			"Get-FileHash $sidecarExe.FullName",
			"Get-FileHash $builtSidecar",
		],
	},
	{
		path: "apps/examples/desktop-app/scripts/desktop-startup.test.ts",
		markers: [
			"sidecar-capability/v1",
			"sourceCommit",
			"denied.status).toBe(401)",
		],
	},

	{
		path: "apps/examples/desktop-app/sidecar/transport-auth.ts",
		markers: [
			"timingSafeEqual",
			"MAX_TOKEN_BYTES",
			"values.length > 1",
			"hasSidecarAuthentication",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/server.ts",
		markers: [
			"hasSidecarAuthentication(req, approvalToken, true)",
			"authenticated: true",
			"ws.data?.authenticated !== true",
			"MAX_ERROR_REPORT_BYTES",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/lib/desktop-transport-security.ts",
		markers: ["redactDesktopTransportSecrets", "knownToken", "[redacted]"],
	},
	{
		path: "apps/examples/desktop-app/scripts/desktop-startup.test.ts",
		markers: [
			"Authenticated transport smoke timed out",
			"shutdownDenied.status",
			"stale.status",
		],
	},
	{
		path: "docs/DESKTOP_TRANSPORT_AUTH.md",
		markers: ["all WebSocket commands", "Originless integrations", "No TLS"],
	},
	{
		path: "sdk/packages/core/scripts/android-investigation-worker.py",
		markers: [
			"MAX_WORK",
			"DEX Adler32 mismatch",
			"verifiedBinding",
			"methodsTruncated",
			"unsafe/duplicate/encrypted ZIP member",
			"Not evidence of encryption",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/android-investigation-index.ts",
		markers: [
			"cline-android-investigation/v1",
			"content hash mismatch",
			"await link(stagedFile, file)",
			"Queries only cover indexed evidence",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/schemas.ts",
		markers: [
			"artifact_discovery",
			"android_relationships",
			"android_method",
			"investigation_query",
		],
	},
	{
		path: "scripts/validate-advanced-build.mjs",
		markers: [
			"Check Android worker embed",
			"android-investigation.test.ts",
			"android-investigation-index.test.ts",
		],
	},
	{
		path: "docs/ANDROID_INVESTIGATION.md",
		markers: [
			"Not a runtime sandbox",
			"RegisterNatives",
			"Not yet implemented",
		],
	},
	{
		path: "apps/examples/desktop-app/scripts/desktop-startup.test.ts",
		markers: [
			"HUB_BOOTSTRAP_TIMEOUT_MS",
			"timeout: HUB_BOOTSTRAP_TIMEOUT_MS",
			"SIDECAR_READY_TIMEOUT_MS",
			"expect(health.ok).toBe(true)",
			"expect(restartedHealth.ok).toBe(true)",
			"duplicate session fork operation id",
		],
	},

	{
		path: "scripts/validate-advanced-build.mjs",
		markers: [
			"Test desktop chat UI",
			"Run desktop customization tests",
			"analysis-task-orchestrator.test.ts",
			"analysis-sandbox-client.test.ts",
			"engineering-control-plane.test.ts",
			"engineering-git-review.test.ts",
			"engineering-worktree-manager.test.ts",
			"engineering-workspace.test.tsx",
			"commands-workbench.test.ts",
			"process-session-manager.test.ts",
			"reverse-engineering.test.ts",
			"runtime-builder.test.ts",
			"repository-tool.test.ts",
			"notion-agent-bridge.test.ts",
			"notion-agent-patch.test.ts",
			"functions-view.test.tsx",
			"notion-provenance.test.ts",
			"permission-profile.test.ts",
			"Verify custom fork preservation",
			"Build SDK packages",
			"Run required desktop sidecar regression suite",
			"Test Windows installer configuration",
			"Test AI task report",
			"Test desktop chat UI",
			"Run desktop customization tests",
			"Run focused SDK safety tests",
			"--testTimeout=60000",
			"runValidation",
			"runJobs",
			"timeoutMs",
			"summary.json",
		],
	},

	{
		path: "sdk/packages/core/src/extensions/tools/executors/advanced-analysis.ts",
		markers: [
			"CLINE_RE_ALLOW_DECRYPTION",
			"CLINE_RE_PRIVATE_KEY_FILE",
			"host-gated-authenticated-decryption",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/analysis-evidence-graph.ts",
		markers: [
			"buildEvidenceGraph",
			"queryEvidenceGraph",
			"content-identity-not-authentication",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/analysis-notebook.ts",
		markers: [
			"prepareNotebook",
			"runAnalysisNotebook",
			"Input changed during analysis",
			"Checkpoint budget exceeded",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/advanced-analysis.ts",
		markers: [
			"cline-advanced-analysis/v1",
			"prepareProcessEnvironment",
			"external-adapter-required",
			"killTree",
			"advancedEvidenceBundle",
		],
	},
	{
		path: "CUSTOMIZATIONS.md",
		markers: [
			"Separate Notion-assisted Functions",
			"AI task execution UI",
			"Permanent Custom AI Instructions",
			"Windows reliability",
			"Command execution performance",
			"Scoped Windows computer use",
			"Lightweight built-in browser",
			"Objective Codex-parity benchmark",
			"Required validation",
			"vitest.config.mts",
		],
	},
	{
		path: "docs/BUILT_IN_BROWSER.md",
		markers: [
			"structured `browser` tool",
			"WebView2 runtime",
			"Password fields are rejected",
			"not an operating-system sandbox",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/browser-manager.ts",
		markers: [
			"DesktopBrowserManager",
			"MAX_SESSIONS = 8",
			"MAX_SESSION_AGE_MS",
			"Child agents cannot start",
		],
	},
	{
		path: "apps/examples/desktop-app/src-tauri/src/built_in_browser.rs",
		markers: [
			"built_in_browser_start",
			"built_in_browser_cdp",
			"CallDevToolsProtocolMethod",
			"accepts only http and https URLs",
		],
	},
	{
		path: ".github/workflows/build-custom-windows-installer.yml",
		markers: [
			"Run consolidated custom fork validation",
			"timeout-minutes: 35",
			'CLINE_VALIDATION_PARALLEL: "1"',
			"validate:advanced",
			"include-hidden-files: true",
			"Build custom Windows installer",
			"Get-AuthenticodeSignature",
			"Upload verified setup.exe",
			"CUSTOMIZATIONS.md",
			"BUILD-INFO.txt",
			"CLINE_TEST_SIDECAR_BIN",
			"scripts/desktop-startup.test.ts",
			"Record installer smoke-test result",
			"Run process-session terminal smoke test",
			"always() && steps.installer.outcome == 'success'",
			"process-session-terminal-smoke.ts",
			"scripts/read-bun-version.mjs",
			"bun-version: ${{ steps.toolchain.outputs.version }}",
			"SBOM.spdx.json",
			"Select unsigned private installer",
			"steps.ui_acceptance.outcome == 'success'",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/analysis-task-orchestrator.ts",
		markers: [
			"AnalysisTaskOrchestrator",
			"awaiting-approval",
			"executionToken",
			"canonical full-request one-time token",
			"timingSafeEqual",
			"targetIdentity",
			"expiresAt",
			"resultHash",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/analysis-workbench.tsx",
		markers: [
			"prepare_analysis_task",
			"approve_analysis_task",
			"Approval boundary",
			"Evidence ledger",
			"Deep check",
			"Export evidence bundle",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/analysis-sandbox-client.ts",
		markers: [
			"cline-analysis-worker/v1",
			"pinned public key",
			"ephemeralSnapshots",
			"attestation signature",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/engineering-control-plane.ts",
		markers: [
			"EngineeringControlPlane",
			"PRAGMA journal_mode = WAL",
			"requireWorktreeForWrites",
			"claimReadyTasks",
			"Only the agent that claimed the task may update it",
			"Repository-writing tasks require worktree evidence",
			"evaluateExecutionPolicy",
			"scoreReviewRisk",
			"routeEngineeringModel",
			"isolated-vm",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/engineering-worktree-manager.ts",
		markers: [
			"EngineeringWorktreeManager",
			"cline/engineering/",
			"baseRevision",
			"outside the managed root",
			"explicit discard confirmation",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/engineering-git-review.ts",
		markers: [
			"buildEngineeringGitReview",
			"Invalid Git comparison base",
			"sensitiveFiles",
			"publicApiChanged",
			"symbols",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/engineering/engineering-workspace.tsx",
		markers: [
			"Engineering Control Center",
			"Normal Cline chat remains unchanged",
			"plan_engineering_mission",
			"claim_engineering_tasks",
			"Prepare next agent drafts",
			"Git review evidence",
			"Secure execution",
			"Parallel agents",
			"Git review",
			"Model intelligence",
		],
	},
	{
		path: "docs/ENGINEERING_CONTROL_CENTER.md",
		markers: [
			"Trust boundary",
			"Normal chat isolation",
			"Windows Sandbox",
			"isolated VM",
			"does not execute a mission",
		],
	},
	{
		path: "docs/ANALYSIS_TRUST_BOUNDARY.md",
		markers: [
			"complete normalized request",
			"single-use token",
			"Dynamic analysis",
			"administrator responsibility",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/repository-tool.ts",
		markers: [
			"createRepositoryExecutor",
			"confirm_write=true",
			"confirm_remote=true",
			"--ff-only",
			"--set-upstream",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/pull-request-bar.tsx",
		markers: [
			"fetchComposioStatus",
			"connectComposioIntegration",
			"repository, issue, and pull request tools",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/lib/composio.ts",
		markers: ["composio_integrations", "connectComposioIntegration"],
	},
	{
		path: "sdk/packages/core/src/extensions/composio/composio-tools-extension.ts",
		markers: ["createComposioToolsExtension", "executeComposioTool", "/tools/"],
	},
	{
		path: "docs/STRUCTURED_REPOSITORY_AND_DIAGNOSTICS.md",
		markers: [
			"Structured repository tool",
			"composio_integrations",
			"repository, issue, pull request",
			"Browser page diagnostics",
			"Diagnostics center",
			"does not create a GitHub Release",
		],
	},
	{
		path: "evals/parity/codex-parity.ts",
		markers: [
			"evaluateParity",
			"coveragePercent",
			"weightedCandidateScore",
			"weightedReferenceScore",
			"parityPercent",
			"Unknown parity scenario",
		],
	},
	{
		path: "evals/parity/corpus.v1.json",
		markers: [
			"repository-repair",
			"generic-computer-use-form",
			"restricted-profile-escape",
			"background-automation-retry",
		],
	},
	{
		path: "evals/parity/README.md",
		markers: [
			"versioned task",
			"comparable environment",
			"deliberately omits a Codex-relative percentage",
		],
	},
	{
		path: "apps/examples/desktop-app/scripts/desktop-startup.test.ts",
		markers: [
			"SIDECAR_READY_TIMEOUT_MS = 30_000",
			"Backend never became ready",
		],
	},
	{
		path: "sdk/packages/core/src/hub/daemon/index.ts",
		markers: [
			"HUB_STARTUP_TIMEOUT_MS = 90_000",
			"pendingHubStarts",
			"Join daemon readiness",
		],
	},
	{
		path: "vitest.config.mts",
		markers: [
			"vitest/config",
			"defineConfig",
			"sdk/packages/core/vitest.config.ts",
		],
	},
	{
		path: "apps/examples/vscode/vitest.config.mts",
		markers: ["vitest/config", "defineConfig", "src/**/*.test.ts"],
	},
	{
		path: "apps/examples/desktop-app/vitest.config.mts",
		markers: [
			"vitest/config",
			"import.meta.url",
			"defineConfig",
			'new URL("./test/vitest-setup.ts", import.meta.url)',
		],
	},
	{
		path: "apps/examples/desktop-app/test/vitest-setup.ts",
		markers: [
			'"ResizeObserver" in globalThis',
			"ResizeObserverStub",
			"disconnect()",
		],
	},
	{
		path: "apps/examples/desktop-app/package.json",
		markers: ["vitest.config.mts", "test:sidecar", "test:windows-installer"],
	},
	{
		path: "apps/examples/desktop-app/webview/lib/chat-schema.ts",
		markers: [
			"TaskProtocolEventSchema",
			"TaskExecutionStatusSchema",
			"acceptanceCriteria",
			"transitions",
			"taskStepId",
			"taskEvent",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/task-state-machine.ts",
		markers: [
			"advanceDurableTaskState",
			"persistDurableTaskState",
			"readDurableTaskState",
			"readOrMigrateDurableTaskState",
			"rollbackDurableTaskState",
			"Skipped task step requires a reason",
			"Only one task step may be in progress",
			"Work cannot advance past a failed step",
			"sharedSessionTaskStatePath",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/task-validation.ts",
		markers: [
			"runDurableTaskValidations",
			"validationCandidates",
			"Validation timed out",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/lib/task-report.ts",
		markers: ["formatTaskReportText", "plan.updated", "taskStepId"],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/task-report-panel.tsx",
		markers: ["AI task report", "Copy report", "evidenceByStep"],
	},
	{
		path: "apps/examples/desktop-app/sidecar/desktop-settings.ts",
		markers: [
			"customAiInstructions",
			"mergeDesktopAiInstructions",
			"computerUseEnabled",
			"computerUseAllowedApplications",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/computer-use-manager.ts",
		markers: [
			"DesktopComputerUseManager",
			"MAX_ACTIONS = 200",
			"MAX_SESSION_AGE_MS",
			"Child agents cannot start computer control",
			"target_agent_id",
			"updateComputerUseMetrics",
			"Foreground application instance changed",
			"Coordinates are outside the allowlisted foreground window",
			"Post-action verification failed",
			"Password controls cannot be targeted",
			"Foreground application left the allowlisted executable",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/computer-use-metrics.ts",
		markers: [
			"ComputerUseMetrics",
			"accessibilityActions",
			"coordinateActions",
			"focusLossPauses",
			"updateQueue",
		],
	},
	{
		path: "apps/examples/desktop-app/scripts/computer-use-windows.test.ts",
		markers: [
			"deterministic Windows computer-use fixture",
			"commitButton",
			"passwordBox",
			"taskkill.exe",
		],
	},
	{
		path: "apps/examples/desktop-app/scripts/windows-installer.test.ts",
		markers: [
			"terminateProcessTree",
			"taskkill.exe",
			"Timed out after 90000ms",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/commands.ts",
		markers: [
			"set_custom_ai_instructions",
			"set_computer_use_settings",
			"take_over_computer_use",
			"prepare_notion_agent_bridge",
			"filesystemPathKey",
			"rev-parse",
			"worktree",
			"update-ref",
			"handoff_git_worktree",
			"Apply to Local conflicted",
			"Discard requires explicit confirmation",
			'"rundll32"',
			"url.dll,FileProtocolHandler",
			"onAuthorization",
			"authorizationUrl",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/team/spawn-agent-tool.ts",
		markers: [
			"SubAgentControlHandle",
			"onSubAgentControlReady",
			"consumePendingUserMessage",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/team/writer-worktree.ts",
		markers: [
			"createWriterWorktree",
			"listWriterWorktreeChanges",
			"ownerAgentId",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/worktree-handoff-bar.tsx",
		markers: [
			"Apply to Local",
			"Create Branch",
			"Open PR",
			"Keep",
			"Discard worktree",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/agent-header.tsx",
		markers: [
			"onControlAgent",
			'"stop"',
			'"steer"',
			'"retry"',
			"Guidance for",
			"Handoff blocked by overlapping edits",
			"Open worktree to resolve",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/team/multi-agent.ts",
		markers: ["cancelAgentWork", "pendingSteerMessage", "maxConcurrentRuns"],
	},
	{
		path: "apps/examples/desktop-app/sidecar/chat-session.ts",
		markers: ["mergeDesktopAiInstructions", "taskToolStepIds"],
	},
	{
		path: "sdk/packages/core/src/runtime/orchestration/runtime-builder.ts",
		markers: [
			"OFFICIAL_NOTION_MCP_URL",
			"isOfficialNotionRegistration",
			"officialNotionOnly",
			"minimumToolTimeoutMs",
			"Notion session preflight failed",
			'"project-notion-bridge"',
		],
	},
	{
		path: "apps/examples/desktop-app/webview/lib/notion-agent-routing.ts",
		markers: [
			"requestsProjectNotionBridge",
			"NOTION_AGENT_TARGET",
			"LOCAL_PROJECT_CONTEXT",
		],
	},
	{
		path: "docs/PROJECT_NOTION_BRIDGE.md",
		markers: [
			"Project + Notion Agent runtime",
			"fails session startup",
			"never represent a local file as an upload",
			"Evidence-grounded review loop",
			"five-minute MCP request floor",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/settings/functions-view.tsx",
		markers: [
			"Notion-assisted functions",
			"Uses your current Cline model",
			"https://mcp.notion.com/mcp",
			"No special database",
			"Open in new session",
			"Local function audit",
			"Create reusable function",
			"Pinned Notion context",
			"Prepare Notion Agent handoff",
			"Import Notion Agent review",
			"Project Intelligence workspace",
			"Visual approval center",
			"Analyze project intelligence",
			"Run Notion health check",
			"Export audit",
			"Notion Agent Bridge",
			"Deep evidence review",
			"Complete project evidence manifest",
			"Evidence transfer batches",
			"Prepare secure preview",
			"Ask Notion Agent",
			"Discover agents",
			"Notion Agent review-to-patch",
			"Dry-run patch",
			"Apply on isolated branch",
			"Agent Bridge privacy and provenance",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/notion-agent-bridge.ts",
		markers: [
			"prepareNotionAgentBridgePackage",
			"git",
			"--exclude-standard",
			"sensitive filename",
			"[REDACTED:token]",
			"Bridge path escapes the workspace",
			"buildEvidenceBatches",
			"metadata-only",
			"Transfer protocol",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/notion-agent-patch.ts",
		markers: [
			"previewNotionAgentPatch",
			"applyNotionAgentPatch",
			"rollbackNotionAgentPatch",
			"git",
			"--check",
			"Patch target changed after sharing with Notion",
			"notion-agent/",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/lib/desktop-app-state.ts",
		markers: ["initialPromptDraft?: string", 'type: "new-thread"'],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/settings/settings-view.tsx",
		markers: [
			"Custom AI instructions",
			"set_custom_ai_instructions",
			"Agent permission capability matrix",
			"Full interaction",
			"DiagnosticsContent",
			"Copy sanitized report",
			"Scoped computer use",
			"set_computer_use_settings",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/app/page.tsx",
		markers: ["Computer control active", "Stop and take over"],
	},
	{
		path: "apps/examples/desktop-app/webview/hooks/use-chat-session.ts",
		markers: ['process.env.NODE_ENV === "test"', "shouldLogVerboseCoreLogs()"],
	},
	{
		path: "apps/examples/desktop-app/webview/lib/desktop-client.ts",
		markers: ['process.env.NODE_ENV === "development"'],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/welcome-workspace-controls.test.tsx",
		markers: ["async function renderControls", "await act(async () =>"],
	},
	{
		path: "apps/examples/desktop-app/webview/lib/image-attachments.test.ts",
		markers: ["IS_REACT_ACT_ENVIRONMENT"],
	},
	{
		path: "apps/examples/desktop-app/sidecar/oauth-login.ts",
		markers: [
			"startClineDeviceAuth",
			"completeClineDeviceAuth",
			"onAuthorization",
			"verificationUriComplete",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/hooks/use-oauth-user-code.ts",
		markers: [
			'desktopClient.subscribe("provider_oauth_user_code"',
			"lifetime of the mounted login surface",
			"authorizationUrl",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/oauth-authorization-prompt.tsx",
		markers: ["Cline sign-in URL", "Open sign-in page", "Copy sign-in link"],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/schemas.ts",
		markers: ["StructuredCommandInputSchema", "invoke an executable directly"],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/definitions.ts",
		markers: [
			"cline.run_commands.duration_ms",
			"cline.run_commands.time_to_first_output_ms",
			"cline.run_commands.output_chunk_count",
			"emittedCommandMetadata",
			"Prefer { command, args } with explicit argv",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/bash.ts",
		markers: [
			"COMMAND_PROGRESS_FLUSH_INTERVAL_MS",
			"emittedOutput",
			"prepareProcessEnvironment",
			"allowedSensitiveEnvironmentVariables",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/process-environment-policy.ts",
		markers: [
			"prepareProcessEnvironment",
			"isSensitiveEnvironmentVariable",
			"createStreamingSecretRedactor",
			"OTEL_EXPORTER_OTLP_HEADERS",
			"PRIVATE_KEY_PATTERN",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/permission-profile.ts",
		markers: [
			"createPermissionProfileExtension",
			'"read-only"',
			'"workspace-network"',
			'"full-access"',
			'"notion-functions"',
			'"project-notion-bridge"',
			"only the official Notion MCP tools",
			"only read-only local inspection",
			"unclassified plugin or MCP tool",
			"not an operating-system sandbox",
			"desktop computer control is disabled",
		],
	},
	{
		path: "docs/SCOPED_COMPUTER_USE.md",
		markers: [
			"disabled by default",
			"exact absolute Windows `.exe` paths",
			"Stop and take over",
			"Password controls",
			"revoke_delegation",
			"Aggregate local diagnostics",
			"post-action `verify`",
			"not an operating-system sandbox",
		],
	},
	{
		path: "docs/PERMISSION_PROFILES.md",
		markers: [
			"beforeTool",
			"delegated agents",
			"not an operating-system sandbox",
			"no-release policy",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/process-session-manager.ts",
		markers: [
			"ProcessSessionManager",
			"DEFAULT_MAX_PROCESS_SESSIONS = 64",
			"DEFAULT_PROCESS_OUTPUT_BYTES = 1024 * 1024",
			"spawnBunTerminalProcess",
			"new bun.Terminal",
			"terminalColumns",
			"resize(",
			"highestDroppedCursor",
			"process.kill(-pid",
			"taskkill.exe",
			"initializeRecovery",
			"processStartToken",
			"recoveredAfterRestart",
			"prior output and stdin are unavailable",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/schemas.ts",
		markers: [
			"ProcessSessionInputSchema",
			'action: z.literal("start")',
			'action: z.literal("resize")',
			"Windows ConPTY",
			"signal: z",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/definitions.ts",
		markers: [
			'name: "process_session"',
			"requireProcessSessionOwner",
			"createProcessSessionTool",
			"Windows ConPTY",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/runtime.ts",
		markers: ["process_session", "enableProcessSessions"],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts",
		markers: [
			'path.join(process.env.USERPROFILE, "Documents")',
			"listMatchingDirectories(parent, prefixes, 2)",
			"GHIDRA_INSTALL_DIR",
			"cline_decompile_all.py",
			"ida_hexrays.decompile(function)",
			"artifactVerified",
			"acknowledge_external_output=true",
			"boundedUserRegex",
			"external-approved",
			"MAX_ARTIFACT_HASH_BYTES",
			"FORENSIC_REPORT_STATE",
			"apkSecurityInspection",
			"renderForensicHtml",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/supervised-process.ts",
		markers: [
			'child.once("close"',
			"process.kill(-child.pid",
			"exited_early",
			"outputDrainTimedOut",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/live-debugger.ts",
		markers: [
			"acknowledge_risk=true",
			"confirm_execution_control=true",
			"inspect_dump",
			"inspectMinidump",
			"inspect-only",
			"persistentSession",
			"process detach",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/schemas.ts",
		markers: ["SAFE_DEBUGGER_LOCATION_PATTERN"],
	},
	{
		path: "docs/LIVE_DEBUGGING.md",
		markers: [
			"one-shot",
			"acknowledge_risk: true",
			"Remote debugging is rejected",
		],
	},
	{
		path: "docs/ANDROID_DEVICE_AUTOMATION.md",
		markers: ["Unrestricted shell", "acknowledge_risk: true", "screenChanged"],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/android-device.ts",
		markers: [
			"redactSensitiveText",
			"confirm_package_change=true",
			"confirm_log_clear=true",
		],
	},
	{
		path: "docs/FORENSIC_TOOL_RELIABILITY.md",
		markers: [
			"Forensic tool reliability",
			"acknowledge_external_output: true",
			"confirm_execution_control: true",
			"confirm_package_change: true",
			"native Windows sandboxing",
		],
	},
	{
		path: "docs/ADVANCED_FORENSIC_ANALYSIS.md",
		markers: [
			"Advanced forensic analysis",
			"cline-forensic-report-state.json",
			"apk_security_report",
			"inspect_dump",
			"does not publish a GitHub Release",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/command-latency-baseline.ts",
		markers: [
			"MIN_SHELL_BASELINE_SAMPLES",
			"MIN_SHELL_STARTUP_RATIO",
			"evaluatePowerShellWorkerEligibility",
		],
	},
	{
		path: "docs/CODEX_LIKE_COMMAND_EXECUTION.md",
		markers: [
			"Structured direct execution",
			"Immediate first output",
			"cline.run_commands.time_to_first_output_ms",
			"Prewarmed PowerShell worker",
			"Do not publish a GitHub Release",
		],
	},
	{
		path: "docs/EXECUTION_WORKBENCH.md",
		markers: [
			"Desktop execution and analysis workbench",
			"not an operating-system sandbox",
			"strict subset",
			"owned or authorized",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/ui/markdown.tsx",
		markers: [
			"isInlinePreviewArtifactPath",
			'primaryAction={previewsInApp ? "preview" : "open"}',
			"event.preventDefault()",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/artifact-context-menu.tsx",
		markers: [
			'primaryAction?: "open" | "preview"',
			"cloneElement",
			"Open with default app",
			"Show in folder",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/commands.ts",
		markers: [
			"spawnDetachedAndWait",
			"windowsExplorerRevealArgs",
			'/select,"',
			"windowsVerbatimArguments",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/workspace-terminal.tsx",
		markers: [
			"workspace_terminal_start",
			"confirmFullAccess",
			"workspace_terminal_signal",
			"secret-redacted output",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/analysis-workbench.tsx",
		markers: [
			"discover_analysis_tools",
			"run_static_analysis",
			"run_debugger_action",
			"confirmAuthorized",
		],
	},
	{
		path: "docs/CODEX_PARITY_ROADMAP.md",
		markers: [
			"Resumable process sessions",
			"Durable task state machine",
			"Worktree-first isolation and handoff",
			"Additive permission profiles",
			"Parallel agent orchestration",
			"isolated-writer",
			"prewarmed PowerShell worker",
			"Scoped computer use",
			"atomically persists a versioned task-state artifact",
			"Do not publish a GitHub Release",
		],
	},
	{
		path: "docs/WORKTREE_HANDOFF.md",
		markers: [
			"Apply to Local",
			"explicit confirmation",
			"Cleanup is idempotent",
			"does not publish a GitHub Release",
		],
	},
	{
		path: "docs/DURABLE_TASK_EXECUTION.md",
		markers: [
			"Automatic validation",
			"Checkpoint rollback",
			"migration.projected-report",
			"does not publish a GitHub Release",
		],
	},
	{
		path: "docs/PROCESS_ENVIRONMENT_SECURITY.md",
		markers: [
			"allowedSensitiveEnvironmentVariables",
			"Output redaction",
			"Security boundary",
			"does not publish a GitHub Release",
		],
	},
	{
		path: "apps/examples/desktop-app/CUSTOM_DESKTOP.md",
		markers: [
			"bounded two-level search",
			"ida_hexrays.decompile()",
			"acknowledge_risk: true",
		],
	},
];

requiredMarkers.push(
	{
		path: "sdk/packages/core/src/extensions/tools/executors/analysis-program-evidence.ts",
		markers: [
			"analyzeProgramCfg",
			"analyzeProgramTrace",
			"not-proven",
			"output budget",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/analysis-document-store.ts",
		markers: [
			"confirmWrite",
			"validateNotebook",
			"expectedSha256",
			"Document changed since review",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/analysis-sandbox-client.ts",
		markers: [
			"bindRuntimeAnalysisRequest",
			"submitAnalysisSandbox",
			"worker_key_sha256",
			'redirect: "error"',
			"Receipt does not bind approved job",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/notion-agent-bridge.ts",
		markers: ["evidenceId", "serialized", "split"],
	},
);
requiredMarkers.push(
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/analysis-authoring.tsx",
		markers: [
			"expectedSha256",
			"Saving never executes analysis",
			"graph_query",
		],
	},
	{
		path: ".github/workflows/build-custom-windows-installer.yml",
		markers: [
			"Validate portable Windows analysis engines",
			"advanced-windows-engine-smoke.test.ts",
			"Real portable engine execution failed",
		],
	},
);
requiredMarkers.push(
	{
		path: "apps/examples/desktop-app/sidecar/analysis-document-store.test.ts",
		markers: [
			"bounded atomic analysis document publication",
			"bounds serialized bytes",
			"allows exactly one concurrent",
			"never deletes another caller",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/analysis-document-store.ts",
		markers: [
			"Serialized document byte budget exceeded",
			"await link(stage,path)",
		],
	},
);
const forbiddenPaths = [
	"vitest.config.ts",
	"apps/examples/vscode/vitest.config.ts",
	"apps/examples/desktop-app/vitest.config.ts",
];
const failures: string[] = [];

requiredMarkers.push(
	{
		path: "sdk/packages/shared/src/hub.ts",
		markers: [
			"HUB_SESSION_LIFECYCLE_TIMEOUT_MS",
			'case "session.create":',
			'case "session.restore":',
		],
	},
	{
		path: "apps/examples/desktop-app/webview/lib/desktop-client.ts",
		markers: [
			"HUB_SESSION_LIFECYCLE_TIMEOUT_MS",
			"defaultCommandTimeoutMs",
			"SESSION_LIFECYCLE_TIMEOUT_MS",
		],
	},
	{
		path: "scripts/validate-advanced-build.mjs",
		markers: [
			"Test desktop transport recovery",
			"Test Hub lifecycle deadlines",
			"session-runtime-orchestrator.test.ts",
		],
	},
	{
		path: "docs/LONG_SESSION_RECOVERY.md",
		markers: [
			"Authentication is separate",
			"No automatic replay of sends",
			"ten minutes",
		],
	},
);

requiredMarkers.push(
	{
		path: "workers/managed-emulation/engines/selftest.py",
		markers: [
			"def regular_bytes(",
			"os.O_NOFOLLOW | os.O_NONBLOCK",
			"total > MAX_BUNDLE_BYTES",
			"Special runtime file",
			"INVOKE_STDOUT_LIMIT = 1024*1024",
			"os.WEXITED | os.WNOHANG | os.WNOWAIT",
			"os.killpg(process.pid,signal.SIGKILL)",
		],
	},
	{
		path: "workers/managed-emulation/image/build_image.py",
		markers: [
			"Unsealed exported runtime file",
			"Exported runtime file schema",
			"Exported runtime link mismatch",
		],
	},
);

requiredMarkers.push(
	{
		path: "workers/managed-emulation/host/src/windows_roots.rs",
		markers: [
			"LocalSystem broker required; no host settings changed",
			"Impersonated protected storage access forbidden",
			"O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
			"FILE_SHARE_READ | FILE_SHARE_WRITE",
			"FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT",
			"pub fn open_existing()",
			"real_owned_junctions_are_refused_as_roots_and_ancestors",
			"READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY",
		],
	},
	{
		path: "workers/managed-emulation/host/test-system-roots.ps1",
		markers: [
			"New-ScheduledTaskPrincipal -UserId 'SYSTEM'",
			"No -Force: never overwrite an existing task",
			"LastRunTime.Year -gt 2000",
			"Owned fixture executable changed before launch",
			"Owned task termination unresolved",
		],
	},
	{
		path: "workers/managed-emulation/host/src/bin/owned-system-roots-fixture.rs",
		markers: ["SystemRoots::create_new()", "SystemRoots::open_existing()", "std::fs::remove_dir(path)", "No recursive deletion"],
	},
	{
		path: "workers/managed-emulation/host/Cargo.toml",
		markers: ['required-features = ["owned-system-acceptance"]', 'version = "=0.52.0"'],
	},
);

requiredMarkers.push(
	{
		path: "workers/managed-emulation/host/src/windows_roots.rs",
		markers: ["pub struct SystemJob<'roots>", "pub struct ProtectedStore<'job, 'roots>", "Protected job identity mismatch", "Protected store fenced; reopen and inspect", "Store::create_protected", "self.job.revalidate()?", "material.write_media(&self.directories[2].0)?"],
	},
	{
		path: "workers/managed-emulation/host/src/bin/owned-system-roots-fixture.rs",
		markers: ["roots.create_job()", "opened_job.open_store", "Event::RecoveryRequested", "store.journal().recovery_required()", "ImpersonateSelf(SecurityImpersonation)", "job.write_boot_media()", "MEDIA_BYTES as u64", 'std::fs::remove_file(path.join("recovery.sqlite"))'],
	},
);

requiredMarkers.push(
	{
		path: "workers/managed-emulation/host/src/windows_identity.rs",
		markers: ["CRYPTPROTECT_UI_FORBIDDEN", "CryptProtectData", "CryptUnprotectData", "std::ptr::write_volatile", "file.sync_all()", "Installation record schema mismatch", "mac.update(KEY_DOMAIN)", "pub struct InstallationStore", "Installation store fenced; reopen and inspect", "derived_recovery_keys_bind_every_identity_field_and_master"],
	},
	{
		path: "workers/managed-emulation/host/src/windows_roots.rs",
		markers: ["pub(crate) fn installation_file", "info.nNumberOfLinks != 1", "validate_security(raw, &Policy::system()?, 0)?", "Single-link protected regular installation file required"],
	},
	{
		path: "workers/managed-emulation/host/src/bin/owned-system-roots-fixture.rs",
		markers: ["installation_acceptance(&roots)?", "SystemIdentity::create(roots)", "SystemIdentity::open(roots)", "owner.open_store(&job", "Installation store fenced; reopen and inspect"],
	},
);

for (const forbiddenPath of forbiddenPaths) {
	if (existsSync(forbiddenPath)) {
		failures.push(`${forbiddenPath}: obsolete file must remain deleted`);
	}
}

for (const requirement of requiredMarkers) {
	let source: string;
	try {
		source = readFileSync(requirement.path, "utf8");
	} catch {
		failures.push(`${requirement.path}: file is missing`);
		continue;
	}
	for (const marker of requirement.markers) {
		if (!source.includes(marker)) {
			failures.push(`${requirement.path}: missing ${JSON.stringify(marker)}`);
		}
	}
}

if (failures.length > 0) {
	console.error("Custom fork preservation check failed:");
	for (const failure of failures) console.error(`- ${failure}`);
	console.error(
		"If the customization changed intentionally, update CUSTOMIZATIONS.md and this verifier in the same commit.",
	);
	process.exit(1);
}

console.log(
	`Custom fork preservation check passed (${requiredMarkers.length} source contracts; ${forbiddenPaths.length} obsolete path blocked).`,
);

const sqliteRestartSource = readFileSync(
	"sdk/packages/shared/src/db/sqlite-db.ts",
	"utf8",
);
if (
	sqliteRestartSource.indexOf('db.exec("PRAGMA busy_timeout = 5000;")') >
	sqliteRestartSource.indexOf('db.exec("PRAGMA journal_mode = WAL;")')
) {
	throw new Error(
		"Session WAL recovery must configure bounded busy handling first",
	);
}
