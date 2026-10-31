//! Development-only real SCM host/owned acceptance. No UI grant, target/VM work,
//! automatic host installation, release bootstrap, or readiness promotion.
use crate::{
    windows_ipc::{Cancellation, ClientScope, ProbeServer},
    windows_roots::{require_system, SystemRoots},
    Result,
};
use std::{
    ffi::{c_void, OsStr},
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    ptr::{null, null_mut},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_CALL_NOT_IMPLEMENTED, ERROR_GEN_FAILURE, ERROR_INVALID_PARAMETER, HANDLE,
        WAIT_OBJECT_0,
    },
    Security::SC_HANDLE,
    System::{
        LibraryLoader::{SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_SYSTEM32},
        Services::*,
        Threading::{
            GetCurrentProcess, GetExitCodeProcess, OpenProcess, WaitForSingleObject,
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        },
    },
};
const NAME: &str = "ClineOwnedManagedProbeV1";
fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}
fn name() -> Vec<u16> {
    wide(OsStr::new(NAME))
}
struct Reporter {
    handle: SERVICE_STATUS_HANDLE,
    current: u32,
}
impl Reporter {
    fn set(&mut self, state: u32, error: u32) {
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: if state == SERVICE_RUNNING {
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            } else {
                0
            },
            dwWin32ExitCode: error,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: if state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING {
                1
            } else {
                0
            },
            dwWaitHint: if state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING {
                3000
            } else {
                0
            },
        };
        if unsafe { SetServiceStatus(self.handle, &status) } == 0 {
            std::process::abort();
        }
        self.current = state;
    }
}
struct State {
    cancel: Cancellation,
    reporter: Mutex<Reporter>,
}
static STATE: OnceLock<State> = OnceLock::new();
unsafe extern "system" fn control(
    code: u32,
    _event: u32,
    _data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    if code == SERVICE_CONTROL_INTERROGATE {
        return 0;
    }
    if code != SERVICE_CONTROL_STOP && code != SERVICE_CONTROL_SHUTDOWN {
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
    if let Some(state) = STATE.get() {
        // The handler never waits on pipe I/O or performs cleanup. Monotonic
        // status under the same lock prevents a late STOP reviving STOPPED.
        let Ok(mut reporter) = state.reporter.lock() else {
            std::process::abort();
        };
        if reporter.current == SERVICE_RUNNING {
            reporter.set(SERVICE_STOP_PENDING, 0);
        }
        if reporter.current != SERVICE_STOPPED {
            state.cancel.signal();
        }
    }
    0
}
fn report(state: u32, error: u32) {
    let Some(shared) = STATE.get() else {
        std::process::abort();
    };
    let Ok(mut reporter) = shared.reporter.lock() else {
        std::process::abort();
    };
    reporter.set(state, error);
}
unsafe extern "system" fn service_main(argc: u32, argv: *mut *mut u16) {
    // First fallible SCM operation; initialization errors can now be reported.
    let handle = unsafe { RegisterServiceCtrlHandlerExW(name().as_ptr(), Some(control), null()) };
    if handle == 0 {
        return;
    }
    let mut reporter = Reporter { handle, current: 0 };
    reporter.set(SERVICE_START_PENDING, 0);
    let valid = argc == 1 && !argv.is_null() && unsafe { matches_name(*argv) };
    if !valid {
        reporter.set(SERVICE_STOPPED, ERROR_INVALID_PARAMETER);
        return;
    }
    let Ok(cancel) = Cancellation::new() else {
        reporter.set(SERVICE_STOPPED, ERROR_GEN_FAILURE);
        return;
    };
    if STATE
        .set(State {
            cancel,
            reporter: Mutex::new(reporter),
        })
        .is_err()
    {
        std::process::abort();
    }
    let result = work();
    // work's local pipe/file/root guards have drained/dropped before STOPPED.
    report(
        SERVICE_STOPPED,
        if result.is_ok() { 0 } else { ERROR_GEN_FAILURE },
    );
}
unsafe fn matches_name(value: *const u16) -> bool {
    if value.is_null() {
        return false;
    }
    for (i, expected) in name().iter().enumerate() {
        if unsafe { *value.add(i) } != *expected {
            return false;
        }
    }
    true
}
fn work() -> Result<()> {
    require_system()?;
    let roots = SystemRoots::open_existing()?;
    // Only an exact pre-staged protected CI job executable is admitted. No
    // adoption of a user-writable workspace executable or installation path.
    let exe = std::env::current_exe().map_err(|_| "Service image unavailable")?;
    let parent = exe.parent().ok_or("Owned service image required")?;
    let job_id = parent
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("Owned service job required")?;
    crate::exact_hex::<16>(job_id)?;
    if parent != roots.job_parent().join(job_id) {
        return Err("Protected service job required");
    }
    let job = roots.open_job(job_id)?;
    if exe != job.owned_service_path() {
        return Err("Exact protected service image required");
    }
    let _image = job.owned_service_file(false)?;
    let scope = ClientScope::observe_current_process()?;
    let server = ProbeServer::bind(scope)?;
    let stop = &STATE.get().ok_or("Service state unavailable")?.cancel;
    report(SERVICE_RUNNING, 0);
    loop {
        let result = server.serve_controlled(stop);
        if stop.cancelled() {
            break;
        }
        if result.is_err() && result.err() != Some("IPC operation deadline") {
            return Err("Owned service request failed");
        }
        server.reset_connection()?;
    }
    Ok(())
}
/// SCM dispatch only; no console fallback or install/start command-line mode.
pub fn dispatch() -> Result<()> {
    require_system()?;
    if std::env::args_os().len() != 1 {
        return Err("No service command-line arguments allowed");
    }
    if unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) } == 0 {
        return Err("System DLL policy unavailable");
    }
    let mut service = name();
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: service.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err("Actual SCM dispatch required");
    }
    Ok(())
}

struct Sc(SC_HANDLE);
impl Drop for Sc {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}
fn status(service: &Sc) -> Result<SERVICE_STATUS_PROCESS> {
    let mut value: SERVICE_STATUS_PROCESS = unsafe { zeroed() };
    let mut needed = 0;
    if unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            (&mut value as *mut SERVICE_STATUS_PROCESS).cast(),
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        )
    } == 0
        || value.dwServiceType != SERVICE_WIN32_OWN_PROCESS
    {
        return Err("Owned SCM status unavailable");
    }
    Ok(value)
}
fn wait_state(service: &Sc, desired: u32) -> Result<SERVICE_STATUS_PROCESS> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let value = status(service)?;
        if value.dwCurrentState == desired {
            return Ok(value);
        }
        if desired == SERVICE_RUNNING && value.dwCurrentState == SERVICE_STOPPED {
            return Err("Owned service failed startup");
        }
        if Instant::now() >= deadline {
            return Err("Owned SCM state deadline; retained service unresolved");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn checked_text(buffer: &[usize], used: usize, value: *const u16) -> Result<Vec<u16>> {
    let begin = buffer.as_ptr() as usize;
    let at = value as usize;
    if value.is_null()
        || at < begin
        || at % 2 != 0
        || at.checked_add(2).ok_or("Owned SCM string boundary")? > begin + used
    {
        return Err("Owned SCM string boundary");
    }
    let maximum = (begin + used - at) / 2;
    for length in 0..maximum {
        if unsafe { *value.add(length) } == 0 {
            return Ok(unsafe { std::slice::from_raw_parts(value, length) }.to_vec());
        }
    }
    Err("Owned SCM unterminated string")
}
fn exact_config(service: &Sc, binary: &[u16]) -> Result<()> {
    let mut buffer = [0usize; 512];
    let mut used = 0;
    if unsafe {
        QueryServiceConfigW(
            service.0,
            buffer.as_mut_ptr().cast(),
            size_of::<[usize; 512]>() as u32,
            &mut used,
        )
    } == 0
    {
        return Err("Owned SCM configuration budget");
    }
    let used = size_of::<[usize; 512]>();
    let value = unsafe { &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
    let path = checked_text(&buffer, used, value.lpBinaryPathName)?;
    let account = checked_text(&buffer, used, value.lpServiceStartName)?;
    let deps = if value.lpDependencies.is_null() {
        Vec::new()
    } else {
        checked_text(&buffer, used, value.lpDependencies)?
    };
    if value.dwServiceType != SERVICE_WIN32_OWN_PROCESS
        || value.dwStartType != SERVICE_DEMAND_START
        || value.dwErrorControl != SERVICE_ERROR_NORMAL
        || path != binary[..binary.len() - 1]
        || account != wide(OsStr::new("LocalSystem"))[..11]
        || !deps.is_empty()
    {
        return Err("Owned SCM configuration mismatch");
    }
    Ok(())
}
fn start(service: &Sc) -> Result<OwnedHandle> {
    if unsafe { StartServiceW(service.0, 0, null()) } == 0 {
        return Err("Owned SCM start failed");
    }
    let value = wait_state(service, SERVICE_RUNNING)?;
    if value.dwProcessId == 0 || value.dwWin32ExitCode != 0 {
        return Err("Owned service process evidence missing");
    }
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            value.dwProcessId,
        )
    };
    if process == 0 {
        return Err("Owned service process unavailable");
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(process as _) })
}
fn process_exit(process: HANDLE) -> Result<u32> {
    // GetExitCodeProcess alone is insufficient: a live process returns
    // STILL_ACTIVE, which can also be a real exit code. Require a signalled
    // process first, then query its actual exit code.
    if unsafe { WaitForSingleObject(process, 0) } != WAIT_OBJECT_0 {
        return Err("Owned service process has not exited");
    }
    let mut code = 0;
    if unsafe { GetExitCodeProcess(process, &mut code) } == 0 {
        return Err("Owned service process exit code unavailable");
    }
    Ok(code)
}
fn clean_exit(process: HANDLE) -> Result<()> {
    if process_exit(process)? != 0 {
        return Err("Owned service process exited unsuccessfully");
    }
    Ok(())
}
fn stop(service: &Sc, process: &OwnedHandle) -> Result<()> {
    let mut prior: SERVICE_STATUS = unsafe { zeroed() };
    if unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut prior) } == 0 {
        return Err("Owned SCM stop submission failed");
    }
    let ended = wait_state(service, SERVICE_STOPPED)?;
    if ended.dwWin32ExitCode != 0
        || ended.dwServiceSpecificExitCode != 0
        || unsafe { WaitForSingleObject(process.as_raw_handle() as HANDLE, 5000) } != WAIT_OBJECT_0
    {
        return Err("Owned service stop/process exit unresolved");
    }
    clean_exit(process.as_raw_handle() as HANDLE)
}
pub(crate) fn digest(file: &std::fs::File) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek, SeekFrom};
    let size = file
        .metadata()
        .map_err(|_| "Owned service metadata unavailable")?
        .len();
    if size == 0 || size > 64 * 1024 * 1024 {
        return Err("Owned service image budget");
    }
    let mut copy = file
        .try_clone()
        .map_err(|_| "Owned service handle unavailable")?;
    copy.seek(SeekFrom::Start(0))
        .map_err(|_| "Owned service read unavailable")?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 32768];
    let mut total = 0u64;
    loop {
        let n = copy
            .read(&mut buffer)
            .map_err(|_| "Owned service read failed")?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > size {
            return Err("Owned service image changed");
        }
        hash.update(&buffer[..n]);
    }
    if total != size {
        return Err("Owned service image changed");
    }
    Ok(hash.finalize().into())
}
/// Explicit native CI only: exclusive creation, no adoption or automatic repair.
/// On ambiguous failure retain service/binary/job state; never recursive cleanup.
pub fn owned_acceptance(roots: &SystemRoots) -> std::result::Result<(), i32> {
    use std::io::{Read, Seek, SeekFrom, Write};
    require_system().map_err(|_| 100)?;
    let job = roots.create_job().map_err(|_| 101)?;
    let id = job.id().to_owned();
    let path = job.owned_service_path();
    let source = std::env::current_exe()
        .map_err(|_| 102)?
        .parent()
        .ok_or(102)?
        .join("owned-local-service-fixture.exe");
    let mut source = std::fs::File::open(source).map_err(|_| 103)?;
    let expected = digest(&source).map_err(|_| 104)?;
    source.seek(SeekFrom::Start(0)).map_err(|_| 104)?;
    let mut staged = job.owned_service_file(true).map_err(|_| 105)?;
    // Bounded copy; no external executable/path/argv supplied to the fixture.
    let mut buffer = [0u8; 32768];
    let mut count = 0usize;
    loop {
        let n = source.read(&mut buffer).map_err(|_| 106)?;
        if n == 0 {
            break;
        }
        count += n;
        if count > 64 * 1024 * 1024 {
            return Err(107);
        }
        staged.write_all(&buffer[..n]).map_err(|_| 108)?;
    }
    staged.sync_all().map_err(|_| 109)?;
    drop(staged);
    let staged = job.owned_service_file(false).map_err(|_| 110)?;
    if digest(&staged).map_err(|_| 111)? != expected {
        return Err(112);
    }
    crate::windows_child::owned_acceptance(&job, &staged)?;
    // Prove that the same exit verifier refuses both a live process and an
    // actual failed child, not merely an SCM STOPPED status. The exact protected
    // fixture already rejects every command-line argument with exit code 2;
    // this adds no console execution mode, shell, target path or new authority.
    if clean_exit(unsafe { GetCurrentProcess() }) != Err("Owned service process has not exited") {
        return Err(139);
    }
    use std::os::windows::process::CommandExt;
    let mut refused = std::process::Command::new(&path)
        .arg("unexpected-owned-argument")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
        .spawn()
        .map_err(|_| 140)?;
    let refused_handle = refused.as_raw_handle() as HANDLE;
    if unsafe { WaitForSingleObject(refused_handle, 5000) } != WAIT_OBJECT_0
        || process_exit(refused_handle) != Ok(2)
        || clean_exit(refused_handle) != Err("Owned service process exited unsuccessfully")
    {
        return Err(141);
    }
    if refused.wait().map_err(|_| 142)?.code() != Some(2) {
        return Err(142);
    }
    drop(refused);
    let manager = Sc(unsafe {
        OpenSCManagerW(
            null(),
            null(),
            SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
        )
    });
    if manager.0 == 0 {
        return Err(113);
    }
    let quoted = format!("\"{}\"", path.to_str().ok_or(114)?);
    let binary = wide(OsStr::new(&quoted));
    let service = Sc(unsafe {
        CreateServiceW(
            manager.0,
            name().as_ptr(),
            name().as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            binary.as_ptr(),
            null(),
            null_mut(),
            null(),
            null(),
            null(),
        )
    });
    if service.0 == 0 {
        return Err(115);
    } // Never OpenService/adopt an existing entry.
    exact_config(&service, &binary).map_err(|_| 116)?;
    let duplicate = unsafe {
        CreateServiceW(
            manager.0,
            name().as_ptr(),
            name().as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            binary.as_ptr(),
            null(),
            null_mut(),
            null(),
            null(),
            null(),
        )
    };
    if duplicate != 0 {
        drop(Sc(duplicate));
        return Err(132);
    }
    if unsafe { windows_sys::Win32::Foundation::GetLastError() }
        != windows_sys::Win32::Foundation::ERROR_SERVICE_EXISTS
    {
        return Err(132);
    }
    match std::fs::OpenOptions::new().write(true).open(&path) {
        Err(error)
            if error.raw_os_error()
                == Some(windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION as i32) => {}
        _ => return Err(133),
    }
    // Service start arguments are not a configuration/command channel.
    let unexpected = wide(OsStr::new("unexpected-owned-argument"));
    let args = [unexpected.as_ptr()];
    unsafe {
        StartServiceW(service.0, 1, args.as_ptr());
    }
    let rejected = wait_state(&service, SERVICE_STOPPED).map_err(|_| 134)?;
    if rejected.dwWin32ExitCode != ERROR_INVALID_PARAMETER {
        return Err(135);
    }
    let process = start(&service).map_err(|_| 117)?;
    crate::windows_ipc::probe_system_server().map_err(|_| 118)?;
    exact_config(&service, &binary).map_err(|_| 119)?;
    stop(&service, &process).map_err(|_| 120)?;
    drop(process);
    if digest(&staged).map_err(|_| 121)? != expected {
        return Err(122);
    }
    // Fresh process restart, then a connected client deliberately sends nothing.
    let process = start(&service).map_err(|_| 123)?;
    let _silent = crate::windows_ipc::owned_silent_client().map_err(|_| 124)?;
    let began = Instant::now();
    stop(&service, &process).map_err(|_| 125)?;
    if began.elapsed() >= Duration::from_secs(3) {
        return Err(126);
    }
    drop(_silent);
    drop(process);
    exact_config(&service, &binary).map_err(|_| 127)?;
    job.revalidate().map_err(|_| 136)?;
    if digest(&staged).map_err(|_| 137)? != expected {
        return Err(138);
    }
    if unsafe { DeleteService(service.0) } == 0 {
        return Err(128);
    }
    drop(service);
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let found = unsafe { OpenServiceW(manager.0, name().as_ptr(), SERVICE_QUERY_STATUS) };
        if found == 0
            && unsafe { windows_sys::Win32::Foundation::GetLastError() }
                == windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST
        {
            break;
        }
        if found != 0 {
            drop(Sc(found));
        }
        if Instant::now() >= until {
            return Err(131);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(manager);
    drop(staged);
    drop(job);
    // Only exact files/empty roots from this successful exclusive invocation.
    std::fs::remove_file(path).map_err(|_| 129)?;
    for parent in [
        roots.journal_parent(),
        roots.anchor_parent(),
        roots.job_parent(),
    ] {
        std::fs::remove_dir(parent.join(&id)).map_err(|_| 130)?;
    }
    Ok(())
}
