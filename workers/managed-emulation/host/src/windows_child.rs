//! Trusted fixed native child supervision. No shell, target bytes, arbitrary
//! command/path, inherited credentials or VM effect. This is NOT a security
//! boundary against malicious SYSTEM code or a Hyper-V job cancellation receipt.
//! CreateProcess/local image I/O are synchronous; the independent wait budget
//! covers child COM work, not a hard deadline for those OS calls themselves.
use crate::{
    windows_boot::HostBoot,
    windows_roots::{require_system, SystemJob, SystemRoots},
    Result,
};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    ptr::{null, null_mut},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        DuplicateHandle, GetLastError, ERROR_INSUFFICIENT_BUFFER, HANDLE, INVALID_HANDLE_VALUE,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    System::{
        Console::{GetStdHandle, STD_INPUT_HANDLE},
        JobObjects::*,
        SystemInformation::GetWindowsDirectoryW,
        SystemServices::JOB_OBJECT_QUERY,
        Threading::*,
    },
};

const ARG: &str = "--managed-native-provider-probe/v1";
#[cfg(feature = "owned-system-acceptance")]
const OWNED_EXIT: &str = "--owned-native-child-exit/v1";
#[cfg(feature = "owned-system-acceptance")]
const OWNED_HANG: &str = "--owned-native-child-wait/v1";
#[cfg(feature = "owned-system-acceptance")]
const OWNED_DESCENDANT: &str = "--owned-native-child-descendant/v1";
enum Action {
    Provider,
    #[cfg(feature = "owned-system-acceptance")]
    Exit,
    #[cfg(feature = "owned-system-acceptance")]
    Wait,
    #[cfg(feature = "owned-system-acceptance")]
    Descendant,
}
impl Action {
    fn argument(&self) -> &'static str {
        match self {
            Self::Provider => ARG,
            #[cfg(feature = "owned-system-acceptance")]
            Self::Exit => OWNED_EXIT,
            #[cfg(feature = "owned-system-acceptance")]
            Self::Wait => OWNED_HANG,
            #[cfg(feature = "owned-system-acceptance")]
            Self::Descendant => OWNED_DESCENDANT,
        }
    }
}

const POLICY: u32 = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;

fn wide(value: &OsStr) -> Result<Vec<u16>> {
    let mut value: Vec<u16> = value.encode_wide().collect();
    if value.is_empty()
        || value.len() > 2048
        || value.contains(&0)
        || value.contains(&(b'"' as u16))
    {
        return Err("Native child path budget/encoding");
    }
    value.push(0);
    Ok(value)
}
// Finite native observations only: never format OS messages, paths or argv.
fn creation_error() -> &'static str {
    match unsafe { GetLastError() } {
        2 => "Native child image not found by loader",
        5 => "Native child process creation access denied",
        6 => "Native child process creation invalid handle",
        50 => "Native child process creation unsupported",
        87 => "Native child process creation invalid parameter",
        193 => "Native child process image format rejected",
        1816 => "Native child process creation quota refused",
        _ => "Atomic native child creation failed; no retry",
    }
}
fn diagnostic_code(error: &str) -> i32 {
    match error {
        "Native child image not found by loader" => 1,
        "Native child process creation access denied" => 2,
        "Native child process creation invalid handle" => 3,
        "Native child process creation unsupported" => 4,
        "Native child process creation invalid parameter" => 5,
        "Native child process image format rejected" => 6,
        "Native child process creation quota refused" => 7,
        "Atomic native child creation failed; no retry" => 8,
        "Atomic native child job binding unavailable; no fallback" => 9,
        "Native child job policy rejected" => 10,
        "Native child job membership unavailable" => 11,
        "Native child resume failed; retained outcome unknown" => 12,
        "Native child exact job policy required" => 13,
        "Native child job accounting unavailable" => 14,
        "System data directory unavailable" => 20,
        "Local absolute system data path required" => 21,
        "Native child private environment required" => 22,
        "Exact protected native child required" => 23,
        "Single owned native process required" => 24,
        "Native child job reports zero processes" => 40,
        "Native child job reports two processes" => 41,
        "Native child job reports multiple processes" => 42,
        "Native child exact inherited job required" => 43,
        "Native child DLL policy unavailable" => 25,
        "Exclusive native child executable required" => 26,
        "Impersonated protected storage access forbidden" => 27,
        "LocalSystem broker required; no host settings changed" => 28,
        _ => 99,
    }
}
fn owned(raw: HANDLE) -> Result<OwnedHandle> {
    if raw == 0 || raw == INVALID_HANDLE_VALUE {
        return Err("Native child handle unavailable");
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(raw as _) })
}
fn raw(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle() as HANDLE
}
struct KillJob(OwnedHandle);
impl Drop for KillJob {
    fn drop(&mut self) {
        unsafe {
            TerminateJobObject(raw(&self.0), 124);
        }
    }
}
fn limits(job: HANDLE) -> Result<JOBOBJECT_EXTENDED_LIMIT_INFORMATION> {
    let mut value = unsafe { zeroed() };
    if unsafe {
        QueryInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&mut value as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            null_mut(),
        )
    } == 0
    {
        return Err("Native child job policy unavailable");
    }
    Ok(value)
}
fn require_policy(job: HANDLE) -> Result<()> {
    let value = limits(job)?;
    if value.BasicLimitInformation.LimitFlags != POLICY
        || value.BasicLimitInformation.ActiveProcessLimit != 1
    {
        return Err("Native child exact job policy required");
    }
    Ok(())
}
fn active(job: HANDLE) -> Result<u32> {
    let mut value: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
    if unsafe {
        QueryInformationJobObject(
            job,
            JobObjectBasicAccountingInformation,
            (&mut value as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            null_mut(),
        )
    } == 0
    {
        return Err("Native child job accounting unavailable");
    }
    Ok(value.ActiveProcesses)
}
struct Attributes {
    storage: Vec<usize>,
}
impl Attributes {
    fn new() -> Result<Self> {
        let mut bytes = 0;
        if unsafe { InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut bytes) } != 0
            || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
            || !(size_of::<usize>()..=16384).contains(&bytes)
        {
            return Err("Native child attribute size unavailable");
        }
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        if unsafe {
            InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 2, 0, &mut bytes)
        } == 0
        {
            return Err("Native child attributes unavailable");
        }
        Ok(Self { storage })
    }
    fn ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.ptr());
        }
    }
}

/// Process-only outcome after signalled process AND zero active job processes.
/// Exited(0) is not engine readiness, VM termination or permission to execute.
#[derive(Debug, PartialEq, Eq)]
pub enum ChildOutcome {
    Exited(u32),
    DeadlineStopped,
    CancelledStopped,
    CancelledBeforeStart,
}
struct Child<'job, 'roots> {
    job: KillJob,
    process: OwnedHandle,
    _thread: OwnedHandle,
    _image: File,
    storage: &'job SystemJob<'roots>,
    boot: HostBoot,
}
impl<'job, 'roots> Child<'job, 'roots> {
    fn start(storage: &'job SystemJob<'roots>, action: Action) -> Result<Self> {
        require_system()?;
        storage.revalidate()?;
        let boot = HostBoot::observe()?;
        let image = storage.native_child_file(false)?;
        let path = storage.native_child_path();
        let application = wide(path.as_os_str())?;
        let cwd = wide(
            path.parent()
                .ok_or("Native child protected directory required")?
                .as_os_str(),
        )?;
        let argument = action.argument();
        // Only a fixed library-owned action reaches here.
        let mut command = vec![b'"' as u16];
        command.extend_from_slice(&application[..application.len() - 1]);
        command.extend("\" ".encode_utf16());
        command.extend(argument.encode_utf16());
        command.push(0);
        let job = KillJob(owned(unsafe { CreateJobObjectW(null(), null()) })?);
        let mut policy: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        policy.BasicLimitInformation.LimitFlags = POLICY;
        policy.BasicLimitInformation.ActiveProcessLimit = 1;
        if unsafe {
            SetInformationJobObject(
                raw(&job.0),
                JobObjectExtendedLimitInformation,
                (&policy as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err("Native child job policy rejected");
        }
        require_policy(raw(&job.0))?;
        // The child receives QUERY only, not assignment, termination or policy rights.
        let mut query_handle = 0;
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                raw(&job.0),
                GetCurrentProcess(),
                &mut query_handle,
                JOB_OBJECT_QUERY,
                1,
                0,
            )
        } == 0
        {
            return Err("Native child query handle unavailable");
        }
        let query_handle = owned(query_handle)?;
        // Attribute values must outlive the list, including error returns.
        let inherited = [raw(&query_handle)];
        let jobs = [raw(&job.0)];
        let mut attributes = Attributes::new()?;
        if unsafe {
            UpdateProcThreadAttribute(
                attributes.ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                jobs.as_ptr().cast(),
                size_of::<HANDLE>(),
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err("Atomic native child job binding unavailable; no fallback");
        }
        if unsafe {
            UpdateProcThreadAttribute(
                attributes.ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                inherited.as_ptr().cast(),
                size_of::<HANDLE>(),
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err("Native child exact handle list unavailable");
        }
        let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        // stdin is an opaque QUERY-only job handle, never a stream or request input.
        // The exact handle list excludes every other inheritable parent handle.
        startup.StartupInfo.hStdInput = raw(&query_handle);
        startup.lpAttributeList = attributes.ptr();
        let environment = environment()?;
        let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
        require_system()?;
        storage.revalidate()?;
        HostBoot::observe()?.require_same(boot.id())?;
        if unsafe {
            CreateProcessW(
                application.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                1,
                CREATE_SUSPENDED
                    | CREATE_NO_WINDOW
                    | CREATE_UNICODE_ENVIRONMENT
                    | EXTENDED_STARTUPINFO_PRESENT,
                environment.as_ptr().cast(),
                cwd.as_ptr(),
                &startup.StartupInfo,
                &mut info,
            )
        } == 0
        {
            return Err(creation_error());
        }
        drop(attributes);
        let process = owned(info.hProcess)?;
        let thread = owned(info.hThread)?;
        let value = Self {
            job,
            process,
            _thread: thread,
            _image: image,
            storage,
            boot,
        };
        let mut member = 0;
        if unsafe { IsProcessInJob(raw(&value.process), raw(&value.job.0), &mut member) } == 0
            || member == 0
            || active(raw(&value.job.0))? != 1
        {
            return Err("Native child job membership unavailable");
        }
        value.require_current()?;
        if unsafe { ResumeThread(raw(&value._thread)) } != 1 {
            return Err("Native child resume failed; retained outcome unknown");
        }
        Ok(value)
    }
    fn require_current(&self) -> Result<()> {
        require_system()?;
        self.storage.revalidate()?;
        HostBoot::observe()?.require_same(self.boot.id())?;
        require_policy(raw(&self.job.0))
    }
    fn wait(self, cancel: &AtomicBool, budget: Duration) -> Result<ChildOutcome> {
        let deadline = Instant::now() + budget;
        loop {
            self.require_current()?;
            if cancel.load(Ordering::Acquire) {
                return self.stop(ChildOutcome::CancelledStopped);
            }
            match unsafe { WaitForSingleObject(raw(&self.process), 20) } {
                WAIT_OBJECT_0 => {
                    self.empty()?;
                    let mut code = 0;
                    if unsafe { GetExitCodeProcess(raw(&self.process), &mut code) } == 0 {
                        return Err("Native child exit code unavailable");
                    }
                    self.require_current()?;
                    return Ok(ChildOutcome::Exited(code));
                }
                WAIT_TIMEOUT => {}
                _ => return Err("Native child process wait unavailable; no exit inferred"),
            }
            if Instant::now() >= deadline {
                return self.stop(ChildOutcome::DeadlineStopped);
            }
        }
    }
    fn stop(&self, outcome: ChildOutcome) -> Result<ChildOutcome> {
        if unsafe { TerminateJobObject(raw(&self.job.0), 124) } == 0
            || unsafe { WaitForSingleObject(raw(&self.process), 2000) } != WAIT_OBJECT_0
        {
            return Err("Native child termination unconfirmed; retain operation state");
        }
        self.empty()?;
        self.require_current()?;
        Ok(outcome)
    }
    fn empty(&self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if active(raw(&self.job.0))? == 0 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("Native child job not drained; retain operation state");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
fn environment() -> Result<Vec<u16>> {
    let mut root = [0u16; 1024];
    let used = unsafe { GetWindowsDirectoryW(root.as_mut_ptr(), root.len() as u32) } as usize;
    if used < 3 || used >= root.len() {
        return Err("Native Windows directory unavailable");
    }
    // Known-folder resolution expands the OS's SystemDrive-based defaults.
    // Derive it from the native Windows directory, never the caller environment.
    if !((root[0] >= b'A' as u16 && root[0] <= b'Z' as u16)
        || (root[0] >= b'a' as u16 && root[0] <= b'z' as u16))
        || root[1] != b':' as u16
        || root[2] != b'\\' as u16
    {
        return Err("Native local Windows directory required");
    }
    let mut value: Vec<u16> = "SystemDrive=".encode_utf16().collect();
    value.extend_from_slice(&root[..2]);
    value.push(0);
    value.extend("SystemRoot=".encode_utf16());
    value.extend_from_slice(&root[..used]);
    value.extend([0, 0]);
    Ok(value)
}
fn require_environment(entries: Vec<(OsString, OsString)>, expected: &[u16]) -> Result<()> {
    let mut actual: Vec<Vec<u16>> = entries
        .into_iter()
        .map(|(key, value)| {
            let mut entry: Vec<u16> = key.encode_wide().collect();
            entry.push(b'=' as u16);
            entry.extend(value.encode_wide());
            entry
        })
        .collect();
    actual.sort();
    let expected: Vec<Vec<u16>> = expected
        .split(|c| *c == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| entry.to_vec())
        .collect();
    if actual != expected {
        return Err("Native child private environment required");
    }
    Ok(())
}
/// No automatic installation or readiness: the future protected installer must
/// stage the reviewed native executable in this fixed per-job role first.
pub fn probe_local_provider(storage: &SystemJob<'_>, cancel: &AtomicBool) -> Result<ChildOutcome> {
    require_system()?;
    storage.revalidate()?;
    if cancel.load(Ordering::Acquire) {
        return Ok(ChildOutcome::CancelledBeforeStart);
    }
    Child::start(storage, Action::Provider)?.wait(cancel, Duration::from_secs(10))
}
fn child_identity<T>(work: impl FnOnce() -> T) -> Result<T> {
    require_system()?;
    let boot = HostBoot::observe()?;
    let roots = SystemRoots::open_existing()?;
    let path = std::env::current_exe().map_err(|_| "Native child executable unavailable")?;
    let parent = path.parent().ok_or("Native child parent required")?;
    let id = parent
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("Native child job required")?;
    crate::exact_hex::<16>(id)?;
    let job = roots.open_job(id)?;
    if path != job.native_child_path() {
        return Err("Exact protected native child required");
    }
    let _image = job.native_child_file(false)?;
    let supervision = owned(unsafe { GetStdHandle(STD_INPUT_HANDLE) })?;
    let mut member = 0;
    if unsafe { IsProcessInJob(GetCurrentProcess(), raw(&supervision), &mut member) } == 0
        || member == 0
    {
        return Err("Native child exact inherited job required");
    }
    require_policy(raw(&supervision))?;
    match active(raw(&supervision))? {
        1 => {}
        0 => return Err("Native child job reports zero processes"),
        2 => return Err("Native child job reports two processes"),
        _ => return Err("Native child job reports multiple processes"),
    }
    // No inherited provider tokens/options, PATH, HOME, TEMP or boot keys.
    require_environment(std::env::vars_os().collect(), &environment()?)?;
    if unsafe {
        SetDefaultDllDirectories(
            windows_sys::Win32::System::LibraryLoader::LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    } == 0
    {
        return Err("Native child DLL policy unavailable");
    }
    let result = work();
    require_system()?;
    job.revalidate()?;
    HostBoot::observe()?.require_same(boot.id())?;
    Ok(result)
}
use windows_sys::Win32::System::LibraryLoader::SetDefaultDllDirectories;
/// Finite trusted child mode only. Unrecognized arguments retain the executable's
/// existing refusal path. No stdin parsing, target loading or VM management effect.
pub fn dispatch() -> Option<i32> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 2 {
        return None;
    }
    let argument = &args[1];
    let provider = argument == OsStr::new(ARG);
    #[cfg(feature = "owned-system-acceptance")]
    let owned = [OWNED_EXIT, OWNED_HANG, OWNED_DESCENDANT]
        .iter()
        .any(|v| argument == OsStr::new(v));
    #[cfg(not(feature = "owned-system-acceptance"))]
    let owned = false;
    if !provider && !owned {
        return None;
    }
    Some(
        match child_identity(|| {
            if provider {
                return Some(
                    if crate::windows_hyperv::HyperVManagement::connect().is_ok() {
                        0
                    } else {
                        65
                    },
                );
            }
            #[cfg(feature = "owned-system-acceptance")]
            {
                if argument == OsStr::new(OWNED_EXIT) {
                    return Some(7);
                }
                if argument == OsStr::new(OWNED_HANG) {
                    loop {
                        std::thread::sleep(Duration::from_secs(60));
                    }
                }
                if argument == OsStr::new(OWNED_DESCENDANT) {
                    let Ok(executable) = std::env::current_exe() else {
                        return Some(67);
                    };
                    let mut command = std::process::Command::new(executable);
                    command.arg("owned-forbidden-descendant");
                    return Some(match command.spawn() {
                        Err(error) if error.raw_os_error() == Some(1816) => 8,
                        Ok(mut unexpected) => {
                            let _ = unexpected.kill();
                            let _ = unexpected.wait();
                            67
                        }
                        Err(_) => 67,
                    });
                }
            }
            Some(66)
        }) {
            Ok(Some(code)) => code,
            Err(error) => 100 + diagnostic_code(error),
            Ok(None) => 66,
        },
    )
}

/// Real protected file/process tests only; never invokes the Hyper-V provider.
#[cfg(feature = "owned-system-acceptance")]
pub(crate) fn owned_acceptance(
    storage: &SystemJob<'_>,
    source: &File,
) -> std::result::Result<(), i32> {
    let mut stage = 150;
    let result = (|| -> Result<()> {
        use std::io::{Read, Seek, SeekFrom, Write};
        use windows_sys::Win32::Security::{ImpersonateSelf, RevertToSelf, SecurityImpersonation};
        let expected = crate::windows_service::digest(source)?;
        let mut source = source
            .try_clone()
            .map_err(|_| "Owned native source handle unavailable")?;
        source
            .seek(SeekFrom::Start(0))
            .map_err(|_| "Owned native source seek failed")?;
        let size = source
            .metadata()
            .map_err(|_| "Owned native source metadata unavailable")?
            .len();
        if size == 0 || size > 64 * 1024 * 1024 {
            return Err("Owned native source budget");
        }
        let mut target = storage.native_child_file(true)?;
        let copied = std::io::copy(&mut source.take(size + 1), &mut target)
            .map_err(|_| "Owned native staging failed")?;
        if copied != size {
            return Err("Owned native staging length changed");
        }
        target
            .flush()
            .map_err(|_| "Owned native staging flush failed")?;
        target
            .sync_all()
            .map_err(|_| "Owned native staging sync failed")?;
        drop(target);
        let image = storage.native_child_file(false)?;
        if crate::windows_service::digest(&image)? != expected {
            return Err("Owned native image changed");
        }
        let no = AtomicBool::new(false);
        let yes = AtomicBool::new(true);
        stage = 151;
        if probe_local_provider(storage, &yes)? != ChildOutcome::CancelledBeforeStart {
            return Err("Owned cancelled probe launched");
        }
        stage = 152;
        expect_owned_outcome(
            Child::start(storage, Action::Exit)?.wait(&no, Duration::from_secs(5))?,
            ChildOutcome::Exited(7),
            &mut stage,
        )?;
        stage = 153;
        expect_owned_outcome(
            Child::start(storage, Action::Descendant)?.wait(&no, Duration::from_secs(5))?,
            ChildOutcome::Exited(8),
            &mut stage,
        )?;
        stage = 154;
        expect_owned_outcome(
            Child::start(storage, Action::Wait)?.wait(&no, Duration::from_millis(250))?,
            ChildOutcome::DeadlineStopped,
            &mut stage,
        )?;
        stage = 155;
        expect_owned_outcome(
            Child::start(storage, Action::Wait)?.wait(&yes, Duration::from_secs(5))?,
            ChildOutcome::CancelledStopped,
            &mut stage,
        )?;
        stage = 156;
        let child = Child::start(storage, Action::Wait)?;
        let process = child
            .process
            .try_clone()
            .map_err(|_| "Owned native process retain failed")?;
        let job = child
            .job
            .0
            .try_clone()
            .map_err(|_| "Owned native job retain failed")?;
        drop(child);
        observed_stopped(&process, &job)?;
        drop(process);
        drop(job);
        stage = 157;
        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                if unsafe { RevertToSelf() } == 0 {
                    std::process::abort();
                }
            }
        }
        {
            if unsafe { ImpersonateSelf(SecurityImpersonation) } == 0 {
                return Err("Owned native impersonation unavailable");
            }
            let _revert = Revert;
            if Child::start(storage, Action::Exit).err()
                != Some("Impersonated protected storage access forbidden")
            {
                return Err("Owned impersonated native start accepted");
            }
        }
        stage = 158;
        let child = Child::start(storage, Action::Wait)?;
        let process = child
            .process
            .try_clone()
            .map_err(|_| "Owned native process retain failed")?;
        let job = child
            .job
            .0
            .try_clone()
            .map_err(|_| "Owned native job retain failed")?;
        {
            if unsafe { ImpersonateSelf(SecurityImpersonation) } == 0 {
                return Err("Owned native impersonation unavailable");
            }
            let _revert = Revert;
            if child.wait(&no, Duration::from_secs(5)).err()
                != Some("Impersonated protected storage access forbidden")
            {
                return Err("Owned impersonated native wait accepted");
            }
        }
        observed_stopped(&process, &job)?;
        drop(process);
        drop(job);
        stage = 159;
        if crate::windows_service::digest(&image)? != expected {
            return Err("Owned native image changed after execution");
        }
        storage.revalidate()?;
        drop(image);
        std::fs::remove_file(storage.native_child_path())
            .map_err(|_| "Owned native image cleanup failed")?;
        if Child::start(storage, Action::Exit).err()
            != Some("Exclusive native child executable required")
        {
            return Err("Missing native child image accepted");
        }
        Ok(())
    })();
    result.map_err(|error| {
        if stage < 1000 {
            stage * 1000 + diagnostic_code(error)
        } else {
            stage
        }
    })
}

#[cfg(feature = "owned-system-acceptance")]
fn expect_owned_outcome(
    actual: ChildOutcome,
    expected: ChildOutcome,
    stage: &mut i32,
) -> Result<()> {
    if actual == expected {
        return Ok(());
    }
    *stage = *stage * 1000
        + match actual {
            ChildOutcome::Exited(code) => code.min(999) as i32,
            ChildOutcome::DeadlineStopped => 900,
            ChildOutcome::CancelledStopped => 901,
            ChildOutcome::CancelledBeforeStart => 902,
        };
    Err("Owned native child outcome mismatch")
}
#[cfg(feature = "owned-system-acceptance")]
fn observed_stopped(process: &OwnedHandle, job: &OwnedHandle) -> Result<()> {
    if unsafe { WaitForSingleObject(raw(process), 2000) } != WAIT_OBJECT_0 {
        return Err("Owned native child drop did not stop process");
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while active(raw(job))? != 0 {
        if Instant::now() >= deadline {
            return Err("Owned native child drop did not drain job");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_failure_categories_are_finite_and_unknown_is_not_success() {
        assert_eq!(
            diagnostic_code("Native child process creation access denied"),
            2
        );
        assert_eq!(diagnostic_code("System data directory unavailable"), 20);
        assert_eq!(diagnostic_code("untrusted path, command or OS message"), 99);
    }
    #[cfg(feature = "owned-system-acceptance")]
    #[test]
    fn owned_outcome_mismatch_retains_exit_without_accepting_matching_numbers() {
        let mut stage = 152;
        expect_owned_outcome(ChildOutcome::Exited(7), ChildOutcome::Exited(7), &mut stage).unwrap();
        assert_eq!(stage, 152);
        assert!(expect_owned_outcome(
            ChildOutcome::Exited(120),
            ChildOutcome::Exited(7),
            &mut stage
        )
        .is_err());
        assert_eq!(stage, 152120);
        let mut stage = 154;
        assert!(expect_owned_outcome(
            ChildOutcome::Exited(0),
            ChildOutcome::DeadlineStopped,
            &mut stage
        )
        .is_err());
        assert_eq!(stage, 154000);
        let mut stage = 153;
        assert!(expect_owned_outcome(
            ChildOutcome::Exited(u32::MAX),
            ChildOutcome::Exited(8),
            &mut stage
        )
        .is_err());
        assert_eq!(stage, 153999);
    }
    #[test]
    fn child_path_encoding_is_bounded_and_unambiguous() {
        assert_eq!(
            wide(OsStr::new(r"C:\owned path\native-child.exe"))
                .unwrap()
                .last(),
            Some(&0)
        );
        for value in ["", "a\0b", "a\"b", &"a".repeat(2049)] {
            assert!(wide(OsStr::new(value)).is_err());
        }
    }
    #[test]
    fn explicit_native_environment_contains_only_observed_os_roots() {
        let value = environment().unwrap();
        assert!(value.starts_with(&"SystemDrive=".encode_utf16().collect::<Vec<_>>()));
        assert!(value.ends_with(&[0, 0]));
        assert_eq!(value.iter().filter(|x| **x == 0).count(), 3);
        let entries = value
            .split(|c| *c == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf16(s).unwrap())
            .map(|s| {
                let (key, value) = s.split_once('=').unwrap();
                (OsString::from(key), OsString::from(value))
            })
            .collect::<Vec<_>>();
        require_environment(entries.clone(), &value).unwrap();
        let mut extra = entries.clone();
        extra.push((OsString::from("PATH"), OsString::from("untrusted")));
        assert!(require_environment(extra, &value).is_err());
        assert!(require_environment(entries[1..].to_vec(), &value).is_err());
        let mut changed = entries;
        changed[0].1 = OsString::from("not-an-os-drive");
        assert!(require_environment(changed, &value).is_err());
    }
    #[test]
    fn exact_job_limits_are_read_back_and_empty_job_is_not_a_process_exit() {
        let job = KillJob(owned(unsafe { CreateJobObjectW(null(), null()) }).unwrap());
        assert_eq!(active(raw(&job.0)).unwrap(), 0);
        assert!(require_policy(raw(&job.0)).is_err());
        let mut policy: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        policy.BasicLimitInformation.LimitFlags = POLICY;
        policy.BasicLimitInformation.ActiveProcessLimit = 1;
        assert_ne!(
            unsafe {
                SetInformationJobObject(
                    raw(&job.0),
                    JobObjectExtendedLimitInformation,
                    (&policy as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            },
            0
        );
        require_policy(raw(&job.0)).unwrap();
        assert_eq!(active(raw(&job.0)).unwrap(), 0);
    }
}
