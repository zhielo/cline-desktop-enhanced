//! Native, local-only caller authentication for the future managed service.
//! Fixed inert exchange only: no service installation, VM operation, target,
//! client-selected path/command, readiness promotion or privilege grant.
use crate::{windows_roots::require_system, Result};
use std::{
    ffi::{c_void, OsStr},
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        GetLastError, LocalFree, ERROR_IO_PENDING, ERROR_NO_TOKEN, ERROR_PIPE_CONNECTED, HANDLE,
        INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    },
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SE_FILE_OBJECT,
        },
        CreateWellKnownSid, GetTokenInformation, IsValidSid, RevertToSelf, TokenSessionId,
        TokenStatistics, TokenUser, WinLocalSystemSid, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_INFORMATION_CLASS, TOKEN_QUERY,
        TOKEN_STATISTICS, TOKEN_USER,
    },
    Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
        FILE_READ_DATA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, OPEN_EXISTING, READ_CONTROL,
        SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, SYNCHRONIZE,
    },
    System::{
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, ImpersonateNamedPipeClient,
            SetNamedPipeHandleState, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_TYPE_MESSAGE, PIPE_WAIT,
        },
        Threading::{
            CreateEventW, GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
            WaitForMultipleObjects, WaitForSingleObject,
        },
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
    },
};

#[cfg(any(test, feature = "owned-system-acceptance"))]
use windows_sys::Win32::System::Threading::SetEvent;
#[cfg(feature = "owned-system-acceptance")]
use windows_sys::Win32::{
    Foundation::ERROR_PIPE_NOT_CONNECTED, System::Pipes::DisconnectNamedPipe,
};

const PIPE: &str = r"\\.\pipe\ClineEnhancedManagedProbe.v1";
const DEADLINE: Duration = Duration::from_secs(5);
// Never GENERIC_WRITE: it also grants FILE_CREATE_PIPE_INSTANCE on pipes.
const CLIENT_ACCESS: u32 =
    READ_CONTROL | SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES;
const REQUEST_SIZE: usize = 33;
const RESPONSE_SIZE: usize = 34;

struct LocalMemory(*mut c_void);
impl Drop for LocalMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Sid {
    words: [u64; 9],
    size: usize,
}
impl Sid {
    fn system() -> Result<Self> {
        let mut value = Self {
            words: [0; 9],
            size: 72,
        };
        let mut length = 72;
        if unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                null_mut(),
                value.words.as_mut_ptr().cast(),
                &mut length,
            )
        } == 0
            || length != 12
        {
            return Err("IPC SYSTEM principal unavailable");
        }
        value.size = length as usize;
        Ok(value)
    }
    fn from_bounded(buffer: &[u64], used: usize, sid: *mut c_void, floor: usize) -> Result<Self> {
        let begin = buffer.as_ptr() as usize;
        let at = sid as usize;
        if at < begin + floor || at.checked_add(8).ok_or("IPC SID boundary")? > begin + used {
            return Err("IPC SID boundary");
        }
        let count = unsafe { *((at as *const u8).add(1)) } as usize;
        let size = 8 + count * 4;
        if count > 15 || at + size > begin + used || unsafe { IsValidSid(sid) } == 0 {
            return Err("IPC SID boundary");
        }
        let mut value = Self {
            words: [0; 9],
            size,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                sid.cast::<u8>(),
                value.words.as_mut_ptr().cast::<u8>(),
                size,
            );
        }
        Ok(value)
    }
    fn text(&self) -> Result<String> {
        let mut output = null_mut();
        if unsafe { ConvertSidToStringSidW(self.words.as_ptr() as _, &mut output) } == 0 {
            return Err("IPC principal unavailable");
        }
        let _memory = LocalMemory(output.cast());
        let mut length = 0;
        while length < 184 && unsafe { *output.add(length) } != 0 {
            length += 1;
        }
        if length == 184 {
            return Err("IPC principal budget");
        }
        String::from_utf16(unsafe { std::slice::from_raw_parts(output, length) })
            .map_err(|_| "IPC principal unavailable")
    }
}

/// OS-observed principal/logon/session, not a client assertion or an approval.
/// The future installer must independently authorize and protect registration.
/// No constructor accepts a SID, PID, token value, session, string or JSON.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientScope {
    user: Sid,
    authentication: (u32, i32),
    session: u32,
}

fn require_unimpersonated() -> Result<()> {
    let mut token = 0;
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } != 0 {
        drop(unsafe { OwnedHandle::from_raw_handle(token as _) });
        return Err("IPC caller observation must not be impersonated");
    }
    if unsafe { GetLastError() } != ERROR_NO_TOKEN {
        return Err("IPC thread identity unavailable");
    }
    Ok(())
}

fn scalar<T>(token: HANDLE, kind: TOKEN_INFORMATION_CLASS) -> Result<T> {
    let mut value: T = unsafe { zeroed() };
    let mut needed = 0;
    if unsafe {
        GetTokenInformation(
            token,
            kind,
            (&mut value as *mut T).cast(),
            size_of::<T>() as u32,
            &mut needed,
        )
    } == 0
        || needed != size_of::<T>() as u32
    {
        return Err("IPC token scalar unavailable");
    }
    Ok(value)
}

impl ClientScope {
    pub fn observe_current_process() -> Result<Self> {
        require_unimpersonated()?;
        let mut token = 0;
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err("IPC process identity unavailable");
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token as _) };
        Self::from_token(token.as_raw_handle() as HANDLE)
    }
    fn from_token(token: HANDLE) -> Result<Self> {
        let mut buffer = [0u64; 128];
        let mut used = 0;
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size_of::<[u64; 128]>() as u32,
                &mut used,
            )
        } == 0
            || used < size_of::<TOKEN_USER>() as u32
            || used > size_of::<[u64; 128]>() as u32
        {
            return Err("IPC user token budget");
        }
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let user = Sid::from_bounded(
            &buffer,
            used as usize,
            user.User.Sid,
            size_of::<TOKEN_USER>(),
        )?;
        let stats: TOKEN_STATISTICS = scalar(token, TokenStatistics)?;
        let session = scalar(token, TokenSessionId)?;
        Ok(Self {
            user,
            authentication: (
                stats.AuthenticationId.LowPart,
                stats.AuthenticationId.HighPart,
            ),
            session,
        })
    }
    fn require(&self, actual: &Self) -> Result<()> {
        if self != actual {
            return Err("IPC client scope mismatch");
        }
        Ok(())
    }
}

struct RevertGuard(bool);
impl RevertGuard {
    fn finish(mut self) -> Result<()> {
        // Failure cannot unwind into privileged work under the wrong identity.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
        self.0 = false;
        require_unimpersonated()
    }
}
impl Drop for RevertGuard {
    fn drop(&mut self) {
        if self.0 && unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

fn authenticate_client(pipe: HANDLE, expected: &ClientScope) -> Result<()> {
    require_unimpersonated()?;
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err("IPC client impersonation unavailable");
    }
    let revert = RevertGuard(true);
    let observed = (|| {
        let mut token = 0;
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
            return Err("IPC client token unavailable");
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token as _) };
        expected.require(&ClientScope::from_token(token.as_raw_handle() as HANDLE)?)
    })();
    revert.finish()?;
    observed
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}
fn owned(handle: HANDLE) -> Result<OwnedHandle> {
    if handle == 0 || handle == INVALID_HANDLE_VALUE {
        return Err("IPC handle unavailable");
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as _) })
}
fn raw(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle() as HANDLE
}

/// Unnamed service-stop event; no externally supplied event name/handle.
pub(crate) struct Cancellation(OwnedHandle);
impl Cancellation {
    #[cfg(any(test, feature = "owned-system-acceptance"))]
    pub(crate) fn new() -> Result<Self> {
        Ok(Self(owned(unsafe { CreateEventW(null(), 1, 0, null()) })?))
    }
    #[cfg(any(test, feature = "owned-system-acceptance"))]
    pub(crate) fn signal(&self) {
        if unsafe { SetEvent(raw(&self.0)) } == 0 {
            std::process::abort();
        }
    }
    pub(crate) fn cancelled(&self) -> bool {
        (unsafe { WaitForSingleObject(raw(&self.0), 0) }) == WAIT_OBJECT_0
    }
}

struct Pending<'a> {
    pipe: &'a OwnedHandle,
    event: OwnedHandle,
    overlap: Box<OVERLAPPED>,
    active: bool,
    cancellation: Option<&'a Cancellation>,
}
impl<'a> Pending<'a> {
    fn controlled(pipe: &'a OwnedHandle, cancellation: Option<&'a Cancellation>) -> Result<Self> {
        if cancellation.is_some_and(Cancellation::cancelled) {
            return Err("IPC operation cancelled");
        }
        let event = owned(unsafe { CreateEventW(null(), 1, 0, null()) })?;
        let mut overlap: Box<OVERLAPPED> = Box::new(unsafe { zeroed() });
        overlap.hEvent = raw(&event);
        Ok(Self {
            pipe,
            event,
            overlap,
            active: false,
            cancellation,
        })
    }
    fn finish(&mut self, immediate: i32, deadline: Instant, connect: bool) -> Result<usize> {
        if immediate == 0 {
            let error = unsafe { GetLastError() };
            if connect && error == ERROR_PIPE_CONNECTED {
                return Ok(0);
            }
            if error != ERROR_IO_PENDING {
                return Err("IPC operation rejected");
            }
            self.active = true;
            let remaining = deadline.saturating_duration_since(Instant::now());
            let millis = remaining.as_millis().min(5000) as u32;
            if remaining.is_zero() {
                return Err("IPC operation deadline");
            }
            let observed = if let Some(stop) = self.cancellation {
                let handles = [raw(&stop.0), raw(&self.event)];
                let result = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, millis) };
                if result == WAIT_OBJECT_0 {
                    return Err("IPC operation cancelled");
                }
                result.checked_sub(1).unwrap_or(u32::MAX)
            } else {
                unsafe { WaitForSingleObject(raw(&self.event), millis) }
            };
            if observed != WAIT_OBJECT_0 {
                return Err("IPC operation deadline");
            }
        }
        let mut transferred = 0;
        let ok =
            unsafe { GetOverlappedResult(raw(self.pipe), &*self.overlap, &mut transferred, 0) };
        self.active = false; // completed (success or error), no pending buffer
        if ok == 0 {
            return Err("IPC operation incomplete");
        }
        if Instant::now() >= deadline {
            return Err("IPC operation deadline");
        }
        if self.cancellation.is_some_and(Cancellation::cancelled) {
            return Err("IPC operation cancelled");
        }
        Ok(transferred as usize)
    }
}
impl Drop for Pending<'_> {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                CancelIoEx(raw(self.pipe), &*self.overlap);
            }
            // Retain the OVERLAPPED and its buffer until completion. Never free
            // live async storage; if cancellation cannot drain, terminate this
            // process rather than continue privileged work or use freed memory.
            if unsafe { WaitForSingleObject(raw(&self.event), 1000) } != WAIT_OBJECT_0 {
                std::process::abort();
            }
            let mut count = 0;
            unsafe {
                GetOverlappedResult(raw(self.pipe), &*self.overlap, &mut count, 0);
            }
        }
    }
}
fn read(pipe: &OwnedHandle, buffer: &mut [u8], deadline: Instant) -> Result<usize> {
    read_controlled(pipe, buffer, deadline, None)
}
fn read_controlled(
    pipe: &OwnedHandle,
    buffer: &mut [u8],
    deadline: Instant,
    cancel: Option<&Cancellation>,
) -> Result<usize> {
    let mut op = Pending::controlled(pipe, cancel)?;
    let ok = unsafe {
        ReadFile(
            raw(pipe),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            null_mut(),
            &mut *op.overlap,
        )
    };
    op.finish(ok, deadline, false)
}
fn write(pipe: &OwnedHandle, buffer: &[u8], deadline: Instant) -> Result<()> {
    write_controlled(pipe, buffer, deadline, None)
}
fn write_controlled(
    pipe: &OwnedHandle,
    buffer: &[u8],
    deadline: Instant,
    cancel: Option<&Cancellation>,
) -> Result<()> {
    let mut op = Pending::controlled(pipe, cancel)?;
    let ok = unsafe {
        WriteFile(
            raw(pipe),
            buffer.as_ptr(),
            buffer.len() as u32,
            null_mut(),
            &mut *op.overlap,
        )
    };
    if op.finish(ok, deadline, false)? != buffer.len() {
        return Err("IPC short message");
    }
    Ok(())
}

/// One bounded local inert connection. Not a running SCM service or installer.
pub struct ProbeServer {
    pipe: OwnedHandle,
    scope: ClientScope,
}
impl ProbeServer {
    pub fn bind(scope: ClientScope) -> Result<Self> {
        require_system()?;
        Self::bind_at(PIPE, scope)
    }
    fn bind_at(name: &str, scope: ClientScope) -> Result<Self> {
        let owner = ClientScope::observe_current_process()?.user.text()?;
        let client = scope.user.text()?;
        let owner_access = if owner == "S-1-5-18" {
            String::new()
        } else {
            format!("(A;;FA;;;{owner})")
        };
        let extra = if client == "S-1-5-18" || client == owner {
            String::new()
        } else {
            format!("(A;;0x00120103;;;{client})")
        };
        let sddl = wide(&format!("O:{owner}D:P(A;;FA;;;SY){owner_access}{extra}"));
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err("IPC descriptor unavailable");
        }
        let _descriptor = LocalMemory(descriptor);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let pipe = owned(unsafe {
            CreateNamedPipeW(
                wide(name).as_ptr(),
                FILE_READ_DATA
                    | FILE_WRITE_DATA
                    | FILE_FLAG_FIRST_PIPE_INSTANCE
                    | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                64,
                64,
                0,
                &attributes,
            )
        })?;
        Ok(Self { pipe, scope })
    }
    pub fn serve_once(self) -> Result<()> {
        require_system()?;
        self.exchange(Instant::now() + DEADLINE)
    }
    #[cfg(feature = "owned-system-acceptance")]
    pub(crate) fn serve_controlled(&self, cancel: &Cancellation) -> Result<()> {
        require_system()?;
        self.exchange_controlled(Instant::now() + DEADLINE, Some(cancel))
    }
    #[cfg(feature = "owned-system-acceptance")]
    pub(crate) fn reset_connection(&self) -> Result<()> {
        require_system()?;
        if unsafe { DisconnectNamedPipe(raw(&self.pipe)) } == 0
            && unsafe { GetLastError() } != ERROR_PIPE_NOT_CONNECTED
        {
            return Err("IPC connection reset failed");
        }
        Ok(())
    }
    fn exchange(&self, deadline: Instant) -> Result<()> {
        self.exchange_controlled(deadline, None)
    }
    fn exchange_controlled(&self, deadline: Instant, cancel: Option<&Cancellation>) -> Result<()> {
        let mut op = Pending::controlled(&self.pipe, cancel)?;
        let ok = unsafe { ConnectNamedPipe(raw(&self.pipe), &mut *op.overlap) };
        op.finish(ok, deadline, true)?;
        drop(op);
        let mut request = [0; REQUEST_SIZE];
        if read_controlled(&self.pipe, &mut request, deadline, cancel)? != REQUEST_SIZE
            || request[0] != 1
        {
            return Err("IPC fixed request required");
        }
        authenticate_client(raw(&self.pipe), &self.scope)?;
        let mut response = [0; RESPONSE_SIZE];
        response[..REQUEST_SIZE].copy_from_slice(&request);
        // Byte 33 is fixed zero: no installation/readiness/VM claim.
        write_controlled(&self.pipe, &response, deadline, cancel)?;
        let mut acknowledgement = [0];
        if read_controlled(&self.pipe, &mut acknowledgement, deadline, cancel)? != 1
            || acknowledgement != [1]
        {
            return Err("IPC acknowledgement missing");
        }
        Ok(())
    }
}

fn require_server_owner(pipe: &OwnedHandle, expected: &Sid) -> Result<()> {
    let mut owner = null_mut();
    let mut descriptor = null_mut();
    if unsafe {
        GetSecurityInfo(
            raw(pipe),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    } != 0
    {
        return Err("IPC server owner unavailable");
    }
    let _descriptor = LocalMemory(descriptor);
    if owner.is_null() || unsafe { IsValidSid(owner) } == 0 {
        return Err("IPC server owner unavailable");
    }
    // The descriptor was allocated/validated by Windows, not client bytes.
    if unsafe { windows_sys::Win32::Security::EqualSid(owner, expected.words.as_ptr() as _) } == 0 {
        return Err("IPC server owner mismatch");
    }
    Ok(())
}
fn client_at(name: &str, expected_owner: &Sid, request_version: u8) -> Result<()> {
    client_with_qos(
        name,
        expected_owner,
        request_version,
        SECURITY_IDENTIFICATION,
    )
}
fn client_with_qos(name: &str, expected_owner: &Sid, request_version: u8, qos: u32) -> Result<()> {
    require_unimpersonated()?;
    let deadline = Instant::now() + DEADLINE;
    let pipe = owned(unsafe {
        CreateFileW(
            wide(name).as_ptr(),
            CLIENT_ACCESS,
            0,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | qos,
            0,
        )
    })?;
    require_server_owner(&pipe, expected_owner)?;
    let mode = PIPE_READMODE_MESSAGE;
    if unsafe { SetNamedPipeHandleState(raw(&pipe), &mode, null(), null()) } == 0 {
        return Err("IPC message mode unavailable");
    }
    let mut request = [0; REQUEST_SIZE];
    request[0] = request_version;
    getrandom::fill(&mut request[1..]).map_err(|_| "IPC nonce unavailable")?;
    write(&pipe, &request, deadline)?;
    let mut response = [0; RESPONSE_SIZE];
    if read(&pipe, &mut response, deadline)? != RESPONSE_SIZE
        || response[..REQUEST_SIZE] != request
        || response[REQUEST_SIZE] != 0
    {
        return Err("IPC fixed response required");
    }
    write(&pipe, &[1], deadline)
}

/// Explicit inert client probe of the fixed local SYSTEM-owned endpoint. No
/// auto-connect/polling, retries, installation, execution or readiness claim.
pub fn probe_system_server() -> Result<()> {
    client_at(PIPE, &Sid::system()?, 1)
}

/// CI-owned native acceptance, not an application service or readiness test.
#[cfg(feature = "owned-system-acceptance")]
pub fn owned_system_acceptance() -> Result<()> {
    require_system()?;
    let scope = ClientScope::observe_current_process()?;
    let server = ProbeServer::bind(scope)?;
    let worker = std::thread::spawn(move || server.serve_once());
    let result = probe_system_server();
    let served = worker.join().map_err(|_| "IPC owned server failed")?;
    result?;
    served?;
    require_system()
}

#[cfg(feature = "owned-system-acceptance")]
pub(crate) fn owned_silent_client() -> Result<OwnedHandle> {
    require_system()?;
    let pipe = owned(unsafe {
        CreateFileW(
            wide(PIPE).as_ptr(),
            CLIENT_ACCESS,
            0,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            0,
        )
    })?;
    require_server_owner(&pipe, &Sid::system()?)?;
    Ok(pipe)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn name() -> String {
        let mut id = [0; 16];
        getrandom::fill(&mut id).unwrap();
        format!(r"\\.\pipe\ClineOwnedIpcTest-{}", hex::encode(id))
    }
    fn scope() -> ClientScope {
        ClientScope::observe_current_process().unwrap()
    }
    #[test]
    fn scopes_bind_real_user_logon_and_session_without_impersonation() {
        let original = scope();
        assert!(original.require(&scope()).is_ok());
        let mut other = original.clone();
        other.session ^= 1;
        assert!(original.require(&other).is_err());
        other = original.clone();
        other.authentication.0 ^= 1;
        assert!(original.require(&other).is_err());
        other = original.clone();
        other.user.words[1] ^= 1;
        assert!(original.require(&other).is_err());
        assert!(require_unimpersonated().is_ok());
    }
    #[test]
    fn actual_message_pipe_authenticates_and_reverts_before_return() {
        let scope = scope();
        let name = name();
        let owner = scope.user.clone();
        let server = ProbeServer::bind_at(&name, scope).unwrap();
        let thread = std::thread::spawn(move || server.exchange(Instant::now() + DEADLINE));
        client_at(&name, &owner, 1).unwrap();
        thread.join().unwrap().unwrap();
        require_unimpersonated().unwrap();
    }
    #[test]
    fn actual_pipe_denies_wrong_logon_without_response_or_token_leak() {
        let mut expected = scope();
        let owner = expected.user.clone();
        expected.authentication.0 ^= 1;
        let name = name();
        let server = ProbeServer::bind_at(&name, expected).unwrap();
        let thread = std::thread::spawn(move || {
            let result = server.exchange(Instant::now() + DEADLINE);
            require_unimpersonated().unwrap();
            result
        });
        assert!(client_at(&name, &owner, 1).is_err());
        assert_eq!(
            thread.join().unwrap().err(),
            Some("IPC client scope mismatch")
        );
    }
    #[test]
    fn first_instance_and_fixed_protocol_are_enforced() {
        let scope = scope();
        let name = name();
        let owner = scope.user.clone();
        let server = ProbeServer::bind_at(&name, scope.clone()).unwrap();
        assert!(ProbeServer::bind_at(&name, scope).is_err());
        let thread = std::thread::spawn(move || server.exchange(Instant::now() + DEADLINE));
        assert!(client_at(&name, &owner, 2).is_err());
        assert_eq!(
            thread.join().unwrap().err(),
            Some("IPC fixed request required")
        );
    }
    #[test]
    fn absent_client_times_out_and_cancels_pending_connection() {
        let server = ProbeServer::bind_at(&name(), scope()).unwrap();
        let start = Instant::now();
        assert_eq!(
            server.exchange(start + Duration::from_millis(40)).err(),
            Some("IPC operation deadline")
        );
        assert!(start.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn client_refuses_untrusted_server_owner_before_sending() {
        let actual = scope();
        let name = name();
        let mut wrong = actual.user.clone();
        wrong.words[1] ^= 1;
        let _server = ProbeServer::bind_at(&name, actual).unwrap();
        assert_eq!(
            client_at(&name, &wrong, 1).err(),
            Some("IPC server owner mismatch")
        );
    }
    #[test]
    fn anonymous_client_is_denied_without_identity_fallback() {
        use windows_sys::Win32::Storage::FileSystem::SECURITY_ANONYMOUS;
        let scope = scope();
        let name = name();
        let owner = scope.user.clone();
        let server = ProbeServer::bind_at(&name, scope).unwrap();
        let thread = std::thread::spawn(move || {
            let result = server.exchange(Instant::now() + DEADLINE);
            require_unimpersonated().unwrap();
            result
        });
        assert!(client_with_qos(&name, &owner, 1, SECURITY_ANONYMOUS).is_err());
        let error = thread.join().unwrap().unwrap_err();
        assert!(
            error == "IPC client impersonation unavailable"
                || error == "IPC client token unavailable"
        );
    }
    #[test]
    fn connected_silent_client_cancels_read_before_buffer_is_freed() {
        let scope = scope();
        let name = name();
        let server = ProbeServer::bind_at(&name, scope).unwrap();
        let thread = std::thread::spawn(move || {
            server.exchange(Instant::now() + Duration::from_millis(500))
        });
        let _silent = owned(unsafe {
            CreateFileW(
                wide(&name).as_ptr(),
                CLIENT_ACCESS,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                0,
            )
        })
        .unwrap();
        assert_eq!(thread.join().unwrap().err(), Some("IPC operation deadline"));
    }
    #[test]
    fn public_server_requires_real_system_without_escalation() {
        if require_system().is_err() {
            assert!(ProbeServer::bind(scope()).is_err());
        }
    }
    #[test]
    fn explicit_cancellation_drains_connect_without_waiting_for_deadline() {
        let server = ProbeServer::bind_at(&name(), scope()).unwrap();
        let cancel = std::sync::Arc::new(Cancellation::new().unwrap());
        let other = cancel.clone();
        let thread = std::thread::spawn(move || {
            server.exchange_controlled(Instant::now() + DEADLINE, Some(&other))
        });
        std::thread::sleep(Duration::from_millis(30));
        let began = Instant::now();
        cancel.signal();
        assert_eq!(
            thread.join().unwrap().err(),
            Some("IPC operation cancelled")
        );
        assert!(began.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn pre_cancelled_exchange_opens_no_new_operation() {
        let server = ProbeServer::bind_at(&name(), scope()).unwrap();
        let cancel = Cancellation::new().unwrap();
        cancel.signal();
        assert_eq!(
            server
                .exchange_controlled(Instant::now() + DEADLINE, Some(&cancel))
                .err(),
            Some("IPC operation cancelled")
        );
    }
    #[test]
    fn impersonated_observer_is_refused_and_outer_token_is_not_reverted() {
        use windows_sys::Win32::Security::{ImpersonateSelf, SecurityImpersonation};
        assert_ne!(unsafe { ImpersonateSelf(SecurityImpersonation) }, 0);
        let revert = RevertGuard(true);
        assert_eq!(
            ClientScope::observe_current_process()
                .err()
                .map(|_| "refused"),
            Some("refused")
        );
        assert!(require_unimpersonated().is_err());
        revert.finish().unwrap();
    }
}
