//! SYSTEM-only, fixed-location broker storage provisioning. No service install,
//! VM operation, target execution or readiness claim. Administrators/SYSTEM are
//! the trusted boundary; this cannot protect state against a malicious admin.
use crate::Result;
use std::{
    ffi::{c_void, OsStr, OsString},
    mem::{size_of, zeroed},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Component, Path, PathBuf, Prefix},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{GetLastError, LocalFree, ERROR_NO_TOKEN, HANDLE, INVALID_HANDLE_VALUE, PSID},
    Security::{
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
            GetSecurityInfo, SE_FILE_OBJECT,
        },
        EqualSid, GetAce, GetSecurityDescriptorControl, GetTokenInformation, IsValidSid, TokenUser,
        ACE_HEADER, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, SE_DACL_PRESENT,
        SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
    },
    System::{
        Com::CoTaskMemFree,
        Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
    },
    UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath},
};

const SYSTEM_SID: &str = "S-1-5-18";
const ADMIN_SID: &str = "S-1-5-32-544";
const ROOT_NAME: &str = "ClineEnhancedManaged";
const LEAVES: [&str; 4] = ["journals", "anchors", "jobs", "images"];
const SYSTEM_SDDL: &str = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

fn wide(value: &OsStr) -> Result<Vec<u16>> {
    let mut value: Vec<u16> = value.encode_wide().collect();
    if value.is_empty() || value.len() > 1024 || value.contains(&0) {
        return Err("Protected storage path budget");
    }
    value.push(0);
    Ok(value)
}

struct LocalAllocation(*mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}
struct Sid(LocalAllocation);
impl Sid {
    fn new(text: &str) -> Result<Self> {
        let text = wide(OsStr::new(text))?;
        let mut sid = null_mut();
        if unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut sid) } == 0 {
            return Err("Protected storage principal unavailable");
        }
        Ok(Self(LocalAllocation(sid)))
    }
    fn matches(&self, value: PSID) -> bool {
        !value.is_null()
            && unsafe { IsValidSid(value) } != 0
            && unsafe { EqualSid(self.0 .0, value) } != 0
    }
}
struct Policy {
    owner: Sid,
    allowed: Vec<Sid>,
}
impl Policy {
    fn system() -> Result<Self> {
        Ok(Self {
            owner: Sid::new(SYSTEM_SID)?,
            allowed: vec![Sid::new(SYSTEM_SID)?, Sid::new(ADMIN_SID)?],
        })
    }
}
struct Descriptor(LocalAllocation);
impl Descriptor {
    fn new(text: &str) -> Result<Self> {
        let text = wide(OsStr::new(text))?;
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err("Protected storage descriptor unavailable");
        }
        Ok(Self(LocalAllocation(descriptor)))
    }
}

pub(crate) fn require_system() -> Result<()> {
    // A service must never create/open protected state while impersonating a
    // client, even if its process is SYSTEM. No RevertToSelf side effect.
    let mut thread = 0;
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut thread) } != 0 {
        drop(unsafe { OwnedHandle::from_raw_handle(thread as _) });
        return Err("Impersonated protected storage access forbidden");
    }
    if unsafe { GetLastError() } != ERROR_NO_TOKEN {
        return Err("Protected storage thread identity unavailable");
    }
    with_current_sid(|sid| {
        if Sid::new(SYSTEM_SID)?.matches(sid) {
            Ok(())
        } else {
            Err("LocalSystem broker required; no host settings changed")
        }
    })
}
fn with_current_sid<T>(inspect: impl FnOnce(PSID) -> Result<T>) -> Result<T> {
    // Keep storage at its final address during the API call and SID inspection.
    let mut token = 0;
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err("Protected storage process identity unavailable");
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token as _) };
    let mut buffer = [0u64; 64];
    let mut needed = 0;
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size_of::<[u64; 64]>() as u32,
            &mut needed,
        )
    } == 0
        || needed < size_of::<TOKEN_USER>() as u32
        || needed > size_of::<[u64; 64]>() as u32
    {
        return Err("Protected storage token budget");
    }
    let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let begin = buffer.as_ptr() as usize;
    let at = user.User.Sid as usize;
    if at < begin + size_of::<TOKEN_USER>()
        || at.checked_add(8).ok_or("Token SID budget")? > begin + needed as usize
    {
        return Err("Protected storage SID boundary");
    }
    let count = unsafe { *((at as *const u8).add(1)) } as usize;
    if count > 15
        || at + 8 + count * 4 > begin + needed as usize
        || unsafe { IsValidSid(user.User.Sid) } == 0
    {
        return Err("Protected storage SID budget");
    }
    inspect(user.User.Sid)
}

fn directory_handle(path: &Path) -> Result<OwnedHandle> {
    let path = wide(path.as_os_str())?;
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            // Attribute-only opens do not participate in Windows share checks.
            // Directory read access is required for denial of delete sharing.
            READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err("Protected directory handle unavailable");
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(handle as _) };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(handle.as_raw_handle() as HANDLE, &mut info) } == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err("Non-reparse protected directory required");
    }
    Ok(handle)
}
fn validate(handle: &OwnedHandle, policy: &Policy) -> Result<()> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(handle.as_raw_handle() as HANDLE, &mut info) } == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err("Non-reparse protected directory required");
    }
    validate_security(
        handle.as_raw_handle() as HANDLE,
        policy,
        (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
    )
}
fn validate_security(handle: HANDLE, policy: &Policy, flags: u8) -> Result<()> {
    let mut owner = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    if unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    } != 0
    {
        return Err("Protected directory security unavailable");
    }
    let _descriptor = LocalAllocation(descriptor);
    if !policy.owner.matches(owner) || dacl.is_null() {
        return Err("Protected directory owner or ACL mismatch");
    }
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || control & (SE_DACL_PROTECTED | SE_DACL_PRESENT) != SE_DACL_PROTECTED | SE_DACL_PRESENT
    {
        return Err("Explicit protected directory ACL required");
    }
    let acl = unsafe { &*dacl };
    if acl.AceCount as usize != policy.allowed.len() || (acl.AclSize as usize) < size_of::<ACL>() {
        return Err("Protected directory ACL shape mismatch");
    }
    let start = dacl as usize;
    let end = start + acl.AclSize as usize;
    let mut seen = vec![false; policy.allowed.len()];
    for index in 0..acl.AceCount {
        let mut raw = null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut raw) } == 0 || raw.is_null() {
            return Err("Protected directory ACL entry unavailable");
        }
        let at = raw as usize;
        if at < start + size_of::<ACL>()
            || at
                .checked_add(size_of::<ACE_HEADER>())
                .ok_or("ACL budget")?
                > end
        {
            return Err("Protected directory ACL entry boundary");
        }
        let header = unsafe { std::ptr::read_unaligned(raw.cast::<ACE_HEADER>()) };
        if header.AceType != 0
            || header.AceFlags != flags
            || header.AceSize < 16
            || at + header.AceSize as usize > end
        {
            return Err("Protected directory ACL entry type");
        }
        let mask = unsafe { std::ptr::read_unaligned((at + 4) as *const u32) };
        let sid = (at + 8) as PSID;
        let count = unsafe { *((sid as *const u8).add(1)) } as usize;
        if mask != FILE_ALL_ACCESS || count > 15 || 16 + count * 4 > header.AceSize as usize {
            return Err("Protected directory ACL rights or SID budget");
        }
        let which = policy
            .allowed
            .iter()
            .position(|principal| principal.matches(sid))
            .ok_or("Unexpected protected directory principal")?;
        if seen[which] {
            return Err("Duplicate protected directory principal");
        }
        seen[which] = true;
    }
    if seen.iter().any(|present| !present) {
        return Err("Incomplete protected directory ACL");
    }
    Ok(())
}
fn create_directory(path: &Path, descriptor: &Descriptor, policy: &Policy) -> Result<OwnedHandle> {
    let wide = wide(path.as_os_str())?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0 .0,
        bInheritHandle: 0,
    };
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0 {
        return Err("New protected directory required; inspect retained state");
    }
    let handle = directory_handle(path)?;
    validate(&handle, policy)?;
    Ok(handle)
}
fn program_data() -> Result<PathBuf> {
    let mut value = null_mut();
    if unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, 0, &mut value) } < 0
        || value.is_null()
    {
        return Err("System data directory unavailable");
    }
    let result = (|| {
        let mut length = 0;
        while length <= 1024 && unsafe { *value.add(length) } != 0 {
            length += 1;
        }
        if length == 0 || length > 1024 {
            return Err("System data path budget");
        }
        Ok(PathBuf::from(OsString::from_wide(unsafe {
            std::slice::from_raw_parts(value, length)
        })))
    })();
    unsafe { CoTaskMemFree(value.cast()) };
    result
}
fn pin_ancestors(path: &Path) -> Result<Vec<OwnedHandle>> {
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_)))
        || components.next() != Some(Component::RootDir)
    {
        return Err("Local absolute system data path required");
    }
    if components
        .clone()
        .any(|component| !matches!(component, Component::Normal(_)))
        || components.count() > 31
    {
        return Err("System data ancestor shape or budget");
    }
    let mut current = PathBuf::new();
    let mut handles = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) => current.push(component.as_os_str()),
            Component::RootDir | Component::Normal(_) => {
                current.push(component.as_os_str());
                handles.push(directory_handle(&current)?);
            }
            _ => return Err("System data path traversal forbidden"),
        }
        if handles.len() > 32 {
            return Err("System data ancestor budget");
        }
    }
    Ok(handles)
}

/// Kept alive by the future SYSTEM service across all operations. Directory and
/// ancestor handles deny delete-sharing to pin their names. No client path,
/// endpoint, credential, image or VM identity is accepted here.
pub struct SystemRoots {
    _ancestors: Vec<OwnedHandle>,
    root: OwnedHandle,
    leaves: Vec<(PathBuf, OwnedHandle)>,
}
impl SystemRoots {
    /// Exclusive initial creation only. Partial state is retained on error;
    /// never silently adopt, repair, delete or reuse an existing installation.
    pub fn create_new() -> Result<Self> {
        Self::access(true)
    }
    /// Validates all existing protected roots; does not create or repair them.
    pub fn open_existing() -> Result<Self> {
        Self::access(false)
    }
    fn access(create: bool) -> Result<Self> {
        require_system()?;
        let parent = program_data()?;
        let ancestors = pin_ancestors(&parent)?;
        let path = parent.join(ROOT_NAME);
        let policy = Policy::system()?;
        let descriptor = Descriptor::new(SYSTEM_SDDL)?;
        let root = if create {
            create_directory(&path, &descriptor, &policy)?
        } else {
            let handle = directory_handle(&path)?;
            validate(&handle, &policy)?;
            handle
        };
        let mut leaves = Vec::new();
        for name in LEAVES {
            let path = path.join(name);
            let handle = if create {
                create_directory(&path, &descriptor, &policy)?
            } else {
                let handle = directory_handle(&path)?;
                validate(&handle, &policy)?;
                handle
            };
            leaves.push((path, handle));
        }
        Ok(Self {
            _ancestors: ancestors,
            root,
            leaves,
        })
    }
    /// Recheck held-object ACLs before future broker effects. This does not
    /// establish service authorization, VM ownership or anti-admin rollback.
    pub fn revalidate(&self) -> Result<()> {
        require_system()?;
        let policy = Policy::system()?;
        for handle in &self._ancestors {
            let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
            if unsafe { GetFileInformationByHandle(handle.as_raw_handle() as HANDLE, &mut info) }
                == 0
                || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
                || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                return Err("Protected ancestor changed");
            }
        }
        validate(&self.root, &policy)?;
        for (_, handle) in &self.leaves {
            validate(handle, &policy)?;
        }
        Ok(())
    }
    /// Creates three fixed-role, explicitly protected job leaves from fresh OS
    /// entropy. No caller-selected path or reused job identifier is accepted.
    pub fn create_job(&self) -> Result<SystemJob<'_>> {
        self.revalidate()?;
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).map_err(|_| "Protected job entropy unavailable")?;
        SystemJob::access(self, hex::encode(id), true)
    }
    /// Protected bytes alone are NOT VM ownership or caller authorization. The
    /// future broker must obtain this exact ID from its protected ownership record.
    pub fn open_job(&self, job: &str) -> Result<SystemJob<'_>> {
        self.revalidate()?;
        crate::exact_hex::<16>(job)?;
        SystemJob::access(self, job.into(), false)
    }
    pub(crate) fn installation_file(&self, create: bool) -> Result<std::fs::File> {
        self.revalidate()?;
        let path = self
            .anchor_parent()
            .parent()
            .ok_or("Fixed installation parent required")?
            .join(crate::windows_identity::INSTALLATION_FILE);
        protected_regular_file(&path, create)
    }

    pub fn journal_parent(&self) -> &Path {
        &self.leaves[0].0
    }
    pub fn anchor_parent(&self) -> &Path {
        &self.leaves[1].0
    }
    pub fn job_parent(&self) -> &Path {
        &self.leaves[2].0
    }
    pub fn image_parent(&self) -> &Path {
        &self.leaves[3].0
    }
}

fn protected_regular_file(path: &Path, create: bool) -> Result<std::fs::File> {
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE},
        Storage::FileSystem::{CREATE_NEW, FILE_FLAG_WRITE_THROUGH},
    };
    require_system()?;
    let path = wide(path.as_os_str())?;
    let descriptor = Descriptor::new("O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)")?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0 .0,
        bInheritHandle: 0,
    };
    let raw = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | READ_CONTROL | if create { GENERIC_WRITE } else { 0 },
            0,
            if create { &attributes } else { null() },
            if create { CREATE_NEW } else { OPEN_EXISTING },
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
            0,
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err("Exclusive protected installation record required; inspect retained state");
    }
    let file = unsafe { std::fs::File::from_raw_handle(raw as _) };
    validate_system_file(&file, create)?;
    Ok(file)
}

pub(crate) fn validate_system_file(file: &std::fs::File, allow_empty: bool) -> Result<u64> {
    require_system()?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    let raw = file.as_raw_handle() as HANDLE;
    if unsafe { GetFileInformationByHandle(raw, &mut info) } == 0
        || info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || info.nNumberOfLinks != 1
    {
        return Err("Single-link protected regular installation file required");
    }
    let size = ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64;
    if size > 16384 || (!allow_empty && size == 0) {
        return Err("Protected installation record budget");
    }
    validate_security(raw, &Policy::system()?, 0)?;
    Ok(size)
}

/// Pinned per-job roots. Borrowing the parent keeps its protected namespace
/// alive. No deletion/VM API is supplied; ambiguous state is retained for recovery.
pub struct SystemJob<'roots> {
    parents: &'roots SystemRoots,
    id: String,
    directories: Vec<(PathBuf, OwnedHandle)>,
}
impl<'roots> SystemJob<'roots> {
    fn access(parents: &'roots SystemRoots, id: String, create: bool) -> Result<Self> {
        crate::exact_hex::<16>(&id)?;
        let policy = Policy::system()?;
        let descriptor = Descriptor::new(SYSTEM_SDDL)?;
        let mut directories = Vec::new();
        for parent in [
            parents.journal_parent(),
            parents.anchor_parent(),
            parents.job_parent(),
        ] {
            let path = parent.join(&id);
            let handle = if create {
                create_directory(&path, &descriptor, &policy)?
            } else {
                let handle = directory_handle(&path)?;
                validate(&handle, &policy)?;
                handle
            };
            directories.push((path, handle));
        }
        Ok(Self {
            parents,
            id,
            directories,
        })
    }
    pub(crate) fn vm_record_file(&self, create: bool) -> Result<std::fs::File> {
        self.revalidate()?;
        protected_regular_file(
            &self.directories[2]
                .0
                .join(crate::windows_identity::OWNERSHIP_FILE),
            create,
        )
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn revalidate(&self) -> Result<()> {
        self.parents.revalidate()?;
        let policy = Policy::system()?;
        for (_, handle) in &self.directories {
            validate(handle, &policy)?;
        }
        Ok(())
    }
    /// Fresh, exclusive credential media only. Not a boot/VM authorization.
    pub fn write_boot_media(&self) -> Result<crate::boot_media::BootMaterial> {
        self.revalidate()?;
        let material = crate::boot_media::BootMaterial::generate()?;
        material.write_media(&self.directories[2].0)?;
        Ok(material)
    }
    fn require_identity(&self, identity: &crate::lifecycle::Identity) -> Result<()> {
        self.revalidate()?;
        if identity.job != self.id {
            return Err("Protected job identity mismatch");
        }
        Ok(())
    }
    /// The in-process key/installation/VM claims must come from the future
    /// protected broker, never a model/client. This does not persist that key.
    pub fn create_store(
        &self,
        identity: crate::lifecycle::Identity,
        key: [u8; 32],
    ) -> Result<ProtectedStore<'_, 'roots>> {
        let key = zeroize::Zeroizing::new(key);
        self.require_identity(&identity)?;
        let store = crate::store::Store::create_protected(
            &self.directories[0].0,
            &self.directories[1].0,
            identity,
            *key,
        )?;
        Ok(ProtectedStore {
            job: self,
            store,
            fenced: false,
        })
    }
    pub fn open_store(
        &self,
        identity: crate::lifecycle::Identity,
        key: [u8; 32],
    ) -> Result<ProtectedStore<'_, 'roots>> {
        let key = zeroize::Zeroizing::new(key);
        self.require_identity(&identity)?;
        let store = crate::store::Store::open(
            &self.directories[0].0,
            &self.directories[1].0,
            identity,
            *key,
        )?;
        Ok(ProtectedStore {
            job: self,
            store,
            fenced: false,
        })
    }
}
/// No mutable/raw Store escape: every durable transition rechecks real SYSTEM
/// identity and pinned parent/job ACLs. Any failed transition fences this handle.
pub struct ProtectedStore<'job, 'roots> {
    job: &'job SystemJob<'roots>,
    store: crate::store::Store,
    fenced: bool,
}
impl ProtectedStore<'_, '_> {
    pub fn journal(&self) -> &crate::lifecycle::Journal {
        self.store.journal()
    }
    pub fn advance(&mut self, event: crate::lifecycle::Event) -> Result<()> {
        if self.fenced {
            return Err("Protected store fenced; reopen and inspect");
        }
        self.fenced = true;
        self.job.revalidate()?;
        self.store.advance(event)?;
        self.fenced = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use windows_sys::Win32::Security::SetFileSecurityW;
    use windows_sys::Win32::Security::{
        Authorization::ConvertSidToStringSidW, ImpersonateSelf, RevertToSelf,
        SecurityImpersonation, PROTECTED_DACL_SECURITY_INFORMATION,
    };

    fn fixture_policy() -> (Policy, Descriptor, String) {
        let owner = with_current_sid(|sid| {
            let mut value = null_mut();
            if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 {
                return Err("Owned fixture SID conversion failed");
            }
            let _value = LocalAllocation(value.cast());
            let mut length = 0;
            while length < 184 && unsafe { *value.add(length) } != 0 {
                length += 1;
            }
            if length == 184 {
                return Err("Owned fixture SID budget");
            }
            String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) })
                .map_err(|_| "Owned fixture SID conversion failed")
        })
        .unwrap();
        let mut principals = vec![owner.clone()];
        for sid in [SYSTEM_SID, ADMIN_SID] {
            if !principals.iter().any(|p| p == sid) {
                principals.push(sid.into());
            }
        }
        use std::fmt::Write;
        let mut entries = String::new();
        for sid in &principals {
            write!(&mut entries, "(A;OICI;FA;;;{sid})").unwrap();
        }
        let descriptor = Descriptor::new(&format!("O:{owner}D:P{entries}")).unwrap();
        let policy = Policy {
            owner: Sid::new(&owner).unwrap(),
            allowed: principals
                .iter()
                .map(|sid| Sid::new(sid).unwrap())
                .collect(),
        };
        (policy, descriptor, owner)
    }
    struct Fixture {
        parent: PathBuf,
        path: PathBuf,
        handle: Option<OwnedHandle>,
        policy: Policy,
    }
    impl Fixture {
        fn new() -> Self {
            let mut random = [0u8; 16];
            getrandom::fill(&mut random).unwrap();
            let parent =
                std::env::temp_dir().join(format!("cline-owned-acl-{}", hex::encode(random)));
            fs::create_dir(&parent).unwrap();
            let path = parent.join("protected");
            let (policy, descriptor, _) = fixture_policy();
            let handle = Some(create_directory(&path, &descriptor, &policy).unwrap());
            Self {
                parent,
                path,
                handle,
                policy,
            }
        }
        fn handle(&self) -> &OwnedHandle {
            self.handle.as_ref().unwrap()
        }
        fn replace_acl(&self, sddl: &str) {
            let descriptor = Descriptor::new(sddl).unwrap();
            let path = wide(self.path.as_os_str()).unwrap();
            assert_ne!(
                unsafe {
                    SetFileSecurityW(
                        path.as_ptr(),
                        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                        descriptor.0 .0,
                    )
                },
                0,
                "Owned fixture ACL change failed"
            );
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            drop(self.handle.take());
            fs::remove_dir_all(&self.parent).unwrap();
        }
    }

    #[test]
    fn actual_explicit_owned_acl_is_valid_and_directory_identity_is_pinned() {
        let fixture = Fixture::new();
        validate(fixture.handle(), &fixture.policy).unwrap();
        assert!(
            fs::rename(&fixture.path, fixture.parent.join("moved")).is_err(),
            "Pinned owned directory must deny rename/delete sharing"
        );
        assert!(fixture.path.is_dir());
    }
    #[test]
    fn existing_directory_is_never_adopted_overwritten_or_cleaned_up() {
        let fixture = Fixture::new();
        let (_, descriptor, _) = fixture_policy();
        fs::write(fixture.path.join("retained"), b"owned retained state").unwrap();
        assert!(create_directory(&fixture.path, &descriptor, &fixture.policy).is_err());
        assert_eq!(
            fs::read(fixture.path.join("retained")).unwrap(),
            b"owned retained state"
        );
    }
    #[test]
    fn world_access_and_null_acl_are_rejected_using_real_security_descriptors() {
        for sddl in ["D:P(A;OICI;FA;;;WD)", "D:NO_ACCESS_CONTROL"] {
            let fixture = Fixture::new();
            fixture.replace_acl(sddl);
            assert!(validate(fixture.handle(), &fixture.policy).is_err());
        }
    }
    #[test]
    fn duplicate_missing_principals_and_weakened_rights_fail_closed() {
        for change in ["duplicate", "missing", "read-only"] {
            let fixture = Fixture::new();
            let (_, _, owner) = fixture_policy();
            let sddl = match change {
                "duplicate" => {
                    format!("D:P(A;OICI;FA;;;{owner})(A;OICI;FA;;;SY)(A;OICI;FA;;;{owner})")
                }
                "missing" => format!("D:P(A;OICI;FA;;;{owner})(A;OICI;FA;;;SY)"),
                _ => format!("D:P(A;OICI;FR;;;{owner})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"),
            };
            fixture.replace_acl(&sddl);
            assert!(validate(fixture.handle(), &fixture.policy).is_err());
        }
    }
    #[test]
    fn inherited_unprotected_acl_is_not_promoted_to_a_protected_root() {
        let fixture = Fixture::new();
        let (_, _, owner) = fixture_policy();
        let descriptor = Descriptor::new(&format!(
            "O:{owner}D:(A;OICI;FA;;;{owner})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        ))
        .unwrap();
        let path = fixture.path.join("unprotected");
        assert!(create_directory(&path, &descriptor, &fixture.policy).is_err());
        assert!(
            path.is_dir(),
            "Rejected state must be retained, not auto-deleted"
        );
    }

    #[test]
    fn a_file_cannot_be_substituted_for_a_protected_directory() {
        let fixture = Fixture::new();
        let path = fixture.path.join("not-directory");
        fs::write(&path, b"owned").unwrap();
        assert!(directory_handle(&path).is_err());
    }
    #[test]
    fn real_owned_junctions_are_refused_as_roots_and_ancestors() {
        use windows_sys::Win32::{Foundation::GENERIC_WRITE, System::IO::DeviceIoControl};
        let fixture = Fixture::new();
        let junction = fixture.parent.join("junction");
        fs::create_dir(&junction).unwrap();
        let target = fs::canonicalize(&fixture.path).unwrap();
        let text = target.to_str().unwrap().trim_start_matches("\\\\?\\");
        let substitute: Vec<u16> = format!("\\??\\{text}").encode_utf16().collect();
        let printed: Vec<u16> = text.encode_utf16().collect();
        let mut data = Vec::new();
        data.extend(0xA0000003u32.to_le_bytes()); // IO_REPARSE_TAG_MOUNT_POINT
        data.extend((8u16 + ((substitute.len() + printed.len() + 2) * 2) as u16).to_le_bytes());
        data.extend(0u16.to_le_bytes());
        data.extend(0u16.to_le_bytes());
        data.extend(((substitute.len() * 2) as u16).to_le_bytes());
        data.extend((((substitute.len() + 1) * 2) as u16).to_le_bytes());
        data.extend(((printed.len() * 2) as u16).to_le_bytes());
        for character in substitute.into_iter().chain([0]).chain(printed).chain([0]) {
            data.extend(character.to_le_bytes());
        }
        let path = wide(junction.as_os_str()).unwrap();
        let raw = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                0,
            )
        };
        assert_ne!(raw, INVALID_HANDLE_VALUE, "Owned junction handle failed");
        let handle = unsafe { OwnedHandle::from_raw_handle(raw as _) };
        let mut returned = 0;
        assert_ne!(
            unsafe {
                DeviceIoControl(
                    raw,
                    0x900A4,
                    data.as_ptr().cast(),
                    data.len() as u32,
                    null_mut(),
                    0,
                    &mut returned,
                    null_mut(),
                )
            },
            0,
            "Owned junction creation failed"
        );
        drop(handle);
        assert!(directory_handle(&junction).is_err());
        assert!(pin_ancestors(&junction.join("nested")).is_err());
        fs::remove_dir(&junction).unwrap();
    }

    #[test]
    fn ordinary_or_admin_user_cannot_provision_production_system_roots() {
        with_current_sid(|sid| {
            if Sid::new(SYSTEM_SID)?.matches(sid) {
                return Err("Owned CI must not run as SYSTEM");
            }
            Ok(())
        })
        .unwrap();
        // These checks fail before resolving ProgramData or creating any file.
        assert!(SystemRoots::create_new().is_err());
        assert!(SystemRoots::open_existing().is_err());
        let fixture = Fixture::new();
        assert!(validate(fixture.handle(), &Policy::system().unwrap()).is_err());
    }
    #[test]
    fn impersonated_access_is_rejected_without_changing_thread_identity() {
        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                assert_ne!(unsafe { RevertToSelf() }, 0);
            }
        }
        assert_ne!(unsafe { ImpersonateSelf(SecurityImpersonation) }, 0);
        let _revert = Revert;
        assert_eq!(
            require_system().err(),
            Some("Impersonated protected storage access forbidden")
        );
        let mut token = 0;
        assert_ne!(
            unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) },
            0,
            "Guard must not silently revert client impersonation"
        );
        drop(unsafe { OwnedHandle::from_raw_handle(token as _) });
    }
    #[test]
    fn path_shape_and_string_budgets_are_rejected_before_host_access() {
        for path in [
            "relative",
            "C:\\foo\\..\\bar",
            "\\\\server\\share",
            "\\\\?\\C:\\root",
        ] {
            assert!(pin_ancestors(Path::new(path)).is_err());
        }
        assert!(wide(OsStr::new("bad\0path")).is_err());
        assert!(wide(OsStr::new(&"x".repeat(1025))).is_err());
    }
}
