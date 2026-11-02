//! Read-only native Hyper-V v2 provider adapter for the future VM factory.
//! Retained creation-job readback is still observation data, not invocation provenance.
//! Never creates/starts/stops/adopts a VM, advances a journal or grants readiness.
//! COM connection/query setup can block: use a supervised broker child before
//! production/UI integration. Only enumeration has an independent local budget.
use crate::{
    hyperv_creation::{JobReference, PendingDefinition, SystemReference},
    windows_boot::HostBoot,
    windows_creation::CreationReply,
    windows_identity::OwnedVmRecord,
    windows_roots::require_system,
    Result,
};
use std::{
    marker::PhantomData,
    mem::ManuallyDrop,
    rc::Rc,
    sync::OnceLock,
    time::{Duration, Instant},
};
use windows::{
    core::{w, BSTR, PCWSTR, VARIANT},
    Win32::{
        Security::PSECURITY_DESCRIPTOR,
        System::{
            Com::{
                CoCreateInstance, CoInitializeEx, CoInitializeSecurity, CoSetProxyBlanket,
                CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, EOAC_DISABLE_AAA,
                EOAC_NONE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
            },
            Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE},
            Variant::{VT_BSTR, VT_I4, VT_NULL},
            Wmi::{
                IWbemClassObject, IWbemLocator, IWbemServices, WbemLocator, CIM_REFERENCE,
                CIM_STRING, CIM_UINT16, CIM_UINT32, WBEM_FLAG_CONNECT_USE_MAX_WAIT,
                WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_S_FALSE,
                WBEM_S_NO_ERROR, WBEM_S_TIMEDOUT,
            },
        },
    },
};

static SECURITY: OnceLock<Result<()>> = OnceLock::new();
struct Apartment(PhantomData<Rc<()>>);
impl Apartment {
    fn open() -> Result<Self> {
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
            .ok()
            .map_err(|_| "Native management COM apartment unavailable")?;
        let apartment = Self(PhantomData);
        // An ambient/too-late security policy is not assumed equivalent.
        (*SECURITY.get_or_init(|| {
            unsafe {
                CoInitializeSecurity(
                    PSECURITY_DESCRIPTOR::default(),
                    -1,
                    None,
                    None,
                    RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                    RPC_C_IMP_LEVEL_IMPERSONATE,
                    None,
                    EOAC_DISABLE_AAA,
                    None,
                )
            }
            .map_err(|_| "Native management process security unavailable; no fallback")
        }))?;
        Ok(apartment)
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

/// Not Clone/Deserialize: an observation is not ownership or termination proof.
pub struct VmObservation {
    vm_id: String,
    enabled_state: u16,
    health_state: u16,
}
impl VmObservation {
    pub fn vm_id(&self) -> &str {
        &self.vm_id
    }
    pub fn enabled_state(&self) -> u16 {
        self.enabled_state
    }
    pub fn health_state(&self) -> u16 {
        self.health_state
    }
}

/// Thread-affine native connection, no remote namespace or arbitrary WQL API.
/// COM proxies drop before apartment teardown (field declaration order).
pub struct HyperVManagement {
    services: IWbemServices,
    boot: HostBoot,
    _apartment: Apartment,
}
fn blanket<T: windows::core::Interface>(proxy: &T) -> Result<()> {
    let unknown = proxy
        .cast::<windows::core::IUnknown>()
        .map_err(|_| "Native management proxy unavailable")?;
    unsafe {
        CoSetProxyBlanket(
            &unknown,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            PCWSTR::null(),
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )
    }
    .map_err(|_| "Native management proxy security unavailable")
}
impl HyperVManagement {
    pub fn connect() -> Result<Self> {
        require_system()?;
        let boot = HostBoot::observe()?;
        let apartment = Apartment::open()?;
        let locator: IWbemLocator =
            unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) }
                .map_err(|_| "Native management locator unavailable")?;
        // Fixed local namespace and current SYSTEM identity. No credentials,
        // network server, CIMV2/PowerShell or shell fallback.
        let services = unsafe {
            locator.ConnectServer(
                &BSTR::from(r"ROOT\virtualization\v2"),
                &BSTR::new(),
                &BSTR::new(),
                &BSTR::new(),
                WBEM_FLAG_CONNECT_USE_MAX_WAIT.0,
                &BSTR::new(),
                None,
            )
        }
        .map_err(|_| "Local Hyper-V v2 provider unavailable")?;
        blanket(&services)?;
        require_system()?;
        HostBoot::observe()?.require_same(boot.id())?;
        Ok(Self {
            services,
            boot,
            _apartment: apartment,
        })
    }
    pub fn observe_reserved(
        &self,
        reservation: &OwnedVmRecord<'_, '_, '_, '_>,
    ) -> Result<VmObservation> {
        require_system()?;
        reservation.revalidate()?;
        HostBoot::observe()?.require_same(self.boot.id())?;
        let id = reservation.identity().vm_id.as_str();
        let query = query(id)?;
        let row = self.exact_row(&query)?;
        let observed = row.as_ref().map(|row| observation(row, id)).transpose()?;
        require_system()?;
        reservation.revalidate()?;
        HostBoot::observe()?.require_same(self.boot.id())?;
        // Absence is never inferred stop/removal, nor authority to create/adopt.
        observed.ok_or("Reserved VM not observed; no termination or removal inferred")
    }
    fn require_current(&self) -> Result<()> {
        require_system()?;
        HostBoot::observe()?.require_same(self.boot.id())
    }
    fn exact_row(&self, query: &str) -> Result<Option<IWbemClassObject>> {
        self.require_current()?;
        let cursor = unsafe {
            self.services.ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from(query),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )
        }
        .map_err(|_| "Exact native object query unavailable")?;
        blanket(&cursor)?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut observed = None;
        loop {
            if Instant::now() >= deadline {
                return Err("Exact native object enumeration deadline");
            }
            let mut rows: [Option<IWbemClassObject>; 2] = [None, None];
            let mut returned = 0;
            let status = unsafe { cursor.Next(100, &mut rows, &mut returned) };
            let done = batch(
                status.0,
                returned,
                rows.iter().filter(|row| row.is_some()).count(),
            )?;
            if returned > 0 {
                if observed.is_some() || returned != 1 {
                    return Err("Ambiguous native object observation");
                }
                observed = Some(rows[0].take().ok_or("Missing native object")?);
            }
            if done {
                break;
            }
        }
        self.require_current()?;
        Ok(observed)
    }
    fn read_creation_job(&self, job: &JobReference) -> Result<NativeJobObservation> {
        let row = self
            .exact_row(&job.observation_query())?
            .ok_or("Creation job missing; retain attempt without inferred completion")?;
        let (value, kind) = property(&row, w!("__CLASS"))?;
        if text(&value, kind)? != "Msvm_ConcreteJob" {
            return Err("Exact native creation job class required");
        }
        let (value, kind) = property(&row, w!("InstanceID"))?;
        if text(&value, kind)? != job.instance_id() {
            return Err("Native creation job identity mismatch");
        }
        let (value, kind) = property(&row, w!("JobState"))?;
        let state = number(&value, kind)?;
        let (value, kind) = property(&row, w!("ErrorCode"))?;
        let error = optional_number(&value, kind)?;
        // Nonterminal/error states cannot trigger association lookup or bind a VM.
        let system = if state == 7 && error == Some(0) {
            let affected = self
                .exact_row(&job.affected_system_query())?
                .ok_or("Completed creation lacks exact affected VM; retain attempt")?;
            let (value, kind) = property(&affected, w!("__CLASS"))?;
            if text(&value, kind)? != "Msvm_ComputerSystem" {
                return Err("Exact affected VM class required");
            }
            let (value, kind) = property(&affected, w!("Name"))?;
            let id = text(&value, kind)?.to_ascii_lowercase();
            crate::hyperv_address(&id)?;
            Some(format!("Msvm_ComputerSystem.Name=\"{id}\""))
        } else {
            None
        };
        self.require_current()?;
        Ok(NativeJobObservation {
            state,
            error,
            system,
        })
    }
}
struct NativeJobObservation {
    state: u16,
    error: Option<u16>,
    system: Option<String>,
}
/// Protected response lifetime plus a single exact asynchronous-job tracker.
/// A recorded response alone is NOT proof DefineSystem ran. This type cannot
/// create/boot/adopt/control a VM, advance a journal or grant readiness.
/// Every error/completion fences this live watcher; retained files are not removed.
pub struct DefinitionJob<'a, 'o, 'r, 'j, 'jr> {
    retained: CreationReply<'a, 'o, 'r, 'j, 'jr>,
    tracker: PendingDefinition,
    fenced: bool,
}
impl<'a, 'o, 'r, 'j, 'jr> DefinitionJob<'a, 'o, 'r, 'j, 'jr> {
    pub fn from_retained(retained: CreationReply<'a, 'o, 'r, 'j, 'jr>) -> Result<Self> {
        let tracker = PendingDefinition::from_reply(retained.reply()?)?;
        Ok(Self {
            retained,
            tracker,
            fenced: false,
        })
    }
    /// One native observation, never an unbounded polling loop. COM operations
    /// still require the future supervised broker child before product use.
    pub fn poll(&mut self, management: &HyperVManagement) -> Result<Option<SystemReference>> {
        self.poll_observed(|job| {
            management.require_current()?;
            let observed = management.read_creation_job(job)?;
            management.require_current()?;
            Ok((observed, native_computer_name()?))
        })
    }
    fn poll_observed(
        &mut self,
        read: impl FnOnce(&JobReference) -> Result<(NativeJobObservation, String)>,
    ) -> Result<Option<SystemReference>> {
        if self.fenced {
            return Err("Native creation watcher fenced; inspect retained attempt");
        }
        self.fenced = true;
        self.retained.revalidate()?;
        let (observed, local) = read(self.tracker.job())?;
        self.retained.revalidate()?;
        let completed = self.tracker.observe(
            &self.tracker.job().relative_path(),
            observed.state,
            observed.error,
            observed.system.as_deref(),
            &local,
        )?;
        if completed.is_none() {
            self.fenced = false;
        }
        Ok(completed)
    }
}
/// CI-only real protected-file guards with fabricated job observations, not
/// Hyper-V/provider execution. Used by the explicit owned SYSTEM fixture.
#[cfg(feature = "owned-system-acceptance")]
pub(crate) fn owned_watcher_acceptance(
    retained: CreationReply<'_, '_, '_, '_, '_>,
    scenario: u8,
) -> Result<()> {
    use windows_sys::Win32::Security::{ImpersonateSelf, RevertToSelf, SecurityImpersonation};
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            if unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
        }
    }
    const VM: &str = "Msvm_ComputerSystem.Name=\"12345678-1234-4234-8234-123456789abc\"";
    if scenario == 0 {
        if DefinitionJob::from_retained(retained).err()
            != Some("Pending creation requires asynchronous reply")
        {
            return Err("Owned synchronous response admitted an asynchronous watcher");
        }
        return Ok(());
    }
    let mut watcher = DefinitionJob::from_retained(retained)?;
    let observation = |state, error, system: Option<&str>| {
        Ok((
            NativeJobObservation {
                state,
                error,
                system: system.map(str::to_owned),
            },
            "OWNED".to_owned(),
        ))
    };
    let first = match scenario {
        1 => {
            for error in [None, Some(0)] {
                if watcher
                    .poll_observed(|_| observation(4, error, None))?
                    .is_some()
                {
                    return Err("Owned pending observation promoted completion");
                }
            }
            let actual = watcher
                .poll_observed(|_| observation(7, Some(0), Some(VM)))?
                .ok_or("Owned completed observation missing")?;
            if actual.vm_id() != "12345678-1234-4234-8234-123456789abc" {
                return Err("Owned completed observation identity differs");
            }
            Ok(Some(actual))
        }
        2 => watcher.poll_observed(|_| Err("owned native query interruption")),
        3 => watcher.poll_observed(|_| observation(7, None, Some(VM))),
        4 => watcher.poll_observed(|_| {
            observation(
                7,
                Some(0),
                Some("Msvm_ComputerSystem.Name=\"12345678-1234-4234-8234-123456789abd\""),
            )
        }),
        5 => {
            if unsafe { ImpersonateSelf(SecurityImpersonation) } == 0 {
                return Err("Owned watcher impersonation unavailable");
            }
            let _revert = Revert;
            let mut called = false;
            let result = watcher.poll_observed(|_| {
                called = true;
                observation(4, None, None)
            });
            if called
                || result.as_ref().err() != Some(&"Impersonated protected storage access forbidden")
            {
                return Err("Owned watcher read under impersonation");
            }
            result
        }
        6 => {
            let mut revert = None;
            let result = watcher.poll_observed(|_| {
                if unsafe { ImpersonateSelf(SecurityImpersonation) } == 0 {
                    return Err("Owned watcher impersonation unavailable");
                }
                revert = Some(Revert);
                observation(4, None, None)
            });
            drop(revert);
            if result.as_ref().err() != Some(&"Impersonated protected storage access forbidden") {
                return Err("Owned watcher omitted post-read guard");
            }
            result
        }
        _ => return Err("Unknown owned watcher scenario"),
    };
    if (scenario == 1) != first.is_ok() {
        return Err("Owned watcher failure/completion distinction lost");
    }
    let mut called = false;
    let again = watcher.poll_observed(|_| {
        called = true;
        observation(4, None, None)
    });
    if called || again.err() != Some("Native creation watcher fenced; inspect retained attempt") {
        return Err("Owned watcher resumed after failure or completion");
    }
    Ok(())
}
fn query(id: &str) -> Result<String> {
    crate::hyperv_address(id)?;
    Ok(format!(
        "SELECT __CLASS,Name,EnabledState,HealthState FROM Msvm_ComputerSystem WHERE Name='{id}'"
    ))
}
fn batch(status: i32, returned: u32, populated: usize) -> Result<bool> {
    if returned > 2 || populated != returned as usize {
        return Err("Native VM enumeration count mismatch");
    }
    if status == WBEM_S_FALSE.0 {
        return Ok(true);
    }
    if status == WBEM_S_TIMEDOUT.0 {
        return Ok(false);
    }
    if status == WBEM_S_NO_ERROR.0 && returned > 0 {
        return Ok(false);
    }
    Err("Native VM enumeration failed or made no progress")
}
fn property(object: &IWbemClassObject, name: PCWSTR) -> Result<(VARIANT, i32)> {
    let mut value = VARIANT::new();
    let mut kind = 0;
    unsafe { object.Get(name, 0, &mut value, Some(&mut kind), None) }
        .map_err(|_| "Required native VM property unavailable")?;
    Ok((value, kind))
}
fn text(value: &VARIANT, kind: i32) -> Result<String> {
    bounded_text(value, kind, CIM_STRING.0, 128)
}
fn bounded_text(value: &VARIANT, kind: i32, expected: i32, budget: usize) -> Result<String> {
    // Inspect VT before borrowing the union; never coerce/copy native pointers.
    let raw = unsafe { &value.as_raw().Anonymous.Anonymous };
    if kind != expected || raw.vt != VT_BSTR.0 {
        return Err("Exact native VM string type required");
    }
    let borrowed = ManuallyDrop::new(unsafe { BSTR::from_raw(raw.Anonymous.bstrVal) });
    if borrowed.is_empty() || borrowed.len() > budget {
        return Err("Native VM string budget");
    }
    let result = String::from_utf16(borrowed.as_wide()).map_err(|_| "Native VM string encoding")?;
    if result.contains('\0') {
        return Err("Native VM embedded terminator");
    }
    Ok(result)
}
fn method_return(value: &VARIANT, kind: i32) -> Result<u32> {
    let raw = unsafe { &value.as_raw().Anonymous.Anonymous };
    if kind != CIM_UINT32.0 || raw.vt != VT_I4.0 {
        return Err("Exact native method return type required");
    }
    // WMI carries CIM_UINT32 as signed VT_I4 bits, not VT_UI4 or decimal text.
    Ok(unsafe { raw.Anonymous.lVal } as u32)
}
fn optional_reference(value: &VARIANT, kind: i32) -> Result<Option<String>> {
    let raw = unsafe { &value.as_raw().Anonymous.Anonymous };
    if kind == CIM_REFERENCE.0 && raw.vt == VT_NULL.0 {
        return Ok(None);
    }
    bounded_text(value, kind, CIM_REFERENCE.0, 512).map(Some)
}
fn native_computer_name() -> Result<String> {
    use windows_sys::Win32::System::WindowsProgramming::GetComputerNameW;
    let mut buffer = [0u16; 64];
    let mut count = buffer.len() as u32;
    if unsafe { GetComputerNameW(buffer.as_mut_ptr(), &mut count) } == 0
        || count == 0
        || count as usize >= buffer.len()
    {
        return Err("Native local computer name unavailable");
    }
    String::from_utf16(&buffer[..count as usize]).map_err(|_| "Native local computer name encoding")
}
/// Decode output data only; not a factory invocation, VM ownership or receipt.
/// Future callers must pass the actual DefineSystem output, not request data.
/// Native local hostname comes from the OS, never a caller-supplied namespace.
pub fn decode_definition_output(
    object: &IWbemClassObject,
) -> Result<crate::hyperv_creation::DefinitionReply> {
    let (value, kind) = property(object, w!("ReturnValue"))?;
    let code = method_return(&value, kind)?;
    let (value, kind) = property(object, w!("ResultingSystem"))?;
    let system = optional_reference(&value, kind)?;
    let (value, kind) = property(object, w!("Job"))?;
    let job = optional_reference(&value, kind)?;
    crate::hyperv_creation::DefinitionReply::decode(
        code,
        system.as_deref(),
        job.as_deref(),
        &native_computer_name()?,
    )
}

fn number(value: &VARIANT, kind: i32) -> Result<u16> {
    let raw = unsafe { &value.as_raw().Anonymous.Anonymous };
    if kind != CIM_UINT16.0 || raw.vt != VT_I4.0 {
        return Err("Exact native VM integer type required");
    }
    u16::try_from(unsafe { raw.Anonymous.lVal }).map_err(|_| "Native VM integer range")
}
fn optional_number(value: &VARIANT, kind: i32) -> Result<Option<u16>> {
    let raw = unsafe { &value.as_raw().Anonymous.Anonymous };
    if kind == CIM_UINT16.0 && raw.vt == VT_NULL.0 {
        return Ok(None);
    }
    number(value, kind).map(Some)
}
fn observation(object: &IWbemClassObject, expected: &str) -> Result<VmObservation> {
    let (value, kind) = property(object, w!("__CLASS"))?;
    if text(&value, kind)? != "Msvm_ComputerSystem" {
        return Err("Exact native VM class required");
    }
    let (value, kind) = property(object, w!("Name"))?;
    let name = text(&value, kind)?;
    require_identity(&name, expected)?;
    let (value, kind) = property(object, w!("EnabledState"))?;
    let enabled_state = number(&value, kind)?;
    let (value, kind) = property(object, w!("HealthState"))?;
    let health_state = number(&value, kind)?;
    Ok(VmObservation {
        vm_id: expected.to_ascii_lowercase(),
        enabled_state,
        health_state,
    })
}

fn require_identity(observed: &str, expected: &str) -> Result<()> {
    // Provider GUID casing is presentation, not permission to accept a new ID.
    crate::hyperv_address(expected)?;
    let normalized = observed.to_ascii_lowercase();
    crate::hyperv_address(&normalized)?;
    if normalized != expected {
        return Err("Native VM identity mismatch");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn query_is_fixed_local_exact_guid_only() {
        let id = "12345678-1234-4234-8234-123456789abc";
        assert_eq!(query(id).unwrap(), format!("SELECT __CLASS,Name,EnabledState,HealthState FROM Msvm_ComputerSystem WHERE Name='{id}'"));
        for invalid in [
            "",
            "*",
            "name' OR 1=1",
            "\\\\remote\\root",
            "12345678-1234-4234-8234-123456789abc'",
            "00000000",
        ] {
            assert!(query(invalid).is_err());
        }
    }
    #[test]
    fn provider_guid_casing_does_not_change_the_reserved_identity() {
        let id = "12345678-1234-4234-8234-123456789abc";
        assert!(require_identity(&id.to_ascii_uppercase(), id).is_ok());
        for other in [
            "12345678-1234-4234-8234-123456789abd",
            "*",
            "",
            "name' OR 1=1",
        ] {
            assert!(require_identity(other, id).is_err());
        }
        assert!(require_identity(id, &id.to_ascii_uppercase()).is_err());
    }
    #[test]
    fn native_property_types_do_not_coerce_or_accept_arrays_null_and_ranges() {
        assert_eq!(
            text(&VARIANT::from("Msvm_ComputerSystem"), CIM_STRING.0).unwrap(),
            "Msvm_ComputerSystem"
        );
        for value in [
            VARIANT::new(),
            VARIANT::from(3i32),
            VARIANT::from("a\0b"),
            VARIANT::from("x".repeat(129).as_str()),
        ] {
            assert!(text(&value, CIM_STRING.0).is_err());
        }
        assert!(text(&VARIANT::from("valid"), CIM_STRING.0 | 8192).is_err());
        assert_eq!(number(&VARIANT::from(3i32), CIM_UINT16.0).unwrap(), 3);
        for value in [
            VARIANT::new(),
            VARIANT::from("3"),
            VARIANT::from(3u16),
            VARIANT::from(-1i32),
            VARIANT::from(65536i32),
        ] {
            assert!(number(&value, CIM_UINT16.0).is_err());
        }
        assert!(number(&VARIANT::from(3i32), CIM_UINT16.0 | 8192).is_err());
    }
    #[test]
    fn nullable_job_error_is_not_coerced_to_success() {
        let mut raw = *VARIANT::new().as_raw();
        raw.Anonymous.Anonymous.vt = VT_NULL.0;
        let null = unsafe { VARIANT::from_raw(raw) };
        assert_eq!(optional_number(&null, CIM_UINT16.0), Ok(None));
        assert!(optional_number(&null, CIM_STRING.0).is_err());
        assert_eq!(
            optional_number(&VARIANT::from(0i32), CIM_UINT16.0),
            Ok(Some(0))
        );
        for value in [
            VARIANT::new(),
            VARIANT::from("0"),
            VARIANT::from(0u16),
            VARIANT::from(-1i32),
            VARIANT::from(65536i32),
        ] {
            assert!(optional_number(&value, CIM_UINT16.0).is_err());
        }
        assert!(optional_number(&VARIANT::from(0i32), CIM_UINT16.0 | 8192).is_err());
    }
    #[test]
    fn enumeration_never_treats_timeout_or_unknown_success_as_end_of_results() {
        assert_eq!(batch(WBEM_S_FALSE.0, 0, 0), Ok(true));
        assert_eq!(batch(WBEM_S_FALSE.0, 1, 1), Ok(true));
        assert_eq!(batch(WBEM_S_NO_ERROR.0, 1, 1), Ok(false));
        assert_eq!(batch(WBEM_S_TIMEDOUT.0, 0, 0), Ok(false));
        for args in [(0, 0, 0), (0, 3, 3), (1, 1, 0), (2, 0, 0), (-1, 0, 0)] {
            assert!(batch(args.0, args.1, args.2).is_err());
        }
    }
    #[test]
    fn native_method_return_requires_uint32_bits_without_coercion() {
        assert_eq!(
            method_return(&VARIANT::from(4096i32), CIM_UINT32.0),
            Ok(4096)
        );
        assert_eq!(
            method_return(&VARIANT::from(-1i32), CIM_UINT32.0),
            Ok(u32::MAX)
        );
        for value in [
            VARIANT::new(),
            VARIANT::from("4096"),
            VARIANT::from(4096u32),
            VARIANT::from(true),
        ] {
            assert!(method_return(&value, CIM_UINT32.0).is_err());
        }
        assert!(method_return(&VARIANT::from(0i32), CIM_UINT16.0).is_err());
        assert!(method_return(&VARIANT::from(0i32), CIM_UINT32.0 | 8192).is_err());
    }
    #[test]
    fn nullable_references_distinguish_explicit_null_from_missing_empty_and_strings() {
        let mut raw = *VARIANT::new().as_raw();
        raw.Anonymous.Anonymous.vt = VT_NULL.0;
        let null = unsafe { VARIANT::from_raw(raw) };
        assert_eq!(optional_reference(&null, CIM_REFERENCE.0), Ok(None));
        assert!(optional_reference(&null, CIM_STRING.0).is_err());
        let path = "Msvm_ConcreteJob.InstanceID=\"owned-job\"";
        assert_eq!(
            optional_reference(&VARIANT::from(path), CIM_REFERENCE.0),
            Ok(Some(path.into()))
        );
        for value in [
            VARIANT::new(),
            VARIANT::from(""),
            VARIANT::from(1i32),
            VARIANT::from("x".repeat(513).as_str()),
        ] {
            assert!(optional_reference(&value, CIM_REFERENCE.0).is_err());
        }
        assert!(optional_reference(&VARIANT::from(path), CIM_STRING.0).is_err());
        assert!(optional_reference(&VARIANT::from(path), CIM_REFERENCE.0 | 8192).is_err());
    }
    #[test]
    fn local_reference_scope_uses_native_os_name_without_com_or_host_claims() {
        let name = native_computer_name().unwrap();
        let path = format!(
            r#"\\{}\root\virtualization\v2:Msvm_ComputerSystem.Name="12345678-1234-4234-8234-123456789abc""#,
            name
        );
        assert!(
            crate::hyperv_creation::DefinitionReply::decode(0, Some(&path), None, &name).is_ok()
        );
    }
    #[test]
    fn system_guard_precedes_any_com_or_provider_access() {
        if let Err(denied) = require_system() {
            assert_eq!(HyperVManagement::connect().err(), Some(denied));
        }
    }
}
