//! Bounded Hyper-V creation-response data, never ownership or permission.
//! A future native factory must durably record its attempt before DefineSystem,
//! obtain these values from that actual invocation, persist the returned job/VM,
//! and independently read back the realized configuration before any boot.
//! Parsing caller-supplied data cannot establish any of those facts.
use crate::Result;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemReference(String);
impl SystemReference {
    pub fn vm_id(&self) -> &str {
        &self.0
    }
    pub fn relative_path(&self) -> String {
        format!("Msvm_ComputerSystem.Name=\"{}\"", self.0)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobReference(String);
impl JobReference {
    pub fn relative_path(&self) -> String {
        format!("Msvm_ConcreteJob.InstanceID=\"{}\"", self.0)
    }
}

fn host(value: &str) -> Result<()> {
    // The native caller must supply an OS-observed local name, never a request.
    if value.is_empty()
        || value.encode_utf16().count() > 63
        || !value
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        || value.starts_with('-')
        || value.ends_with('-')
    {
        return Err("Exact native local computer name required");
    }
    Ok(())
}
fn relative<'a>(value: &'a str, local: &str) -> Result<&'a str> {
    host(local)?;
    if value.is_empty() || value.len() > 512 {
        return Err("Native creation reference budget/encoding");
    }
    if let Some(absolute) = value.strip_prefix(r"\\") {
        let (server, rest) = absolute
            .split_once('\\')
            .ok_or("Native creation reference server missing")?;
        if !server.eq_ignore_ascii_case(local) {
            return Err("Remote creation reference forbidden");
        }
        let (namespace, object) = rest
            .split_once(':')
            .ok_or("Native creation reference namespace missing")?;
        if !namespace.eq_ignore_ascii_case(r"root\virtualization\v2") {
            return Err("Exact local Hyper-V v2 namespace required");
        }
        Ok(object)
    } else if value.contains('\\') {
        Err("Qualified/escaped creation reference forbidden")
    } else {
        Ok(value)
    }
}
fn key<'a>(value: &'a str, class: &str, property: &str) -> Result<&'a str> {
    let (prefix, quoted) = value
        .split_once('=')
        .ok_or("Exact creation reference key required")?;
    if !prefix.eq_ignore_ascii_case(&format!("{class}.{property}")) {
        return Err("Exact creation reference class/key required");
    }
    let key = quoted
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or("Quoted creation reference key required")?;
    if key.is_empty()
        || key.len() > 128
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:{}.".contains(&b))
    {
        return Err("Creation reference key syntax/budget");
    }
    Ok(key)
}
fn system(value: &str, local: &str) -> Result<SystemReference> {
    let id = key(relative(value, local)?, "Msvm_ComputerSystem", "Name")?.to_ascii_lowercase();
    crate::hyperv_address(&id)?;
    Ok(SystemReference(id))
}
fn job(value: &str, local: &str) -> Result<JobReference> {
    // Do not assume undocumented GUID-only InstanceID semantics. Permit a
    // bounded safe identifier, but never preserve a provider's server/path.
    Ok(JobReference(
        key(relative(value, local)?, "Msvm_ConcreteJob", "InstanceID")?.into(),
    ))
}

/// Provider claims only. Even synchronous completion is not VM configuration,
/// containment, engine readiness, or a journal/cleanup authorization receipt.
#[derive(Debug, PartialEq, Eq)]
pub enum DefinitionReply {
    Completed(SystemReference),
    Pending {
        job: JobReference,
        candidate: Option<SystemReference>,
    },
}
impl DefinitionReply {
    pub fn decode(
        return_value: u32,
        resulting_system: Option<&str>,
        returned_job: Option<&str>,
        native_local_name: &str,
    ) -> Result<Self> {
        host(native_local_name)?;
        match return_value {
            0 => {
                if returned_job.is_some() {
                    return Err("Ambiguous synchronous creation job reference");
                }
                Ok(Self::Completed(system(
                    resulting_system.ok_or("Completed creation lacks resulting system")?,
                    native_local_name,
                )?))
            }
            4096 => Ok(Self::Pending {
                job: job(
                    returned_job.ok_or("Asynchronous creation lacks exact job")?,
                    native_local_name,
                )?,
                candidate: resulting_system
                    .map(|s| system(s, native_local_name))
                    .transpose()?,
            }),
            _ => Err("DefineSystem failed; retain creation attempt without retry"),
        }
    }
}

/// In-memory correlation only. Durable attempt/job persistence and native
/// process supervision must surround this tracker in the future factory.
/// Not Clone/Deserialize: a failed/finished tracker cannot silently be reset.
pub struct PendingDefinition {
    job: JobReference,
    candidate: Option<SystemReference>,
    fenced: bool,
}
impl PendingDefinition {
    pub fn from_reply(reply: DefinitionReply) -> Result<Self> {
        match reply {
            DefinitionReply::Pending { job, candidate } => Ok(Self {
                job,
                candidate,
                fenced: false,
            }),
            DefinitionReply::Completed(_) => Err("Pending creation requires asynchronous reply"),
        }
    }
    pub fn job(&self) -> &JobReference {
        &self.job
    }
    /// Only state 7 with ErrorCode zero and an exact affected-system reference
    /// can produce completed *data*. PercentComplete and a missing job are not
    /// inputs or substitutes. Explicit null ErrorCode is allowed only while
    /// nonterminal, never as completed zero. Any mismatch/failure fences this tracker.
    pub fn observe(
        &mut self,
        job_reference: &str,
        job_state: u16,
        error_code: Option<u16>,
        affected_system: Option<&str>,
        native_local_name: &str,
    ) -> Result<Option<SystemReference>> {
        if self.fenced {
            return Err("Creation tracker fenced; inspect retained attempt");
        }
        self.fenced = true;
        if job(job_reference, native_local_name)? != self.job {
            return Err("Creation job identity mismatch");
        }
        if error_code.is_some_and(|code| code != 0) {
            return Err("Creation job reported an error; retain attempt");
        }
        match job_state {
            2..=6 => {
                // Never bind a partial/nonterminal observation as completion.
                if affected_system.is_some() {
                    return Err("Nonterminal creation cannot bind affected system");
                }
                self.fenced = false;
                Ok(None)
            }
            7 => {
                if error_code != Some(0) {
                    return Err("Completed creation job lacks explicit zero error code");
                }
                let actual = system(
                    affected_system.ok_or("Completed creation job lacks affected system")?,
                    native_local_name,
                )?;
                if self.candidate.as_ref().is_some_and(|c| c != &actual) {
                    return Err("Creation resulting-system identity mismatch");
                }
                Ok(Some(actual))
            }
            _ => Err("Creation job did not complete normally; retain attempt"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const LOCAL: &str = "OWNED-HOST";
    const ID: &str = "12345678-1234-4234-8234-123456789abc";
    const VM: &str = "Msvm_ComputerSystem.Name=\"12345678-1234-4234-8234-123456789abc\"";
    const JOB: &str = "Msvm_ConcreteJob.InstanceID=\"job:1234-ABCD\"";
    fn pending(candidate: Option<&str>) -> PendingDefinition {
        PendingDefinition::from_reply(
            DefinitionReply::decode(4096, candidate, Some(JOB), LOCAL).unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn local_absolute_and_relative_references_rebuild_only_relative_paths() {
        let absolute = format!(r"\\owned-host\ROOT\Virtualization\V2:{VM}");
        let result = system(&absolute.to_ascii_uppercase(), LOCAL).unwrap();
        assert_eq!(result.vm_id(), ID);
        assert_eq!(result.relative_path(), VM);
        assert_eq!(job(JOB, LOCAL).unwrap().relative_path(), JOB);
        for name in ["OWNED_HOST", "测试主机"] {
            let reference = format!(r"\\{}\root\virtualization\v2:{}", name, VM);
            assert_eq!(system(&reference, name).unwrap().vm_id(), ID);
            assert!(system(&reference, LOCAL).is_err());
        }
    }
    #[test]
    fn remote_aliases_namespaces_queries_and_malformed_references_are_refused() {
        for invalid in [
            format!(r"\\remote\root\virtualization\v2:{VM}"),
            format!(r"\\localhost\root\virtualization\v2:{VM}"),
            format!(r"\\.\root\virtualization\v2:{VM}"),
            format!(r"\\OWNED-HOST\root\cimv2:{VM}"),
            format!(r"root\virtualization\v2:{VM}"),
            format!("{VM},Other=\"key\""),
            format!("{VM} OR 1=1"),
            VM.replace("Name", "Caption"),
            VM.replace("Msvm_ComputerSystem", "Win32_Process"),
            VM.replace(ID, "00000000-0000-0000-0000-000000000000"),
            VM.replace(ID, "*"),
            VM.replace(ID, "a\\b"),
            VM.replace(ID, "a\0b"),
            "é".into(),
            "x".repeat(513),
            String::new(),
        ] {
            assert!(system(&invalid, LOCAL).is_err(), "{invalid:?}");
        }
        for invalid in ["", "localhost.", ".", "a\\b", "a:b", "-host", "host-"] {
            assert!(system(VM, invalid).is_err());
        }
    }
    #[test]
    fn job_keys_have_explicit_bounds_without_guid_only_guessing() {
        for key_value in ["id", "Microsoft:job-1234", "{1234}", "a_b.c", "A"] {
            assert!(job(
                &format!("Msvm_ConcreteJob.InstanceID=\"{key_value}\""),
                LOCAL
            )
            .is_ok());
        }
        for key_value in [
            "".to_string(),
            "a".repeat(129),
            "a'b".into(),
            "a b".into(),
            "a=b".into(),
            "a\\b".into(),
            "a\"b".into(),
        ] {
            assert!(job(
                &format!("Msvm_ConcreteJob.InstanceID=\"{key_value}\""),
                LOCAL
            )
            .is_err());
        }
    }
    #[test]
    fn define_system_4096_is_pending_never_synchronous_success() {
        assert!(matches!(
            DefinitionReply::decode(4096, None, Some(JOB), LOCAL),
            Ok(DefinitionReply::Pending {
                candidate: None,
                ..
            })
        ));
        assert!(matches!(
            DefinitionReply::decode(0, Some(VM), None, LOCAL),
            Ok(DefinitionReply::Completed(_))
        ));
        for code in [1, 2, 3, 4, 4097, 32768, u32::MAX] {
            assert!(DefinitionReply::decode(code, Some(VM), Some(JOB), LOCAL).is_err());
        }
        for (code, vm, job_ref) in [
            (0, None, None),
            (0, Some(VM), Some(JOB)),
            (4096, Some(VM), None),
            (4096, None, Some("")),
            (4096, Some(""), Some(JOB)),
        ] {
            assert!(DefinitionReply::decode(code, vm, job_ref, LOCAL).is_err());
        }
    }
    #[test]
    fn normal_job_completion_requires_exact_causal_job_and_vm() {
        let mut tracker = pending(Some(VM));
        for state in 2..=6 {
            assert_eq!(tracker.observe(JOB, state, Some(0), None, LOCAL), Ok(None));
        }
        let actual = tracker
            .observe(JOB, 7, Some(0), Some(VM), LOCAL)
            .unwrap()
            .unwrap();
        assert_eq!(actual.vm_id(), ID);
        assert!(tracker.observe(JOB, 7, Some(0), Some(VM), LOCAL).is_err());
        let mut null_error = pending(None);
        assert_eq!(null_error.observe(JOB, 4, None, None, LOCAL), Ok(None));
        assert!(null_error.observe(JOB, 7, None, Some(VM), LOCAL).is_err());
        assert!(null_error
            .observe(JOB, 7, Some(0), Some(VM), LOCAL)
            .is_err());
        let mut tracker = pending(None);
        assert_eq!(
            tracker
                .observe(JOB, 7, Some(0), Some(VM), LOCAL)
                .unwrap()
                .unwrap()
                .vm_id(),
            ID
        );
    }
    #[test]
    fn any_job_error_mismatch_or_incomplete_result_permanently_fences() {
        for (job_ref, state, error, affected) in [
            (JOB, 7, 1, Some(VM)),
            (JOB, 4, 1, None),
            (JOB, 7, 0, None),
            (JOB, 8, 0, None),
            (JOB, 9, 0, None),
            (JOB, 10, 0, None),
            (JOB, 11, 0, None),
            (JOB, 0, 0, None),
            (JOB, u16::MAX, 0, None),
            (JOB, 4, 0, Some(VM)),
            ("Msvm_ConcreteJob.InstanceID=\"different\"", 7, 0, Some(VM)),
            (
                JOB,
                7,
                0,
                Some("Msvm_ComputerSystem.Name=\"12345678-1234-4234-8234-123456789abd\""),
            ),
        ] {
            let mut tracker = pending(Some(VM));
            assert!(tracker
                .observe(job_ref, state, Some(error), affected, LOCAL)
                .is_err());
            assert!(tracker.observe(JOB, 7, Some(0), Some(VM), LOCAL).is_err());
        }
        assert!(PendingDefinition::from_reply(
            DefinitionReply::decode(0, Some(VM), None, LOCAL).unwrap()
        )
        .is_err());
    }
}
