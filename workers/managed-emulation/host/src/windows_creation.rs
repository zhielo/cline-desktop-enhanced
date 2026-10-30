//! SYSTEM-only durable pre-effect intent and single-use submission issuance.
//! No DefineSystem call, VM creation/ownership, approval, boot or readiness.
//! All interrupted/issued records remain; inspection can never restore a permit.
pub use crate::creation_records::CreationStage;
use crate::{
    creation_records::{self, Context, Role, MAX_BYTES},
    windows_identity::OwnedVmRecord,
    Result,
};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Write};

struct Held {
    role: Role,
    file: File,
    digest: [u8; 32],
}
/// Borrowed protected installation/job/reservation remain alive across issuance.
/// No Clone/Deserialize, raw key, path, handle, command or VM operation escapes.
pub struct CreationAttempt<'a, 'o, 'r, 'j, 'jr> {
    record: &'a OwnedVmRecord<'o, 'r, 'j, 'jr>,
    context: Context,
    files: Vec<Held>,
}
/// Persistence guard only, not execution approval. Future native factory must
/// consume this by value after independent authorization and supervision.
pub struct CreationPermit<'a, 'o, 'r, 'j, 'jr> {
    attempt: CreationAttempt<'a, 'o, 'r, 'j, 'jr>,
    fenced: bool,
}
pub struct CreationInspection {
    stage: CreationStage,
    attempt: String,
}
impl CreationInspection {
    pub fn stage(&self) -> CreationStage {
        self.stage
    }
    pub fn attempt_id(&self) -> &str {
        &self.attempt
    }
}
fn write(record: &OwnedVmRecord<'_, '_, '_, '_>, role: Role, context: &Context) -> Result<Held> {
    record.require_original_boot()?;
    let key = record.creation_key()?;
    let bytes = creation_records::encode(&key, role, context)?;
    let mut file = record.creation_file(role, true)?;
    file.write_all(&bytes)
        .map_err(|_| "Creation record write failed; retain state")?;
    file.sync_all()
        .map_err(|_| "Creation record sync failed; retain state")?;
    if crate::windows_identity::creation_contents(&file, MAX_BYTES)?.as_slice() != bytes {
        return Err("Creation persistence mismatch; retain state");
    }
    record.require_original_boot()?;
    Ok(Held {
        role,
        file,
        digest: Sha256::digest(&bytes).into(),
    })
}
fn empty(record: &OwnedVmRecord<'_, '_, '_, '_>, roles: &[Role]) -> Result<()> {
    for role in roles {
        if record.creation_exists(*role)? {
            return Err("Creation attempt already retained; no retry or overwrite");
        }
    }
    Ok(())
}
impl<'a, 'o, 'r, 'j, 'jr> CreationAttempt<'a, 'o, 'r, 'j, 'jr> {
    pub fn prepare(record: &'a OwnedVmRecord<'o, 'r, 'j, 'jr>) -> Result<Self> {
        Self::prepare_observed(record, |_| Ok(()))
    }
    fn prepare_observed(
        record: &'a OwnedVmRecord<'o, 'r, 'j, 'jr>,
        mut boundary: impl FnMut(Role) -> Result<()>,
    ) -> Result<Self> {
        record.require_original_boot()?;
        empty(record, &Role::ALL)?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| "Creation entropy unavailable")?;
        let context = Context {
            version: 1,
            attempt: hex::encode(nonce),
            reservation: record.creation_digest(),
            host_boot: record.identity().host_boot.clone(),
        };
        let mut files = Vec::new();
        for role in [Role::PrepareAnchor, Role::Intent] {
            files.push(write(record, role, &context)?);
            boundary(role)?;
        }
        let value = Self {
            record,
            context,
            files,
        };
        value.revalidate(2)?;
        Ok(value)
    }
    fn revalidate(&self, count: usize) -> Result<()> {
        self.record.require_original_boot()?;
        if self.files.len() != count {
            return Err("Creation live guard shape mismatch");
        }
        let key = self.record.creation_key()?;
        for held in &self.files {
            let bytes = crate::windows_identity::creation_contents(&held.file, MAX_BYTES)?;
            if <[u8; 32]>::from(Sha256::digest(&bytes)) != held.digest
                || creation_records::decode(&key, held.role, &bytes)? != self.context
            {
                return Err("Creation record changed; retain state");
            }
        }
        self.record.require_original_boot()
    }
    pub fn arm(self) -> Result<CreationPermit<'a, 'o, 'r, 'j, 'jr>> {
        self.arm_observed(|_| Ok(()))
    }
    fn arm_observed(
        mut self,
        mut boundary: impl FnMut(Role) -> Result<()>,
    ) -> Result<CreationPermit<'a, 'o, 'r, 'j, 'jr>> {
        self.revalidate(2)?;
        empty(self.record, &[Role::IssueAnchor, Role::Issued])?;
        for role in [Role::IssueAnchor, Role::Issued] {
            self.files.push(write(self.record, role, &self.context)?);
            boundary(role)?;
        }
        self.revalidate(4)?;
        Ok(CreationPermit {
            attempt: self,
            fenced: false,
        })
    }
}
impl CreationPermit<'_, '_, '_, '_, '_> {
    pub fn require_current(&mut self) -> Result<()> {
        if self.fenced {
            return Err("Creation permit fenced; inspect retained attempt");
        }
        self.fenced = true;
        self.attempt.revalidate(4)?;
        self.fenced = false;
        Ok(())
    }
    pub fn attempt_id(&self) -> &str {
        &self.attempt.context.attempt
    }
}
/// Historical point-in-time data only, including across host reboot. Does not
/// resume/reissue work or infer whether an external operation ever happened.
pub fn inspect(record: &OwnedVmRecord<'_, '_, '_, '_>) -> Result<CreationInspection> {
    record.revalidate()?;
    let key = record.creation_key()?;
    let mut held = Vec::new();
    let mut context = None;
    let mut mask = 0;
    for role in Role::ALL {
        if record.creation_exists(role)? {
            let file = record.creation_file(role, false)?;
            let bytes = crate::windows_identity::creation_contents(&file, MAX_BYTES)?;
            let actual = creation_records::decode(&key, role, &bytes)?;
            if actual.reservation != record.creation_digest()
                || actual.host_boot != record.identity().host_boot
            {
                return Err("Creation reservation identity mismatch");
            }
            if context.as_ref().is_some_and(|c| c != &actual) {
                return Err("Creation attempt records disagree");
            }
            mask |= role.bit();
            context = Some(actual);
            held.push(file);
        }
    }
    record.revalidate()?;
    let stage = creation_records::stage(mask)?;
    let context = context.ok_or("No creation attempt exists")?;
    Ok(CreationInspection {
        stage,
        attempt: context.attempt,
    })
}

/// Explicit SYSTEM fixture only: real fixed files, independent anchors,
/// interruption cuts, reopen and refusal. No VM/native management API invoked.
#[cfg(feature = "owned-system-acceptance")]
pub fn owned_system_acceptance(
    roots: &crate::windows_roots::SystemRoots,
    owner: &crate::windows_identity::SystemIdentity<'_>,
    image: &crate::windows_image::SystemImage<'_>,
) -> Result<()> {
    use std::fs;
    use windows_sys::Win32::{
        Foundation::ERROR_SHARING_VIOLATION,
        Security::{ImpersonateSelf, RevertToSelf, SecurityImpersonation},
    };
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            if unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
        }
    }
    for scenario in 0..8 {
        let job = roots.create_job()?;
        let id = job.id().to_owned();
        let record = owner.reserve_vm(&job, image)?;
        if inspect(&record)
            .err()
            .map(|e| e == "No creation attempt exists")
            != Some(true)
        {
            return Err("New owned creation state was not empty");
        }
        let paths = [
            roots.journal_parent().join(&id),
            roots.anchor_parent().join(&id),
            roots.job_parent().join(&id),
        ];
        let path = |role: Role| paths[if role.anchor() { 1 } else { 2 }].join(role.filename());
        let (expected, mask) = match scenario {
            0 => {
                let attempt = CreationAttempt::prepare(&record)?;
                if CreationAttempt::prepare(&record).is_ok() {
                    return Err("Owned creation preparation was repeated");
                }
                let error = fs::OpenOptions::new()
                    .write(true)
                    .open(path(Role::Intent))
                    .err()
                    .ok_or("Held creation record admitted a writer")?;
                if error.raw_os_error() != Some(ERROR_SHARING_VIOLATION as i32) {
                    return Err("Owned creation writer refusal was not sharing protection");
                }
                let mut permit = attempt.arm()?;
                permit.require_current()?;
                let attempt_id = permit.attempt_id().to_owned();
                crate::exact_hex::<16>(&attempt_id)?;
                if unsafe { ImpersonateSelf(SecurityImpersonation) } == 0 {
                    return Err("Owned creation impersonation unavailable");
                }
                {
                    let _revert = Revert;
                    if permit.require_current().err()
                        != Some("Impersonated protected storage access forbidden")
                    {
                        return Err("Creation permit accepted impersonation");
                    }
                }
                if permit.require_current().err()
                    != Some("Creation permit fenced; inspect retained attempt")
                {
                    return Err("Failed creation permit was revived");
                }
                drop(permit);
                let metadata = inspect(&record)?;
                if metadata.attempt_id() != attempt_id {
                    return Err("Creation issuance identity changed");
                }
                (Some(CreationStage::SubmissionIssued), 15)
            }
            1 => {
                if CreationAttempt::prepare_observed(&record, |role| {
                    if role == Role::PrepareAnchor {
                        Err("owned preparation cut")
                    } else {
                        Ok(())
                    }
                })
                .err()
                .map(|e| e == "owned preparation cut")
                    != Some(true)
                {
                    return Err("Owned preparation boundary did not interrupt");
                }
                (Some(CreationStage::PreparationIncomplete), 1)
            }
            2 => {
                let attempt = CreationAttempt::prepare(&record)?;
                if attempt
                    .arm_observed(|role| {
                        if role == Role::IssueAnchor {
                            Err("owned issuance cut")
                        } else {
                            Ok(())
                        }
                    })
                    .err()
                    .map(|e| e == "owned issuance cut")
                    != Some(true)
                {
                    return Err("Owned issuance boundary did not interrupt");
                }
                (Some(CreationStage::IssuanceIncomplete), 7)
            }
            3 => {
                drop(CreationAttempt::prepare(&record)?);
                (Some(CreationStage::Prepared), 3)
            }
            4 => {
                drop(CreationAttempt::prepare(&record)?);
                fs::write(
                    path(Role::Intent),
                    fs::read(path(Role::PrepareAnchor))
                        .map_err(|_| "Owned creation anchor read failed")?,
                )
                .map_err(|_| "Owned cross-role mutation failed")?;
                if inspect(&record)
                    .err()
                    .map(|e| e == "Creation record authentication failed")
                    != Some(true)
                {
                    return Err("Owned cross-role record was admitted");
                }
                (None, 3)
            }
            5 => {
                drop(CreationAttempt::prepare(&record)?);
                fs::write(path(Role::Intent), [])
                    .map_err(|_| "Owned creation truncation failed")?;
                if inspect(&record)
                    .err()
                    .map(|e| e == "Protected installation record budget")
                    != Some(true)
                {
                    return Err("Owned partial creation record was admitted");
                }
                (None, 3)
            }
            6 => {
                drop(CreationAttempt::prepare(&record)?.arm()?);
                fs::remove_file(path(Role::Intent))
                    .map_err(|_| "Owned creation gap mutation failed")?;
                if inspect(&record)
                    .err()
                    .map(|e| e == "Creation record layout inconsistent; retain state")
                    != Some(true)
                {
                    return Err("Owned creation record gap was admitted");
                }
                (None, 13)
            }
            _ => {
                // All four writes persisted, but no live permit was delivered.
                // This diagnostic stage must never imply an API call happened.
                let attempt = CreationAttempt::prepare(&record)?;
                if attempt
                    .arm_observed(|role| {
                        if role == Role::Issued {
                            Err("owned issued-delivery cut")
                        } else {
                            Ok(())
                        }
                    })
                    .err()
                    != Some("owned issued-delivery cut")
                {
                    return Err("Owned final issuance boundary did not interrupt");
                }
                (Some(CreationStage::SubmissionIssued), 15)
            }
        };
        if let Some(expected) = expected {
            if inspect(&record)?.stage() != expected {
                return Err("Owned creation interruption stage mismatch");
            }
        }
        if CreationAttempt::prepare(&record).is_ok() {
            return Err("Retained creation state allowed a retry");
        }
        drop(record);
        // Real protected-file reopen is diagnostic only; there is no resume API.
        let reopened = owner.open_vm(&job)?;
        if let Some(expected) = expected {
            if inspect(&reopened)?.stage() != expected {
                return Err("Owned creation stage changed on reopen");
            }
        }
        drop(reopened);
        drop(job);
        for role in Role::ALL {
            if mask & role.bit() != 0 {
                fs::remove_file(path(role)).map_err(|_| "Owned closed creation cleanup failed")?;
            }
        }
        fs::remove_file(paths[2].join(crate::windows_identity::OWNERSHIP_FILE))
            .map_err(|_| "Owned creation reservation cleanup failed")?;
        for path in paths {
            fs::remove_dir(path).map_err(|_| "Owned creation directory cleanup failed")?;
        }
    }
    Ok(())
}
