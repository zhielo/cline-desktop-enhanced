//! CI-only native SYSTEM acceptance, never shipped or installed. No arguments,
//! target bytes, VM effects, service installation, secrets or arbitrary paths.
#[cfg(windows)]
fn owned() -> Result<(), i32> {
    use cline_managed_inert_probe::windows_roots::SystemRoots;
    if std::env::args_os().len() != 1 {
        return Err(10);
    }
    // This executable requires an explicit test-only Cargo feature. Public
    // root APIs independently require real LocalSystem and no impersonation.
    let roots = SystemRoots::create_new().map_err(|_| 11)?;
    roots.revalidate().map_err(|_| 12)?;
    let paths = [
        roots.journal_parent().to_path_buf(),
        roots.anchor_parent().to_path_buf(),
        roots.job_parent().to_path_buf(),
        roots.image_parent().to_path_buf(),
    ];
    if SystemRoots::create_new().is_ok() {
        return Err(13);
    }
    let reopened = SystemRoots::open_existing().map_err(|_| 14)?;
    reopened.revalidate().map_err(|_| 15)?;
    if paths.iter().any(|path| std::fs::remove_dir(path).is_ok()) {
        return Err(16);
    }
    // Real SYSTEM integration: no test-only substitute identity policy here.
    let job = roots.create_job().map_err(|_| 20)?;
    let id = job.id().to_owned();
    if roots.open_job("../outside").is_ok() {
        return Err(21);
    }
    let opened_job = roots.open_job(&id).map_err(|_| 22)?;
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *key).map_err(|_| 23)?;
    let identity = cline_managed_inert_probe::lifecycle::Identity {
        installation: "12".repeat(16),
        job: id.clone(),
        vm_id: "12345678-1234-1234-1234-123456789abc".into(),
        image_sha256: "34".repeat(32),
        host_boot: "56".repeat(16),
    };
    let mut wrong = identity.clone();
    wrong.job = "00".repeat(16);
    if job.create_store(wrong, *key).is_ok() {
        return Err(24);
    }
    let mut store = job.create_store(identity.clone(), *key).map_err(|_| 25)?;
    if job.create_store(identity.clone(), *key).is_ok() {
        return Err(26);
    }
    store
        .advance(cline_managed_inert_probe::lifecycle::Event::VmCreated {})
        .map_err(|_| 27)?;
    // This is a reducer event only; no actual VM is created by the fixture.
    drop(store);
    let mut store = opened_job
        .open_store(identity.clone(), *key)
        .map_err(|_| 28)?;
    if store.journal().phase() != cline_managed_inert_probe::lifecycle::Phase::Created
        || !store.journal().recovery_required()
    {
        return Err(29);
    }
    {
        use windows_sys::Win32::Security::{ImpersonateSelf, RevertToSelf, SecurityImpersonation};
        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                unsafe {
                    RevertToSelf();
                }
            }
        }
        if unsafe { ImpersonateSelf(SecurityImpersonation) } == 0 {
            return Err(30);
        }
        let _revert = Revert;
        if store
            .advance(cline_managed_inert_probe::lifecycle::Event::RecoveryRequested {})
            .err()
            != Some("Impersonated protected storage access forbidden")
        {
            return Err(31);
        }
    }
    // Failed identity validation fences even after the thread stops impersonating.
    if store
        .advance(cline_managed_inert_probe::lifecycle::Event::RecoveryRequested {})
        .err()
        != Some("Protected store fenced; reopen and inspect")
    {
        return Err(32);
    }
    drop(store);
    let mut store = opened_job.open_store(identity, *key).map_err(|_| 33)?;
    store
        .advance(cline_managed_inert_probe::lifecycle::Event::RecoveryRequested {})
        .map_err(|_| 34)?;
    if store.journal().phase() != cline_managed_inert_probe::lifecycle::Phase::StopRequired
        || store.journal().recovery_required()
    {
        return Err(43);
    }
    drop(store);
    let material = job.write_boot_media().map_err(|_| 35)?;
    if job.write_boot_media().is_ok() {
        return Err(36);
    }
    let media = roots
        .job_parent()
        .join(&id)
        .join(cline_managed_inert_probe::boot_media::MEDIA_NAME);
    if std::fs::metadata(&media).map_err(|_| 37)?.len()
        != cline_managed_inert_probe::boot_media::MEDIA_BYTES as u64
    {
        return Err(38);
    }
    drop(material);
    let job_paths = [
        roots.journal_parent().join(&id),
        roots.anchor_parent().join(&id),
        roots.job_parent().join(&id),
    ];
    if job_paths
        .iter()
        .any(|path| std::fs::rename(path, path.with_extension("moved")).is_ok())
    {
        return Err(39);
    }
    drop(opened_job);
    drop(job);
    // Exactly the owned media and two closed SQLite files; no recursive removal.
    std::fs::remove_file(media).map_err(|_| 40)?;
    for path in &job_paths[..2] {
        std::fs::remove_file(path.join("recovery.sqlite")).map_err(|_| 41)?;
    }
    for path in &job_paths {
        std::fs::remove_dir(path).map_err(|_| 42)?;
    }
    installation_acceptance(&roots)?;
    reservation_acceptance(&roots)?;
    let parent = paths[0].parent().ok_or(17)?.to_path_buf();
    drop(reopened);
    drop(roots);
    // Only directories created by this successful exclusive fixture invocation
    // are cleaned. No recursive deletion or adoption of pre-existing state.
    for path in &paths {
        std::fs::remove_dir(path).map_err(|_| 18)?;
    }
    std::fs::remove_dir(parent).map_err(|_| 19)?;
    Ok(())
}
#[cfg(windows)]
fn main() {
    match owned() {
        Ok(()) => println!("Owned SYSTEM root acceptance passed; no VM or readiness established."),
        Err(code) => {
            eprintln!("Owned SYSTEM root acceptance failed; retained state requires inspection.");
            std::process::exit(code);
        }
    }
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Owned SYSTEM root acceptance requires native Windows CI.");
    std::process::exit(2);
}

#[cfg(windows)]
fn installation_acceptance(
    roots: &cline_managed_inert_probe::windows_roots::SystemRoots,
) -> Result<(), i32> {
    use cline_managed_inert_probe::{
        lifecycle::{Event, Identity, Phase},
        windows_identity::{SystemIdentity, INSTALLATION_FILE},
    };
    let owner = SystemIdentity::create(roots).map_err(|_| 50)?;
    let installation = owner.installation().to_owned();
    if SystemIdentity::create(roots).is_ok() || SystemIdentity::open(roots).is_ok() {
        return Err(51);
    }
    let job = roots.create_job().map_err(|_| 52)?;
    let id = job.id().to_owned();
    let expected = Identity {
        installation: installation.clone(),
        job: id.clone(),
        vm_id: "11223344-5566-7788-99aa-bbccddeeff00".into(),
        image_sha256: "78".repeat(32),
        host_boot: "9a".repeat(16),
    };
    let mut wrong = expected.clone();
    wrong.installation = "00".repeat(16);
    if owner.create_store(&job, wrong).is_ok() {
        return Err(53);
    }
    let mut store = owner.create_store(&job, expected.clone()).map_err(|_| 54)?;
    store.advance(Event::VmCreated {}).map_err(|_| 55)?;
    drop(store);
    drop(owner);
    // Real SYSTEM-user DPAPI decrypt and key re-derivation after handle teardown.
    let owner = SystemIdentity::open(roots).map_err(|_| 56)?;
    if owner.installation() != installation {
        return Err(57);
    }
    let mut wrong = expected.clone();
    wrong.image_sha256 = "ab".repeat(32);
    if owner.open_store(&job, wrong).is_ok() {
        return Err(58);
    }
    let mut store = owner.open_store(&job, expected.clone()).map_err(|_| 59)?;
    if store.journal().phase() != Phase::Created || !store.journal().recovery_required() {
        return Err(60);
    }
    {
        use windows_sys::Win32::Security::{ImpersonateSelf, RevertToSelf, SecurityImpersonation};
        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                unsafe {
                    RevertToSelf();
                }
            }
        }
        if unsafe { ImpersonateSelf(SecurityImpersonation) } == 0 {
            return Err(61);
        }
        let _revert = Revert;
        if SystemIdentity::open(roots).err()
            != Some("Impersonated protected storage access forbidden")
            || store.advance(Event::RecoveryRequested {}).err()
                != Some("Impersonated protected storage access forbidden")
        {
            return Err(62);
        }
    }
    if store.advance(Event::RecoveryRequested {}).err()
        != Some("Installation store fenced; reopen and inspect")
    {
        return Err(63);
    }
    drop(store);
    let mut store = owner.open_store(&job, expected).map_err(|_| 64)?;
    store.advance(Event::RecoveryRequested {}).map_err(|_| 65)?;
    if store.journal().phase() != Phase::StopRequired || store.journal().recovery_required() {
        return Err(66);
    }
    drop(store);
    drop(owner);
    let record = roots
        .anchor_parent()
        .parent()
        .ok_or(67)?
        .join(INSTALLATION_FILE);
    std::fs::remove_file(record).map_err(|_| 68)?;
    let paths = [
        roots.journal_parent().join(&id),
        roots.anchor_parent().join(&id),
        roots.job_parent().join(&id),
    ];
    drop(job);
    for path in &paths[..2] {
        std::fs::remove_file(path.join("recovery.sqlite")).map_err(|_| 69)?;
    }
    for path in &paths {
        std::fs::remove_dir(path).map_err(|_| 70)?;
    }
    Ok(())
}

#[cfg(windows)]
fn reservation_acceptance(
    roots: &cline_managed_inert_probe::windows_roots::SystemRoots,
) -> Result<(), i32> {
    use cline_managed_inert_probe::{
        lifecycle::{Event, Phase},
        windows_identity::{SystemIdentity, INSTALLATION_FILE, OWNERSHIP_FILE},
    };
    let boot = cline_managed_inert_probe::windows_boot::HostBoot::observe().map_err(|_| 108)?;
    let owner = SystemIdentity::create(roots).map_err(|_| 80)?;
    let job = roots.create_job().map_err(|_| 81)?;
    let id = job.id().to_owned();
    if owner.open_vm(&job).is_ok() {
        return Err(82);
    }
    let record = owner.reserve_vm(&job, &"35".repeat(32)).map_err(|_| 83)?;
    let expected = record.identity().clone();
    if expected.installation != owner.installation()
        || expected.job != id
        || expected.vm_id.as_bytes()[14] != b'4'
        || !b"89ab".contains(&expected.vm_id.as_bytes()[19])
        || expected.image_sha256 != "35".repeat(32)
        || expected.host_boot != boot.id()
        || owner.reserve_vm(&job, &"35".repeat(32)).is_ok()
        || owner.open_vm(&job).is_ok()
    {
        return Err(84);
    }
    record.revalidate().map_err(|_| 85)?;
    record.require_original_boot().map_err(|_| 109)?;
    let mut store = record.create_store().map_err(|_| 86)?;
    store.advance(Event::VmCreated {}).map_err(|_| 87)?;
    drop(store);
    drop(record);
    drop(owner);
    let owner = SystemIdentity::open(roots).map_err(|_| 88)?;
    let record = owner.open_vm(&job).map_err(|_| 89)?;
    if record.identity() != &expected {
        return Err(90);
    }
    let mut store = record.open_store().map_err(|_| 91)?;
    if store.journal().phase() != Phase::Created || !store.journal().recovery_required() {
        return Err(92);
    }
    store.advance(Event::RecoveryRequested {}).map_err(|_| 93)?;
    if store.journal().phase() != Phase::StopRequired {
        return Err(94);
    }
    drop(store);
    drop(record);
    let record_path = roots.job_parent().join(&id).join(OWNERSHIP_FILE);
    let original = std::fs::read(&record_path).map_err(|_| 95)?;
    let mut value: serde_json::Value = serde_json::from_slice(&original).map_err(|_| 96)?;
    value["mac"] = "00".repeat(32).into();
    // Fixture-only mutation of this exact closed owned file; production has no repair API.
    std::fs::write(&record_path, serde_json::to_vec(&value).map_err(|_| 97)?).map_err(|_| 98)?;
    if owner.open_vm(&job).err() != Some("VM reservation authentication failed") {
        return Err(99);
    }
    std::fs::write(&record_path, &original).map_err(|_| 100)?;
    let record = owner.open_vm(&job).map_err(|_| 101)?;
    record.revalidate().map_err(|_| 102)?;
    drop(record);
    drop(owner);
    let installation = roots
        .anchor_parent()
        .parent()
        .ok_or(103)?
        .join(INSTALLATION_FILE);
    let paths = [
        roots.journal_parent().join(&id),
        roots.anchor_parent().join(&id),
        roots.job_parent().join(&id),
    ];
    drop(job);
    std::fs::remove_file(record_path).map_err(|_| 104)?;
    std::fs::remove_file(installation).map_err(|_| 105)?;
    for path in &paths[..2] {
        std::fs::remove_file(path.join("recovery.sqlite")).map_err(|_| 106)?;
    }
    for path in &paths {
        std::fs::remove_dir(path).map_err(|_| 107)?;
    }
    Ok(())
}
