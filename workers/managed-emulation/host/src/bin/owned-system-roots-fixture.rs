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
    if store.journal().phase() != cline_managed_inert_probe::lifecycle::Phase::Created {
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
            .advance(cline_managed_inert_probe::lifecycle::Event::StopRequested {})
            .is_ok()
        {
            return Err(31);
        }
    }
    // Failed identity validation fences even after the thread stops impersonating.
    if store
        .advance(cline_managed_inert_probe::lifecycle::Event::StopRequested {})
        .is_ok()
    {
        return Err(32);
    }
    drop(store);
    let mut store = opened_job.open_store(identity, *key).map_err(|_| 33)?;
    store
        .advance(cline_managed_inert_probe::lifecycle::Event::StopRequested {})
        .map_err(|_| 34)?;
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
