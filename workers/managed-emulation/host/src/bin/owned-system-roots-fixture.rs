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
