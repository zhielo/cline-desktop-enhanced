//! Explicit CI-only SCM host. Not packaged, auto-installed or a framework service.
#[cfg(windows)]
fn main() {
    // Independent CI-only whole-process bound; never a VM termination receipt.
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(120));
        std::process::exit(124);
    });
    if cline_managed_inert_probe::windows_service::dispatch().is_err() {
        std::process::exit(2);
    }
}
#[cfg(not(windows))]
fn main() {
    std::process::exit(2);
}
