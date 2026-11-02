//! CI-only owned media generator. No VM, host probe, ready state or credential output.
use cline_managed_inert_probe::boot_media::BootMaterial;
fn run() -> Result<(), &'static str> {
    let mut args = std::env::args_os().skip(1);
    let path = args.next().ok_or("Private fixture directory required")?;
    if args.next().is_some() {
        return Err("One private fixture directory required");
    }
    BootMaterial::generate()?.write_media(std::path::Path::new(&path))
}
fn main() {
    if run().is_err() {
        eprintln!("Owned boot media generation failed; no readiness established.");
        std::process::exit(1);
    }
    println!("Owned private boot media written; no VM or readiness established.");
}
