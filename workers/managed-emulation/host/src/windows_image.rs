//! Read-only admission of an already staged exact protected shipping image.
//! No downloader, installer, VM attachment, target execution or readiness claim.
use crate::{
    image_policy::{self, Engine, Pin},
    windows_roots::SystemRoots,
    Result,
};
use std::{fs::File, io::Read, os::windows::fs::FileExt};

pub struct SystemImage<'roots> {
    roots: &'roots SystemRoots,
    file: File,
    pin: Pin,
}

// Explicit offset reads never depend on a shared file cursor or clone/reset it.
struct Reader<'file> {
    file: &'file File,
    offset: u64,
}
impl Read for Reader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let count = self.file.seek_read(out, self.offset)?;
        self.offset += count as u64;
        Ok(count)
    }
}

impl<'roots> SystemImage<'roots> {
    /// Only the native compiled catalog can authorize a production image.
    /// Missing pins refuse before any file is opened. No caller digest or path.
    pub fn open(roots: &'roots SystemRoots, engine: Engine) -> Result<Self> {
        roots.revalidate()?;
        let pin = image_policy::reviewed(engine).ok_or("No reviewed shipping image available")?;
        Self::admit(roots, pin)
    }
    fn admit(roots: &'roots SystemRoots, pin: Pin) -> Result<Self> {
        let file = roots.image_file(&pin.filename()?)?;
        let value = Self { roots, file, pin };
        value.revalidate()?;
        Ok(value)
    }
    /// The held single-link, protected, non-reparse file permits read sharing
    /// only. The parent guards stay borrowed; no raw handle/path escapes here.
    pub fn revalidate(&self) -> Result<()> {
        self.roots.revalidate()?;
        if crate::windows_roots::validate_image_file(&self.file)? != self.pin.bytes {
            return Err("Protected image size mismatch");
        }
        image_policy::verify(
            &mut Reader {
                file: &self.file,
                offset: 0,
            },
            &self.pin,
        )?;
        if crate::windows_roots::validate_image_file(&self.file)? != self.pin.bytes {
            return Err("Protected image changed");
        }
        Ok(())
    }
    pub fn sha256(&self) -> &str {
        self.pin.sha256
    }

    /// Exact public data fixture only; feature-gated binary never ships.
    #[cfg(feature = "owned-system-acceptance")]
    pub fn create_owned_fixture(roots: &'roots SystemRoots) -> Result<Self> {
        use std::io::Write;
        roots.revalidate()?;
        let pin = image_policy::owned_pin();
        let mut file = roots.create_owned_image_fixture(&pin.filename()?)?;
        file.write_all(image_policy::OWNED_BYTES)
            .map_err(|_| "Owned image fixture write failed; retain state")?;
        file.sync_all()
            .map_err(|_| "Owned image fixture sync failed; retain state")?;
        drop(file);
        Self::admit(roots, pin)
    }
}

/// Actual SYSTEM file/namespace checks with fixed public, nonbootable data only.
/// No production pin is populated and no VM, service or readiness is created.
#[cfg(feature = "owned-system-acceptance")]
pub fn owned_system_acceptance(roots: &SystemRoots) -> Result<()> {
    use std::fs;
    for engine in [
        Engine::Qiling,
        Engine::Unidbg,
        Engine::Rnidbg,
        Engine::Speakeasy,
    ] {
        if SystemImage::open(roots, engine).err() != Some("No reviewed shipping image available") {
            return Err("Development image incorrectly admitted as shipping");
        }
    }
    let image = SystemImage::create_owned_fixture(roots)?;
    let path = roots
        .image_parent()
        .join(image_policy::owned_pin().filename()?);
    image.revalidate()?;
    {
        use windows_sys::Win32::Security::{ImpersonateSelf, RevertToSelf, SecurityImpersonation};
        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                if unsafe { RevertToSelf() } == 0 {
                    std::process::abort();
                }
            }
        }
        if unsafe { ImpersonateSelf(SecurityImpersonation) } == 0 {
            return Err("Owned image impersonation fixture failed");
        }
        let _revert = Revert;
        if image.revalidate().err() != Some("Impersonated protected storage access forbidden") {
            return Err("Impersonated image was admitted");
        }
    }
    image.revalidate()?;
    if SystemImage::create_owned_fixture(roots).is_ok() {
        return Err("Owned image fixture overwritten");
    }
    // Reader sharing supports the future VM reader; write and rename must fail
    // for the actual sharing boundary, not for unrelated resource exhaustion.
    drop(fs::File::open(&path).map_err(|_| "Image read sharing unavailable")?);
    if fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .err()
        .and_then(|e| e.raw_os_error())
        != Some(32)
        || fs::rename(&path, path.with_extension("moved"))
            .err()
            .and_then(|e| e.raw_os_error())
            != Some(32)
    {
        return Err("Held image write/rename boundary failed");
    }
    drop(image);
    let mut changed = image_policy::OWNED_BYTES.to_vec();
    changed[0] ^= 1;
    fs::write(&path, changed).map_err(|_| "Owned image mutation failed")?;
    if SystemImage::admit(roots, image_policy::owned_pin()).err()
        != Some("Protected image identity mismatch")
    {
        return Err("Changed image was admitted");
    }
    fs::write(&path, image_policy::OWNED_BYTES).map_err(|_| "Owned image restoration failed")?;
    let linked = path.with_extension("owned-link");
    fs::hard_link(&path, &linked).map_err(|_| "Owned image link fixture failed")?;
    if SystemImage::admit(roots, image_policy::owned_pin()).err()
        != Some("Single-link protected regular installation file required")
    {
        return Err("Linked image was admitted");
    }
    fs::remove_file(&linked).map_err(|_| "Owned image link cleanup failed")?;
    drop(SystemImage::admit(roots, image_policy::owned_pin())?);
    fs::write(&path, []).map_err(|_| "Owned empty image fixture failed")?;
    if SystemImage::admit(roots, image_policy::owned_pin()).is_ok() {
        return Err("Empty image was admitted");
    }
    fs::write(&path, image_policy::OWNED_BYTES).map_err(|_| "Owned image restoration failed")?;
    drop(SystemImage::admit(roots, image_policy::owned_pin())?);
    fs::remove_file(&path).map_err(|_| "Owned exact image cleanup failed")?;
    Ok(())
}
