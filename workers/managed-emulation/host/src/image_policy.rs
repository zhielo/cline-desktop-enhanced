//! Compiled image admission policy, not a shipping image catalog or readiness.
//! Development images are deliberately excluded from production admission.
#[cfg(any(windows, test))]
use crate::Result;

#[derive(Clone, Copy)]
pub enum Engine {
    Qiling,
    Unidbg,
    Rnidbg,
    Speakeasy,
}

#[cfg(any(windows, test))]
pub(crate) struct Pin {
    pub(crate) bytes: u64,
    pub(crate) sha256: &'static str,
}

/// Must be populated only with reviewed shipping images/source/notices. Never
/// derive pins from a request, sidecar JSON, development manifest or disk bytes.
#[cfg(any(windows, test))]
pub(crate) fn reviewed(_engine: Engine) -> Option<Pin> {
    None
}

#[cfg(any(windows, test))]
pub(crate) const MAX_IMAGE_BYTES: u64 = 768 * 1024 * 1024;

#[cfg(any(windows, test))]
impl Pin {
    pub(crate) fn filename(&self) -> Result<String> {
        crate::exact_hex::<32>(self.sha256)?;
        if self.bytes == 0 || self.bytes > MAX_IMAGE_BYTES {
            return Err("Reviewed image byte budget");
        }
        Ok(format!("{}.iso", self.sha256))
    }
}

/// Bounded streaming comparison; never loads an ISO or executes its contents.
#[cfg(any(windows, test))]
pub(crate) fn verify(reader: &mut impl std::io::Read, pin: &Pin) -> Result<()> {
    use sha2::{Digest, Sha256};
    pin.filename()?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut total = 0u64;
    loop {
        let allowance = (pin.bytes - total + 1).min(buffer.len() as u64) as usize;
        let count = reader
            .read(&mut buffer[..allowance])
            .map_err(|_| "Protected image read failed")?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > pin.bytes {
            return Err("Protected image grew");
        }
        hash.update(&buffer[..count]);
    }
    if total != pin.bytes || hex::encode(hash.finalize()) != pin.sha256 {
        return Err("Protected image identity mismatch");
    }
    Ok(())
}

#[cfg(all(windows, feature = "owned-system-acceptance"))]
pub(crate) const OWNED_BYTES: &[u8] = b"cline-owned-image-admission-fixture/v1\n";
#[cfg(all(windows, feature = "owned-system-acceptance"))]
pub(crate) fn owned_pin() -> Pin {
    Pin {
        bytes: OWNED_BYTES.len() as u64,
        sha256: "5195816fc7c17ac91f1e197f36250cf30f54fd2b486bb0db36192b37bf7ed6eb",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor, Read};
    const SHA: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    fn pin() -> Pin {
        Pin {
            bytes: 5,
            sha256: SHA,
        }
    }
    #[test]
    fn development_images_never_supply_shipping_pins() {
        for engine in [
            Engine::Qiling,
            Engine::Unidbg,
            Engine::Rnidbg,
            Engine::Speakeasy,
        ] {
            assert!(reviewed(engine).is_none());
        }
    }
    #[test]
    fn exact_bytes_and_digest_only() {
        assert_eq!(pin().filename().unwrap(), format!("{SHA}.iso"));
        assert!(verify(&mut Cursor::new(b"hello"), &pin()).is_ok());
        for bytes in [b"".as_slice(), b"hell", b"hellp", b"hello!"] {
            assert!(verify(&mut Cursor::new(bytes), &pin()).is_err());
        }
        for p in [
            Pin {
                bytes: 0,
                sha256: SHA,
            },
            Pin {
                bytes: MAX_IMAGE_BYTES + 1,
                sha256: SHA,
            },
            Pin {
                bytes: 5,
                sha256: "../outside",
            },
        ] {
            assert!(p.filename().is_err());
        }
    }
    #[test]
    fn short_reads_work_and_overflow_is_bounded() {
        struct Short(Cursor<Vec<u8>>);
        impl Read for Short {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                self.0.read(&mut out[..1])
            }
        }
        assert!(verify(&mut Short(Cursor::new(b"hello".to_vec())), &pin()).is_ok());
        let mut extra = Cursor::new(vec![0; 1024]);
        assert_eq!(verify(&mut extra, &pin()), Err("Protected image grew"));
        assert_eq!(extra.position(), 6);
    }
    #[test]
    fn read_error_is_not_identity_evidence() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("private diagnostic must not escape"))
            }
        }
        assert_eq!(
            verify(&mut Broken, &pin()),
            Err("Protected image read failed")
        );
    }
}
