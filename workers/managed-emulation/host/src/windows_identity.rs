//! Fixed SYSTEM-user DPAPI installation identity and domain-bound recovery keys.
//! Not a caller authenticator, installer, VM ownership record or rollback attestation.
use crate::{
    lifecycle::{Event, Identity, Journal},
    windows_roots::{ProtectedStore, SystemJob, SystemRoots},
    Result,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Write, os::windows::fs::FileExt, ptr::null_mut};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    },
};
use zeroize::Zeroizing;

pub const INSTALLATION_FILE: &str = "installation.bin";
const MAGIC: &[u8] = b"cline-managed-identity/v1\0";
const ENTROPY: &[u8] = b"cline-managed-SYSTEM-installation/v1";
const KEY_DOMAIN: &[u8] = b"cline-managed-recovery-key/v1\0";
const MAX_BLOB: usize = 16384;

struct NativeBlob(CRYPT_INTEGER_BLOB);
impl Drop for NativeBlob {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            // DPAPI allocations may contain plaintext, including on parse errors.
            for at in 0..self.0.cbData as usize {
                unsafe { std::ptr::write_volatile(self.0.pbData.add(at), 0) };
            }
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
            unsafe { LocalFree(self.0.pbData.cast()) };
        }
    }
}
fn crypt(input: &[u8], protect: bool) -> Result<Zeroizing<Vec<u8>>> {
    if input.is_empty() || input.len() > MAX_BLOB {
        return Err("Installation cryptographic input budget");
    }
    let data = CRYPT_INTEGER_BLOB {
        cbData: input.len() as u32,
        pbData: input.as_ptr().cast_mut(),
    };
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: ENTROPY.len() as u32,
        pbData: ENTROPY.as_ptr().cast_mut(),
    };
    let mut output = NativeBlob(CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    });
    // SYSTEM user scope, never CRYPTPROTECT_LOCAL_MACHINE, never a UI prompt.
    let ok = unsafe {
        if protect {
            CryptProtectData(
                &data,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        } else {
            CryptUnprotectData(
                &data,
                null_mut(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        }
    };
    if ok == 0
        || output.0.pbData.is_null()
        || output.0.cbData == 0
        || output.0.cbData as usize > MAX_BLOB
    {
        return Err("SYSTEM installation protection unavailable; inspect retained state");
    }
    Ok(Zeroizing::new(
        unsafe { std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize) }.to_vec(),
    ))
}
fn contents(file: &File) -> Result<Zeroizing<Vec<u8>>> {
    let size = crate::windows_roots::validate_system_file(file, false)? as usize;
    let mut bytes = Zeroizing::new(vec![0; size]);
    let mut offset = 0;
    while offset < size {
        let read = file
            .seek_read(&mut bytes[offset..], offset as u64)
            .map_err(|_| "Installation record read failed")?;
        if read == 0 {
            return Err("Installation record truncated");
        }
        offset += read;
    }
    let mut extra = [0u8; 1];
    if file
        .seek_read(&mut extra, size as u64)
        .map_err(|_| "Installation record read failed")?
        != 0
        || crate::windows_roots::validate_system_file(file, false)? as usize != size
    {
        return Err("Installation record changed");
    }
    Ok(bytes)
}

/// No Debug/Clone/Serialize or key accessor. The exclusive file handle and roots
/// remain held for the installation/store lifetime. Admins/SYSTEM are trusted.
pub struct SystemIdentity<'roots> {
    roots: &'roots SystemRoots,
    file: File,
    digest: [u8; 32],
    id: String,
    key: Zeroizing<[u8; 32]>,
}
impl<'roots> SystemIdentity<'roots> {
    /// New record only; failure leaves partial state. No overwrite or recovery by guessing.
    pub fn create(roots: &'roots SystemRoots) -> Result<Self> {
        roots.revalidate()?;
        let mut random = Zeroizing::new([0u8; 48]);
        getrandom::fill(&mut *random).map_err(|_| "Installation entropy unavailable")?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(MAGIC.len() + 48));
        plaintext.extend_from_slice(MAGIC);
        plaintext.extend_from_slice(random.as_slice());
        let ciphertext = crypt(&plaintext, true)?;
        let mut file = roots.installation_file(true)?;
        file.write_all(&ciphertext)
            .map_err(|_| "Installation record write failed; retain state")?;
        file.sync_all()
            .map_err(|_| "Installation record sync failed; retain state")?;
        let stored = contents(&file)?;
        if stored.as_slice() != ciphertext.as_slice() {
            return Err("Installation persistence mismatch");
        }
        Self::decode(roots, file, &stored, &plaintext)
    }
    /// Decrypts the existing exact protected record under real SYSTEM. Creates nothing.
    pub fn open(roots: &'roots SystemRoots) -> Result<Self> {
        roots.revalidate()?;
        let file = roots.installation_file(false)?;
        let ciphertext = contents(&file)?;
        let plaintext = crypt(&ciphertext, false)?;
        Self::decode(roots, file, &ciphertext, &plaintext)
    }
    fn decode(
        roots: &'roots SystemRoots,
        file: File,
        ciphertext: &[u8],
        plaintext: &[u8],
    ) -> Result<Self> {
        if plaintext.len() != MAGIC.len() + 48 || !plaintext.starts_with(MAGIC) {
            return Err("Installation record schema mismatch");
        }
        let id = hex::encode(&plaintext[MAGIC.len()..MAGIC.len() + 16]);
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&plaintext[MAGIC.len() + 16..]);
        Ok(Self {
            roots,
            file,
            digest: Sha256::digest(ciphertext).into(),
            id,
            key,
        })
    }
    pub fn installation(&self) -> &str {
        &self.id
    }
    pub fn revalidate(&self) -> Result<()> {
        self.roots.revalidate()?;
        if <[u8; 32]>::from(Sha256::digest(contents(&self.file)?.as_slice())) != self.digest {
            return Err("Installation record changed; explicit recovery required");
        }
        Ok(())
    }
    fn recovery_key(
        &self,
        job: &SystemJob<'_>,
        identity: &Identity,
    ) -> Result<Zeroizing<[u8; 32]>> {
        self.revalidate()?;
        job.revalidate()?;
        if identity.installation != self.id || identity.job != job.id() {
            return Err("Installation/job ownership identity mismatch");
        }
        derive_key(&self.key, identity)
    }
    pub fn create_store<'installation, 'job, 'r>(
        &'installation self,
        job: &'job SystemJob<'r>,
        identity: Identity,
    ) -> Result<InstallationStore<'installation, 'roots, 'job, 'r>> {
        let key = self.recovery_key(job, &identity)?;
        let store = job.create_store(identity, *key)?;
        Ok(InstallationStore {
            owner: self,
            store,
            fenced: false,
        })
    }
    pub fn open_store<'installation, 'job, 'r>(
        &'installation self,
        job: &'job SystemJob<'r>,
        identity: Identity,
    ) -> Result<InstallationStore<'installation, 'roots, 'job, 'r>> {
        let key = self.recovery_key(job, &identity)?;
        let store = job.open_store(identity, *key)?;
        Ok(InstallationStore {
            owner: self,
            store,
            fenced: false,
        })
    }
}
fn derive_key(master: &[u8; 32], identity: &Identity) -> Result<Zeroizing<[u8; 32]>> {
    crate::exact_hex::<16>(&identity.installation)?;
    crate::exact_hex::<16>(&identity.job)?;
    crate::exact_hex::<16>(&identity.host_boot)?;
    crate::exact_hex::<32>(&identity.image_sha256)?;
    crate::hyperv_address(&identity.vm_id)?;
    let body = serde_json::to_vec(identity).map_err(|_| "Installation key context invalid")?;
    if body.len() > 1024 {
        return Err("Installation key context budget");
    }
    let mut mac =
        Hmac::<Sha256>::new_from_slice(master).map_err(|_| "Installation key unavailable")?;
    mac.update(KEY_DOMAIN);
    mac.update(&(body.len() as u32).to_be_bytes());
    mac.update(&body);
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

/// Installation identity stays borrowed through every recovery-store transition.
pub struct InstallationStore<'installation, 'roots, 'job, 'job_roots> {
    owner: &'installation SystemIdentity<'roots>,
    store: ProtectedStore<'job, 'job_roots>,
    fenced: bool,
}
impl InstallationStore<'_, '_, '_, '_> {
    pub fn journal(&self) -> &Journal {
        self.store.journal()
    }
    pub fn advance(&mut self, event: Event) -> Result<()> {
        if self.fenced {
            return Err("Installation store fenced; reopen and inspect");
        }
        self.fenced = true;
        self.owner.revalidate()?;
        self.store.advance(event)?;
        self.fenced = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn derived_recovery_keys_bind_every_identity_field_and_master() {
        let identity = Identity {
            installation: "11".repeat(16),
            job: "22".repeat(16),
            vm_id: "11223344-5566-7788-99aa-bbccddeeff00".into(),
            image_sha256: "33".repeat(32),
            host_boot: "44".repeat(16),
        };
        let master = Zeroizing::new([0x41; 32]);
        let original = derive_key(&master, &identity).unwrap();
        assert_eq!(
            original.as_slice(),
            derive_key(&master, &identity).unwrap().as_slice()
        );
        for field in 0..5 {
            let mut changed = identity.clone();
            match field {
                0 => changed.installation = "12".repeat(16),
                1 => changed.job = "23".repeat(16),
                2 => changed.vm_id = "11223344-5566-7788-99aa-bbccddeeff01".into(),
                3 => changed.image_sha256 = "34".repeat(32),
                _ => changed.host_boot = "45".repeat(16),
            }
            assert_ne!(
                original.as_slice(),
                derive_key(&master, &changed).unwrap().as_slice()
            );
        }
        assert_ne!(
            original.as_slice(),
            derive_key(&[0x42; 32], &identity).unwrap().as_slice()
        );
        let mut malformed = identity;
        malformed.job = "../outside".into();
        assert!(derive_key(&master, &malformed).is_err());
    }
    #[test]
    fn native_dpapi_owned_roundtrip_rejects_tamper_and_bad_budgets() {
        let plaintext =
            Zeroizing::new(b"owned DPAPI fixture; not a production credential".to_vec());
        let ciphertext = crypt(&plaintext, true).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());
        assert_eq!(
            crypt(&ciphertext, false).unwrap().as_slice(),
            plaintext.as_slice()
        );
        let mut altered = Zeroizing::new(ciphertext.to_vec());
        altered[0] ^= 1;
        assert!(crypt(&altered, false).is_err());
        assert!(crypt(&ciphertext[..3], false).is_err());
        assert!(crypt(&[], true).is_err());
        assert!(crypt(&vec![0; MAX_BLOB + 1], false).is_err());
    }
}
