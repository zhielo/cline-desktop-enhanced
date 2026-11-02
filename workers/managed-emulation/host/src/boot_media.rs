//! Native one-file ISO9660 boot credential provisioning. No external tools,
//! downloads, guest execution, VM creation, or credential logging. The caller
//! must provision a protected job root/ancestors and verify exact VM ownership.
use crate::{hyperv_address, Result, PROTOCOL};
use serde::Serialize;
use std::{
    fs,
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const BLOCK: usize = 2048;
pub const MEDIA_BYTES: usize = 22 * BLOCK;
pub const MEDIA_NAME: &str = "boot.iso";
const LIFETIME_SECONDS: u64 = 180;

/// Intentionally not Debug, Clone, Serialize or Deserialize. Fresh OS entropy
/// is generated in-process, never accepted from argv, environment or old media.
pub struct BootMaterial {
    key: Zeroizing<[u8; 32]>,
    session: [u8; 16],
    challenge: [u8; 32],
    expires_at: u64,
}

fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| "Boot clock unavailable")
}

impl BootMaterial {
    pub fn generate() -> Result<Self> {
        let mut entropy = Zeroizing::new([0u8; 80]);
        getrandom::fill(&mut *entropy).map_err(|_| "Boot entropy unavailable")?;
        Self::from_entropy(&entropy, now()?)
    }

    fn from_entropy(entropy: &[u8; 80], created_at: u64) -> Result<Self> {
        let expires_at = created_at
            .checked_add(LIFETIME_SECONDS)
            .ok_or("Boot clock budget")?;
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&entropy[..32]);
        let mut session = [0u8; 16];
        session.copy_from_slice(&entropy[32..48]);
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&entropy[48..]);
        Ok(Self {
            key,
            session,
            challenge,
            expires_at,
        })
    }

    pub fn session(&self) -> &[u8; 16] {
        &self.session
    }
    pub fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    fn require_fresh(&self) -> Result<()> {
        let current = now()?;
        if self.expires_at <= current || self.expires_at > current.saturating_add(LIFETIME_SECONDS)
        {
            return Err("Boot material expired or clock changed; explicit new boot required");
        }
        Ok(())
    }

    fn record(&self) -> Result<Zeroizing<Vec<u8>>> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Record<'a> {
            protocol: &'a str,
            session: &'a str,
            key: &'a str,
            expires_at: u64,
        }
        let key = Zeroizing::new(hex::encode(self.key.as_slice()));
        let session = hex::encode(self.session);
        let bytes = serde_json::to_vec(&Record {
            protocol: PROTOCOL,
            session: &session,
            key: &key,
            expires_at: self.expires_at,
        })
        .map_err(|_| "Boot record unavailable")?;
        if bytes.len() > 1024 {
            return Err("Boot record budget");
        }
        Ok(Zeroizing::new(bytes))
    }

    /// Writes ONLY boot.iso, exclusively, beneath the caller's protected job root.
    /// Success means bytes were synced, not that a VM is owned, running or ready.
    /// Failed/partial files are retained; never auto-reuse, overwrite or delete.
    pub fn write_media(&self, protected_job_root: &Path) -> Result<()> {
        self.require_fresh()?;
        private_root(protected_job_root)?;
        let record = self.record()?;
        let image = iso9660(&record)?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(protected_job_root.join(MEDIA_NAME))
            .map_err(|_| "New private boot media required")?;
        file.write_all(&image)
            .and_then(|_| file.sync_all())
            .map_err(|_| "Boot media incomplete; inspect before retry")?;
        // Recheck lifetime after I/O. An error never authorizes attaching the file.
        self.require_fresh()
    }

    /// Send only through a private parent-owned pipe to the existing native probe.
    /// A valid GUID is NOT proof of VM ownership or authority to connect.
    pub fn write_probe_input(&self, vm_id: &str, private_pipe: &mut impl Write) -> Result<()> {
        self.require_fresh()?;
        hyperv_address(vm_id)?;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Input<'a> {
            vm_id: &'a str,
            session: String,
            key: &'a str,
            challenge: String,
        }
        let key = Zeroizing::new(hex::encode(self.key.as_slice()));
        let bytes = Zeroizing::new(
            serde_json::to_vec(&Input {
                vm_id,
                session: hex::encode(self.session),
                key: &key,
                challenge: hex::encode(self.challenge),
            })
            .map_err(|_| "Private probe input unavailable")?,
        );
        if bytes.len() > 1024 {
            return Err("Private probe input budget");
        }
        private_pipe
            .write_all(&bytes)
            .map_err(|_| "Private probe input incomplete")
    }
}

fn private_root(path: &Path) -> Result<()> {
    let info = fs::symlink_metadata(path).map_err(|_| "Protected job root unavailable")?;
    if !info.is_dir() || info.file_type().is_symlink() {
        return Err("Private job directory required");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if info.permissions().mode() & 0o077 != 0 {
            return Err("Private job directory required");
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if info.file_attributes() & 0x400 != 0 {
            return Err("Reparse job root forbidden");
        }
        // ACL/ancestor/owner protection belongs to the future privileged broker.
    }
    Ok(())
}

fn both16(out: &mut [u8], value: u16) {
    out[..2].copy_from_slice(&value.to_le_bytes());
    out[2..4].copy_from_slice(&value.to_be_bytes());
}
fn both32(out: &mut [u8], value: u32) {
    out[..4].copy_from_slice(&value.to_le_bytes());
    out[4..8].copy_from_slice(&value.to_be_bytes());
}
fn directory_record(extent: u32, size: u32, directory: bool, name: &[u8]) -> Vec<u8> {
    let length = (33 + name.len() + 1) & !1;
    let mut out = vec![0u8; length];
    out[0] = length as u8;
    both32(&mut out[2..10], extent);
    both32(&mut out[10..18], size);
    out[18..25].copy_from_slice(&[126, 1, 1, 0, 0, 0, 0]);
    out[25] = if directory { 2 } else { 0 };
    both16(&mut out[28..32], 1);
    out[32] = name.len() as u8;
    out[33..33 + name.len()].copy_from_slice(name);
    out
}

/// Minimal fixed ISO9660 layout. No archive paths, extensions, executable code,
/// extra files, Rock Ridge symlinks, shell tools or variable allocation budgets.
fn iso9660(record: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if record.is_empty() || record.len() > 1024 {
        return Err("Boot record budget");
    }
    let mut image = Zeroizing::new(vec![0u8; MEDIA_BYTES]);
    let pvd = &mut image[16 * BLOCK..17 * BLOCK];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    pvd[8..72].fill(b' ');
    pvd[8..20].copy_from_slice(b"CLINEMANAGED");
    pvd[40..49].copy_from_slice(b"CLINEBOOT");
    both32(&mut pvd[80..88], 22);
    both16(&mut pvd[120..124], 1);
    both16(&mut pvd[124..128], 1);
    both16(&mut pvd[128..132], BLOCK as u16);
    both32(&mut pvd[132..140], 10);
    pvd[140..144].copy_from_slice(&18u32.to_le_bytes());
    pvd[148..152].copy_from_slice(&19u32.to_be_bytes());
    pvd[156..190].copy_from_slice(&directory_record(20, BLOCK as u32, true, &[0]));
    pvd[190..813].fill(b' ');
    for offset in [813, 830, 847, 864] {
        pvd[offset..offset + 16].copy_from_slice(b"2026010100000000");
    }
    for offset in [847, 864] {
        pvd[offset..offset + 16].copy_from_slice(b"0000000000000000");
    }
    pvd[881] = 1;
    let terminator = &mut image[17 * BLOCK..18 * BLOCK];
    terminator[0] = 255;
    terminator[1..6].copy_from_slice(b"CD001");
    terminator[6] = 1;
    for (block, big) in [(18, false), (19, true)] {
        let table = &mut image[block * BLOCK..(block + 1) * BLOCK];
        table[0] = 1;
        table[2..6].copy_from_slice(&if big {
            20u32.to_be_bytes()
        } else {
            20u32.to_le_bytes()
        });
        table[6..8].copy_from_slice(&if big {
            1u16.to_be_bytes()
        } else {
            1u16.to_le_bytes()
        });
    }
    let mut cursor = 20 * BLOCK;
    for entry in [
        directory_record(20, BLOCK as u32, true, &[0]),
        directory_record(20, BLOCK as u32, true, &[1]),
        directory_record(21, record.len() as u32, false, b"BOOT.JSON;1"),
    ] {
        image[cursor..cursor + entry.len()].copy_from_slice(&entry);
        cursor += entry.len();
    }
    image[21 * BLOCK..21 * BLOCK + record.len()].copy_from_slice(record);
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn iso_has_fixed_bounded_dual_endian_structure_and_one_record() {
        let material = BootMaterial::from_entropy(&std::array::from_fn(|i| i as u8), 10).unwrap();
        let record = material.record().unwrap();
        let image = iso9660(&record).unwrap();
        assert_eq!(image.len(), MEDIA_BYTES);
        assert_eq!(
            &image[16 * BLOCK + 80..16 * BLOCK + 88],
            &[22, 0, 0, 0, 0, 0, 0, 22]
        );
        assert_eq!(&image[16 * BLOCK + 128..16 * BLOCK + 132], &[0, 8, 8, 0]);
        assert_eq!(image[17 * BLOCK], 255);
        let root = &image[20 * BLOCK..21 * BLOCK];
        let first = root[0] as usize;
        let second = root[first] as usize;
        let entry = &root[first + second..];
        assert_eq!(&entry[33..44], b"BOOT.JSON;1");
        let size = u32::from_le_bytes(entry[10..14].try_into().unwrap()) as usize;
        assert_eq!(&image[21 * BLOCK..21 * BLOCK + size], &*record);
        assert!(image[21 * BLOCK + size..].iter().all(|b| *b == 0));
        let value: serde_json::Value = serde_json::from_slice(&record).unwrap();
        assert_eq!(value["expiresAt"], 190);
        assert_eq!(value["key"], hex::encode(&material.key[..]));
        assert_eq!(value.as_object().unwrap().len(), 4);
    }
    #[test]
    fn expired_material_is_rejected_before_creating_media_or_sending_input() {
        let material = BootMaterial::from_entropy(&[1; 80], 0).unwrap();
        let mut pipe = Vec::new();
        assert!(material
            .write_probe_input("12345678-1234-5678-90ab-123456789abc", &mut pipe)
            .is_err());
        assert!(pipe.is_empty());
        assert!(material
            .write_media(Path::new("not-a-protected-root"))
            .is_err());
        assert!(iso9660(&[]).is_err());
        assert!(iso9660(&[0; 1025]).is_err());
        assert!(BootMaterial::from_entropy(&[1; 80], u64::MAX).is_err());
    }
}
