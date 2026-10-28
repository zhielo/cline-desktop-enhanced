//! Read-only native OS boot observation. No clock/uptime/process inference,
//! shell, registry modification, elevation, VM effect or termination proof.
use crate::Result;
use std::ffi::c_void;

const SYSTEM_BOOT_ENVIRONMENT_INFORMATION: u32 = 90;
#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(
        information_class: u32,
        information: *mut c_void,
        information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}
#[repr(C, align(8))]
struct BootEnvironment([u8; 32]);

/// Only native observation constructs this value. Not host/hardware attestation;
/// a different OS boot does not establish that a retained VM has terminated.
pub struct HostBoot {
    id: String,
}
impl HostBoot {
    pub fn observe() -> Result<Self> {
        let mut data = BootEnvironment([0; 32]);
        let mut returned = 0;
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_BOOT_ENVIRONMENT_INFORMATION,
                data.0.as_mut_ptr().cast(),
                data.0.len() as u32,
                &mut returned,
            )
        };
        Ok(Self {
            id: decode(status, returned, &data.0)?,
        })
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn require_same(&self, expected: &str) -> Result<()> {
        crate::exact_hex::<16>(expected)?;
        if self.id != expected {
            return Err("OS boot changed; explicit VM recovery required");
        }
        Ok(())
    }
}
fn decode(status: i32, returned: u32, data: &[u8; 32]) -> Result<String> {
    if status != 0 || !(16..=32).contains(&returned) {
        return Err("Native OS boot identity unavailable; no fallback");
    }
    let mut guid: [u8; 16] = data[..16]
        .try_into()
        .map_err(|_| "OS boot identity budget")?;
    if guid == [0; 16] || guid == [255; 16] {
        return Err("Concrete native OS boot identity required");
    }
    // Native GUID's first three fields are little-endian; retain canonical
    // lower-case GUID octets without separators, matching lifecycle's 128 bits.
    guid[..4].reverse();
    guid[4..6].reverse();
    guid[6..8].reverse();
    Ok(hex::encode(guid))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_boot_observation_is_stable_and_exact() {
        let first = HostBoot::observe().unwrap();
        let second = HostBoot::observe().unwrap();
        crate::exact_hex::<16>(first.id()).unwrap();
        second.require_same(first.id()).unwrap();
        assert!(second.require_same(&"00".repeat(16)).is_err());
        assert!(second.require_same("client-supplied-boot").is_err());
    }
    #[test]
    fn boot_decode_refuses_failure_missing_length_and_placeholder_ids() {
        let mut bytes = [0; 32];
        bytes[..16].copy_from_slice(&[
            0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0x88, 0x77, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x01,
        ]);
        assert_eq!(
            decode(0, 32, &bytes).unwrap(),
            "112233445566778899aabbccddeeff01"
        );
        for length in [0, 15, 33, u32::MAX] {
            assert!(decode(0, length, &bytes).is_err());
        }
        for status in [-1, 1, i32::MIN] {
            assert!(decode(status, 32, &bytes).is_err());
        }
        assert!(decode(0, 32, &[0; 32]).is_err());
        assert!(decode(0, 32, &[255; 32]).is_err());
    }
}
