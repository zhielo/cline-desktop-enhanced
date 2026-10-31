use cline_managed_inert_probe::{
    boot_media::{BootMaterial, MEDIA_BYTES, MEDIA_NAME},
    PROTOCOL,
};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
struct PrivateRoot(PathBuf);
impl PrivateRoot {
    fn new() -> Self {
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "cline-media-{}-{}",
            std::process::id(),
            hex::encode(nonce)
        ));
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = builder;
            builder.mode(0o700);
            builder
        };
        builder.create(&path).unwrap();
        Self(path)
    }
}
impl Drop for PrivateRoot {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn record(image: &[u8]) -> serde_json::Value {
    let directory = &image[20 * 2048..21 * 2048];
    let entry = &directory[directory[0] as usize + directory[directory[0] as usize] as usize..];
    let length = u32::from_le_bytes(entry[10..14].try_into().unwrap()) as usize;
    serde_json::from_slice(&image[21 * 2048..21 * 2048 + length]).unwrap()
}
#[test]
fn os_generated_media_and_private_probe_input_share_exact_boot_identity() {
    let root = PrivateRoot::new();
    let material = BootMaterial::generate().unwrap();
    material.write_media(&root.0).unwrap();
    let bytes = fs::read(root.0.join(MEDIA_NAME)).unwrap();
    assert_eq!(bytes.len(), MEDIA_BYTES);
    let media = record(&bytes);
    let mut pipe = Vec::new();
    material
        .write_probe_input("12345678-1234-5678-90ab-123456789abc", &mut pipe)
        .unwrap();
    let input: serde_json::Value = serde_json::from_slice(&pipe).unwrap();
    assert_eq!(media["protocol"], PROTOCOL);
    assert_eq!(media["session"], input["session"]);
    assert!(
        media["key"] == input["key"],
        "Private boot identity mismatch"
    );
    assert_eq!(input["challenge"], hex::encode(material.challenge()));
    assert_eq!(media["session"], hex::encode(material.session()));
    assert_eq!(media["expiresAt"], material.expires_at());
    let current = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(material.expires_at() > current && material.expires_at() <= current + 180);
    let second = BootMaterial::generate().unwrap();
    assert_ne!(material.session(), second.session());
    assert_ne!(material.challenge(), second.challenge());
    assert!(material.write_media(&root.0).is_err());
    assert!(
        bytes == fs::read(root.0.join(MEDIA_NAME)).unwrap(),
        "Retained media changed"
    );
}
#[test]
fn private_input_refuses_special_vm_identity_and_write_errors() {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let material = BootMaterial::generate().unwrap();
    let mut pipe = Vec::new();
    assert!(material
        .write_probe_input("00000000-0000-0000-0000-000000000000", &mut pipe)
        .is_err());
    assert!(pipe.is_empty());
    assert!(material
        .write_probe_input("12345678-1234-5678-90ab-123456789abc", &mut Broken)
        .is_err());
}
#[test]
fn native_fixture_cli_writes_no_keys_or_raw_paths_and_never_overwrites() {
    let root = PrivateRoot::new();
    let output = Command::new(env!("CARGO_BIN_EXE_owned-boot-media-fixture"))
        .arg(&root.0)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty(), "Unexpected fixture diagnostics");
    assert!(
        output.stdout == b"Owned private boot media written; no VM or readiness established.\n",
        "Unexpected fixture output"
    );
    let before = fs::read(root.0.join(MEDIA_NAME)).unwrap();
    let repeated = Command::new(env!("CARGO_BIN_EXE_owned-boot-media-fixture"))
        .arg(&root.0)
        .output()
        .unwrap();
    assert!(!repeated.status.success());
    assert!(repeated.stdout.is_empty());
    assert!(
        repeated.stderr == b"Owned boot media generation failed; no readiness established.\n",
        "Unexpected fixture diagnostics"
    );
    assert!(
        before == fs::read(root.0.join(MEDIA_NAME)).unwrap(),
        "Retained media changed"
    );
}
#[cfg(unix)]
#[test]
fn private_file_modes_and_symlink_rejection_use_real_filesystem() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let root = PrivateRoot::new();
    let material = BootMaterial::generate().unwrap();
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(material.write_media(&root.0).is_err());
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
    let other = PrivateRoot::new();
    symlink(&other.0, root.0.join("linked-root")).unwrap();
    assert!(material.write_media(&root.0.join("linked-root")).is_err());
    symlink(other.0.join("target"), root.0.join(MEDIA_NAME)).unwrap();
    assert!(material.write_media(&root.0).is_err());
    assert!(!other.0.join("target").exists());
    fs::remove_file(root.0.join(MEDIA_NAME)).unwrap();
    material.write_media(&root.0).unwrap();
    assert_eq!(
        fs::metadata(root.0.join(MEDIA_NAME))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}
