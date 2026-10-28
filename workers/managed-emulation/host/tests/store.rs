use cline_managed_inert_probe::{
    lifecycle::{Event, Identity, Phase},
    store::Store,
};
use rusqlite::{params, Connection};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
const KEY: [u8; 32] = [0x59; 32];
fn identity() -> Identity {
    Identity {
        installation: "11".repeat(16),
        job: "22".repeat(16),
        vm_id: "12345678-1234-5678-90ab-123456789abc".into(),
        image_sha256: "33".repeat(32),
        host_boot: "44".repeat(16),
    }
}
struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cline-store-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).unwrap();
        Self { root }
    }
    fn a(&self) -> PathBuf {
        self.root.join("snapshots")
    }
    fn b(&self) -> PathBuf {
        self.root.join("anchors")
    }
    fn create(&self) -> Store {
        Store::create(&self.a(), &self.b(), identity(), KEY).unwrap()
    }
    fn open(&self) -> Result<Store, &'static str> {
        Store::open(&self.a(), &self.b(), identity(), KEY)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn body(path: &Path) -> Vec<u8> {
    Connection::open(path.join("recovery.sqlite"))
        .unwrap()
        .query_row("SELECT body FROM records WHERE name='current'", [], |r| {
            r.get(0)
        })
        .unwrap()
}

#[test]
fn real_storage_reopen_requires_recovery_and_never_infers_termination() {
    let f = Fixture::new();
    let mut store = f.create();
    store.advance(Event::VmCreated {}).unwrap();
    drop(store);
    let mut store = f.open().unwrap();
    assert_eq!(store.journal().phase(), Phase::Created);
    assert!(store.journal().recovery_required());
    store.advance(Event::RecoveryRequested {}).unwrap();
    assert_eq!(store.journal().phase(), Phase::StopRequired);
    assert!(store.advance(Event::RemoveRequested {}).is_err());
}
#[test]
fn independent_current_anchor_rejects_valid_old_snapshot_only_rollback() {
    let f = Fixture::new();
    let mut store = f.create();
    let old = body(&f.b());
    store.advance(Event::VmCreated {}).unwrap();
    drop(store);
    let current: serde_json::Value = serde_json::from_slice(&body(&f.b())).unwrap();
    let old: serde_json::Value = serde_json::from_slice(&old).unwrap();
    let db = Connection::open(f.a().join("recovery.sqlite")).unwrap();
    let bytes: Vec<u8> = db
        .query_row(
            "SELECT body FROM records WHERE name=?1",
            params![old["snapshot"].as_str().unwrap()],
            |r| r.get(0),
        )
        .unwrap();
    db.execute(
        "UPDATE records SET body=?1 WHERE name=?2",
        params![bytes, current["snapshot"].as_str().unwrap()],
    )
    .unwrap();
    assert!(f.open().is_err());
}
#[test]
fn stale_writer_cannot_overwrite_current_anchor_and_is_fenced() {
    let f = Fixture::new();
    let mut first = f.create();
    let mut stale = f.open().unwrap();
    first.advance(Event::VmCreated {}).unwrap();
    assert!(stale.advance(Event::RecoveryRequested {}).is_err());
    assert!(stale.advance(Event::RecoveryRequested {}).is_err());
    assert_eq!(f.open().unwrap().journal().checkpoint().sequence, 2);
}
#[test]
fn invalid_event_fences_handle_without_changing_durable_state() {
    let f = Fixture::new();
    let mut store = f.create();
    let before = body(&f.b());
    assert!(store.advance(Event::RemoveRequested {}).is_err());
    assert!(store.advance(Event::VmCreated {}).is_err());
    assert_eq!(before, body(&f.b()));
}
#[test]
fn wrong_key_identity_missing_snapshot_and_unknown_schema_fail_closed() {
    let f = Fixture::new();
    drop(f.create());
    assert!(Store::open(&f.a(), &f.b(), identity(), [1; 32]).is_err());
    let mut wrong = identity();
    wrong.job = "55".repeat(16);
    assert!(Store::open(&f.a(), &f.b(), wrong, KEY).is_err());
    let db = Connection::open(f.a().join("recovery.sqlite")).unwrap();
    db.execute("DELETE FROM records", []).unwrap();
    assert!(f.open().is_err());
    db.execute("CREATE TABLE unexpected (body TEXT)", [])
        .unwrap();
    assert!(f.open().is_err());
}
#[test]
fn create_never_reuses_retained_state_and_roots_must_be_independent() {
    let f = Fixture::new();
    drop(f.create());
    assert!(Store::create(&f.a(), &f.b(), identity(), KEY).is_err());
    assert!(Store::open(&f.a(), &f.a(), identity(), KEY).is_err());
    let g = Fixture::new();
    assert!(Store::create(&g.a(), &g.a(), identity(), KEY).is_err());
    assert!(!g.a().exists());
}
#[test]
fn secret_key_is_not_persisted_in_database_or_journal() {
    let f = Fixture::new();
    let mut store = f.create();
    store.advance(Event::VmCreated {}).unwrap();
    drop(store);
    for root in [f.a(), f.b()] {
        for entry in fs::read_dir(root).unwrap() {
            let bytes = fs::read(entry.unwrap().path()).unwrap();
            assert!(!bytes.windows(KEY.len()).any(|v| v == KEY));
            assert!(!bytes.windows(64).any(|v| v == hex::encode(KEY).as_bytes()));
        }
    }
}
#[cfg(unix)]
#[test]
fn links_sidecars_and_permissive_roots_are_refused() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let f = Fixture::new();
    drop(f.create());
    symlink(
        f.a().join("recovery.sqlite"),
        f.b().join("recovery.sqlite-journal"),
    )
    .unwrap();
    assert!(f.open().is_err());
    fs::remove_file(f.b().join("recovery.sqlite-journal")).unwrap();
    fs::set_permissions(f.a(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(f.open().is_err());
    fs::set_permissions(f.a(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::hard_link(f.a().join("recovery.sqlite"), f.root.join("linked")).unwrap();
    assert!(f.open().is_err());
}

#[test]
fn terminal_removal_requires_exact_observations_and_survives_restart() {
    let f = Fixture::new();
    let mut store = f.create();
    store.advance(Event::VmCreated {}).unwrap();
    store.advance(Event::StopRequested {}).unwrap();
    store
        .advance(Event::StopObserved {
            vm_id: identity().vm_id,
        })
        .unwrap();
    store.advance(Event::RemoveRequested {}).unwrap();
    store
        .advance(Event::RemovalObserved {
            vm_id: identity().vm_id,
        })
        .unwrap();
    drop(store);
    let mut store = f.open().unwrap();
    assert_eq!(store.journal().phase(), Phase::Removed);
    assert!(!store.journal().recovery_required());
    assert!(store.advance(Event::RecoveryRequested {}).is_err());
}

#[test]
fn oversized_database_and_anchor_fields_are_rejected() {
    let f = Fixture::new();
    drop(f.create());
    let db = Connection::open(f.b().join("recovery.sqlite")).unwrap();
    let mut anchor: serde_json::Value = serde_json::from_slice(&body(&f.b())).unwrap();
    anchor["unexpected"] = true.into();
    db.execute(
        "UPDATE records SET body=?1",
        params![serde_json::to_vec(&anchor).unwrap()],
    )
    .unwrap();
    assert!(f.open().is_err());
    drop(db);
    fs::OpenOptions::new()
        .write(true)
        .open(f.a().join("recovery.sqlite"))
        .unwrap()
        .set_len(16 * 1024 * 1024 + 1)
        .unwrap();
    assert!(f.open().is_err());
}
