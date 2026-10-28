//! Development persistence, not a privileged VM broker. Both parent roots MUST be
//! independently protected by the caller. Separate files do not prevent rollback
//! of both roots by their owner. The key is supplied privately, never stored here.
use crate::lifecycle::{Checkpoint, Event, Identity, Journal, MAX_JOURNAL_BYTES};
use crate::Result;
use rusqlite::{config::DbConfig, params, Connection, OpenFlags, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::Path, time::Duration};
use zeroize::Zeroizing;

const MAX_DATABASE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SNAPSHOTS: i64 = 256;
const SCHEMA: &str =
    "CREATE TABLE records (name TEXT PRIMARY KEY NOT NULL, body BLOB NOT NULL) WITHOUT ROWID";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    version: u8,
    identity: Identity,
    checkpoint: Checkpoint,
    snapshot: String,
}

/// Metadata-only crash boundaries. An observer must never execute a VM operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitStage {
    SnapshotWrittenBeforeCommit,
    SnapshotCommitted,
    AnchorWrittenBeforeCommit,
    AnchorCommitted,
}

pub struct Store {
    snapshots: Connection,
    anchors: Connection,
    identity: Identity,
    anchor: Vec<u8>,
    journal: Journal,
    key: Zeroizing<[u8; 32]>,
    poisoned: bool,
}

fn storage<T>(result: rusqlite::Result<T>) -> Result<T> {
    result.map_err(|_| "Recovery storage unavailable; inspect before retry")
}

fn root(path: &Path) -> Result<std::path::PathBuf> {
    let info = fs::symlink_metadata(path).map_err(|_| "Protected storage root unavailable")?;
    if !info.is_dir() || info.file_type().is_symlink() {
        return Err("Protected storage directory required");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if info.file_attributes() & 0x400 != 0 {
            return Err("Reparse storage root forbidden");
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if info.permissions().mode() & 0o077 != 0 {
            return Err("Private storage directory required");
        }
    }
    fs::canonicalize(path).map_err(|_| "Protected storage root unavailable")
}

fn distinct(a: &Path, b: &Path) -> Result<()> {
    if a.starts_with(b) || b.starts_with(a) {
        return Err("Independent journal and anchor roots required");
    }
    Ok(())
}

fn new_root(path: &Path) -> Result<std::path::PathBuf> {
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    // No recursive creation, reuse or automatic deletion of retained state.
    builder
        .create(path)
        .map_err(|_| "New protected storage directory required")?;
    root(path)
}

fn check_file(path: &Path) -> Result<()> {
    let info = fs::symlink_metadata(path).map_err(|_| "Recovery file unavailable")?;
    if !info.is_file() || info.file_type().is_symlink() || info.len() > MAX_DATABASE_BYTES {
        return Err("Recovery file type or budget");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if info.nlink() != 1 || info.mode() & 0o077 != 0 {
            return Err("Private single-link recovery file required");
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if info.file_attributes() & 0x400 != 0 {
            return Err("Reparse recovery file forbidden");
        }
        // ACL and hard-link ownership remain the privileged root provisioner's duty.
    }
    Ok(())
}

fn database(root: &Path, create: bool, app_id: i32) -> Result<Connection> {
    let path = root.join("recovery.sqlite");
    if create {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(&path)
            .map_err(|_| "New recovery database required")?;
    }
    check_file(&path)?;
    // Reject linked sidecars before SQLite's own hot-journal recovery. Trusted
    // parent protection is required against concurrent namespace replacement.
    for suffix in ["-journal", "-wal", "-shm"] {
        let sidecar = root.join(format!("recovery.sqlite{suffix}"));
        match fs::symlink_metadata(&sidecar) {
            Ok(_) => check_file(&sidecar)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err("Recovery sidecar unavailable"),
        }
    }
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let connection = storage(Connection::open_with_flags(path, flags))?;
    storage(connection.busy_timeout(Duration::from_secs(2)))?;
    storage(connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true))?;
    storage(connection.execute_batch(
        "PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; \
         PRAGMA cell_size_check=ON; PRAGMA max_page_count=4096;",
    ))?;
    if create {
        storage(connection.execute_batch(SCHEMA))?;
        storage(connection.pragma_update(None, "application_id", app_id))?;
        storage(connection.pragma_update(None, "user_version", 1))?;
    }
    let actual: i32 = storage(connection.pragma_query_value(None, "application_id", |r| r.get(0)))?;
    let version: i32 = storage(connection.pragma_query_value(None, "user_version", |r| r.get(0)))?;
    let mut statement =
        storage(connection.prepare("SELECT name, sql FROM sqlite_schema ORDER BY name"))?;
    let rows = storage(statement.query_map([], |r| Ok((r.get(0)?, r.get(1)?))))?;
    let schema: Vec<(String, String)> = storage(rows.collect())?;
    drop(statement);
    if actual != app_id || version != 1 || schema != [("records".into(), SCHEMA.into())] {
        return Err("Recovery database schema mismatch");
    }
    let integrity: String =
        storage(connection.query_row("PRAGMA quick_check(1)", [], |r| r.get(0)))?;
    if integrity != "ok" {
        return Err("Recovery database integrity failure");
    }
    Ok(connection)
}

fn read_record(connection: &Connection, name: &str, limit: usize) -> Result<Vec<u8>> {
    // Check the SQL length before allocating the body in Rust.
    storage(connection.query_row(
        "SELECT body FROM records WHERE name=?1 AND typeof(body)='blob' AND length(body) BETWEEN 1 AND ?2",
        params![name, limit as i64], |r| r.get(0),
    ))
}

impl Store {
    /// Creates NEW leaf directories beneath caller-protected, independent roots.
    /// A failed/ambiguous create leaves retained state; never auto-delete/retry it.
    pub fn create(
        snapshot_root: &Path,
        anchor_root: &Path,
        identity: Identity,
        key: [u8; 32],
    ) -> Result<Self> {
        Self::create_in_roots(snapshot_root, anchor_root, identity, key, false)
    }

    /// Windows-only adapter for already exclusively provisioned SYSTEM job roots.
    /// The caller must retain and revalidate all root/ancestor handles.
    #[cfg(windows)]
    pub(crate) fn create_protected(
        snapshot_root: &Path,
        anchor_root: &Path,
        identity: Identity,
        key: [u8; 32],
    ) -> Result<Self> {
        Self::create_in_roots(snapshot_root, anchor_root, identity, key, true)
    }

    fn create_in_roots(
        snapshot_root: &Path,
        anchor_root: &Path,
        identity: Identity,
        key: [u8; 32],
        provisioned: bool,
    ) -> Result<Self> {
        let key = Zeroizing::new(key);
        let journal = Journal::reserve(identity.clone(), &key)?;
        // Check parent topology before making either leaf.
        let a = fs::canonicalize(snapshot_root.parent().ok_or("Storage parent required")?)
            .map_err(|_| "Storage parent required")?
            .join(snapshot_root.file_name().ok_or("Storage leaf required")?);
        let b = fs::canonicalize(anchor_root.parent().ok_or("Storage parent required")?)
            .map_err(|_| "Storage parent required")?
            .join(anchor_root.file_name().ok_or("Storage leaf required")?);
        distinct(&a, &b)?;
        let a = if provisioned {
            root(&a)?
        } else {
            new_root(&a)?
        };
        let b = if provisioned {
            root(&b)?
        } else {
            new_root(&b)?
        };
        let snapshots = database(&a, true, 0x434c5301)?;
        let anchors = database(&b, true, 0x434c4101)?;
        let mut store = Self {
            snapshots,
            anchors,
            identity,
            anchor: Vec::new(),
            journal,
            key,
            poisoned: false,
        };
        let candidate = store.journal.clone();
        store.commit(candidate, &mut |_| {})?;
        Ok(store)
    }

    /// Never infer the trusted checkpoint from snapshots or the highest sequence.
    pub fn open(
        snapshot_root: &Path,
        anchor_root: &Path,
        expected: Identity,
        key: [u8; 32],
    ) -> Result<Self> {
        let key = Zeroizing::new(key);
        let a = root(snapshot_root)?;
        let b = root(anchor_root)?;
        distinct(&a, &b)?;
        let snapshots = database(&a, false, 0x434c5301)?;
        let anchors = database(&b, false, 0x434c4101)?;
        let anchor = read_record(&anchors, "current", 4096)?;
        let decoded: Anchor =
            serde_json::from_slice(&anchor).map_err(|_| "Invalid recovery anchor")?;
        if decoded.version != 1 || decoded.identity != expected {
            return Err("Recovery anchor identity mismatch");
        }
        crate::exact_hex::<32>(&decoded.snapshot)?;
        let bytes = read_record(&snapshots, &decoded.snapshot, MAX_JOURNAL_BYTES)?;
        if hex::encode(Sha256::digest(&bytes)) != decoded.snapshot {
            return Err("Recovery snapshot digest mismatch");
        }
        let journal = Journal::restore(&bytes, &expected, &decoded.checkpoint, &key)?;
        Ok(Self {
            snapshots,
            anchors,
            identity: expected,
            anchor,
            journal,
            key,
            poisoned: false,
        })
    }

    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    pub fn advance(&mut self, event: Event) -> Result<()> {
        self.advance_observed(event, |_| {})
    }

    /// Testable durable boundaries, NOT a host-effect callback or commit permission.
    pub fn advance_observed(
        &mut self,
        event: Event,
        mut observer: impl FnMut(CommitStage),
    ) -> Result<()> {
        if self.poisoned {
            return Err("Recovery store fenced; reopen and inspect");
        }
        // Even invalid/stale requests fence the handle; no effect may have begun.
        self.poisoned = true;
        let candidate = self.journal.append(event, &self.key)?;
        self.commit(candidate, &mut observer)?;
        self.poisoned = false;
        Ok(())
    }

    fn commit(&mut self, candidate: Journal, observer: &mut impl FnMut(CommitStage)) -> Result<()> {
        let body = candidate.encode()?;
        let digest = hex::encode(Sha256::digest(&body));
        let next = serde_json::to_vec(&Anchor {
            version: 1,
            identity: self.identity.clone(),
            checkpoint: candidate.checkpoint(),
            snapshot: digest.clone(),
        })
        .map_err(|_| "Invalid recovery anchor")?;
        let transaction = storage(
            self.snapshots
                .transaction_with_behavior(TransactionBehavior::Immediate),
        )?;
        let count: i64 =
            storage(transaction.query_row("SELECT count(*) FROM records", [], |r| r.get(0)))?;
        if count >= MAX_SNAPSHOTS {
            return Err("Recovery snapshot budget; explicit maintenance required");
        }
        storage(transaction.execute(
            "INSERT OR IGNORE INTO records(name,body) VALUES(?1,?2)",
            params![digest, body],
        ))?;
        if read_record(&transaction, &digest, MAX_JOURNAL_BYTES)? != body {
            return Err("Recovery snapshot collision");
        }
        observer(CommitStage::SnapshotWrittenBeforeCommit);
        storage(transaction.commit())?;
        observer(CommitStage::SnapshotCommitted);
        let transaction = storage(
            self.anchors
                .transaction_with_behavior(TransactionBehavior::Immediate),
        )?;
        let changed = if self.anchor.is_empty() {
            storage(transaction.execute(
                "INSERT INTO records(name,body) VALUES('current',?1)",
                params![next],
            ))?
        } else {
            storage(transaction.execute(
                "UPDATE records SET body=?1 WHERE name='current' AND body=?2",
                params![next, self.anchor],
            ))?
        };
        if changed != 1 {
            return Err("Recovery anchor changed; stale writer fenced");
        }
        observer(CommitStage::AnchorWrittenBeforeCommit);
        storage(transaction.commit())?;
        observer(CommitStage::AnchorCommitted);
        // Only both successful commits update the in-memory state. Orphan snapshots
        // are never promoted, and errors never trigger host effects or auto retries.
        self.anchor = next;
        self.journal = candidate;
        Ok(())
    }
}
