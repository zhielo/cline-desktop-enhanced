//! Actual process termination at SQLite commit boundaries, not simulated errors.
use cline_managed_inert_probe::{
    lifecycle::{Event, Identity, Phase},
    store::{CommitStage, Store},
};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
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
fn paths(root: &Path) -> (PathBuf, PathBuf) {
    (root.join("snapshots"), root.join("anchors"))
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--crash-child") {
        let root = Path::new(&args[2]);
        let (a, b) = paths(root);
        let mut store = Store::open(&a, &b, identity(), KEY).expect("open child");
        store
            .advance_observed(Event::RecoveryRequested {}, |stage| {
                if format!("{stage:?}") == args[3] {
                    println!("COMMIT_BOUNDARY_REACHED");
                    std::io::stdout().flush().unwrap();
                    loop {
                        std::thread::park();
                    }
                }
            })
            .unwrap();
        panic!("requested boundary not reached");
    }
    // Cargo may append harness-style flags; this binary always runs all cases.
    for stage in [
        CommitStage::SnapshotWrittenBeforeCommit,
        CommitStage::SnapshotCommitted,
        CommitStage::AnchorWrittenBeforeCommit,
        CommitStage::AnchorCommitted,
    ] {
        crash(stage);
    }
    println!("4 real kill/reopen commit-boundary cases passed; no VM effects tested");
}
fn crash(stage: CommitStage) {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).unwrap();
    let root = std::env::temp_dir().join(format!(
        "cline-store-crash-{}-{}",
        std::process::id(),
        hex::encode(nonce)
    ));
    fs::create_dir(&root).unwrap();
    let (a, b) = paths(&root);
    drop(Store::create(&a, &b, identity(), KEY).unwrap());
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--crash-child",
            root.to_str().unwrap(),
            &format!("{stage:?}"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = tx.send(result);
    });
    let boundary = rx.recv_timeout(Duration::from_secs(15));
    let _ = child.kill();
    let exit = child.wait().unwrap();
    reader.join().unwrap();
    assert!(!exit.success(), "child must be forcibly terminated");
    assert_eq!(boundary.unwrap().unwrap().trim(), "COMMIT_BOUNDARY_REACHED");
    let mut restored = Store::open(&a, &b, identity(), KEY).unwrap();
    let committed = stage == CommitStage::AnchorCommitted;
    assert_eq!(
        restored.journal().checkpoint().sequence,
        if committed { 2 } else { 1 }
    );
    assert_eq!(
        restored.journal().phase(),
        if committed {
            Phase::StopRequired
        } else {
            Phase::Reserved
        }
    );
    assert!(restored.journal().recovery_required());
    assert!(
        restored.advance(Event::VmCreated {}).is_err(),
        "reopen must never replay create"
    );
    drop(restored);
    fs::remove_dir_all(root).unwrap();
}
