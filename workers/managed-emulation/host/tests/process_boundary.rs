use std::io::Write;
use std::process::{Command, Stdio};

fn invoke(input: &[u8], args: &[&str]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cline-managed-inert-probe"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if args.is_empty() {
        child.stdin.take().unwrap().write_all(input).unwrap();
    } else {
        drop(child.stdin.take());
    }
    child.wait_with_output().unwrap()
}

#[test]
fn invalid_private_input_never_echoes_credentials_or_peer_diagnostics() {
    let private = "PRIVATE_SENTINEL_DO_NOT_ECHO";
    for input in [
        format!(r#"{{"key":"{private}"}}"#).into_bytes(),
        vec![b'a'; 1025],
        vec![],
        br#"{"vmId":"00000000-0000-0000-0000-000000000000","session":"000102030405060708090a0b0c0d0e0f","key":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","challenge":"abababababababababababababababababababababababababababababababab"}"#.to_vec(),
    ] {
        let result = invoke(&input, &[]);
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert_eq!(String::from_utf8(result.stderr).unwrap().trim(),
                   "Managed inert probe failed; no readiness established.");
    }
}

#[test]
fn credentials_and_commands_are_never_accepted_from_argv() {
    let result = invoke(b"", &["--key", "PRIVATE_SENTINEL_DO_NOT_ECHO"]);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert_eq!(
        String::from_utf8(result.stderr).unwrap().trim(),
        "Managed inert probe failed; no readiness established."
    );
}
