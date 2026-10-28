//! Development probe only. The app-owned VM lifecycle/credential broker is not implemented.
//! Stdin must be a closed private parent pipe; never pass boot keys in argv/env.
use cline_managed_inert_probe::{exact_hex, hyperv_address, Result};
use serde::Deserialize;
use std::io::Read;
use zeroize::Zeroize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Input {
    vm_id: String,
    session: String,
    key: String,
    challenge: String,
}

impl Drop for Input {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(windows)]
fn probe(input: &Input) -> Result<()> {
    use cline_managed_inert_probe::{
        encode_frame, receive_frame, verify_response, write_frame, ProbeRequest,
    };
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::io::{self, Read, Write};
    use std::time::{Duration, Instant};

    let address = hyperv_address(&input.vm_id)?;
    // The initialized bytes exactly fill SOCKADDR_HV; no DNS/IP/TCP path exists.
    let (_, address) = unsafe {
        SockAddr::try_init(|storage, length| {
            std::ptr::copy_nonoverlapping(address.as_ptr(), storage.cast::<u8>(), address.len());
            *length = address.len() as _;
            Ok(())
        })
    }
    .map_err(|_| "Hyper-V address unavailable")?;
    let socket = Socket::new(Domain::from(34), Type::STREAM, Some(Protocol::from(1)))
        .map_err(|_| "Hyper-V socket unavailable")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    socket
        .connect_timeout(&address, Duration::from_secs(10))
        .map_err(|_| "Hyper-V connection unavailable")?;
    struct BoundedSocket {
        socket: Socket,
        deadline: Instant,
    }
    impl Read for BoundedSocket {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let remaining = self
                .deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(io::ErrorKind::TimedOut)?;
            self.socket.set_read_timeout(Some(remaining))?;
            (&self.socket).read(output)
        }
    }
    impl Write for BoundedSocket {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            let remaining = self
                .deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(io::ErrorKind::TimedOut)?;
            self.socket.set_write_timeout(Some(remaining))?;
            (&self.socket).write(input)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut transport = BoundedSocket { socket, deadline };
    let mut key = exact_hex::<32>(&input.key)?;
    let session = exact_hex::<16>(&input.session)?;
    let result = (|| {
        let frame = encode_frame(
            &key,
            &session,
            1,
            &ProbeRequest {
                operation: "owned-probe",
                challenge: &input.challenge,
            },
        )?;
        write_frame(&mut transport, &frame)?;
        let body = receive_frame(&mut transport, &key, &session, 2)?;
        let response = verify_response(&body, &input.challenge)?;
        // Validated fixed response only; no credentials/raw peer diagnostics.
        let output = serde_json::to_vec(&response).map_err(|_| "Response unavailable")?;
        std::io::stdout()
            .write_all(&output)
            .map_err(|_| "Output unavailable")?;
        Ok(())
    })();
    key.zeroize();
    result
}

#[cfg(not(windows))]
fn probe(_: &Input) -> Result<()> {
    Err("Windows Hyper-V host required")
}

fn run() -> Result<()> {
    if std::env::args_os().len() != 1 {
        return Err("Arguments forbidden");
    }
    let mut bytes = Vec::new();
    let result = (|| {
        std::io::stdin()
            .take(1025)
            .read_to_end(&mut bytes)
            .map_err(|_| "Private input unavailable")?;
        if bytes.is_empty() || bytes.len() > 1024 {
            return Err("Input budget");
        }
        let input: Input = serde_json::from_slice(&bytes).map_err(|_| "Invalid private input")?;
        hyperv_address(&input.vm_id)?;
        exact_hex::<16>(&input.session)?;
        exact_hex::<32>(&input.key)?;
        exact_hex::<32>(&input.challenge)?;
        probe(&input)
    })();
    bytes.zeroize();
    result
}

fn main() {
    // Independent whole-process bound: stdin EOF and stdout delivery are not
    // covered by socket timeouts. This kills ONLY this probe, never the VM.
    let (done, waiting) = std::sync::mpsc::channel();
    let watchdog = std::thread::Builder::new()
        .name("managed-inert-deadline".into())
        .spawn(move || {
            if matches!(
                waiting.recv_timeout(std::time::Duration::from_secs(15)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                // Do not write to a possibly blocked diagnostic pipe on timeout.
                // No readiness, cleanup or VM-termination receipt is produced.
                std::process::exit(124);
            }
        });
    let Ok(watchdog) = watchdog else {
        std::process::exit(1);
    };
    let result = run();
    if result.is_err() {
        // Error delivery is inside the whole-process budget too.
        use std::io::Write;
        let _ = writeln!(
            std::io::stderr(),
            "Managed inert probe failed; no readiness established."
        );
    }
    let _ = done.send(());
    if watchdog.join().is_err() || result.is_err() {
        std::process::exit(1);
    }
}
