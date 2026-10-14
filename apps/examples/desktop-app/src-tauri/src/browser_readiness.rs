use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::{sleep_until, timeout_at, Instant};

/// Tauri's off-thread builder queues window creation without acknowledging it.
/// WebView2 creation pumps messages before the runtime registers the window, so
/// an early with_webview callback may be dropped. Probe registration only: never
/// recreate the window or replay CDP, capture, navigation or Execute operations.
pub async fn await_browser_ready<F>(mut dispatch: F, timeout: Duration) -> Result<(), String>
where
    F: FnMut() -> Result<oneshot::Receiver<Result<(), String>>, String>,
{
    if timeout.is_zero() || timeout > Duration::from_secs(30) {
        return Err("Invalid browser readiness deadline".into());
    }
    let deadline = Instant::now() + timeout;
    for _ in 0..300 {
        if Instant::now() >= deadline {
            break;
        }
        let receiver = dispatch()?;
        match timeout_at(deadline, receiver).await {
            Ok(Ok(result)) => return result,
            // A dropped read-only probe is not acknowledgement of creation.
            Ok(Err(_)) => {}
            Err(_) => break,
        }
        sleep_until((Instant::now() + Duration::from_millis(100)).min(deadline)).await;
    }
    Err("Native browser readiness timed out; creation was not acknowledged".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(future: impl std::future::Future<Output = ()>) {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(future);
    }

    #[test]
    fn browser_capture_readiness_requires_an_actual_callback() {
        run(async {
            let mut probes = 0;
            await_browser_ready(
                || {
                    probes += 1;
                    let (sender, receiver) = oneshot::channel();
                    if probes == 2 {
                        sender.send(Ok(())).unwrap();
                    }
                    Ok(receiver)
                },
                Duration::from_secs(1),
            )
            .await
            .unwrap();
            assert_eq!(probes, 2);
        });
    }

    #[test]
    fn browser_capture_readiness_does_not_retry_core_failure() {
        run(async {
            let mut probes = 0;
            let result = await_browser_ready(
                || {
                    probes += 1;
                    let (sender, receiver) = oneshot::channel();
                    sender.send(Err("core unavailable".into())).unwrap();
                    Ok(receiver)
                },
                Duration::from_secs(1),
            )
            .await;
            assert_eq!(result.unwrap_err(), "core unavailable");
            assert_eq!(probes, 1);
        });
    }

    #[test]
    fn browser_capture_readiness_bounds_a_never_called_probe() {
        run(async {
            let mut retained = Vec::new();
            let result = await_browser_ready(
                || {
                    let (sender, receiver) = oneshot::channel();
                    retained.push(sender);
                    Ok(receiver)
                },
                Duration::from_millis(20),
            )
            .await;
            assert!(result.unwrap_err().contains("not acknowledged"));
            assert_eq!(retained.len(), 1);
        });
    }

    #[test]
    fn browser_capture_readiness_dropped_probes_cannot_report_success() {
        run(async {
            let mut probes = 0;
            let result = await_browser_ready(
                || {
                    probes += 1;
                    let (_, receiver) = oneshot::channel();
                    Ok(receiver)
                },
                Duration::from_millis(20),
            )
            .await;
            assert!(result.unwrap_err().contains("not acknowledged"));
            assert_eq!(probes, 1);
        });
    }

    #[test]
    fn browser_capture_readiness_rejects_dispatch_failure_and_invalid_deadline() {
        run(async {
            let mut probes = 0;
            for timeout in [Duration::ZERO, Duration::from_secs(31)] {
                assert!(await_browser_ready(
                    || {
                        probes += 1;
                        Err("dispatch unavailable".into())
                    },
                    timeout,
                )
                .await
                .unwrap_err()
                .contains("Invalid"));
            }
            assert_eq!(probes, 0);
            assert_eq!(
                await_browser_ready(
                    || {
                        probes += 1;
                        Err("dispatch unavailable".into())
                    },
                    Duration::from_secs(1),
                )
                .await
                .unwrap_err(),
                "dispatch unavailable"
            );
            assert_eq!(probes, 1);
        });
    }
}
