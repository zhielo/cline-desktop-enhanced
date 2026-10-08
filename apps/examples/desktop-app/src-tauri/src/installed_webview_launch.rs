use std::path::PathBuf;

// Match the pinned Wry default when overriding additional browser arguments.
const WRY_DEFAULT_ARGS: &str =
    "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection";

pub struct AcceptanceWebviewOptions {
    pub additional_browser_args: String,
    pub data_directory: PathBuf,
    pub port: u16,
}

/// An explicit fixture-only opt-in, not a normal launch or IPC authentication bypass.
pub fn acceptance_webview_options(
    enabled: Option<&str>,
    arguments: Option<&str>,
    profile: Option<&str>,
) -> Result<Option<AcceptanceWebviewOptions>, String> {
    if enabled != Some("1") {
        return Ok(None);
    }
    let parts: Vec<&str> = arguments.unwrap_or("").split_whitespace().collect();
    if parts.len() != 2 || parts[1] != "--remote-debugging-address=127.0.0.1" {
        return Err("Acceptance requires exact loopback WebView2 arguments".into());
    }
    let port = parts[0]
        .strip_prefix("--remote-debugging-port=")
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port > 0)
        .ok_or("Acceptance requires a valid nonzero WebView2 debugging port")?;
    let data_directory = PathBuf::from(profile.unwrap_or(""));
    if !data_directory.is_absolute() {
        return Err("Acceptance requires an absolute private WebView2 profile".into());
    }
    Ok(Some(AcceptanceWebviewOptions {
        additional_browser_args: format!(
            "{WRY_DEFAULT_ARGS} --remote-debugging-port={port} --remote-debugging-address=127.0.0.1"
        ),
        data_directory,
        port,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARGS: &str =
        "--remote-debugging-port=12345 --remote-debugging-address=127.0.0.1";

    #[test]
    fn normal_launch_does_not_apply_debugging_options() {
        assert!(acceptance_webview_options(None, Some(ARGS), None)
            .unwrap()
            .is_none());
        assert!(acceptance_webview_options(Some("true"), Some(ARGS), None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn opted_in_fixture_retains_defaults_and_exact_private_profile() {
        let profile = std::env::temp_dir().join("owned webview profile");
        let options =
            acceptance_webview_options(Some("1"), Some(ARGS), profile.to_str())
                .unwrap()
                .unwrap();
        assert_eq!(options.port, 12345);
        assert_eq!(options.data_directory, profile);
        assert!(options.additional_browser_args.starts_with(WRY_DEFAULT_ARGS));
        assert!(options.additional_browser_args.ends_with(ARGS));
    }

    #[test]
    fn non_loopback_and_extra_arguments_are_rejected() {
        for arguments in [
            "--remote-debugging-port=12345 --remote-debugging-address=0.0.0.0",
            "--remote-debugging-port=12345 --remote-debugging-address=127.0.0.1 --no-sandbox",
            "--remote-debugging-port=12345",
        ] {
            assert!(acceptance_webview_options(Some("1"), Some(arguments), Some("owned"))
                .is_err());
        }
    }

    #[test]
    fn invalid_ports_are_rejected() {
        let profile = std::env::temp_dir();
        for port in ["0", "65536", "-1", "not-a-port"] {
            let arguments = format!(
                "--remote-debugging-port={port} --remote-debugging-address=127.0.0.1"
            );
            assert!(acceptance_webview_options(Some("1"), Some(&arguments), profile.to_str())
                .is_err());
        }
    }

    #[test]
    fn missing_or_relative_profiles_are_rejected() {
        for profile in [None, Some(""), Some("relative/profile")] {
            assert!(acceptance_webview_options(Some("1"), Some(ARGS), profile).is_err());
        }
    }
}