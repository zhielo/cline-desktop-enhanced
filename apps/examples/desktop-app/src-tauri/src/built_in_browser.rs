use serde_json::Value;
use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

const LABEL_PREFIX: &str = "cline-browser-";

fn browser_label(session_id: &str) -> Result<String, String> {
    if session_id.len() != 36
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    {
        return Err("invalid browser session id".to_string());
    }
    Ok(format!("{LABEL_PREFIX}{session_id}"))
}

fn safe_url(value: &str) -> Result<tauri::Url, String> {
    if value == "about:blank" {
        return value
            .parse()
            .map_err(|error| format!("invalid browser URL: {error}"));
    }
    let url: tauri::Url = value
        .parse()
        .map_err(|error| format!("invalid browser URL: {error}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("the built-in browser accepts only http and https URLs".to_string());
    }
    Ok(url)
}

#[tauri::command]
pub fn built_in_browser_start(
    app: tauri::AppHandle,
    session_id: String,
    url: String,
) -> Result<Value, String> {
    let label = browser_label(&session_id)?;
    if app.get_webview_window(&label).is_some() {
        return Err("browser session already exists".to_string());
    }
    let target = safe_url(&url)?;
    let window = WebviewWindowBuilder::new(&app, &label, WebviewUrl::External(target))
        .title("Cline Built-in Browser")
        .inner_size(1240.0, 820.0)
        .min_inner_size(720.0, 480.0)
        .resizable(true)
        .on_navigation(|url| matches!(url.scheme(), "http" | "https" | "about"))
        .build()
        .map_err(|error| format!("failed creating built-in browser: {error}"))?;
    window
        .show()
        .map_err(|error| format!("failed showing built-in browser: {error}"))?;
    Ok(serde_json::json!({ "browserSessionId": session_id, "url": url }))
}

#[tauri::command]
pub fn built_in_browser_stop(app: tauri::AppHandle, session_id: String) -> Result<Value, String> {
    let label = browser_label(&session_id)?;
    if let Some(window) = app.get_webview_window(&label) {
        window
            .close()
            .map_err(|error| format!("failed closing built-in browser: {error}"))?;
    }
    Ok(serde_json::json!({ "browserSessionId": session_id, "stopped": true }))
}

#[cfg(windows)]
#[tauri::command]
pub async fn built_in_browser_cdp(
    app: tauri::AppHandle,
    session_id: String,
    method: String,
    params: Value,
) -> Result<Value, String> {
    use webview2_com::CallDevToolsProtocolMethodCompletedHandler;
    use windows::core::HSTRING;

    if method.len() > 128
        || !method
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.')
    {
        return Err("invalid CDP method".to_string());
    }
    let label = browser_label(&session_id)?;
    let window = app
        .get_webview_window(&label)
        .ok_or_else(|| "unknown built-in browser session".to_string())?;
    if method == "Page.navigate" {
        let requested = params
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| "Page.navigate requires a URL".to_string())?;
        safe_url(requested)?;
    }
    let params_json = serde_json::to_string(&params)
        .map_err(|error| format!("invalid CDP parameters: {error}"))?;
    let (sender, receiver) = tokio::sync::oneshot::channel::<Result<String, String>>();
    window
        .with_webview(move |webview| unsafe {
            let controller = webview.controller();
            let core = match controller.CoreWebView2() {
                Ok(core) => core,
                Err(error) => {
                    let _ = sender.send(Err(format!("failed reading WebView2 core: {error}")));
                    return;
                }
            };
            let callback = CallDevToolsProtocolMethodCompletedHandler::create(Box::new(
                move |status, result_json| {
                    let result = if status.is_ok() {
                        Ok(result_json)
                    } else {
                        Err(format!("WebView2 CDP call failed: {status:?}"))
                    };
                    let _ = sender.send(result);
                    Ok(())
                },
            ));
            if let Err(error) = core.CallDevToolsProtocolMethod(
                &HSTRING::from(method),
                &HSTRING::from(params_json),
                &callback,
            ) {
                // The completion callback owns the sender after construction;
                // WebView2 reports asynchronous failures through it.
                eprintln!("[built-in-browser] CDP dispatch failed: {error}");
            }
        })
        .map_err(|error| format!("failed accessing built-in browser: {error}"))?;
    let raw = tokio::time::timeout(std::time::Duration::from_secs(30), receiver)
        .await
        .map_err(|_| "built-in browser CDP call timed out".to_string())?
        .map_err(|_| "built-in browser CDP callback was dropped".to_string())??;
    serde_json::from_str(&raw).map_err(|error| format!("invalid CDP JSON: {error}"))
}

#[cfg(not(windows))]
#[tauri::command]
pub async fn built_in_browser_cdp(
    _app: tauri::AppHandle,
    _session_id: String,
    _method: String,
    _params: Value,
) -> Result<Value, String> {
    Err("structured built-in browser control is currently available on Windows only".to_string())
}
