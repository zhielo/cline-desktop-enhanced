// Metadata-only CDP events. No request bodies, headers, cookies, console arguments or screenshots.
use serde_json::{json, Value};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
pub struct EventBuffer { pub events: Vec<Value>, pub dropped: usize, pub stopped: bool, pub began: Instant, pub epoch_ms: u64 }
impl EventBuffer {
 pub fn new() -> Self { Self { events: Vec::new(), dropped:0, stopped:false, began:Instant::now(), epoch_ms:SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64 } }
 pub fn record(&mut self, method:&str, value:&Value) {
  if self.stopped { return; }
  if self.began.elapsed().as_secs()>=120 || self.events.len()>=256 {self.dropped+=1;return;}
  let origin = |url:&str| tauri::Url::parse(url).ok().filter(|u| matches!(u.scheme(),"http"|"https")).map(|u|u.origin().ascii_serialization()).filter(|s|s.len()<=256);
  let event=match method {
   "Network.requestWillBeSent" => json!({"kind":"network-request","origin":value.pointer("/request/url").and_then(Value::as_str).and_then(origin),"method":value.pointer("/request/method").and_then(Value::as_str).filter(|m|matches!(*m,"GET"|"POST"|"PUT"|"DELETE"|"PATCH"|"HEAD"|"OPTIONS")),"atMs":self.began.elapsed().as_millis() as u64}),
   "Network.responseReceived" => json!({"kind":"network-response","origin":value.pointer("/response/url").and_then(Value::as_str).and_then(origin),"status":value.pointer("/response/status").and_then(Value::as_u64).filter(|n|*n<1000),"atMs":self.began.elapsed().as_millis() as u64}),
   "Runtime.consoleAPICalled" => {
    if value.get("timestamp").and_then(Value::as_f64).map(|t|t<(self.epoch_ms as f64)).unwrap_or(false){return;}
    json!({"kind":"console-event","level":value.get("type").and_then(Value::as_str).filter(|v|matches!(*v,"log"|"debug"|"info"|"error"|"warning"|"assert"|"trace")),"argumentCount":value.get("args").and_then(Value::as_array).map(|a|a.len().min(100)),"atMs":self.began.elapsed().as_millis() as u64})
   },
   _=>return
  };self.events.push(event);
 }
 pub fn snapshot(&self,cleanup:bool)->Value { json!({"schemaVersion":1,"coverage":"browser-action-and-origin-console-metadata","events":self.events,"dropped":self.dropped,"expired":self.began.elapsed().as_secs()>=120,"cleanupVerified":cleanup,"limits":{"maxEvents":256,"maxSeconds":120},"limitations":["Origins only: paths, queries, bodies, headers, cookies and console arguments are omitted.","Timing and same-origin observations do not prove feature or cross-process causality."]}) }
}
#[cfg(windows)]
mod native {
 use super::*;
 use std::{cell::RefCell, collections::HashMap, sync::{Arc,Mutex}};
 use webview2_com::{DevToolsProtocolEventReceivedEventHandler,CoTaskMemPWSTR};
 use webview2_com::Microsoft::Web::WebView2::Win32::{ICoreWebView2,ICoreWebView2DevToolsProtocolEventReceiver};
 use windows::core::{HSTRING,PWSTR};
 struct Capture { subscriptions:Vec<(ICoreWebView2DevToolsProtocolEventReceiver,i64)>, buffer:Arc<Mutex<EventBuffer>> }
 thread_local! { static CAPTURES:RefCell<HashMap<String,Capture>>=RefCell::new(HashMap::new()); }
 pub unsafe fn begin(core:&ICoreWebView2,label:&str)->Result<Value,String> {
  CAPTURES.with(|registry| {let mut captures=registry.borrow_mut();if captures.contains_key(label)||captures.len()>=8{return Err("Existing capture or capture budget reached; stop before restarting".into());}
   let buffer=Arc::new(Mutex::new(EventBuffer::new()));let mut subscriptions=Vec::new();
   for name in ["Network.requestWillBeSent","Network.responseReceived","Runtime.consoleAPICalled"] {
    let receiver=match core.GetDevToolsProtocolEventReceiver(&HSTRING::from(name)){Ok(r)=>r,Err(_)=>{if let Ok(mut b)=buffer.lock(){b.stopped=true;}for(r,t) in &subscriptions{let _=ICoreWebView2DevToolsProtocolEventReceiver::remove_DevToolsProtocolEventReceived(r,*t);}return Err("Event receiver unavailable".into());}};
    let events=buffer.clone();
    let handler=DevToolsProtocolEventReceivedEventHandler::create(Box::new(move |_,args|{
     if events.lock().map(|mut b|{if b.events.len()>=256&&!b.stopped{b.dropped+=1;}b.stopped||b.began.elapsed().as_secs()>=120||b.events.len()>=256}).unwrap_or(true){return Ok(());}
     if let Some(args)=args {let mut raw=PWSTR::null();args.ParameterObjectAsJson(&mut raw)?;let guard=CoTaskMemPWSTR::from(raw);let ptr=guard.as_ref().as_pcwstr().as_ptr();if ptr.is_null(){return Ok(());}let mut len=0;while len<=65536&&*ptr.add(len)!=0{len+=1;}
      if len>65536{if let Ok(mut b)=events.lock(){b.dropped+=1;}}else{let text=String::from_utf16_lossy(std::slice::from_raw_parts(ptr,len));if let Ok(value)=serde_json::from_str::<Value>(&text){if let Ok(mut b)=events.lock(){b.record(name,&value);}}}
     }Ok(())
    }));
    let mut token=0;if receiver.add_DevToolsProtocolEventReceived(&handler,&mut token).is_err(){if let Ok(mut b)=buffer.lock(){b.stopped=true;}for(r,t)in &subscriptions{let _=ICoreWebView2DevToolsProtocolEventReceiver::remove_DevToolsProtocolEventReceived(r,*t);}return Err("Event registration failed".into());}
    subscriptions.push((receiver,token));
   }
   captures.insert(label.to_string(),Capture{subscriptions,buffer});Ok(json!({"recording":true,"metadataOnly":true,"maxSeconds":120}))
  })
 }
 pub unsafe fn end(label:&str)->Result<Value,String>{CAPTURES.with(|registry|{let capture=registry.borrow_mut().remove(label).ok_or("No active native capture")?;capture.buffer.lock().map_err(|_|"Capture state unavailable")?.stopped=true;let mut cleanup=true;for(receiver,token)in capture.subscriptions{cleanup &= receiver.remove_DevToolsProtocolEventReceived(token).is_ok();}let value=capture.buffer.lock().map_err(|_|"Capture state unavailable")?.snapshot(cleanup);Ok(value)})}
}
#[cfg(windows)] pub use native::{begin,end};
#[cfg(test)] mod tests {use super::*;#[test]fn metadata_never_retains_url_credentials_or_console_arguments(){let mut b=EventBuffer::new();b.record("Network.requestWillBeSent",&json!({"request":{"url":"https://user:password@owned.invalid/private-token?q=secret","method":"GET","headers":{"Authorization":"secret"},"postData":"secret"}}));b.record("Runtime.consoleAPICalled",&json!({"type":"log","args":[{"value":"private-secret"}]}));let s=b.snapshot(true).to_string();assert!(s.contains("https://owned.invalid"));assert!(!s.contains("private-token"));assert!(!s.contains("password"));assert!(!s.contains("private-secret"));assert!(!s.contains("Authorization"));}#[test]fn expired_and_stopped_captures_do_not_accumulate(){let mut b=EventBuffer::new();b.stopped=true;b.record("Runtime.consoleAPICalled",&json!({"type":"log"}));assert!(b.events.is_empty());b.stopped=false;for _ in 0..300{b.record("Runtime.consoleAPICalled",&json!({"type":"log"}));}assert_eq!(b.events.len(),256);assert_eq!(b.dropped,44);}}
#[cfg(test)] mod extra_tests {
 use super::*;
 #[test] fn cached_console_and_expired_windows_are_not_recorded(){let mut b=EventBuffer::new();b.record("Runtime.consoleAPICalled",&json!({"type":"log","timestamp":1,"args":[{"value":"old-secret"}]}));assert!(b.events.is_empty());b.began=Instant::now().checked_sub(std::time::Duration::from_secs(121)).unwrap();b.record("Network.responseReceived",&json!({"response":{"url":"https://owned.invalid/private","status":200}}));assert!(b.events.is_empty());assert_eq!(b.dropped,1);assert_eq!(b.snapshot(false)["expired"],true);assert_eq!(b.snapshot(false)["cleanupVerified"],false);}
 #[test] fn invalid_or_oversized_origins_are_omitted(){let mut b=EventBuffer::new();b.record("Network.requestWillBeSent",&json!({"request":{"url":format!("https://{}.invalid/private", "x".repeat(300)),"method":"SECRET-METHOD"}}));assert_eq!(b.events[0]["origin"],Value::Null);assert_eq!(b.events[0]["method"],Value::Null);}
}
