/// ExLAP WASM hook for aa-proxy-rs.
///
/// Implements the full ExLAP protocol state machine (matching ExlapReader.java)
/// inside the aa-proxy-rs WASM hooks engine. The hook intercepts packets on
/// channel 0x7E (configurable via custom-configs), runs auth + session setup,
/// then streams sensor data updates to the web UI via `host::send_ws_event`.
///
/// Key fix over the native implementation: the auth challenge now correctly
/// includes `useHash="sha256"` so the HU knows which digest algorithm to use.
///
/// EV-relevant values (tankLevelSecondary, outsideTemperature) are forwarded
/// to the AA energy model via `POST /battery` (on the REST whitelist).
///
/// Subscribe/Unsubscribe for additional URLs are triggered from the web UI
/// via WS `script_event` messages routed to `ws_script_handler`.
///
/// Working credential index is persisted via `host::set_config` so the hook
/// starts with the right credential on the next connection.

#[allow(warnings)]
mod bindings;

use bindings::aa::packet::host;
use bindings::aa::packet::types::{
    ConfigView, CustomConfigEntry, CustomConfigSection, Decision, ModifyContext, Packet,
};
use bindings::Guest;

use base64::Engine as _;
use sha2::Digest as _;
use std::sync::{Mutex, OnceLock};

// ── Credentials (from ExlapReader.java, in index order) ──────────────────────

const CREDENTIALS: &[(&str, &str)] = &[
    ("Test_TB-105000", "s4T2K6BAv0a7LQvrv3vdaUl17xEl2WJOpTmAThpRZe0=="),
    ("RSE_L-CA2000", "T53Facvq51jO8vQJrBNx3MqLWmPcHf/hkow7yLu7SuA=="),
    ("RSE_3-DE1400", "KozPo8iE0j72pkbWXKcP0QihpxgML3Opp8fNJZ0wN24=="),
    ("ML_74-125000", "Fo7arEpPhAgMMznzxRlV8B7eeZgNDIYQcy0Gr7Ad1Fg=="),
];

// ── Packet flags (mirroring mitm.rs constants) ───────────────────────────────

const ENCRYPTED: u8 = 1 << 3;
const FRAME_TYPE_FIRST: u8 = 1 << 1;
const FRAME_TYPE_LAST: u8 = 1 << 0;
const CONTROL_FLAG: u8 = 1 << 2;
const CHAN_OPEN_RSP: u16 = 0x000A;

// ── Protocol phase ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Phase {
    WaitChanOpen,
    WaitConnReturn,
    WaitInit,
    WaitCapabilities,
    WaitAuthChallenge,
    WaitAuthResponse,
    WaitUrlList,
    Active,
    Failed,
}

// ── Session state ─────────────────────────────────────────────────────────────

struct ExlapState {
    /// Which channel to intercept (default 0x7E, configurable).
    exlap_channel: u8,
    /// Current protocol phase.
    phase: Phase,
    /// Random hex session ID generated in on_create.
    session_id: String,
    /// Monotonically increasing request ID.
    req_id: u32,
    /// Fragment reassembly buffer.
    assemble_buf: Vec<u8>,
    /// Index into CREDENTIALS table being tried.
    cred_idx: usize,
    /// Last tankLevelSecondary value received.
    tank_level: Option<f32>,
    /// Last outsideTemperature value received.
    outside_temp: Option<f32>,
    /// Whether the HU reported subscriptionLimitReached.
    subscription_limit_reached: bool,
}

impl ExlapState {
    fn new(exlap_channel: u8, start_cred: usize) -> Self {
        let session_id = make_session_id();
        Self {
            exlap_channel,
            phase: Phase::WaitChanOpen,
            session_id,
            req_id: 42,
            assemble_buf: Vec::new(),
            cred_idx: start_cred.min(CREDENTIALS.len() - 1),
            tank_level: None,
            outside_temp: None,
            subscription_limit_reached: false,
        }
    }

    fn next_id(&mut self) -> u32 {
        let id = self.req_id;
        self.req_id += 1;
        id
    }

    fn make_req(&mut self, body: &str) -> String {
        let id = self.next_id();
        format!(
            r#"<ExlapStatement session_id="{sid}"><Req id="{id}">{body}</Req></ExlapStatement>"#,
            sid = self.session_id,
        )
    }

    fn make_pkt(&self, xml: &str) -> Packet {
        Packet {
            proxy_type: bindings::aa::packet::types::ProxyType::MobileDevice,
            channel: self.exlap_channel,
            packet_flags: ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
            final_length: None,
            message_id: 0,
            payload: xml.as_bytes().to_vec(),
        }
    }

    fn user(&self) -> &'static str {
        CREDENTIALS[self.cred_idx].0
    }

    fn password(&self) -> &'static str {
        CREDENTIALS[self.cred_idx].1
    }
}

/// Generate a 16-byte random session ID as a lowercase hex string.
fn make_session_id() -> String {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).unwrap_or(());
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── Global state (single-threaded WASM) ──────────────────────────────────────

static STATE: OnceLock<Mutex<ExlapState>> = OnceLock::new();

fn with_state<R>(f: impl FnOnce(&mut ExlapState) -> R) -> R {
    let mutex = STATE.get().expect("STATE not initialized");
    let mut guard = mutex.lock().expect("STATE lock poisoned");
    f(&mut guard)
}

// ── WIT bindings export ───────────────────────────────────────────────────────

struct ExlapHook;

impl Guest for ExlapHook {
    fn on_create() {
        let channel: u8 = host::get_config("exlap_channel")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0x7E);
        let start_cred: usize = host::get_config("exlap_cred_idx")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0usize);

        STATE
            .set(Mutex::new(ExlapState::new(channel, start_cred)))
            .ok();

        host::info(&format!(
            "exlap-hook: created, channel={:#04x} start_cred={}",
            channel, start_cred
        ));
    }

    fn on_destroy() {
        host::info("exlap-hook: destroyed");
    }

    fn custom_configs() -> Vec<CustomConfigSection> {
        vec![CustomConfigSection {
            title: "ExLAP".to_string(),
            values: vec![
                CustomConfigEntry {
                    name: "exlap_channel".to_string(),
                    typ: "u8".to_string(),
                    description: "AA vendor channel id for ExLAP (default 0x7E = 126)".to_string(),
                    default_value: "126".to_string(),
                    values: None,
                },
                CustomConfigEntry {
                    name: "exlap_cred_idx".to_string(),
                    typ: "u8".to_string(),
                    description: "ExLAP credential index to try first (0–3; auto-updated on successful auth)".to_string(),
                    default_value: "0".to_string(),
                    values: None,
                },
            ],
        }]
    }

    fn on_config_changed(name: String, value: String) {
        with_state(|s| match name.as_str() {
            "exlap_channel" => {
                if let Ok(ch) = value.parse::<u8>() {
                    s.exlap_channel = ch;
                    host::info(&format!("exlap-hook: channel updated to {:#04x}", ch));
                }
            }
            "exlap_cred_idx" => {
                if let Ok(idx) = value.parse::<usize>() {
                    let idx = idx.min(CREDENTIALS.len() - 1);
                    s.cred_idx = idx;
                    host::info(&format!("exlap-hook: cred_idx updated to {}", idx));
                }
            }
            _ => {}
        });
    }

    fn modify_packet(_ctx: ModifyContext, pkt: Packet, _cfg: ConfigView) -> Decision {
        let channel = with_state(|s| s.exlap_channel);

        if pkt.channel != channel {
            return Decision::Forward;
        }

        process_packet(pkt);
        Decision::Drop
    }

    fn ws_script_handler(topic: String, payload: String) -> String {
        if topic != "exlap-hook" {
            return String::new();
        }

        let Ok(val) = serde_json::from_str::<serde_json::Value>(&payload) else {
            return "error: invalid JSON".to_string();
        };

        let cmd = val.get("cmd").and_then(|v| v.as_str()).unwrap_or("");

        match cmd {
            "subscribe" => {
                let url = match val.get("url").and_then(|v| v.as_str()) {
                    Some(u) => u.to_string(),
                    None => return "error: missing url".to_string(),
                };
                with_state(|s| {
                    if s.phase != Phase::Active {
                        return "error: not active".to_string();
                    }
                    let body = format!(r#"<Subscribe url="{}" timeStamp="true"/>"#, url);
                    let xml = s.make_req(&body);
                    host::send(&s.make_pkt(&xml));
                    host::info(&format!("exlap-hook: subscribed to {}", url));
                    "ok".to_string()
                })
            }
            "unsubscribe" => {
                let url = match val.get("url").and_then(|v| v.as_str()) {
                    Some(u) => u.to_string(),
                    None => return "error: missing url".to_string(),
                };
                with_state(|s| {
                    if s.phase != Phase::Active {
                        return "error: not active".to_string();
                    }
                    let body = format!(r#"<Unsubscribe url="{}"/>"#, url);
                    let xml = s.make_req(&body);
                    host::send(&s.make_pkt(&xml));
                    host::info(&format!("exlap-hook: unsubscribed from {}", url));
                    "ok".to_string()
                })
            }
            "list" => {
                // Re-emit the state snapshot so the UI can refresh
                with_state(|s| {
                    let state_str = phase_str(&s.phase);
                    let snapshot = serde_json::json!({
                        "connection_state": state_str,
                        "subscription_limit_reached": s.subscription_limit_reached,
                        "urls": [],
                    });
                    host::send_ws_event("exlap", &snapshot.to_string());
                    "ok".to_string()
                })
            }
            _ => format!("error: unknown cmd {:?}", cmd),
        }
    }
}

bindings::export!(ExlapHook with_types_in bindings);

// ── Packet processing ─────────────────────────────────────────────────────────

fn process_packet(pkt: Packet) {
    let is_control = (pkt.packet_flags & CONTROL_FLAG) != 0;

    if is_control {
        handle_control(&pkt);
        return;
    }

    // Fragment reassembly
    let is_first = (pkt.packet_flags & FRAME_TYPE_FIRST) != 0;
    let is_last = (pkt.packet_flags & FRAME_TYPE_LAST) != 0;

    with_state(|s| {
        if is_first {
            s.assemble_buf.clear();
        }
        s.assemble_buf.extend_from_slice(&pkt.payload);
    });

    if !is_last {
        return;
    }

    let xml = with_state(|s| {
        let result = std::str::from_utf8(&s.assemble_buf)
            .map(|x| x.to_owned())
            .ok();
        s.assemble_buf.clear();
        result
    });

    let Some(xml) = xml else {
        host::error("exlap-hook: invalid UTF-8 in packet, dropping");
        return;
    };

    handle_xml(&xml);
}

fn handle_control(pkt: &Packet) {
    if pkt.payload.len() < 2 {
        return;
    }
    let msg_id = u16::from_be_bytes([pkt.payload[0], pkt.payload[1]]);

    with_state(|s| {
        if msg_id == CHAN_OPEN_RSP && s.phase == Phase::WaitChanOpen {
            host::info(&format!(
                "exlap-hook: channel {:#04x} open confirmed; sending ExlapConnectionRequest (cred={})",
                s.exlap_channel, s.cred_idx
            ));
            s.phase = Phase::WaitConnReturn;
            let xml = format!(r#"<ExlapConnectionRequest session_id="{}"/>"#, s.session_id);
            host::send(&s.make_pkt(&xml));
        }
    });
}

fn handle_xml(xml: &str) {
    let root = xml_root_tag(xml).unwrap_or_default();

    match root.as_str() {
        "ExlapBeacon" => {}
        "ExlapConnectionClosed" => {
            host::info("exlap-hook: server closed ExLAP connection, resetting to WaitInit");
            with_state(|s| {
                s.phase = Phase::WaitInit;
                push_connection_state(s);
            });
        }
        "ExlapConnectionReturn" => {
            with_state(|s| {
                if s.phase != Phase::WaitConnReturn {
                    return;
                }
                let connected = xml_attr_in_tag(xml, "ExlapConnectionReturn", "connected")
                    .map(|v| v == "true")
                    .unwrap_or(false);
                if !connected {
                    host::error("exlap-hook: ExlapConnectionReturn connected=false");
                    return;
                }
                host::info("exlap-hook: ExLAP connection established; waiting for Init");
                s.phase = Phase::WaitInit;
                push_connection_state(s);
            });
        }
        "ExlapStatement" => {
            let sid = xml_attr_in_tag(xml, "ExlapStatement", "session_id").unwrap_or_default();
            let our_sid = with_state(|s| s.session_id.clone());
            if sid != our_sid {
                return;
            }
            advance_statement(xml);
        }
        other => {
            host::info(&format!("exlap-hook: ignoring unknown root: {}", other));
        }
    }
}

fn advance_statement(xml: &str) {
    let phase = with_state(|s| s.phase.clone());

    match phase {
        Phase::WaitInit => {
            if xml.contains("<Init") {
                host::info("exlap-hook: got Init; sending Protocol request");
                with_state(|s| {
                    let req = s.make_req(r#"<Protocol version="1" returnCapabilities="true"/>"#);
                    let pkt = s.make_pkt(&req);
                    s.phase = Phase::WaitCapabilities;
                    push_connection_state(s);
                    host::send(&pkt);
                });
            }
        }
        Phase::WaitCapabilities => {
            if xml.contains("<Capabilities") {
                with_state(|s| {
                    host::info(&format!(
                        "exlap-hook: got Capabilities; sending auth challenge (cred={} \"{}\")",
                        s.cred_idx,
                        s.user()
                    ));
                    // KEY FIX: include useHash="sha256" so the HU knows which algorithm we use
                    let req = s.make_req(r#"<Authenticate phase="challenge" useHash="sha256"/>"#);
                    let pkt = s.make_pkt(&req);
                    s.phase = Phase::WaitAuthChallenge;
                    host::send(&pkt);
                });
            }
        }
        Phase::WaitAuthChallenge => {
            if let Some(nonce_b64) = xml_attr_in_tag(xml, "Challenge", "nonce") {
                with_state(|s| {
                    match compute_auth_response(&nonce_b64, s.user(), s.password()) {
                        Ok((cnonce_b64, digest_b64)) => {
                            let body = format!(
                                r#"<Authenticate phase="response" user="{}" cnonce="{}" digest="{}"/>"#,
                                s.user(),
                                cnonce_b64,
                                digest_b64
                            );
                            let req = s.make_req(&body);
                            let pkt = s.make_pkt(&req);
                            s.phase = Phase::WaitAuthResponse;
                            host::send(&pkt);
                        }
                        Err(e) => {
                            host::error(&format!("exlap-hook: auth compute failed: {}", e));
                        }
                    }
                });
            }
        }
        Phase::WaitAuthResponse => {
            if xml.contains("<Rsp") {
                let empty = match extract_rsp_inner(xml) {
                    None => true,
                    Some(inner) => !inner.trim().contains('<'),
                };
                if empty {
                    // Auth success
                    with_state(|s| {
                        host::info(&format!(
                            "exlap-hook: authenticated with cred={} (\"{}\")",
                            s.cred_idx,
                            s.user()
                        ));
                        // Persist the working credential index
                        host::set_config("exlap_cred_idx", &s.cred_idx.to_string());

                        let req = s.make_req("<Dir/>");
                        let pkt = s.make_pkt(&req);
                        s.phase = Phase::WaitUrlList;
                        push_connection_state(s);
                        host::send(&pkt);
                    });
                } else {
                    // Auth failure — try next credential
                    with_state(|s| {
                        let next = s.cred_idx + 1;
                        if next < CREDENTIALS.len() {
                            host::info(&format!(
                                "exlap-hook: cred={} failed; trying cred={}",
                                s.cred_idx, next
                            ));
                            s.cred_idx = next;
                            // Re-issue challenge for fresh nonce
                            let req = s
                                .make_req(r#"<Authenticate phase="challenge" useHash="sha256"/>"#);
                            let pkt = s.make_pkt(&req);
                            s.phase = Phase::WaitAuthChallenge;
                            host::send(&pkt);
                        } else {
                            host::error("exlap-hook: all credentials exhausted; ExLAP auth permanently failed");
                            s.phase = Phase::Failed;
                            push_connection_state(s);
                        }
                    });
                }
            }
        }
        Phase::WaitUrlList => {
            if xml.contains("<UrlList") {
                with_state(|s| {
                    let urls = parse_url_list(xml);
                    host::info(&format!("exlap-hook: HU exposes {} URLs", urls.len()));

                    // Push full state snapshot to web UI
                    let snapshot = serde_json::json!({
                        "connection_state": "active",
                        "subscription_limit_reached": false,
                        "urls": urls,
                        "values": {},
                    });
                    host::send_ws_event("exlap", &snapshot.to_string());

                    s.phase = Phase::Active;
                    s.subscription_limit_reached = false;

                    // Subscribe to EV fields automatically
                    let ev_urls = ["tankLevelSecondary", "outsideTemperature"];
                    for &url in &ev_urls {
                        if urls.is_empty() || urls.iter().any(|e: &serde_json::Value| {
                            e.get("url").and_then(|v| v.as_str()) == Some(url)
                        }) {
                            let body = format!(r#"<Subscribe url="{}" timeStamp="true"/>"#, url);
                            let req = s.make_req(&body);
                            let pkt = s.make_pkt(&req);
                            host::send(&pkt);
                        }
                    }
                });
            }
        }
        Phase::Active => {
            // Check for subscription limit or other Rsp status codes
            if xml.contains("<Rsp") {
                if let Some(status) = xml_attr_in_tag(xml, "Rsp", "status") {
                    match status.as_str() {
                        "subscriptionLimitReached" => {
                            host::info("exlap-hook: subscription limit reached");
                            with_state(|s| {
                                s.subscription_limit_reached = true;
                                push_connection_state(s);
                            });
                        }
                        "noMatchingUrl" => {
                            host::info("exlap-hook: HU returned noMatchingUrl");
                        }
                        _ => {}
                    }
                }
            }
            process_dat_messages(xml);
        }
        _ => {}
    }
}

/// Push a connection state event to the web UI.
fn push_connection_state(s: &ExlapState) {
    let state_str = phase_str(&s.phase);
    let event = serde_json::json!({
        "connection_state": state_str,
        "subscription_limit_reached": s.subscription_limit_reached,
    });
    host::send_ws_event("exlap", &event.to_string());
}

fn phase_str(phase: &Phase) -> &'static str {
    match phase {
        Phase::Active => "active",
        Phase::Failed => "failed",
        Phase::WaitChanOpen => "connecting",
        _ => "connecting",
    }
}

// ── Dat message processing ────────────────────────────────────────────────────

fn process_dat_messages(xml: &str) {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut current_url: Option<String> = None;
    let mut current_val = String::new();
    let mut current_val_type = String::new();
    let mut current_state = String::new();
    let mut current_timestamp: Option<String> = None;
    let mut dat_depth: u32 = 0;

    let mut changes: Vec<serde_json::Value> = Vec::new();
    let mut ev_updated = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let tag = std::str::from_utf8(e.name().local_name().as_ref())
                    .unwrap_or("")
                    .to_string();
                match tag.as_str() {
                    "Dat" if dat_depth == 0 => {
                        current_url = attr_value(e, b"url");
                        current_timestamp = attr_value(e, b"timestamp");
                        current_val.clear();
                        current_val_type.clear();
                        current_state = "ok".to_string();
                        dat_depth = 1;
                    }
                    "Rel" | "Abs" | "Act" | "Enm" | "Txt" | "Tim" | "Bin" if dat_depth == 1 => {
                        let val = attr_value(e, b"val").unwrap_or_default();
                        let state =
                            attr_value(e, b"state").unwrap_or_else(|| "ok".to_string());
                        current_val_type = tag.clone();
                        current_val = val.clone();
                        current_state = state.clone();

                        // EV telemetry handling
                        if state != "nodata" && state != "error" {
                            if let (Some(url), Ok(v)) =
                                (current_url.as_deref(), val.parse::<f32>())
                            {
                                match url {
                                    "tankLevelSecondary" => {
                                        host::info(&format!(
                                            "exlap-hook: tankLevelSecondary = {}%",
                                            v
                                        ));
                                        with_state(|s| {
                                            s.tank_level = Some(v);
                                        });
                                        ev_updated = true;
                                    }
                                    "outsideTemperature" => {
                                        host::info(&format!(
                                            "exlap-hook: outsideTemperature = {}°C",
                                            v
                                        ));
                                        with_state(|s| {
                                            s.outside_temp = Some(v);
                                        });
                                    }
                                    _ => {}
                                }
                            }
                        }
                        dat_depth += 1;
                    }
                    _ if dat_depth > 0 => {
                        dat_depth += 1;
                    }
                    _ => {}
                }
            }
            Ok(Event::End(ref e)) => {
                let local = e.name().local_name();
                let tag = std::str::from_utf8(local.as_ref()).unwrap_or("");
                if tag == "Dat" {
                    if let Some(url) = current_url.take() {
                        changes.push(serde_json::json!({
                            "url": url,
                            "val": current_val,
                            "type": current_val_type,
                            "state": current_state,
                            "timestamp": current_timestamp,
                        }));
                    }
                    dat_depth = 0;
                } else if dat_depth > 0 {
                    dat_depth -= 1;
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }

    if ev_updated {
        // POST EV data to /battery (on the WASM REST whitelist)
        let (tank, temp) = with_state(|s| (s.tank_level, s.outside_temp));
        let body = serde_json::json!({
            "battery_level_percentage": tank,
            "external_temp_celsius": temp,
        });
        let result = host::rest_call("POST", "/battery", &body.to_string());
        if !result.contains("\"ok\":true") {
            host::error(&format!("exlap-hook: /battery POST failed: {}", result));
        }
    }

    if !changes.is_empty() {
        let payload = serde_json::to_string(&changes).unwrap_or_default();
        host::send_ws_event("exlap", &payload);
    }
}

// ── Auth ──────────────────────────────────────────────────────────────────────

/// Compute the ExLAP SHA-256 auth digest.
///
/// Matches ExlapReader.java `computeDigest`:
///   sha256("{user:.44}:{password:.44}:{b64(nonce_bytes):.44}:{b64(cnonce_bytes):.44}") → base64
fn compute_auth_response(
    nonce_b64: &str,
    user: &str,
    password: &str,
) -> Result<(String, String), String> {
    let b64 = base64::engine::general_purpose::STANDARD;

    let nonce_bytes = b64.decode(nonce_b64).map_err(|e| e.to_string())?;
    let nonce_clean = b64.encode(&nonce_bytes);

    let mut cnonce_raw = [0u8; 16];
    getrandom::getrandom(&mut cnonce_raw).map_err(|e| e.to_string())?;
    let cnonce_b64 = b64.encode(&cnonce_raw);

    let input = format!(
        "{:.44}:{:.44}:{:.44}:{:.44}",
        user, password, nonce_clean, cnonce_b64
    );
    let hash = sha2::Sha256::digest(input.as_bytes());
    let digest_b64 = b64.encode(hash.as_slice());

    Ok((cnonce_b64, digest_b64))
}

// ── XML helpers ───────────────────────────────────────────────────────────────

fn xml_root_tag(xml: &str) -> Option<String> {
    use quick_xml::events::Event;
    use quick_xml::Reader;
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                return Some(
                    std::str::from_utf8(e.name().local_name().as_ref())
                        .unwrap_or("")
                        .to_owned(),
                );
            }
            Ok(Event::Eof) | Err(_) => return None,
            _ => {}
        }
    }
}

fn xml_attr_in_tag(xml: &str, tag_name: &str, attr_name: &str) -> Option<String> {
    use quick_xml::events::Event;
    use quick_xml::Reader;
    let attr_bytes = attr_name.as_bytes();
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                if std::str::from_utf8(e.name().local_name().as_ref()).unwrap_or("") == tag_name {
                    return attr_value(&e, attr_bytes);
                }
            }
            Ok(Event::Eof) | Err(_) => return None,
            _ => {}
        }
    }
}

/// Parse `<Match url="..." type="..."/>` elements from a `<UrlList>` response.
fn parse_url_list(xml: &str) -> Vec<serde_json::Value> {
    use quick_xml::events::Event;
    use quick_xml::Reader;
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut urls = Vec::new();
    loop {
        match reader.read_event() {
            Ok(Event::Empty(e)) => {
                if std::str::from_utf8(e.name().local_name().as_ref()).unwrap_or("") == "Match" {
                    if let Some(u) = attr_value(&e, b"url") {
                        let url_type = attr_value(&e, b"type").unwrap_or_default();
                        urls.push(serde_json::json!({ "url": u, "url_type": url_type }));
                    }
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    urls
}

fn attr_value(e: &quick_xml::events::BytesStart, name: &[u8]) -> Option<String> {
    e.attributes()
        .filter_map(|a| a.ok())
        .find(|a| a.key.local_name().as_ref() == name)
        .and_then(|a| a.unescape_value().ok())
        .map(|v| v.into_owned())
}

fn extract_rsp_inner(xml: &str) -> Option<&str> {
    let start = xml.find("<Rsp")?;
    let after_bracket = xml[start..].find('>')?;
    let open_end = start + after_bracket;
    if xml.as_bytes().get(open_end.saturating_sub(1)) == Some(&b'/') {
        return None;
    }
    let content_start = open_end + 1;
    let close = xml.find("</Rsp>")?;
    Some(&xml[content_start..close])
}
