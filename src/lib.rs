/// ExLAP WASM hook for aa-proxy-rs.
///
/// Implements the full ExLAP protocol state machine (matching ExlapReader.java)
/// as a standalone plugin for stock aa-proxy-rs (no host modifications required).
///
/// The hook watches all packets. When it sees the HU's ServiceDiscoveryResponse
/// (channel 0, msg_id 6) it finds the ExLAP vendor service, sends a
/// CHANNEL_OPEN_REQUEST on the discovered channel, then takes over all packets
/// on that channel to run auth + session setup.
///
/// Key fix over the native implementation: the auth challenge correctly
/// includes `useHash="sha256"` so the HU knows which digest algorithm to use.
///
/// EV-relevant values (tankLevelSecondary, outsideTemperature) are forwarded
/// to the AA energy model via `POST /battery` (on the REST whitelist).
///
/// The URLs to subscribe to are configurable via `exlap_subscribe_urls`.
/// Subscribe/Unsubscribe can also be triggered at runtime via WS
/// `script_event` messages routed to `ws_script_handler`.

#[allow(warnings)]
mod bindings;

use bindings::aa::packet::host;
use bindings::aa::packet::types::{
    ConfigView, CustomConfigEntry, CustomConfigSection, Decision, ModifyContext, Packet, ProxyType,
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

const DEFAULT_SUBSCRIBE_URLS: &str = "tankLevelSecondary,outsideTemperature";

// ── Packet flags and message IDs (mirroring mitm.rs constants) ───────────────

const ENCRYPTED: u8 = 1 << 3;
const FRAME_TYPE_FIRST: u8 = 1 << 0; // bit 0, matches mitm.rs
const FRAME_TYPE_LAST: u8 = 1 << 1;  // bit 1, matches mitm.rs
const CONTROL_FLAG: u8 = 1 << 2;

const MSG_SERVICE_DISCOVERY_RESPONSE: u16 = 6;
const MSG_CHANNEL_OPEN_REQUEST: u16 = 7;
const MSG_CHANNEL_OPEN_RESPONSE: u16 = 8;

const EXLAP_SERVICE_NAME: &str = "com.vwag.infotainment.gal.exlap";

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
    /// Which channel to intercept; overwritten from the SDR service_id on connect.
    exlap_channel: u8,
    /// Current protocol phase.
    phase: Phase,
    /// Random hex session ID, regenerated on each connection.
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
    /// URLs to auto-subscribe to after URL list is received (configurable).
    subscribe_urls: Vec<String>,
}

impl ExlapState {
    fn new(exlap_channel: u8, start_cred: usize, subscribe_urls: Vec<String>) -> Self {
        Self {
            exlap_channel,
            phase: Phase::WaitChanOpen,
            session_id: make_session_id(),
            req_id: 42,
            assemble_buf: Vec::new(),
            cred_idx: start_cred.min(CREDENTIALS.len() - 1),
            tank_level: None,
            outside_temp: None,
            subscription_limit_reached: false,
            subscribe_urls,
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
            proxy_type: ProxyType::MobileDevice,
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

/// Parse a comma-separated URL list from config.
fn parse_subscribe_urls(s: &str) -> Vec<String> {
    s.split(',')
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
        .collect()
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
        let subscribe_urls = parse_subscribe_urls(
            &host::get_config("exlap_subscribe_urls")
                .unwrap_or_else(|| DEFAULT_SUBSCRIBE_URLS.to_string()),
        );

        host::info(&format!(
            "exlap-hook: created channel={:#04x} cred={} subscribe_urls={:?}",
            channel, start_cred, subscribe_urls
        ));

        STATE
            .set(Mutex::new(ExlapState::new(channel, start_cred, subscribe_urls)))
            .ok();
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
                    description: "Fallback channel id if not found in SDR (default 126 = 0x7E)"
                        .to_string(),
                    default_value: "126".to_string(),
                    values: None,
                },
                CustomConfigEntry {
                    name: "exlap_cred_idx".to_string(),
                    typ: "u8".to_string(),
                    description: "Credential index to try first (0–3; hook tries all on failure)"
                        .to_string(),
                    default_value: "0".to_string(),
                    values: None,
                },
                CustomConfigEntry {
                    name: "exlap_subscribe_urls".to_string(),
                    typ: "string".to_string(),
                    description: format!(
                        "Comma-separated ExLAP URLs to subscribe to. \
                         tankLevelSecondary and outsideTemperature also feed POST /battery. \
                         Default: {DEFAULT_SUBSCRIBE_URLS}"
                    ),
                    default_value: DEFAULT_SUBSCRIBE_URLS.to_string(),
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
                    host::info(&format!("exlap-hook: exlap_channel → {:#04x}", ch));
                }
            }
            "exlap_cred_idx" => {
                if let Ok(idx) = value.parse::<usize>() {
                    let idx = idx.min(CREDENTIALS.len() - 1);
                    s.cred_idx = idx;
                    host::info(&format!("exlap-hook: exlap_cred_idx → {}", idx));
                }
            }
            "exlap_subscribe_urls" => {
                let urls = parse_subscribe_urls(&value);
                host::info(&format!("exlap-hook: exlap_subscribe_urls → {:?}", urls));
                s.subscribe_urls = urls;
            }
            _ => {}
        });
    }

    fn modify_packet(_ctx: ModifyContext, pkt: Packet, _cfg: ConfigView) -> Decision {
        // Intercept the HU's ServiceDiscoveryResponse so we can open the ExLAP
        // channel ourselves — no host-side ExLAP code required.
        if pkt.proxy_type == ProxyType::HeadUnit
            && pkt.channel == 0
            && pkt.message_id == MSG_SERVICE_DISCOVERY_RESPONSE
        {
            handle_sdr(&pkt);
            return Decision::Forward; // Other hooks/handlers still need the SDR.
        }

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
                        return format!("error: not active (phase={:?})", s.phase);
                    }
                    let body = format!(r#"<Subscribe url="{}" timeStamp="true"/>"#, url);
                    let xml = s.make_req(&body);
                    host::send(&s.make_pkt(&xml));
                    host::info(&format!("exlap-hook: ws subscribe → {}", url));
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
                        return format!("error: not active (phase={:?})", s.phase);
                    }
                    let body = format!(r#"<Unsubscribe url="{}"/>"#, url);
                    let xml = s.make_req(&body);
                    host::send(&s.make_pkt(&xml));
                    host::info(&format!("exlap-hook: ws unsubscribe → {}", url));
                    "ok".to_string()
                })
            }
            "list" => with_state(|s| {
                let snapshot = serde_json::json!({
                    "connection_state": phase_str(&s.phase),
                    "subscription_limit_reached": s.subscription_limit_reached,
                    "urls": [],
                });
                host::send_ws_event("exlap", &snapshot.to_string());
                "ok".to_string()
            }),
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
        return; // More fragments coming.
    }

    let xml = with_state(|s| {
        let result = std::str::from_utf8(&s.assemble_buf)
            .map(|x| x.to_owned())
            .ok();
        s.assemble_buf.clear();
        result
    });

    let Some(xml) = xml else {
        host::error("exlap-hook: invalid UTF-8 in packet");
        return;
    };

    handle_xml(&xml);
}

/// Handle a control-flag packet on the ExLAP channel.
fn handle_control(pkt: &Packet) {
    if pkt.payload.len() < 2 {
        return;
    }
    let msg_id = u16::from_be_bytes([pkt.payload[0], pkt.payload[1]]);

    if msg_id != MSG_CHANNEL_OPEN_RESPONSE {
        host::info(&format!(
            "exlap-hook: control msg_id={:#06x} on ExLAP channel (ignored)",
            msg_id
        ));
        return;
    }

    // Parse ChannelOpenResponse status (field 1, varint). STATUS_OK = 0.
    let status = if pkt.payload.len() >= 4 && pkt.payload[2] == 0x08 {
        pkt.payload[3] as i32
    } else {
        0 // field absent → default STATUS_OK
    };

    with_state(|s| {
        if s.phase != Phase::WaitChanOpen {
            host::info(&format!(
                "exlap-hook: unexpected CHANNEL_OPEN_RESPONSE in phase {:?} (status={})",
                s.phase, status
            ));
            return;
        }

        if status != 0 {
            host::error(&format!(
                "exlap-hook: CHANNEL_OPEN_RESPONSE status={} on ch={:#04x}; \
                 channel open may have failed",
                status, s.exlap_channel
            ));
            // Proceed anyway — some HUs return non-zero but still open the channel.
        }

        host::info(&format!(
            "exlap-hook: channel {:#04x} open (status={}); \
             sending ExlapConnectionRequest session_id={} cred={} (\"{}\")",
            s.exlap_channel, status, s.session_id, s.cred_idx, s.user()
        ));
        s.phase = Phase::WaitConnReturn;
        let xml = format!(r#"<ExlapConnectionRequest session_id="{}"/>"#, s.session_id);
        host::send(&s.make_pkt(&xml));
    });
}

/// Intercept the HU's ServiceDiscoveryResponse, find the ExLAP vendor service,
/// and send a CHANNEL_OPEN_REQUEST. Resets state on every SDR to handle
/// reconnections cleanly.
fn handle_sdr(pkt: &Packet) {
    if pkt.payload.len() < 2 {
        return;
    }
    // Payload is [msg_id_hi, msg_id_lo, ...protobuf SDR bytes...].
    let proto = &pkt.payload[2..];

    match find_exlap_service_id(proto) {
        None => {
            host::info("exlap-hook: SDR received — ExLAP service not found");
        }
        Some(service_id) => {
            let channel = service_id as u8;
            with_state(|s| {
                // Reset on every SDR — handles phone reconnections gracefully.
                // Preserve cred_idx (avoid retrying known-bad creds) and subscribe_urls.
                let cred_idx = s.cred_idx;
                let subscribe_urls = std::mem::take(&mut s.subscribe_urls);
                *s = ExlapState::new(channel, cred_idx, subscribe_urls);

                host::info(&format!(
                    "exlap-hook: SDR found ExLAP service_id={} → ch={:#04x}; \
                     sending CHANNEL_OPEN_REQUEST",
                    service_id, channel
                ));
                host::send(&build_chan_open_request(channel, service_id));
            });
        }
    }
}

fn handle_xml(xml: &str) {
    let root = xml_root_tag(xml).unwrap_or_default();

    match root.as_str() {
        "ExlapBeacon" => {}
        "ExlapConnectionClosed" => {
            host::info("exlap-hook: HU closed ExLAP connection");
            with_state(|s| {
                // Preserve subscribe_urls and cred_idx across reconnect.
                let cred_idx = s.cred_idx;
                let subscribe_urls = std::mem::take(&mut s.subscribe_urls);
                let channel = s.exlap_channel;
                *s = ExlapState::new(channel, cred_idx, subscribe_urls);
                push_connection_state(s);
            });
        }
        "ExlapConnectionReturn" => {
            with_state(|s| {
                if s.phase != Phase::WaitConnReturn {
                    host::info(&format!(
                        "exlap-hook: unexpected ExlapConnectionReturn in phase {:?}",
                        s.phase
                    ));
                    return;
                }
                let connected = xml_attr_in_tag(xml, "ExlapConnectionReturn", "connected")
                    .map(|v| v == "true")
                    .unwrap_or(false);
                if !connected {
                    host::error("exlap-hook: ExlapConnectionReturn connected=false");
                    s.phase = Phase::Failed;
                    push_connection_state(s);
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
                host::info(&format!(
                    "exlap-hook: ignoring ExlapStatement session_id={:?} (ours={:?})",
                    sid, our_sid
                ));
                return;
            }
            advance_statement(xml);
        }
        other => {
            host::info(&format!("exlap-hook: unknown root element <{}>", other));
        }
    }
}

fn advance_statement(xml: &str) {
    let phase = with_state(|s| s.phase.clone());

    match phase {
        Phase::WaitInit => {
            if xml.contains("<Init") {
                host::info("exlap-hook: got <Init>; sending Protocol request");
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
                        "exlap-hook: got <Capabilities>; sending auth challenge \
                         cred={} user=\"{}\"",
                        s.cred_idx,
                        s.user()
                    ));
                    let req = s.make_req(r#"<Authenticate phase="challenge" useHash="sha256"/>"#);
                    let pkt = s.make_pkt(&req);
                    s.phase = Phase::WaitAuthChallenge;
                    host::send(&pkt);
                });
            }
        }
        Phase::WaitAuthChallenge => {
            if let Some(nonce_b64) = xml_attr_in_tag(xml, "Challenge", "nonce") {
                host::info(&format!(
                    "exlap-hook: got auth challenge (nonce=\"{}\")",
                    nonce_b64
                ));
                with_state(|s| {
                    match compute_auth_response(&nonce_b64, s.user(), s.password()) {
                        Ok((cnonce_b64, digest_b64)) => {
                            host::info(&format!(
                                "exlap-hook: sending auth response user=\"{}\"",
                                s.user()
                            ));
                            let body = format!(
                                r#"<Authenticate phase="response" user="{}" cnonce="{}" digest="{}"/>"#,
                                s.user(), cnonce_b64, digest_b64
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
            } else if xml.contains("<Challenge") {
                host::error("exlap-hook: <Challenge> element has no nonce attribute");
            }
        }
        Phase::WaitAuthResponse => {
            if xml.contains("<Rsp") {
                let inner = extract_rsp_inner(xml);
                let empty = inner.map(|s| !s.trim().contains('<')).unwrap_or(true);
                if empty {
                    with_state(|s| {
                        host::info(&format!(
                            "exlap-hook: authenticated with cred={} user=\"{}\"",
                            s.cred_idx,
                            s.user()
                        ));
                        let req = s.make_req("<Dir/>");
                        let pkt = s.make_pkt(&req);
                        s.phase = Phase::WaitUrlList;
                        push_connection_state(s);
                        host::send(&pkt);
                    });
                } else {
                    let rsp_content = inner.unwrap_or("").trim().to_string();
                    with_state(|s| {
                        host::info(&format!(
                            "exlap-hook: auth failed cred={} user=\"{}\" rsp={:?}",
                            s.cred_idx,
                            s.user(),
                            rsp_content
                        ));
                        let next = s.cred_idx + 1;
                        if next < CREDENTIALS.len() {
                            host::info(&format!(
                                "exlap-hook: trying cred={} user=\"{}\"",
                                next, CREDENTIALS[next].0
                            ));
                            s.cred_idx = next;
                            let req = s.make_req(
                                r#"<Authenticate phase="challenge" useHash="sha256"/>"#,
                            );
                            let pkt = s.make_pkt(&req);
                            s.phase = Phase::WaitAuthChallenge;
                            host::send(&pkt);
                        } else {
                            host::error(
                                "exlap-hook: all credentials exhausted; ExLAP auth failed",
                            );
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
                    host::info(&format!(
                        "exlap-hook: HU exposes {} URLs:",
                        urls.len()
                    ));
                    for entry in &urls {
                        let url = entry.get("url").and_then(|v| v.as_str()).unwrap_or("?");
                        let typ = entry.get("url_type").and_then(|v| v.as_str()).unwrap_or("?");
                        host::info(&format!("exlap-hook:   {} ({})", url, typ));
                    }

                    let snapshot = serde_json::json!({
                        "connection_state": "active",
                        "subscription_limit_reached": false,
                        "urls": urls,
                        "values": {},
                    });
                    host::send_ws_event("exlap", &snapshot.to_string());

                    s.phase = Phase::Active;
                    s.subscription_limit_reached = false;

                    // Auto-subscribe to configured URLs.
                    let sub_urls = s.subscribe_urls.clone();
                    for url in &sub_urls {
                        let available = urls.iter().any(|e| {
                            e.get("url").and_then(|v| v.as_str()) == Some(url.as_str())
                        });
                        if available {
                            host::info(&format!("exlap-hook: subscribing to {}", url));
                            let body =
                                format!(r#"<Subscribe url="{}" timeStamp="true"/>"#, url);
                            let req = s.make_req(&body);
                            host::send(&s.make_pkt(&req));
                        } else {
                            host::info(&format!(
                                "exlap-hook: configured URL \"{}\" not in HU list, skipping",
                                url
                            ));
                        }
                    }
                });
            }
        }
        Phase::Active => {
            if xml.contains("<Rsp") {
                if let Some(status) = xml_attr_in_tag(xml, "Rsp", "status") {
                    match status.as_str() {
                        "subscriptionLimitReached" => {
                            host::info("exlap-hook: HU subscription limit reached");
                            with_state(|s| {
                                s.subscription_limit_reached = true;
                                push_connection_state(s);
                            });
                        }
                        "noMatchingUrl" => {
                            host::info("exlap-hook: HU returned noMatchingUrl");
                        }
                        other => {
                            host::info(&format!("exlap-hook: Rsp status={:?}", other));
                        }
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
    let event = serde_json::json!({
        "connection_state": phase_str(&s.phase),
        "subscription_limit_reached": s.subscription_limit_reached,
    });
    host::send_ws_event("exlap", &event.to_string());
}

fn phase_str(phase: &Phase) -> &'static str {
    match phase {
        Phase::Active => "active",
        Phase::Failed => "failed",
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

                        if state != "nodata" && state != "error" {
                            if let (Some(url), Ok(v)) =
                                (current_url.as_deref(), val.parse::<f32>())
                            {
                                match url {
                                    "tankLevelSecondary" => {
                                        host::info(&format!(
                                            "exlap-hook: tankLevelSecondary={}%",
                                            v
                                        ));
                                        with_state(|s| s.tank_level = Some(v));
                                        ev_updated = true;
                                    }
                                    "outsideTemperature" => {
                                        host::info(&format!(
                                            "exlap-hook: outsideTemperature={}°C",
                                            v
                                        ));
                                        with_state(|s| s.outside_temp = Some(v));
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
        let (tank, temp) = with_state(|s| (s.tank_level, s.outside_temp));
        let body = serde_json::json!({
            "battery_level_percentage": tank,
            "external_temp_celsius": temp,
        });
        let result = host::rest_call("POST", "/battery", &body.to_string());
        if !result.contains("\"ok\":true") {
            host::error(&format!("exlap-hook: POST /battery failed: {}", result));
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

// ── Channel open helpers ──────────────────────────────────────────────────────

/// Build a CHANNEL_OPEN_REQUEST packet for the given channel and service_id.
fn build_chan_open_request(channel: u8, service_id: i32) -> Packet {
    // Protobuf ChannelOpenRequest { priority: sint32 = 0, service_id: int32 = X }
    // Field 1 (priority, sint32 zigzag): tag=0x08, zigzag(0)=0x00
    // Field 2 (service_id, int32):       tag=0x10, varint(service_id)
    let mut payload = vec![
        (MSG_CHANNEL_OPEN_REQUEST >> 8) as u8,
        (MSG_CHANNEL_OPEN_REQUEST & 0xFF) as u8,
        0x08, 0x00, // priority = 0
        0x10,       // field 2 tag
    ];
    encode_varint(service_id as u64, &mut payload);

    Packet {
        proxy_type: ProxyType::MobileDevice,
        channel,
        packet_flags: ENCRYPTED | CONTROL_FLAG | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
        final_length: None,
        message_id: MSG_CHANNEL_OPEN_REQUEST,
        payload,
    }
}

/// Parse a ServiceDiscoveryResponse protobuf and return the service id of the
/// ExLAP VendorExtensionService, if present.
fn find_exlap_service_id(data: &[u8]) -> Option<i32> {
    let mut pos = 0;
    while pos < data.len() {
        let (tag, n) = read_varint(data, pos)?;
        pos += n;
        let field = (tag >> 3) as u32;
        let wire = (tag & 0x7) as u8;
        match (field, wire) {
            (1, 2) => {
                // services: repeated Service
                let (len, n) = read_varint(data, pos)?;
                pos += n;
                let end = pos + len as usize;
                if end > data.len() {
                    return None;
                }
                if let Some(id) = parse_service_for_exlap(&data[pos..end]) {
                    return Some(id);
                }
                pos = end;
            }
            (_, 2) => {
                let (len, n) = read_varint(data, pos)?;
                pos += n + len as usize;
            }
            (_, 0) => {
                let (_, n) = read_varint(data, pos)?;
                pos += n;
            }
            (_, 5) => pos += 4,
            (_, 1) => pos += 8,
            _ => return None,
        }
    }
    None
}

/// Parse a Service protobuf message, returning its `id` if it has a
/// VendorExtensionService with service_name == EXLAP_SERVICE_NAME.
fn parse_service_for_exlap(data: &[u8]) -> Option<i32> {
    let mut pos = 0;
    let mut id: Option<i32> = None;
    let mut is_exlap = false;

    while pos < data.len() {
        let (tag, n) = read_varint(data, pos)?;
        pos += n;
        let field = (tag >> 3) as u32;
        let wire = (tag & 0x7) as u8;
        match (field, wire) {
            (1, 0) => {
                let (v, n) = read_varint(data, pos)?;
                pos += n;
                id = Some(v as i32);
            }
            (12, 2) => {
                let (len, n) = read_varint(data, pos)?;
                pos += n;
                let end = pos + len as usize;
                if end > data.len() {
                    return None;
                }
                if is_exlap_vendor_service(&data[pos..end]) {
                    is_exlap = true;
                }
                pos = end;
            }
            (_, 2) => {
                let (len, n) = read_varint(data, pos)?;
                pos += n + len as usize;
            }
            (_, 0) => {
                let (_, n) = read_varint(data, pos)?;
                pos += n;
            }
            (_, 5) => pos += 4,
            (_, 1) => pos += 8,
            _ => return None,
        }
    }

    if is_exlap { id } else { None }
}

/// Return true if this VendorExtensionService protobuf has
/// service_name == EXLAP_SERVICE_NAME.
fn is_exlap_vendor_service(data: &[u8]) -> bool {
    let mut pos = 0;
    while pos < data.len() {
        let Some((tag, n)) = read_varint(data, pos) else {
            return false;
        };
        pos += n;
        let field = (tag >> 3) as u32;
        let wire = (tag & 0x7) as u8;
        match (field, wire) {
            (1, 2) => {
                let Some((len, n)) = read_varint(data, pos) else {
                    return false;
                };
                pos += n;
                let end = pos + len as usize;
                if end > data.len() {
                    return false;
                }
                if let Ok(name) = std::str::from_utf8(&data[pos..end]) {
                    if name == EXLAP_SERVICE_NAME {
                        return true;
                    }
                }
                pos = end;
            }
            (_, 2) => {
                let Some((len, n)) = read_varint(data, pos) else {
                    return false;
                };
                pos += n + len as usize;
            }
            (_, 0) => {
                let Some((_, n)) = read_varint(data, pos) else {
                    return false;
                };
                pos += n;
            }
            (_, 5) => pos += 4,
            (_, 1) => pos += 8,
            _ => return false,
        }
    }
    false
}

/// Decode a protobuf varint from `data[pos..]`. Returns `(value, bytes_consumed)`.
fn read_varint(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    let mut n = 0usize;
    loop {
        let byte = *data.get(pos + n)?;
        n += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((result, n));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

/// Append `v` as a protobuf varint to `buf`.
fn encode_varint(mut v: u64, buf: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            buf.push(byte);
            return;
        }
        buf.push(byte | 0x80);
    }
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
        return None; // self-closing
    }
    let content_start = open_end + 1;
    let close = xml.find("</Rsp>")?;
    Some(&xml[content_start..close])
}
