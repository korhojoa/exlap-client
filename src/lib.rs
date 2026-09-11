//! An ExLAP hook for aa-proxy-rs.
//!
//! This plugin runs the ExLAP protocol against a VW, Audi, Skoda or Seat MIB2
//! head unit. It needs no change to aa-proxy-rs. It works on the Android Auto
//! vendor channel `com.vwag.infotainment.gal.exlap`.
//!
//! # This is a transport, not a protocol
//!
//! The session itself is the [`exlap`] crate. Its [`Machine`] holds the
//! handshake, the SHA-256 authentication, the request numbers, the `<Dat>`
//! parser, `<Call>`, `<Interface>`, and the answers to server pings. The same
//! [`Machine`] also runs over a TCP socket. This file adds only what the
//! Android Auto channel needs:
//!
//! * It learns the ExLAP channel from the head unit's ServiceDiscoveryResponse. It moves to that channel if an ExLAP frame comes on a different one.
//! * It does the `ExlapConnectionRequest` and `ExlapConnectionReturn` exchange. This exchange comes before the ExLAP `Init`. It wraps each message in `<ExlapStatement session_id="...">`. This wrapper lets several credentials share the one channel. `ExlapBeacon` retries a connection. `ExlapConnectionClosed` resets the channel.
//! * It reassembles the fragments. It sends a frame only while a packet passes to the head unit.
//! * It skips its own frames when they return to the hook. It reads `<Dat>` from any other ExLAP session on the channel.
//!
//! The hook brings up each credential as a separate session. Each credential
//! gives a different set of URLs, and the sets overlap. The first credential
//! that offers a URL subscribes to it. No URL is subscribed more than once.
//!
//! The hook sends the electric battery values (`tankLevelPrimary/level` and
//! `outsideTemperature`) to the aa-proxy-rs `/battery` endpoint.

#[allow(warnings)]
mod bindings;

use bindings::aa::packet::host;
use bindings::aa::packet::types::{
    ConfigView, CustomConfigEntry, CustomConfigSection, Decision, ModifyContext, Packet, ProxyType,
};
use bindings::Guest;

use exlap::{Dat, Entry, Event, Kind, Machine, Phase, Rate, Value};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

static DEBUG_LOG: AtomicBool = AtomicBool::new(false);

fn debug_log(msg: &str) {
    if DEBUG_LOG.load(Ordering::Relaxed) {
        host::info(msg);
    }
}

const DEFAULT_SUBSCRIBE_URLS: &str = "tankLevelPrimary,outsideTemperature";
/// Default credential bring-up order, the richest credential first. The first
/// credential here that offers a URL claims it (`exlap::divide`). A credential
/// can offer nothing new. That credential gets no URLs and sends no Subscribe.
/// It stays connected and answers the pings.
const DEFAULT_CREDS: &[usize] = &[2, 1, 3, 0];
/// Default subscription interval in milliseconds. The schema default when the
/// attribute is omitted is 0, every change, which floods the channel on a
/// CAN-rate signal; so every subscription states an interval.
const DEFAULT_IVAL_MS: u32 = 2000;

/// Server-heartbeat interval (seconds) requested on connect. ExLAP v1.3 allows
/// 0-60; 0 disables the heartbeat and lets the HU leak sessions across
/// reconnects. Keep nonzero so dead sessions get reaped; the Machine answers
/// the pings, so only a genuinely dead session is reaped.
const HEARTBEAT_IVAL_SECS: u8 = 10;

// -- Packet flags and message IDs (mirroring mitm.rs constants) ---------------

const ENCRYPTED: u8 = 1 << 3;
const FRAME_TYPE_FIRST: u8 = 1 << 0; // bit 0, matches mitm.rs
const FRAME_TYPE_LAST: u8 = 1 << 1; // bit 1, matches mitm.rs
const CONTROL_FLAG: u8 = 1 << 2;

const MSG_SERVICE_DISCOVERY_RESPONSE: u16 = 6;
const MSG_CHANNEL_OPEN_REQUEST: u16 = 7;
const MSG_CHANNEL_OPEN_RESPONSE: u16 = 8;

const EXLAP_SERVICE_NAME: &str = "com.vwag.infotainment.gal.exlap";

// -- Session state -------------------------------------------------------------

/// The Android-Auto-transport phase of one multiplexed session.
///
/// `Pending` and `WaitConnReturn` are BEFORE ExLAP's own `Init`. They are the
/// AA connection handshake that the socket transport does not have. Once the HU
/// answers `ExlapConnectionReturn connected="true"`, an [`exlap::Machine`]
/// takes over and its own [`Phase`] tracks the rest.
enum SessionState {
    /// Not started; waiting for its turn to send `ExlapConnectionRequest`.
    Pending,
    /// `ExlapConnectionRequest` sent; waiting for `ExlapConnectionReturn`.
    WaitConnReturn,
    /// Connected. The Machine drives the session from `Init` onward.
    Running(Machine),
    /// Authentication failed for this credential; do not retry it this cycle.
    Failed,
}

/// One multiplexed ExLAP connection for a single credential (`exlap::USERS[idx]`,
/// where idx is this session's position in `ExlapState::sessions`).
struct Session {
    state: SessionState,
    /// Random hex session ID; empty until this session is started.
    session_id: String,
    /// True once this session has issued its `<Subscribe>` batch.
    subscribed: bool,
    /// Whether the HU reported `subscriptionLimitReached` for this session.
    subscription_limit_reached: bool,
}

impl Session {
    fn pending() -> Self {
        Self {
            state: SessionState::Pending,
            session_id: String::new(),
            subscribed: false,
            subscription_limit_reached: false,
        }
    }

    fn machine(&mut self) -> Option<&mut Machine> {
        match &mut self.state {
            SessionState::Running(m) => Some(m),
            _ => None,
        }
    }

    /// The Machine's phase, or `None` when this session has no Machine yet.
    fn phase(&self) -> Option<Phase> {
        match &self.state {
            SessionState::Running(m) => Some(m.phase()),
            _ => None,
        }
    }

    /// True when the session is Running and its Machine is Ready (past the
    /// handshake and directory).
    fn is_active(&self) -> bool {
        self.phase() == Some(Phase::Ready)
    }
}

/// Wrap a Machine request body for transmission on the AA channel: every ExLAP
/// message a credential sends rides inside its own `<ExlapStatement>`.
fn wrap(session_id: &str, req: &str) -> String {
    format!(r#"<ExlapStatement session_id="{session_id}">{req}</ExlapStatement>"#)
}

/// The inner ExLAP message of an `<ExlapStatement>...</ExlapStatement>` wrapper,
/// or the whole string when it carries no wrapper (a bare `<Status>`). The
/// Machine reasons about the inner element's root tag, so it must never see the
/// wrapper.
fn unwrap_statement(xml: &str) -> &str {
    let Some(open) = xml.find("<ExlapStatement") else {
        return xml;
    };
    let Some(gt) = xml[open..].find('>').map(|i| open + i + 1) else {
        return xml;
    };
    match xml.rfind("</ExlapStatement>") {
        Some(close) if close >= gt => xml[gt..close].trim(),
        _ => xml[gt..].trim(),
    }
}

/// Channel-level state: the AA channel and all multiplexed ExLAP sessions
/// (one per credential) sharing it.
struct ExlapState {
    /// Which channel to intercept; overwritten from the SDR service_id on connect.
    exlap_channel: u8,
    /// True once we've sent the first ExlapConnectionRequest for this
    /// channel-open cycle. Gates the channel self-heal adoption below.
    connecting_started: bool,
    /// Fragment reassembly buffer.
    assemble_buf: Vec<u8>,
    /// Credential bring-up order (preference for `divide`). Sessions are indexed
    /// by their position here.
    creds: Vec<usize>,
    /// One session per credential, in `creds` order.
    sessions: Vec<Session>,
    /// URLs already subscribed by an earlier-up session this cycle. A later
    /// credential subscribes only to what is not yet claimed, the `divide`
    /// policy, applied incrementally as sessions come up in order.
    claimed: HashSet<String>,
    /// Last tankLevelPrimary/level value received, from any session.
    tank_level: Option<f32>,
    /// Last outsideTemperature value received, from any session.
    outside_temp: Option<f32>,
    /// Total battery capacity in Wh (from config), sent with every /battery POST.
    battery_capacity_wh: Option<u64>,
    /// URLs to auto-subscribe to, or a single `*` for everything (configurable).
    subscribe_urls: Vec<String>,
    /// Subscription interval in milliseconds for every auto-subscription.
    subscribe_ival_ms: u32,
    /// Last received value per URL (url -> {fields, ...}), across all sessions.
    current_values: HashMap<String, serde_json::Value>,
    /// Frames queued for transmission toward the HU. host::send routes to the
    /// *current* proxy task's endpoint, and only the MD task reaches the HU, so
    /// we cannot send directly from the (HU-originated) packets that drive the
    /// state machine. Instead we enqueue here and flush from a dir=MD invocation.
    outbound: Vec<Packet>,
    /// XML payloads we recently emitted, so we can recognise and skip our own
    /// frames when they re-enter the hook after being sent (Forward re-traversal).
    recently_sent: Vec<String>,
}

impl ExlapState {
    fn new(exlap_channel: u8, creds: Vec<usize>, subscribe_urls: Vec<String>, ival: u32) -> Self {
        let sessions = creds.iter().map(|_| Session::pending()).collect();
        Self {
            exlap_channel,
            connecting_started: false,
            assemble_buf: Vec::new(),
            creds,
            sessions,
            claimed: HashSet::new(),
            tank_level: None,
            outside_temp: None,
            battery_capacity_wh: None,
            subscribe_urls,
            subscribe_ival_ms: ival,
            current_values: HashMap::new(),
            outbound: Vec::new(),
            recently_sent: Vec::new(),
        }
    }

    /// The credential index for session slot `idx`.
    fn cred(&self, idx: usize) -> usize {
        self.creds[idx]
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

    /// Queue an ExLAP XML frame for transmission toward the HU. See `outbound`.
    /// Records the payload so the frame is skipped when it re-enters the hook.
    fn send_xml(&mut self, xml: &str) {
        let pkt = self.make_pkt(xml);
        self.recently_sent.push(xml.to_string());
        if self.recently_sent.len() > 16 {
            self.recently_sent.remove(0);
        }
        self.outbound.push(pkt);
    }

    /// Flush a Machine's queued requests toward the HU, each wrapped in this
    /// session's `<ExlapStatement>`.
    fn flush_machine(&mut self, idx: usize) {
        let sid = self.sessions[idx].session_id.clone();
        let reqs = match self.sessions[idx].machine() {
            Some(m) => m.take_outbound(),
            None => return,
        };
        for req in reqs {
            let framed = wrap(&sid, &req);
            self.send_xml(&framed);
        }
    }
}

/// Start the next pending credential session, if nothing is already
/// mid-handshake and any remain. Only one `ExlapConnectionRequest` is ever
/// outstanding at a time, since `ExlapConnectionReturn` carries no `session_id`
/// to demux by. Safe to call unconditionally (e.g. on every ExlapBeacon): a
/// no-op unless there is a Pending session and nothing currently WaitConnReturn.
fn try_start_next_session(s: &mut ExlapState) {
    if s.sessions.iter().any(|sess| matches!(sess.state, SessionState::WaitConnReturn)) {
        return; // an attempt is already in flight
    }
    let Some(idx) = s
        .sessions
        .iter()
        .position(|sess| matches!(sess.state, SessionState::Pending))
    else {
        return; // nothing left to start
    };
    s.connecting_started = true;
    s.sessions[idx].session_id = make_session_id();
    s.sessions[idx].state = SessionState::WaitConnReturn;
    debug_log(&format!(
        "exlap-hook: starting session cred={} user=\"{}\" session_id={}",
        s.cred(idx),
        exlap::USERS[s.cred(idx)],
        s.sessions[idx].session_id
    ));
    let xml = format!(
        r#"<ExlapConnectionRequest session_id="{}"/>"#,
        s.sessions[idx].session_id
    );
    s.send_xml(&xml);
}

/// Generate a 16-byte random session ID as a lowercase hex string.
fn make_session_id() -> String {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).unwrap_or(());
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

/// A fresh 16-byte client nonce, base64-encoded, what `Machine::with_cnonce`
/// wants. WASI has no `/dev/urandom`, so the Machine's own source cannot be
/// used here; this is `random_get` through getrandom.
fn make_cnonce() -> String {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).unwrap_or(());
    b64(&buf)
}

/// Standard padded base64, for the client nonce only.
fn b64(input: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(A[((n >> 18) & 63) as usize] as char);
        out.push(A[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { A[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { A[(n & 63) as usize] as char } else { '=' });
    }
    out
}

/// A new Machine for a credential: the shared session core, told to ask for a
/// server heartbeat and to take its client nonce from WASI.
fn new_machine(cred: usize) -> Machine {
    Machine::new(cred)
        .with_server_heartbeat(HEARTBEAT_IVAL_SECS)
        .with_cnonce(make_cnonce)
        // Keep the timestamps the pre-crate hook asked for. What the head
        // unit's wall clock actually reads here is not yet characterised, so
        // the value is passed through to the web UI as-is, not interpreted.
        .with_timestamps(true)
}

/// Parse a comma-separated URL list from config.
fn parse_subscribe_urls(s: &str) -> Vec<String> {
    s.split(',').map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).collect()
}

/// Parse a comma-separated credential index list; falls back to the default.
fn parse_creds(s: &str) -> Vec<usize> {
    let v: Vec<usize> = s
        .split(',')
        .filter_map(|u| u.trim().parse::<usize>().ok())
        .filter(|&i| i < exlap::USERS.len())
        .collect();
    if v.is_empty() {
        DEFAULT_CREDS.to_vec()
    } else {
        v
    }
}

// -- Global state (single-threaded WASM) --------------------------------------

static STATE: OnceLock<Mutex<ExlapState>> = OnceLock::new();

fn with_state<R>(f: impl FnOnce(&mut ExlapState) -> R) -> R {
    let mutex = STATE.get().expect("STATE not initialized");
    let mut guard = mutex.lock().expect("STATE lock poisoned");
    f(&mut guard)
}

// -- WIT bindings export -------------------------------------------------------

struct ExlapHook;

impl Guest for ExlapHook {
    fn on_create() {
        let channel: u8 = host::get_config("exlap_channel")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0x7E);
        let creds = host::get_config("exlap_creds")
            .map(|s| parse_creds(&s))
            .unwrap_or_else(|| DEFAULT_CREDS.to_vec());
        let subscribe_urls = parse_subscribe_urls(
            &host::get_config("exlap_subscribe_urls")
                .unwrap_or_else(|| DEFAULT_SUBSCRIBE_URLS.to_string()),
        );
        let ival = host::get_config("exlap_subscribe_ival_ms")
            .and_then(|s| s.parse().ok())
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_IVAL_MS);

        let battery_capacity_wh: Option<u64> = host::get_config("exlap_battery_capacity_wh")
            .and_then(|s| s.parse().ok())
            .filter(|&v| v > 0);

        let debug = host::get_config("exlap_debug")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        DEBUG_LOG.store(debug, Ordering::Relaxed);

        debug_log(&format!(
            "exlap-hook: created channel={:#04x} creds={:?} subscribe_urls={:?} ival={}ms battery_capacity_wh={:?}",
            channel, creds, subscribe_urls, ival, battery_capacity_wh
        ));

        let mut state = ExlapState::new(channel, creds, subscribe_urls, ival);
        state.battery_capacity_wh = battery_capacity_wh;
        STATE.set(Mutex::new(state)).ok();
    }

    fn on_destroy() {
        // Send <Bye/> on every still-connected session so the HU cleans them up
        // (spec section 3.5.8: client SHOULD send Bye).
        with_state(|s| {
            for idx in 0..s.sessions.len() {
                if let Some(m) = s.sessions[idx].machine() {
                    m.bye();
                }
                s.flush_machine(idx);
            }
            // Bye goes out directly here (on_destroy has no dir=MD carrier).
            let pkts = std::mem::take(&mut s.outbound);
            for p in &pkts {
                host::send(p);
            }
        });
        debug_log("exlap-hook: destroyed");
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
                    name: "exlap_creds".to_string(),
                    typ: "string".to_string(),
                    description:
                        "Comma-separated credential indices (0-3) to bring up, in preference \
                         order, a URL is subscribed by the first credential here that offers \
                         it. Default: 2,1,3,0."
                            .to_string(),
                    default_value: "2,1,3,0".to_string(),
                    values: None,
                },
                CustomConfigEntry {
                    name: "exlap_subscribe_urls".to_string(),
                    typ: "string".to_string(),
                    description: format!(
                        "Comma-separated ExLAP URLs to subscribe to, or \"*\" to subscribe \
                         to every URL the credentials expose (deduplicated across them). \
                         tankLevelPrimary/level and outsideTemperature also feed POST /battery. \
                         Default: {DEFAULT_SUBSCRIBE_URLS}"
                    ),
                    default_value: DEFAULT_SUBSCRIBE_URLS.to_string(),
                    values: None,
                },
                CustomConfigEntry {
                    name: "exlap_subscribe_ival_ms".to_string(),
                    typ: "u32".to_string(),
                    description:
                        "Minimum interval between pushes for each subscription, milliseconds. \
                         0 in the protocol means every change, which floods the channel, so \
                         a nonzero default is used. Default: 2000."
                            .to_string(),
                    default_value: "2000".to_string(),
                    values: None,
                },
                CustomConfigEntry {
                    name: "exlap_debug".to_string(),
                    typ: "bool".to_string(),
                    description: "Enable verbose debug logging for the ExLAP hook (default false)"
                        .to_string(),
                    default_value: "false".to_string(),
                    values: None,
                },
                CustomConfigEntry {
                    name: "exlap_battery_capacity_wh".to_string(),
                    typ: "u64".to_string(),
                    description: "Total battery/tank capacity in Wh. \
                        Sent as battery_capacity_wh with every POST /battery so aa-proxy-rs \
                        can compute the correct energy level from the percentage. \
                        Example: 58000 for a 58 kWh battery. Leave 0 to use the model default."
                        .to_string(),
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
                    debug_log(&format!("exlap-hook: exlap_channel -> {:#04x}", ch));
                }
            }
            "exlap_creds" => {
                let creds = parse_creds(&value);
                debug_log(&format!("exlap-hook: exlap_creds -> {:?} (applies next reconnect)", creds));
                s.creds = creds;
            }
            "exlap_subscribe_urls" => {
                let urls = parse_subscribe_urls(&value);
                debug_log(&format!("exlap-hook: exlap_subscribe_urls -> {:?}", urls));
                s.subscribe_urls = urls;
            }
            "exlap_subscribe_ival_ms" => {
                if let Some(v) = value.parse::<u32>().ok().filter(|&v| v > 0) {
                    s.subscribe_ival_ms = v;
                    debug_log(&format!("exlap-hook: exlap_subscribe_ival_ms -> {}", v));
                }
            }
            "exlap_battery_capacity_wh" => {
                let cap = value.parse::<u64>().ok().filter(|&v| v > 0);
                s.battery_capacity_wh = cap;
                debug_log(&format!("exlap-hook: exlap_battery_capacity_wh -> {:?}", cap));
            }
            "exlap_debug" => {
                let enabled = value == "true" || value == "1";
                DEBUG_LOG.store(enabled, Ordering::Relaxed);
                host::info(&format!("exlap-hook: exlap_debug -> {}", enabled));
            }
            _ => {}
        });
    }

    fn modify_packet(_ctx: ModifyContext, pkt: Packet, _cfg: ConfigView) -> Decision {
        // Flush any queued ExLAP frames toward the HU. host::send routes to the
        // current proxy task's endpoint, and only the MD task (dir=MD) reaches
        // the HU, so we can only emit during a dir=MD invocation. Any dir=MD
        // packet is a usable carrier (phone->HU video is a constant stream), so
        // flush latency is negligible. Done before the channel filter on purpose.
        if pkt.proxy_type == ProxyType::MobileDevice {
            flush_outbound();
        }

        // Intercept the HU's ServiceDiscoveryResponse so we can learn the ExLAP
        // channel, no host-side ExLAP code required.
        if pkt.proxy_type == ProxyType::HeadUnit
            && pkt.channel == 0
            && pkt.message_id == MSG_SERVICE_DISCOVERY_RESPONSE
        {
            handle_sdr(&pkt);
            return Decision::Forward; // Other hooks/handlers still need the SDR.
        }

        // Self-heal the ExLAP channel. The channel is normally learned from the
        // SDR, but a mid-session hot-reload (or a missed SDR) leaves the hook on
        // the config default and deaf to the real ExLAP channel. ExLAP frames are
        // plain "<Exlap..." XML, so if we see one on a channel we aren't tracking
        // and we haven't started connecting yet, adopt that channel. Cheap prefix
        // check on data frames only; gated so we never hijack a live session.
        if pkt.channel != 0
            && (pkt.packet_flags & CONTROL_FLAG) == 0
            && pkt.payload.starts_with(b"<Exlap")
        {
            with_state(|s| {
                if !s.connecting_started && s.exlap_channel != pkt.channel {
                    host::info(&format!(
                        "exlap-hook: adopting ExLAP channel {:#04x} from observed ExLAP frame",
                        pkt.channel
                    ));
                    s.exlap_channel = pkt.channel;
                }
            });
        }

        let channel = with_state(|s| s.exlap_channel);
        if pkt.channel != channel {
            return Decision::Forward;
        }

        process_packet(pkt);
        // NEVER return Decision::Drop here. In this host build a wasm "Drop" is
        // not a discard: run_wasm_hooks maps it to PacketAction::SendBack, which
        // re-queues the packet into the *other* proxy task's rx arm, where this
        // same hook runs again and drops it again, forever (confirmed upstream: a
        // single injected CHANNEL_OPEN_REQUEST ping-ponged the two tasks in a
        // tight busy-loop, starving the shared proxy task and stalling video).
        // Forward terminates (encrypt + transmit), so every packet passes through
        // the hook a bounded number of times. We consume purely via side-effects.
        Decision::Forward
    }

    fn ws_script_handler(topic: String, payload: String) -> String {
        if topic != "exlap-hook" {
            return String::new();
        }

        let Ok(val) = serde_json::from_str::<serde_json::Value>(&payload) else {
            return "error: invalid JSON".to_string();
        };

        let cmd = val.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
        let url = || val.get("url").and_then(|v| v.as_str()).map(|u| u.to_string());

        match cmd {
            "subscribe" => {
                let Some(u) = url() else { return "error: missing url".to_string() };
                with_state(|s| {
                    let ival = s.subscribe_ival_ms;
                    broadcast(s, "subscribe", &u, |m| {
                        m.subscribe_one(&u, ival);
                    })
                })
            }
            "unsubscribe" => {
                let Some(u) = url() else { return "error: missing url".to_string() };
                with_state(|s| broadcast(s, "unsubscribe", &u, |m| {
                    m.request(&format!(r#"<Unsubscribe url="{}"/>"#, exlap::escape_attr(&u)));
                }))
            }
            "get" => {
                let Some(u) = url() else { return "error: missing url".to_string() };
                with_state(|s| broadcast(s, "get", &u, |m| {
                    m.request(&format!(r#"<Get url="{}" timeStamp="true"/>"#, exlap::escape_attr(&u)));
                }))
            }
            "call" => {
                // A function call: {cmd:"call", url:"Sound_Mute", params:[{kind,name,val}]}
                let Some(u) = url() else { return "error: missing url".to_string() };
                let params = parse_params(val.get("params"));
                let body = exlap::call(&u, &params);
                with_state(|s| broadcast(s, "call", &u, |m| {
                    m.request(&body);
                }))
            }
            "interface" => {
                let Some(u) = url() else { return "error: missing url".to_string() };
                let body = exlap::interface(&u);
                with_state(|s| broadcast(s, "interface", &u, |m| {
                    m.request(&body);
                }))
            }
            "list" => with_state(|s| {
                let sessions: Vec<_> = (0..s.sessions.len())
                    .map(|idx| {
                        let cred = s.cred(idx);
                        let urls = url_list_json(&s.sessions[idx]);
                        serde_json::json!({
                            "cred_idx": cred,
                            "user": exlap::USERS[cred],
                            "connection_state": conn_state(&s.sessions[idx]),
                            "subscription_limit_reached": s.sessions[idx].subscription_limit_reached,
                            "urls": urls,
                        })
                    })
                    .collect();
                let snapshot = serde_json::json!({ "sessions": sessions });
                host::send_ws_event("exlap", &snapshot.to_string());
                "ok".to_string()
            }),
            "values" => with_state(|s| {
                let snapshot = serde_json::json!({ "current_values": s.current_values });
                host::send_ws_event("exlap", &snapshot.to_string());
                "ok".to_string()
            }),
            _ => format!("error: unknown cmd {:?}", cmd),
        }
    }
}

bindings::export!(ExlapHook with_types_in bindings);

/// Run `f` on every Running session's Machine, flush each, and report how many
/// answered. The HU replies `noMatchingUrl` on a session that lacks the url, so
/// this is safe even if only some credentials expose it.
fn broadcast(
    s: &mut ExlapState,
    verb: &str,
    url: &str,
    mut f: impl FnMut(&mut Machine),
) -> String {
    let running: Vec<usize> =
        (0..s.sessions.len()).filter(|&i| s.sessions[i].is_active()).collect();
    if running.is_empty() {
        return "error: no active sessions".to_string();
    }
    for idx in &running {
        if let Some(m) = s.sessions[*idx].machine() {
            f(m);
        }
        s.flush_machine(*idx);
    }
    debug_log(&format!("exlap-hook: ws {verb} -> {url} ({} sessions)", running.len()));
    "ok".to_string()
}

/// Parse `params` from a ws `call` command into ExLAP value elements.
/// Each is `{"kind":"Enm","name":"Source","val":"HDD"}`; kind defaults to Txt.
fn parse_params(v: Option<&serde_json::Value>) -> Vec<Value> {
    let Some(arr) = v.and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|p| {
            let name = p.get("name").and_then(|v| v.as_str())?.to_string();
            let raw = p.get("val").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let kind = match p.get("kind").and_then(|v| v.as_str()).unwrap_or("Txt") {
                "Abs" => Kind::Abs,
                "Rel" => Kind::Rel,
                "Act" => Kind::Act,
                "Enm" => Kind::Enm,
                _ => Kind::Txt,
            };
            Some(Value { kind, name, raw })
        })
        .collect()
}

// -- Packet processing ---------------------------------------------------------

fn dir_str(pt: ProxyType) -> &'static str {
    match pt {
        ProxyType::HeadUnit => "HU",
        ProxyType::MobileDevice => "MD",
    }
}

fn process_packet(pkt: Packet) {
    let is_control = (pkt.packet_flags & CONTROL_FLAG) != 0;
    let dir = dir_str(pkt.proxy_type);

    if is_control {
        let msg_id = pkt
            .payload
            .get(0..2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .unwrap_or(0);
        debug_log(&format!("exlap-hook: ch pkt dir={} CONTROL msg_id={:#06x}", dir, msg_id));
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
        let result = std::str::from_utf8(&s.assemble_buf).map(|x| x.to_owned()).ok();
        s.assemble_buf.clear();
        result
    });

    let Some(xml) = xml else {
        host::error("exlap-hook: invalid UTF-8 in packet");
        return;
    };

    // A frame we ourselves emitted, re-entering after host::send + Forward
    // re-traversal. Skip it so we don't parse our own requests as responses.
    let is_echo = with_state(|s| s.recently_sent.iter().any(|p| p.as_str() == xml.as_str()));
    if is_echo {
        debug_log(&format!(
            "exlap-hook: ch DATA dir={} (our own frame echoed back, skipped): {}",
            dir,
            truncate_xml(&xml, 160)
        ));
        return;
    }

    // Only drive the state machine from HU-originated frames. Every HU response
    // is seen twice: once as dir=HU (ingress from the HU) and again as dir=MD
    // when we Forward that same frame on toward the phone. Real ExLAP responses
    // are always dir=HU (the HU is the server), so ignore the dir=MD duplicates.
    if pkt.proxy_type != ProxyType::HeadUnit {
        debug_log(&format!(
            "exlap-hook: ch DATA dir={} (forwarded HU->phone duplicate, not acted on): {}",
            dir,
            truncate_xml(&xml, 120)
        ));
        return;
    }

    debug_log(&format!("exlap-hook: ch DATA dir={} xml: {}", dir, truncate_xml(&xml, 480)));
    handle_xml(&xml);
}

/// Truncate a string to at most `n` characters for logging (ExLAP XML is ASCII).
fn truncate_xml(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let head: String = s.chars().take(n).collect();
        format!("{}...(+{} chars)", head, s.chars().count() - n)
    }
}

/// Flush queued outbound ExLAP frames toward the HU. MUST only be called from a
/// dir=MD invocation (see `outbound` / `modify_packet`).
fn flush_outbound() {
    let pkts = with_state(|s| std::mem::take(&mut s.outbound));
    if pkts.is_empty() {
        return;
    }
    debug_log(&format!("exlap-hook: flushing {} queued frame(s) -> HU", pkts.len()));
    for p in &pkts {
        host::send(p);
    }
}

/// Handle a control-flag packet on the ExLAP channel.
fn handle_control(pkt: &Packet) {
    if pkt.payload.len() < 2 {
        return;
    }
    let msg_id = u16::from_be_bytes([pkt.payload[0], pkt.payload[1]]);

    if msg_id != MSG_CHANNEL_OPEN_RESPONSE {
        debug_log(&format!(
            "exlap-hook: control msg_id={:#06x} dir={} on ExLAP channel (forwarded, not consumed)",
            msg_id,
            dir_str(pkt.proxy_type)
        ));
        return;
    }

    // Parse ChannelOpenResponse status (field 1, varint). STATUS_OK = 0.
    let status = if pkt.payload.len() >= 4 && pkt.payload[2] == 0x08 {
        pkt.payload[3] as i32
    } else {
        0 // field absent -> default STATUS_OK
    };

    with_state(|s| {
        if s.connecting_started {
            debug_log(&format!(
                "exlap-hook: unexpected CHANNEL_OPEN_RESPONSE (already connecting, status={})",
                status
            ));
            return;
        }

        if status != 0 {
            host::error(&format!(
                "exlap-hook: CHANNEL_OPEN_RESPONSE status={} on ch={:#04x}; \
                 channel open may have failed",
                status, s.exlap_channel
            ));
            // Proceed anyway, some HUs return non-zero but still open the channel.
        }

        debug_log(&format!(
            "exlap-hook: channel {:#04x} open (status={}); bringing up {} credential sessions",
            s.exlap_channel,
            status,
            s.sessions.len()
        ));
        try_start_next_session(s);
    });
}

/// Intercept the HU's ServiceDiscoveryResponse, find the ExLAP vendor service,
/// and learn its channel. Resets state on every SDR to handle reconnections
/// cleanly.
fn handle_sdr(pkt: &Packet) {
    if pkt.payload.len() < 2 {
        return;
    }
    // Payload is [msg_id_hi, msg_id_lo, ...protobuf SDR bytes...].
    let proto = &pkt.payload[2..];

    match find_exlap_service_id(proto) {
        None => {
            debug_log("exlap-hook: SDR received,ExLAP service not found");
        }
        Some(service_id) => {
            let channel = service_id as u8;
            with_state(|s| {
                // Reset on every SDR, handles phone reconnections gracefully.
                // Preserve the config: creds, subscribe_urls, ival, capacity.
                let creds = s.creds.clone();
                let subscribe_urls = std::mem::take(&mut s.subscribe_urls);
                let ival = s.subscribe_ival_ms;
                let battery_capacity_wh = s.battery_capacity_wh;
                *s = ExlapState::new(channel, creds, subscribe_urls, ival);
                s.battery_capacity_wh = battery_capacity_wh;

                // We do NOT open the channel ourselves: the phone (Gearhead)
                // opens every SDR-advertised service, including this one, and the
                // HU's CHANNEL_OPEN_RESPONSE to *that* is what drives us into
                // bringing up sessions (see handle_control).
                debug_log(&format!(
                    "exlap-hook: SDR found ExLAP service_id={} -> ch={:#04x}; \
                     waiting for phone to open the channel",
                    service_id, channel
                ));
            });
        }
    }
}

fn handle_xml(xml: &str) {
    let root = xml_root_tag(xml).unwrap_or_default();

    match root.as_str() {
        "ExlapBeacon" => {
            // The HU emits ExlapBeacon (~every 5s) to advertise that its ExLAP
            // server is up and accepting connections. Use it as the (re)connect
            // trigger/retry, try_start_next_session is a no-op unless there is
            // a Pending session and nothing already mid-handshake. This is the
            // recovery path for cases the CHANNEL_OPEN_RESPONSE trigger alone
            // cannot handle: a connect attempt that lost the race (HU's ExLAP
            // server wasn't ready and returned connected="false"), or a session
            // that needs retrying within the same AA session (no new
            // CHANNEL_OPEN_RESPONSE will arrive for an already-open channel).
            with_state(try_start_next_session);
        }
        "ExlapConnectionClosed" => {
            // Not part of the public EXLAP spec and carries no session_id, so its
            // scope is unclear. Treat it conservatively as closing the whole
            // multiplexed channel: reset every session and restart bring-up (the
            // AA channel itself stays open, so no need to wait for another SDR).
            debug_log("exlap-hook: HU closed ExLAP connection(s); restarting all sessions");
            with_state(|s| {
                reset_sessions(s);
                try_start_next_session(s);
            });
        }
        "ExlapConnectionReturn" => {
            with_state(|s| {
                let Some(idx) = s
                    .sessions
                    .iter()
                    .position(|sess| matches!(sess.state, SessionState::WaitConnReturn))
                else {
                    debug_log("exlap-hook: unexpected ExlapConnectionReturn (none awaiting one)");
                    return;
                };
                let connected = xml_attr_in_tag(xml, "ExlapConnectionReturn", "connected")
                    .map(|v| v == "true")
                    .unwrap_or(false);
                if !connected {
                    // The HU rejects the connection when its ExLAP/SAI server
                    // isn't ready yet (lost the startup race). Don't fail this
                    // credential permanently: reset it to Pending and let the
                    // next ExlapBeacon retry the connect.
                    host::error(&format!(
                        "exlap-hook: ExlapConnectionReturn connected=false for cred={}; \
                         retrying on next ExlapBeacon",
                        s.cred(idx)
                    ));
                    s.sessions[idx] = Session::pending();
                    return;
                }
                // Connected: the Machine takes over from ExLAP's own Init.
                debug_log(&format!(
                    "exlap-hook: ExLAP connection established for cred={}; waiting for Init",
                    s.cred(idx)
                ));
                let cred = s.cred(idx);
                let sid = s.sessions[idx].session_id.clone();
                s.sessions[idx].state = SessionState::Running(new_machine(cred));
                push_connection_state(s, idx);
                debug_log(&format!("exlap-hook: session_id={sid} now Running (awaiting Init)"));
            });
        }
        "ExlapStatement" => {
            let sid = xml_attr_in_tag(xml, "ExlapStatement", "session_id").unwrap_or_default();
            let idx = with_state(|s| {
                s.sessions.iter().position(|sess| sess.session_id == sid && !sid.is_empty())
            });
            let Some(idx) = idx else {
                // Not one of our sessions. <Dat> frames are self-describing (url +
                // fields + timestamp), so passively HARVEST measurements from any
                // other session on the channel: an orphaned session, or a
                // phone-side ExLAP client.
                debug_log(&format!("exlap-hook: harvesting Dat from foreign session_id={:?}", sid));
                harvest_foreign(xml);
                return;
            };
            feed_session(idx, unwrap_statement(xml));
        }
        // Bare <Status> elements (Init/Alive/Bye/Dataloss) sent outside an
        // ExlapStatement. These carry no session_id.
        "Status" => handle_status_element(xml),
        other => debug_log(&format!("exlap-hook: unknown root element <{}>", other)),
    }
}

/// A bare `<Status>...</Status>` (no session_id), ambiguous once several sessions
/// share the channel. Init belongs to whichever session is mid-handshake (only
/// one is, since bring-up is serial); Alive is answered for every running
/// session; Bye has no safe single target, so it resets everything.
fn handle_status_element(xml: &str) {
    if xml.contains("Alive") {
        with_state(|s| {
            for idx in 0..s.sessions.len() {
                if matches!(s.sessions[idx].state, SessionState::Running(_)) {
                    // Feeding the Status to the Machine makes it queue an <Alive/>.
                    let _ = feed_machine(s, idx, "<Status><Alive/></Status>");
                }
            }
            debug_log("exlap-hook: bare Alive ping -> answered for all running sessions");
        });
    } else if xml.contains("Bye") {
        debug_log("exlap-hook: HU sent bare Bye (no session_id); resetting all sessions");
        with_state(|s| {
            reset_sessions(s);
            try_start_next_session(s);
        });
    } else if xml.contains("Init") {
        // Route to the session whose Machine is still awaiting Init.
        with_state(|s| {
            let idx = (0..s.sessions.len())
                .find(|&i| s.sessions[i].phase() == Some(Phase::Init));
            let Some(idx) = idx else {
                debug_log("exlap-hook: bare Init with no session awaiting one (ignored)");
                return;
            };
            debug_log(&format!("exlap-hook: bare Init for cred={}", s.cred(idx)));
            let _ = feed_machine(s, idx, xml);
        });
    } else if xml.contains("Dataloss") {
        debug_log("exlap-hook: HU reported Dataloss on ExLAP channel");
    } else {
        debug_log(&format!("exlap-hook: unhandled Status element: {}", xml));
    }
}

/// Feed one unwrapped ExLAP message to session `idx`'s Machine and act on the
/// events it produces. `inner` is the content inside the `<ExlapStatement>` (or
/// a bare `<Status>`), never the wrapper.
fn feed_session(idx: usize, inner: &str) {
    with_state(|s| {
        let _ = feed_machine(s, idx, inner);
    });
}

/// Drive session `idx`'s Machine with `inner`, flush what it wants sent, and
/// handle the resulting events. Returns false if the session is not Running.
fn feed_machine(s: &mut ExlapState, idx: usize, inner: &str) -> bool {
    let events = match s.sessions[idx].machine() {
        Some(m) => match m.feed(inner) {
            Ok(ev) => ev,
            Err(e) => {
                host::error(&format!("exlap-hook: cred={} {}", s.cred(idx), e));
                s.sessions[idx].state = SessionState::Failed;
                push_connection_state(s, idx);
                s.flush_machine(idx);
                try_start_next_session(s);
                return true;
            }
        },
        None => return false,
    };
    // Whatever the Machine queued in response (Protocol, auth, Alive, ...).
    s.flush_machine(idx);

    for ev in events {
        match ev {
            Event::Authenticated => {
                debug_log(&format!("exlap-hook: authenticated cred={}", s.cred(idx)));
                push_connection_state(s, idx);
                // Ask the server what this credential exposes.
                if let Some(m) = s.sessions[idx].machine() {
                    if let Err(e) = m.read_directory() {
                        host::error(&format!("exlap-hook: read_directory cred={}: {e}", s.cred(idx)));
                    }
                }
                s.flush_machine(idx);
            }
            Event::Directory => {
                on_directory(s, idx);
            }
            Event::Data(dat) => {
                on_data(s, dat);
            }
            Event::Reply { id, xml } => {
                if let Some(status) = exlap::reply_status(&xml) {
                    match status.as_str() {
                        "subscriptionLimitReached" => {
                            debug_log(&format!("exlap-hook: cred={} subscription limit reached", s.cred(idx)));
                            s.sessions[idx].subscription_limit_reached = true;
                            push_connection_state(s, idx);
                        }
                        "processing" => {}
                        other => debug_log(&format!(
                            "exlap-hook: cred={} reply id={id} status={other:?}",
                            s.cred(idx)
                        )),
                    }
                }
            }
            Event::Other(m) => {
                debug_log(&format!("exlap-hook: cred={} rx {}", s.cred(idx), truncate_xml(&m, 160)));
            }
        }
    }
    true
}

/// Once a session's directory arrives: subscribe it to the URLs it owns (those
/// not already claimed by an earlier-up credential), then start the next
/// session.
fn on_directory(s: &mut ExlapState, idx: usize) {
    let cred = s.cred(idx);
    // What this credential offers, split from callables, minus what earlier
    // credentials already took (the divide policy, applied incrementally).
    let (offered, callable_n): (Vec<String>, usize) = match s.sessions[idx].machine() {
        Some(m) => {
            let dir = m.directory();
            let offered = dir
                .iter()
                .filter(|e| !e.callable)
                .map(|e| e.url.clone())
                .collect::<Vec<_>>();
            (offered, dir.iter().filter(|e| e.callable).count())
        }
        None => return,
    };

    // Resolve the configured set: "*" means everything this session offers,
    // otherwise the configured URLs the session actually has.
    let want_all = s.subscribe_urls.iter().any(|u| u == "*");
    let mut wanted: Vec<String> = if want_all {
        offered.iter().filter(|u| !s.claimed.contains(*u)).cloned().collect()
    } else {
        s.subscribe_urls
            .iter()
            .filter(|u| offered.contains(u) && !s.claimed.contains(*u))
            .cloned()
            .collect()
    };
    wanted.sort();
    wanted.dedup();

    debug_log(&format!(
        "exlap-hook: cred={cred} exposes {} data URLs ({callable_n} callables); \
         subscribing to {} not already claimed",
        offered.len(),
        wanted.len()
    ));

    let ival = s.subscribe_ival_ms;
    if !wanted.is_empty() {
        if let Some(m) = s.sessions[idx].machine() {
            // rates empty -> every URL at the default interval; `only` narrows the
            // directory to exactly `wanted`.
            if let Err(e) = m.subscribe(&[] as &[Rate], Some(ival), Some(&wanted)) {
                host::error(&format!("exlap-hook: subscribe cred={cred}: {e}"));
            }
        }
        s.flush_machine(idx);
        for u in &wanted {
            s.claimed.insert(u.clone());
        }
        s.sessions[idx].subscribed = true;
    }

    // Push the URL directory to the web UI for this session.
    let urls = url_list_json(&s.sessions[idx]);
    let snapshot = serde_json::json!({
        "cred_idx": cred,
        "user": exlap::USERS[cred],
        "connection_state": "active",
        "subscription_limit_reached": false,
        "urls": urls,
        "values": {},
    });
    host::send_ws_event("exlap", &snapshot.to_string());

    // This credential's session is fully up, start the next one.
    try_start_next_session(s);
}

/// A parsed `<Dat>`: record it, forward EV-relevant values to the energy model,
/// and push the change to the web UI.
fn on_data(s: &mut ExlapState, dat: Dat) {
    let mut ev_updated = false;
    match dat.url.as_str() {
        "tankLevelPrimary" => {
            if let Some(level) = dat.f64("level") {
                let pct = (level * 100.0) as f32;
                debug_log(&format!("exlap-hook: tankLevelPrimary/level={pct}%"));
                s.tank_level = Some(pct);
                ev_updated = true;
            }
        }
        "outsideTemperature" => {
            if let Some(t) = dat.f64("temperature") {
                debug_log(&format!("exlap-hook: outsideTemperature={t} degC"));
                s.outside_temp = Some(t as f32);
            }
        }
        _ => {}
    }

    // Build the web-UI change record from the parsed values. nodata/error
    // fields are in `dat.missing` and deliberately not published as readings.
    let fields: Vec<serde_json::Value> = dat
        .values
        .iter()
        .map(|v| {
            serde_json::json!({
                "name": v.name,
                "type": v.kind.tag(),
                "val": v.raw,
                "unit": dat.unit_for(&v.name),
            })
        })
        .collect();
    // The <Dat timeStamp> the server stamped (subscriptions ask for it). Read
    // from the raw message, since the parser lifts out only values; passed
    // through verbatim rather than interpreted.
    let timestamp = exlap::attr(&dat.raw, "timeStamp");
    let change = serde_json::json!({
        "url": dat.url,
        "fields": fields,
        "missing": dat.missing,
        "state": dat.state,
        "timestamp": timestamp,
    });
    s.current_values.insert(dat.url.clone(), change.clone());

    if ev_updated {
        let body = serde_json::json!({
            "battery_level_percentage": s.tank_level,
            "external_temp_celsius": s.outside_temp,
            "battery_capacity_wh": s.battery_capacity_wh,
        });
        // rest_call_async so the POST doesn't block modify_packet: ureq has no
        // default timeout and a slow local server would exceed the epoch
        // deadline (100 epochs x 10 ms = 1 s) and corrupt the epoch state.
        host::rest_call_async("POST", "/battery", &body.to_string());
    }

    host::send_ws_event("exlap", &serde_json::to_string(&[change]).unwrap_or_default());
}

/// Passively read `<Dat>` out of a session that is not ours (an orphan, or a
/// phone-side client), so a measurement on the shared channel is not wasted.
fn harvest_foreign(xml: &str) {
    let inner = unwrap_statement(xml);
    if let Some(dat) = exlap::parse_dat(inner) {
        with_state(|s| on_data(s, dat));
    }
}

/// Reset every session to Pending and clear the per-cycle claim set.
fn reset_sessions(s: &mut ExlapState) {
    s.sessions = s.creds.iter().map(|_| Session::pending()).collect();
    s.claimed.clear();
    s.connecting_started = false;
    for idx in 0..s.sessions.len() {
        push_connection_state(s, idx);
    }
}

/// The directory as web-UI JSON, or an empty list before it is read.
fn url_list_json(sess: &Session) -> Vec<serde_json::Value> {
    match &sess.state {
        SessionState::Running(m) => m
            .directory()
            .iter()
            .map(|e: &Entry| {
                serde_json::json!({
                    "url": e.url,
                    "url_type": if e.callable { "function" } else { "data" },
                })
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Push a connection-state event to the web UI for one session.
fn push_connection_state(s: &ExlapState, idx: usize) {
    let cred = s.cred(idx);
    let event = serde_json::json!({
        "cred_idx": cred,
        "user": exlap::USERS[cred],
        "connection_state": conn_state(&s.sessions[idx]),
        "subscription_limit_reached": s.sessions[idx].subscription_limit_reached,
    });
    host::send_ws_event("exlap", &event.to_string());
}

/// The web-UI connection-state string for a session.
fn conn_state(sess: &Session) -> &'static str {
    match &sess.state {
        SessionState::Failed => "failed",
        SessionState::Running(m) if m.phase() == Phase::Ready => "active",
        _ => "connecting",
    }
}

// -- ServiceDiscoveryResponse protobuf parsing (AA transport, unchanged) --------

/// Build a CHANNEL_OPEN_REQUEST packet for the given channel and service_id.
/// Currently unused, the phone opens the ExLAP channel itself (see handle_sdr).
/// Kept for a possible future fallback (would need to be enqueued, not sent
/// directly, so it flushes toward the HU from a dir=MD invocation).
#[allow(dead_code)]
fn build_chan_open_request(channel: u8, service_id: i32) -> Packet {
    let mut payload = vec![
        (MSG_CHANNEL_OPEN_REQUEST >> 8) as u8,
        (MSG_CHANNEL_OPEN_REQUEST & 0xFF) as u8,
        0x08,
        0x00, // priority = 0
        0x10, // field 2 tag
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

    if is_exlap {
        id
    } else {
        None
    }
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
#[allow(dead_code)]
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

// -- Tiny XML readers for the AA wrapper elements only --------------------------
//
// The ExLAP payload itself is parsed by the crate. These read the Android Auto
// wrapper elements the crate never sees: <ExlapStatement>, <ExlapConnectionReturn>.

fn xml_root_tag(xml: &str) -> Option<String> {
    let open = xml.find('<')?;
    let rest = &xml[open + 1..];
    let end = rest.find(|c: char| c == ' ' || c == '>' || c == '/').unwrap_or(rest.len());
    let tag = &rest[..end];
    if tag.is_empty() || tag.starts_with('?') || tag.starts_with('!') {
        return None;
    }
    Some(tag.to_string())
}

/// Read `attr="value"` off the first `<tag ...>` element in `xml`.
fn xml_attr_in_tag(xml: &str, tag_name: &str, attr_name: &str) -> Option<String> {
    let open = xml.find(&format!("<{tag_name}"))?;
    let rest = &xml[open..];
    let end = rest.find('>').map(|i| i + 1).unwrap_or(rest.len());
    let elem = &rest[..end];
    let needle = format!("{attr_name}=\"");
    let at = elem.find(&needle)? + needle.len();
    let tail = &elem[at..];
    tail.find('"').map(|e| tail[..e].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwrap_returns_the_inner_message() {
        let x = r#"<ExlapStatement session_id="abc"><Rsp id="5"/></ExlapStatement>"#;
        assert_eq!(unwrap_statement(x), r#"<Rsp id="5"/>"#);
        // A bare status has no wrapper and comes back whole.
        assert_eq!(unwrap_statement("<Status><Init/></Status>"), "<Status><Init/></Status>");
        // A wrapper with attributes on the inner element survives.
        let d = r#"<ExlapStatement session_id="x"><Dat url="vehicleSpeed"><Abs name="speed" val="3"/></Dat></ExlapStatement>"#;
        assert_eq!(unwrap_statement(d), r#"<Dat url="vehicleSpeed"><Abs name="speed" val="3"/></Dat>"#);
    }

    #[test]
    fn wrap_frames_a_request() {
        assert_eq!(
            wrap("sid1", r#"<Req id="9"><Alive/></Req>"#),
            r#"<ExlapStatement session_id="sid1"><Req id="9"><Alive/></Req></ExlapStatement>"#
        );
    }

    #[test]
    fn root_tag_reads_the_first_element() {
        assert_eq!(xml_root_tag("<ExlapBeacon/>").as_deref(), Some("ExlapBeacon"));
        assert_eq!(xml_root_tag(r#"<ExlapStatement session_id="a">"#).as_deref(), Some("ExlapStatement"));
        assert_eq!(xml_root_tag("  <Status><Init/></Status>").as_deref(), Some("Status"));
        assert_eq!(xml_root_tag("garbage"), None);
    }

    #[test]
    fn attr_reads_the_named_wrapper_attribute() {
        let x = r#"<ExlapConnectionReturn session_id="s" connected="true"/>"#;
        assert_eq!(xml_attr_in_tag(x, "ExlapConnectionReturn", "connected").as_deref(), Some("true"));
        assert_eq!(xml_attr_in_tag(x, "ExlapConnectionReturn", "session_id").as_deref(), Some("s"));
        assert_eq!(xml_attr_in_tag(x, "ExlapConnectionReturn", "missing"), None);
    }

    #[test]
    fn creds_parse_with_a_sane_fallback() {
        assert_eq!(parse_creds("2,1,3,0"), vec![2, 1, 3, 0]);
        assert_eq!(parse_creds(" 1 , 2 "), vec![1, 2]);
        assert_eq!(parse_creds("9,8"), DEFAULT_CREDS.to_vec(), "out-of-range -> default");
        assert_eq!(parse_creds(""), DEFAULT_CREDS.to_vec());
    }

    #[test]
    fn call_params_parse_into_typed_values() {
        let v = serde_json::json!([{"kind":"Enm","name":"Source","val":"HDD"}]);
        let params = parse_params(Some(&v));
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].kind, Kind::Enm);
        assert_eq!(exlap::call("Media_SwitchSource", &params),
                   r#"<Call url="Media_SwitchSource"><Enm name="Source" val="HDD"/></Call>"#);
    }
}
