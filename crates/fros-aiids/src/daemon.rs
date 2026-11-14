//! 1.x's `fr-ai-ids` daemon (`frfw.ai_ids.daemon.IDSDaemon`, phases 11
//! and 15, FND-1d) without its threads: the XDP filter's drop events and
//! the resolver's query log, attributed to an internal host (an IPv4
//! address inside an internal network, an IPv6 host by the MAC the
//! apply-helper labelled it with), new conntrack flows from the
//! apply-helper's samples, and once a window every tracked host scored
//! and a flagged one quarantined through the apply-helper, unless it is
//! excluded or infrastructure (the router, a gateway, a DNS server).
//! `fr-ai-ids` (src/bin) runs it on the router; tests/daemon.rs replays
//! 1.x's recorded runs (sensord.jsonl).
//!
//! The settings come from the sensors' JSON view of the config
//! (`ai_ids`, written by the Go apply as `apply.SensorView`), never from
//! the YAML copy.
//!
//! Where 1.x dies on what the apply-helper answers (a reply that isn't
//! an object, flows that aren't a list, a flow key that isn't hashable,
//! a reply its client can't decode) or on its event log (not UTF-8,
//! nested too deep), this logs it and goes on
//! (testdata/reference/decisions.md, "phase 4e-2").

use std::collections::{HashMap, HashSet};
use std::path::Path;

use fros_sensor::helper::{self, HelperError};
use fros_sensor::pyaddr::{Ipv4Net, ipv4_text, ipv6_str, parse_ipv4};
use fros_sensor::pyjson::{self, Dict, Value, float_repr, py_int};
use fros_sensor::pytext::{self, split_fields, splitlines, str_of};
use fros_sensor::statefile::{read_limited, universal_newlines, write_atomic};

use crate::engine::{AnomalyEngine, AnomalyEvent};
use crate::lines::{DnsLogEvent, parse_dns_log_line, parse_sni_drop_line};

/// How often conntrack is sampled and the window checked.
pub const TICK_SECONDS: f64 = 5.0;
/// The event log keeps this many of the latest quarantines.
pub const RECENT_EVENTS_LIMIT: usize = 50;
/// At most this many IPv6 address -> MAC labels are kept between samples.
pub const IPV6_LABELS_LIMIT: usize = 4096;

pub const EVENTS_PATH: &str = "/etc/fr_os/sensors/ai_ids_state.json";
pub const DNS_QUERY_LOG_PATH: &str = "/var/log/fr_os-dns/queries.log";
pub const SNI_EVENTS_PATH: &str = "/var/log/fr_os-sni/events.jsonl";
pub const ADBLOCK_CATEGORY_DIR: &str = "/etc/fr_os/adblock.d";
pub const ROUTE_PATH: &str = "/proc/net/route";
pub const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

/// 1.x's helper protocol's `CONNTRACK_SAMPLE_MAX_BYTES`: a busy router's
/// table is the largest reply there is.
pub const CONNTRACK_SAMPLE_MAX_BYTES: usize = 16 * 1024 * 1024;

/// The event log, the routing table and resolv.conf are read up to this:
/// the daemon writes at most 50 events, the others are a few lines. A
/// larger event log reads as empty, as one that isn't JSON does.
pub const SMALL_FILE_MAX_BYTES: u64 = 1024 * 1024;

/// The daemon's part of the sensors' view (`ai_ids`).
#[derive(Debug, Clone, PartialEq)]
pub struct IdsView {
    pub enabled: bool,
    /// Lowercase, in config order.
    pub excluded_macs: Vec<String>,
    /// The reservation addresses of the excluded MACs.
    pub excluded_ips: Vec<String>,
    pub internal_networks: Vec<Ipv4Net>,
    /// The configured addresses never quarantined; the gateways and the
    /// resolver's servers are added at each evaluation.
    pub infrastructure: Vec<String>,
    /// The malware/phishing categories the ad-block resolver serves.
    pub threat_categories: Vec<String>,
    /// Whether the resolver writes its query log.
    pub query_log: bool,
    pub quarantine_duration_seconds: i64,
}

fn strings(v: Option<&Value>) -> Option<Vec<String>> {
    let Some(Value::List(items)) = v else {
        return None;
    };
    items
        .iter()
        .map(|i| match i {
            Value::Str(s) => Some(s.clone()),
            _ => None,
        })
        .collect()
}

impl IdsView {
    /// The view file's object: `None` when the config it was written
    /// from was refused (`config_error`) or the file isn't the view.
    pub fn from_json(value: &Value) -> Option<IdsView> {
        let Value::Dict(top) = value else { return None };
        let Some(Value::Dict(v)) = top.get("ai_ids") else {
            return None;
        };
        let flag = |key: &str| match v.get(key) {
            Some(Value::Bool(b)) => Some(*b),
            _ => None,
        };
        let internal_networks = strings(v.get("internal_networks"))?
            .iter()
            .map(|n| Ipv4Net::parse(n))
            .collect::<Option<Vec<_>>>()?;
        let duration = match v.get("quarantine_duration_seconds") {
            Some(Value::Int(n)) => n.parse().ok()?,
            _ => return None,
        };
        Some(IdsView {
            enabled: flag("enabled")?,
            excluded_macs: strings(v.get("excluded_macs"))?,
            excluded_ips: strings(v.get("excluded_ips"))?,
            internal_networks,
            infrastructure: strings(v.get("infrastructure"))?,
            threat_categories: strings(v.get("threat_categories"))?,
            query_log: flag("query_log")?,
            quarantine_duration_seconds: duration,
        })
    }

    /// The view file at `path` (at most 1 MiB), as `from_json` reads it.
    pub fn read(path: &Path) -> Option<IdsView> {
        let raw = read_limited(path, 1 << 20).ok()??;
        IdsView::from_json(&pyjson::loads(&raw).ok()?)
    }
}

/// What the daemon asks the apply-helper.
pub trait Helper {
    fn conntrack_sample(&mut self) -> Result<Value, HelperError>;
    fn quarantine_ip(&mut self, ip: &str, duration_seconds: i64) -> Result<Value, HelperError>;
}

/// The apply-helper on its Unix socket (1.x's `helper_client`).
pub struct SocketHelper<'a>(pub &'a Path);

impl Helper for SocketHelper<'_> {
    fn conntrack_sample(&mut self) -> Result<Value, HelperError> {
        conntrack_sample(self.0)
    }
    fn quarantine_ip(&mut self, ip: &str, duration_seconds: i64) -> Result<Value, HelperError> {
        quarantine_ip(self.0, ip, duration_seconds)
    }
}

/// `helper_client.conntrack_sample`.
pub fn conntrack_sample(socket: &Path) -> Result<Value, HelperError> {
    let cmd = Dict(vec![("cmd".into(), Value::Str("conntrack_sample".into()))]);
    helper::send_command(&cmd, socket, helper::TIMEOUT, CONNTRACK_SAMPLE_MAX_BYTES)
}

/// `helper_client.quarantine_ip`.
pub fn quarantine_ip(socket: &Path, ip: &str, duration_seconds: i64) -> Result<Value, HelperError> {
    let cmd = Dict(vec![
        ("cmd".into(), Value::Str("quarantine_ip".into())),
        ("ip".into(), Value::Str(ip.into())),
        ("duration_seconds".into(), Value::int(duration_seconds)),
    ]);
    helper::send_command(&cmd, socket, helper::TIMEOUT, helper::MAX_LINE_BYTES)
}

/// Where a log line goes: 1.x prints some to stdout, some to stderr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Out,
    Err,
}

/// `[0-9a-f]{2}(?::[0-9a-f]{2}){5}\Z`: an IPv6 host's score key.
pub fn is_mac_key(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 17
        && b.iter().enumerate().all(|(i, &c)| {
            if i % 3 == 2 {
                c == b':'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
}

/// A JSON value as a set member, equal where Python's `==` makes two
/// JSON scalars equal (`1 == 1.0 == True`); `None` for a list or dict,
/// which Python can't hash.
fn hash_key(v: &Value) -> Option<String> {
    Some(match v {
        Value::Null => "N".into(),
        Value::Bool(b) => format!("I{}", u8::from(*b)),
        Value::Int(s) => format!("I{s}"),
        Value::Float(f) if f.is_finite() && f.fract() == 0.0 => format!("I{}", py_int(v).ok()?),
        Value::Float(f) => format!("F{}", float_repr(*f)),
        Value::Str(s) => format!("S{s}"),
        Value::List(_) | Value::Dict(_) => return None,
    })
}

type FlowKey = (String, String, String, String, String);

/// Why a flow is left out of a sample: 1.x skips the first kind and
/// dies on the second.
enum BadFlow {
    Skipped,
    Unhashable,
}

/// `(flow["proto"], flow["src"], int(flow["sport"]), flow["dst"],
/// int(flow["dport"]))`, as a set member.
fn flow_key(flow: &Dict) -> Result<FlowKey, BadFlow> {
    let get = |k: &str| flow.get(k).ok_or(BadFlow::Skipped);
    let (proto, src, sport, dst, dport) = (
        get("proto")?,
        get("src")?,
        get("sport")?,
        get("dst")?,
        get("dport")?,
    );
    // int(): TypeError and ValueError are skipped; OverflowError (an
    // infinite float) is not caught by 1.x either way.
    let sport = py_int(sport).map_err(|_| BadFlow::Skipped)?;
    let dport = py_int(dport).map_err(|_| BadFlow::Skipped)?;
    let h = |v: &Value| hash_key(v).ok_or(BadFlow::Unhashable);
    Ok((
        h(proto)?,
        h(src)?,
        format!("I{sport}"),
        h(dst)?,
        format!("I{dport}"),
    ))
}

/// Python's `int(text, 16)` for a field of /proc/net/route, as a 32-bit
/// value; `None` where 1.x skips the route (ValueError) or dies on it
/// (a value `to_bytes(4)` refuses).
fn hex_u32(text: &str) -> Option<u32> {
    let (negative, body) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let (prefixed, digits) = match body.get(..2) {
        Some("0x" | "0X") => (true, &body[2..]),
        _ => (false, body),
    };
    let digits = if prefixed {
        digits.strip_prefix('_').unwrap_or(digits)
    } else {
        digits
    };
    let mut value: u64 = 0;
    let mut last_underscore = true;
    if digits.is_empty() {
        return None;
    }
    for c in digits.chars() {
        if c == '_' {
            if last_underscore {
                return None;
            }
            last_underscore = true;
            continue;
        }
        value = value.checked_mul(16)? + u64::from(c.to_digit(16)?);
        if value > u64::from(u32::MAX) {
            return None;
        }
        last_underscore = false;
    }
    if last_underscore || (negative && value != 0) {
        return None;
    }
    u32::try_from(value).ok()
}

/// Next hops of every IPv4 default route in /proc/net/route's text
/// (addresses in little-endian hex).
pub fn default_gateways(route: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for line in splitlines(route).into_iter().skip(1) {
        let fields = split_fields(line);
        if fields.len() < 3 || fields[1] != "00000000" {
            continue;
        }
        let Some(n) = hex_u32(fields[2]) else {
            continue;
        };
        if n != 0 {
            out.insert(ipv4_text(n.to_le_bytes()));
        }
    }
    out
}

/// The IPv4 `nameserver`s of resolv.conf's text.
pub fn resolv_nameservers(resolv: &str) -> HashSet<String> {
    splitlines(resolv)
        .into_iter()
        .filter_map(|line| {
            let fields = split_fields(line);
            (fields.len() >= 2 && fields[0] == "nameserver")
                .then(|| parse_ipv4(fields[1]).map(ipv4_text))
                .flatten()
        })
        .collect()
}

/// A world-readable file's text, empty where 1.x's `read_text()` raises
/// OSError; bytes that aren't UTF-8 read as U+FFFD.
fn read_text(path: &Path) -> String {
    match read_limited(path, SMALL_FILE_MAX_BYTES) {
        Ok(Some(raw)) => String::from_utf8_lossy(&universal_newlines(&raw)).into_owned(),
        _ => String::new(),
    }
}

/// The event log's events (`_load_events`): anything that isn't a JSON
/// list (missing, unreadable, not UTF-8, too large) reads as none.
pub fn load_events(path: &Path) -> Vec<Value> {
    match read_limited(path, SMALL_FILE_MAX_BYTES) {
        Ok(Some(raw)) => match pyjson::loads(&universal_newlines(&raw)) {
            Ok(Value::List(events)) => events,
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// `dataclasses.asdict(event)`, its fields in their declared order.
pub fn event_fields(e: &AnomalyEvent) -> Vec<(String, Value)> {
    let count = |n: usize| Value::Int(n.to_string());
    vec![
        ("ip".into(), Value::Str(e.ip.clone())),
        ("score".into(), Value::Float(e.score)),
        (
            "reasons".into(),
            Value::List(e.reasons.iter().map(|r| Value::Str((*r).into())).collect()),
        ),
        ("conn_rate".into(), Value::Float(e.conn_rate)),
        ("unique_dst_ratio".into(), Value::Float(e.unique_dst_ratio)),
        ("sni_block_count".into(), count(e.sni_block_count)),
        ("nxdomain_count".into(), count(e.nxdomain_count)),
        ("dga_nxdomain_count".into(), count(e.dga_nxdomain_count)),
        ("dns_threat_count".into(), count(e.dns_threat_count)),
    ]
}

/// Where the files the daemon reads and writes are.
#[derive(Debug, Clone)]
pub struct Paths {
    pub events: std::path::PathBuf,
    pub adblock_category_dir: std::path::PathBuf,
    pub route: std::path::PathBuf,
    pub resolv: std::path::PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Paths {
            events: EVENTS_PATH.into(),
            adblock_category_dir: ADBLOCK_CATEGORY_DIR.into(),
            route: ROUTE_PATH.into(),
            resolv: RESOLV_CONF_PATH.into(),
        }
    }
}

pub struct IdsDaemon {
    pub engine: AnomalyEngine,
    view: IdsView,
    paths: Paths,
    threat_files: HashSet<String>,
    /// IPv6 address -> MAC (the helper's labels), in the order learnt.
    ipv6_macs: HashMap<String, String>,
    /// Each MAC's latest IPv6 address, to quarantine it through.
    mac_address: HashMap<String, String>,
    known_flow_keys: HashSet<FlowKey>,
    log: Vec<(Stream, String)>,
}

impl IdsDaemon {
    pub fn new(view: IdsView, engine: AnomalyEngine, paths: Paths) -> Self {
        let threat_files = view
            .threat_categories
            .iter()
            .map(|name| {
                paths
                    .adblock_category_dir
                    .join(format!("{name}.hosts"))
                    .display()
                    .to_string()
            })
            .collect();
        IdsDaemon {
            engine,
            view,
            paths,
            threat_files,
            ipv6_macs: HashMap::new(),
            mac_address: HashMap::new(),
            known_flow_keys: HashSet::new(),
            log: Vec::new(),
        }
    }

    pub fn view(&self) -> &IdsView {
        &self.view
    }

    /// The lines printed since the last call, in order.
    pub fn take_log(&mut self) -> Vec<(Stream, String)> {
        std::mem::take(&mut self.log)
    }

    fn say(&mut self, stream: Stream, text: String) {
        self.log.push((stream, text));
    }

    fn is_internal(&self, ip: &str) -> bool {
        parse_ipv4(ip).is_some_and(|a| self.view.internal_networks.iter().any(|n| n.contains(a)))
    }

    /// The key a source is scored under, or `None` to leave it alone: an
    /// internal IPv4 address itself; an IPv6 address's MAC, if a sample
    /// labelled it.
    fn source(&self, ip: &str) -> Option<String> {
        if !ip.contains(':') {
            return self.is_internal(ip).then(|| ip.to_owned());
        }
        self.ipv6_macs.get(&ipv6_str(ip)?).cloned()
    }

    /// One line of the XDP filter's event file: a drop counts for its
    /// source.
    pub fn handle_sni_event_line(&mut self, line: &str, now: f64) {
        if let Some(saddr) = parse_sni_drop_line(line)
            && let Some(source) = self.source(&saddr)
        {
            self.engine.observe_sni_block(&source, now);
        }
    }

    /// One line of the resolver's query log: an NXDOMAIN answer, or an
    /// answer from a malware/phishing category file.
    pub fn handle_dns_log_line(&mut self, line: &str, now: f64) {
        match parse_dns_log_line(line, &self.threat_files) {
            Some(DnsLogEvent::Nxdomain {
                client,
                name,
                generated,
            }) => {
                if let Some(c) = self.source(&client) {
                    self.engine.observe_dns_nxdomain(&c, &name, generated, now);
                }
            }
            Some(DnsLogEvent::ThreatBlock { client }) => {
                if let Some(c) = self.source(&client) {
                    self.engine.observe_dns_threat_block(&c, now);
                }
            }
            None => {}
        }
    }

    /// One conntrack sample through the apply-helper: only flows new
    /// since the last sample count as connections.
    pub fn poll_conntrack(&mut self, helper: &mut dyn Helper, now: f64) {
        let response = match helper.conntrack_sample() {
            Ok(r) => r,
            Err(e) => {
                return self.say(
                    Stream::Err,
                    format!("fr-ai-ids: conntrack sample failed: {e}"),
                );
            }
        };
        let Value::Dict(response) = response else {
            // 1.x dies here (AttributeError).
            return self.say(
                Stream::Err,
                "fr-ai-ids: conntrack sample failed: the apply-helper's reply is not an object"
                    .into(),
            );
        };
        if !response.get("ok").is_some_and(Value::truthy) {
            return;
        }
        let flows: Vec<&Dict> = match response.get("flows") {
            None => Vec::new(),
            Some(Value::List(items)) => items
                .iter()
                .filter_map(|f| match f {
                    Value::Dict(d) => Some(d),
                    _ => None,
                })
                .collect(),
            // Iterating a str or a dict yields no dicts.
            Some(Value::Str(_) | Value::Dict(_)) => Vec::new(),
            Some(other) => {
                // 1.x dies here (TypeError).
                return self.say(
                    Stream::Err,
                    format!(
                        "fr-ai-ids: conntrack sample failed: the apply-helper's flows are a {}, not a list",
                        pytext::type_name(other)
                    ),
                );
            }
        };
        self.learn_ipv6_labels(&flows);
        let mut current = HashSet::new();
        for flow in flows {
            let key = match flow_key(flow) {
                Ok(k) => k,
                Err(BadFlow::Skipped) => continue,
                Err(BadFlow::Unhashable) => {
                    // 1.x dies here (TypeError).
                    self.say(
                        Stream::Err,
                        "fr-ai-ids: conntrack sample: skipped a flow whose fields are lists or objects".into(),
                    );
                    continue;
                }
            };
            let fresh = !self.known_flow_keys.contains(&key);
            let dst = key.3.clone();
            current.insert(key);
            if !fresh {
                continue;
            }
            if let Some(Value::Str(src)) = flow.get("src")
                && let Some(source) = self.source(src)
            {
                self.engine.observe_connection(&source, &dst, now);
            }
        }
        self.known_flow_keys = current;
    }

    fn learn_ipv6_labels(&mut self, flows: &[&Dict]) {
        let mut labels: Vec<(String, String)> = Vec::new();
        for flow in flows {
            let (Some(Value::Str(src)), Some(Value::Str(mac))) =
                (flow.get("src"), flow.get("src_mac"))
            else {
                continue;
            };
            if !src.contains(':') {
                continue;
            }
            let mac = pytext::lower(mac);
            if !is_mac_key(&mac) {
                continue;
            }
            let Some(address) = ipv6_str(src) else {
                continue;
            };
            match labels.iter_mut().find(|(a, _)| *a == address) {
                Some(slot) => slot.1 = mac,
                None => labels.push((address, mac)),
            }
        }
        if self.ipv6_macs.len() + labels.len() > IPV6_LABELS_LIMIT {
            self.ipv6_macs.clear();
        }
        for (address, mac) in labels {
            self.ipv6_macs.insert(address.clone(), mac.clone());
            self.mac_address.insert(mac, address);
        }
    }

    /// Score every tracked source once and quarantine each flagged one
    /// that isn't excluded or infrastructure; `wall` is the event log's
    /// clock. Every flagged event, the excluded ones too.
    pub fn evaluate_and_enforce(
        &mut self,
        helper: &mut dyn Helper,
        now: f64,
        wall: f64,
    ) -> Vec<AnomalyEvent> {
        let mut infrastructure: HashSet<String> =
            self.view.infrastructure.iter().cloned().collect();
        infrastructure.extend(default_gateways(&read_text(&self.paths.route)));
        infrastructure.extend(resolv_nameservers(&read_text(&self.paths.resolv)));
        let mut flagged = Vec::new();
        for ip in self.engine.tracked_ips() {
            let Some(event) = self.engine.evaluate(&ip, now) else {
                continue;
            };
            flagged.push(event.clone());
            if self.view.excluded_ips.contains(&ip) || self.view.excluded_macs.contains(&ip) {
                continue;
            }
            if infrastructure.contains(&ip) {
                self.say(
                    Stream::Out,
                    format!(
                        "fr-ai-ids: {ip} scored {} ({}) but is infrastructure (the router, a gateway or a DNS \
                         server); not quarantining it",
                        float_repr(event.score),
                        event.reasons.join(", ")
                    ),
                );
                continue;
            }
            self.enforce(helper, event, wall);
        }
        flagged
    }

    fn enforce(&mut self, helper: &mut dyn Helper, mut event: AnomalyEvent, wall: f64) {
        let duration = self.view.quarantine_duration_seconds;
        let mac = if is_mac_key(&event.ip) {
            event.ip.clone()
        } else {
            String::new()
        };
        let target = if mac.is_empty() {
            event.ip.clone()
        } else if let Some(address) = self.mac_address.get(&mac) {
            address.clone()
        } else {
            return self.say(
                Stream::Err,
                format!(
                    "fr-ai-ids: {mac} scored {} but has no IPv6 address to quarantine it through",
                    float_repr(event.score)
                ),
            );
        };
        let response = match helper.quarantine_ip(&target, duration) {
            Ok(r) => r,
            Err(e) => {
                return self.say(
                    Stream::Err,
                    format!("fr-ai-ids: quarantine request failed: {e}"),
                );
            }
        };
        let Value::Dict(response) = response else {
            // 1.x dies here (AttributeError).
            return self.say(
                Stream::Err,
                "fr-ai-ids: quarantine request failed: the apply-helper's reply is not an object"
                    .into(),
            );
        };
        if !response.get("ok").is_some_and(Value::truthy) {
            let message = response
                .get("message")
                .map_or_else(|| "None".into(), str_of);
            return self.say(
                Stream::Err,
                format!("fr-ai-ids: apply-helper refused to quarantine {target}: {message}"),
            );
        }
        let shown_mac = if mac.is_empty() {
            String::new()
        } else {
            format!(" ({mac})")
        };
        self.say(
            Stream::Out,
            format!(
                "fr-ai-ids: quarantined {target}{shown_mac} for {duration}s (score={}, reasons={})",
                float_repr(event.score),
                event.reasons.join(", ")
            ),
        );
        event.ip = target;
        self.append_event_log(&event, &mac, wall);
    }

    fn append_event_log(&mut self, event: &AnomalyEvent, mac: &str, wall: f64) {
        let mut events = load_events(&self.paths.events);
        let mut entry = vec![("ts".to_owned(), Value::Float(wall))];
        entry.extend(event_fields(event));
        if !mac.is_empty() {
            entry.push(("mac".into(), Value::Str(mac.into())));
        }
        events.push(Value::Dict(Dict(entry)));
        let keep = events.len().saturating_sub(RECENT_EVENTS_LIMIT);
        let text = pyjson::dumps(&Value::List(events.split_off(keep)));
        if let Err(e) = write_atomic(&self.paths.events, &text) {
            // 1.x dies here; the quarantine itself stands.
            self.say(
                Stream::Err,
                format!("fr-ai-ids: writing {}: {e}", self.paths.events.display()),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_fields() {
        assert_eq!(hex_u32("0100000A"), Some(0x0100_000a));
        assert_eq!(hex_u32("0x_ff"), Some(255));
        assert_eq!(hex_u32("f_f"), Some(255));
        for bad in ["zz", "", "_1", "1_", "1__2", "-1", "100000000", "0x"] {
            assert_eq!(hex_u32(bad), None, "{bad}");
        }
        let gw = default_gateways(
            "Iface\tDestination\tGateway\neth0\t00000000\t0100000A\t0003\neth1\t00000000\t00000000\n",
        );
        assert_eq!(gw, HashSet::from(["10.0.0.1".to_owned()]));
        let ns = resolv_nameservers("nameserver 192.0.2.53\nnameserver ::1\nnameserver\n# x\n");
        assert_eq!(ns, HashSet::from(["192.0.2.53".to_owned()]));
    }

    #[test]
    fn mac_keys_and_flow_keys() {
        assert!(is_mac_key("02:00:00:00:00:0a"));
        assert!(!is_mac_key("02:00:00:00:00:0A") && !is_mac_key("02:00:00:00:00:0a\n"));
        assert_eq!(hash_key(&Value::Float(1.0)), hash_key(&Value::Bool(true)));
        assert_eq!(hash_key(&Value::Float(-0.0)), hash_key(&Value::int(0)));
        assert_ne!(hash_key(&Value::Str("1".into())), hash_key(&Value::int(1)));
        assert_eq!(hash_key(&Value::List(vec![])), None);
    }
}
