//! One IoT scan, held to 1.x's `frfw.iot.scanner`: inventory ->
//! classify -> decide -> enforce -> record.
//!
//! The scanner runs unprivileged (it is what parses mDNS answers and
//! DHCP hostnames, untrusted LAN input, security-lessons A1). Its two
//! privileged steps go through the apply-helper: `dhcp_leases` (Kea's
//! lease file belongs to `_kea`) and `iot_sync_isolation` (the kernel's
//! `iot_isolated` set). They, the mDNS socket and the files are the
//! daemon's, behind [`ScanIo`]; this module decides.
//!
//! Configuration comes as the sensor's [`View`], one JSON object the Go
//! side writes at apply time (decided in phase 4c): the IoT zones'
//! interfaces in config order with their static address, the trusted
//! and isolated MACs, `auto_isolate` and the isolation mode. Never the
//! YAML config, which holds secrets this daemon has no business reading.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use fros_sensor::helper::HelperError;
use fros_sensor::pyjson::{self, Dict, PyError, Value};
use fros_sensor::pytext;

use crate::Crash;
use crate::arp::ArpEntry;
use crate::classify::{CATEGORY_IOT, Classification, Observation, classify};
use crate::oui::{VendorDb, normalize_mac, vendor_for};

/// Service types per responding IPv4 address, as the mDNS discovery
/// found them.
pub type MdnsResults = BTreeMap<String, BTreeSet<String>>;

/// An IPv4 interface address, `a.b.c.d/len`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Iface {
    pub ip: [u8; 4],
    pub prefix: u8,
}

impl Ipv4Iface {
    fn parse(text: &str) -> Option<Self> {
        let (ip, prefix) = text.split_once('/')?;
        let ip = parse_ipv4(ip)?;
        if prefix.is_empty() || prefix.len() > 2 || !prefix.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let prefix: u8 = prefix.parse().ok()?;
        (prefix <= 32).then_some(Self { ip, prefix })
    }

    fn contains(&self, addr: [u8; 4]) -> bool {
        let mask = u32::MAX
            .checked_shl(32 - u32::from(self.prefix))
            .unwrap_or(0);
        u32::from_be_bytes(self.ip) & mask == u32::from_be_bytes(addr) & mask
    }

    fn ip_text(&self) -> String {
        let [a, b, c, d] = self.ip;
        format!("{a}.{b}.{c}.{d}")
    }
}

/// Python's `ipaddress.IPv4Address(text)`: four dot-separated decimal
/// octets of one to three ASCII digits, no leading zero, at most 255.
pub fn parse_ipv4(text: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = text.split('.');
    for slot in &mut out {
        let part = parts.next()?;
        if part.is_empty()
            || part.len() > 3
            || !part.bytes().all(|b| b.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
        {
            return None;
        }
        *slot = part.parse().ok()?;
    }
    parts.next().is_none().then_some(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewInterface {
    pub device: String,
    pub address: Option<Ipv4Iface>,
}

/// The IoT part of the configuration, as the sensor gets it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    pub enabled: bool,
    /// Every interface in an IoT zone, in config order.
    pub interfaces: Vec<ViewInterface>,
    pub trusted_macs: Vec<String>,
    pub isolated_macs: Vec<String>,
    pub auto_isolate: bool,
    pub isolation_mode: String,
}

/// Why a view was refused: the key at fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewError(pub String);

impl View {
    /// The view's JSON object. Every key is required and typed; an
    /// address is `a.b.c.d/len` or null.
    pub fn from_json(value: &Value) -> Result<Self, ViewError> {
        let err = |key: &str| ViewError(key.to_owned());
        let Value::Dict(d) = value else {
            return Err(err("view"));
        };
        let boolean = |key: &str| match d.get(key) {
            Some(Value::Bool(b)) => Ok(*b),
            _ => Err(err(key)),
        };
        let text = |v: Option<&Value>, key: &str| match v {
            Some(Value::Str(s)) => Ok(s.clone()),
            _ => Err(err(key)),
        };
        let texts = |key: &str| match d.get(key) {
            Some(Value::List(items)) => items.iter().map(|v| text(Some(v), key)).collect(),
            _ => Err(err(key)),
        };
        let Some(Value::List(items)) = d.get("interfaces") else {
            return Err(err("interfaces"));
        };
        let mut interfaces = Vec::with_capacity(items.len());
        for item in items {
            let Value::Dict(i) = item else {
                return Err(err("interfaces"));
            };
            let address = match i.get("address") {
                Some(Value::Null) => None,
                Some(Value::Str(s)) => Some(Ipv4Iface::parse(s).ok_or_else(|| err("address"))?),
                _ => return Err(err("address")),
            };
            interfaces.push(ViewInterface {
                device: text(i.get("device"), "device")?,
                address,
            });
        }
        Ok(Self {
            enabled: boolean("enabled")?,
            interfaces,
            trusted_macs: texts("trusted_macs")?,
            isolated_macs: texts("isolated_macs")?,
            auto_isolate: boolean("auto_isolate")?,
            isolation_mode: text(d.get("isolation_mode"), "isolation_mode")?,
        })
    }
}

/// What a scan reads and asks, in the order 1.x does it. An mDNS
/// failure is its error text (1.x's MdnsError, which the scan reports
/// and carries on from); a helper failure is the client's
/// [`HelperError`]: its transport text is reported the same way, an
/// exception 1.x's client lets through ends the scan.
pub trait ScanIo {
    /// The apply-helper's `dhcp_leases` reply.
    fn leases(&mut self) -> Result<Value, HelperError>;
    /// mDNS discovery from the router's own addresses on the IoT zones.
    fn mdns(&mut self, addresses: &[String]) -> Result<MdnsResults, String>;
    fn arp_table(&mut self) -> Result<Vec<ArpEntry>, Crash>;
    fn vendor_db(&mut self) -> Result<VendorDb, Crash>;
    /// Where [`ScanIo::vendor_db`] reads, for the message when it's empty.
    fn oui_path(&self) -> String;
    /// The apply-helper's `iot_sync_isolation` reply for these MACs.
    fn sync(&mut self, macs: &[String]) -> Result<Value, HelperError>;
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScanResult {
    /// One dict per device, keys in 1.x's order.
    pub devices: Vec<Value>,
    /// The MACs the helper says are isolated, as it answered them.
    pub isolated: Vec<Value>,
    pub messages: Vec<String>,
    /// The inventory file's text (`json.dumps(indent=2, sort_keys=True)`);
    /// `None` when discovery is off and 1.x writes nothing.
    pub state: Option<String>,
}

const ATTRIBUTE_ERROR: Crash = Crash("AttributeError");
const TYPE_ERROR: Crash = Crash("TypeError");

fn dict(value: &Value) -> Result<&Dict, Crash> {
    match value {
        Value::Dict(d) => Ok(d),
        _ => Err(ATTRIBUTE_ERROR),
    }
}

/// The items `for x in value` walks: a list's items, a str's characters,
/// a dict's keys; anything else is a TypeError.
fn py_iter(value: &Value) -> Result<Vec<Value>, Crash> {
    match value {
        Value::List(items) => Ok(items.clone()),
        Value::Str(s) => Ok(s.chars().map(|c| Value::Str(c.to_string())).collect()),
        Value::Dict(d) => Ok(d.0.iter().map(|(k, _)| Value::Str(k.clone())).collect()),
        _ => Err(TYPE_ERROR),
    }
}

/// `list(d.get(key) or [])`.
fn list_or_empty(d: &Dict, key: &str) -> Result<Vec<Value>, Crash> {
    match d.get(key) {
        Some(v) if v.truthy() => py_iter(v),
        _ => Ok(Vec::new()),
    }
}

/// `str(d.get(key))`.
fn str_get(d: &Dict, key: &str) -> String {
    pytext::str_of(d.get(key).unwrap_or(&Value::Null))
}

/// `normalize_mac(d.get("mac", ""))`: anything but a str is no MAC.
fn mac_of(d: &Dict) -> Option<String> {
    match d.get("mac") {
        None => None,
        Some(Value::Str(s)) => normalize_mac(s),
        Some(_) => None,
    }
}

struct Record {
    ip: String,
    hostname: String,
    interface: String,
}

/// Every source merged into one observation per MAC, on the IoT zones
/// only, sorted by MAC. A lease counts when its address falls in an IoT
/// interface's subnet; a neighbour entry when it was seen on an IoT
/// interface, and a lease wins over it.
pub fn gather_observations(
    view: &View,
    leases: &[Value],
    arp_entries: &[ArpEntry],
    vendor_db: &VendorDb,
    mdns_results: &MdnsResults,
) -> Result<Vec<Observation>, Crash> {
    let zone_devices: HashSet<&str> = view.interfaces.iter().map(|i| i.device.as_str()).collect();
    let networks: Vec<(&str, Ipv4Iface)> = view
        .interfaces
        .iter()
        .filter_map(|i| Some((i.device.as_str(), i.address?)))
        .collect();

    let mut merged: BTreeMap<String, Record> = BTreeMap::new();
    for lease in leases {
        let lease = dict(lease)?;
        let mac = mac_of(lease);
        let (Some(mac), Some(Value::Str(ip))) = (mac, lease.get("ip")) else {
            continue;
        };
        let Some(addr) = parse_ipv4(ip) else {
            continue;
        };
        let Some(&(device, _)) = networks.iter().find(|(_, n)| n.contains(addr)) else {
            continue;
        };
        let hostname = match lease.get("hostname") {
            Some(v) if v.truthy() => pytext::str_of(v),
            _ => String::new(),
        };
        merged.insert(
            mac,
            Record {
                ip: ip.clone(),
                hostname,
                interface: device.to_owned(),
            },
        );
    }
    for entry in arp_entries {
        if !zone_devices.contains(entry.device.as_str()) {
            continue;
        }
        merged.entry(entry.mac.clone()).or_insert_with(|| Record {
            ip: entry.ip.clone(),
            hostname: String::new(),
            interface: entry.device.clone(),
        });
    }

    Ok(merged
        .into_iter()
        .map(|(mac, rec)| {
            let services = mdns_results
                .get(&rec.ip)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();
            let vendor = vendor_for(&mac, vendor_db).map(str::to_owned);
            Observation {
                mac,
                ip: Some(rec.ip),
                hostname: rec.hostname,
                interface: rec.interface,
                vendor,
                services,
            }
        })
        .collect())
}

/// The MACs the kernel set should hold: every `isolated_macs` entry,
/// plus every device classified "iot" when `auto_isolate` is on, minus
/// `trusted_macs` (trusted always wins). Sorted.
pub fn decide_isolation<'a>(
    view: &'a View,
    iot_macs: impl Iterator<Item = &'a str>,
) -> Vec<String> {
    let trusted: HashSet<&str> = view.trusted_macs.iter().map(String::as_str).collect();
    let mut isolated: BTreeSet<&str> = view.isolated_macs.iter().map(String::as_str).collect();
    if view.auto_isolate {
        isolated.extend(iot_macs);
    }
    isolated
        .into_iter()
        .filter(|m| !trusted.contains(m))
        .map(str::to_owned)
        .collect()
}

fn device_record(
    obs: &Observation,
    cls: &Classification,
    view: &View,
    isolated: &HashSet<&str>,
) -> Value {
    let text = |s: &str| Value::Str(s.to_owned());
    let opt = |s: &Option<String>| s.as_deref().map_or(Value::Null, text);
    let texts = |items: &[String]| Value::List(items.iter().map(|s| text(s)).collect());
    Value::Dict(Dict(vec![
        ("mac".into(), text(&obs.mac)),
        ("ip".into(), opt(&obs.ip)),
        ("hostname".into(), text(&obs.hostname)),
        ("interface".into(), text(&obs.interface)),
        ("vendor".into(), opt(&obs.vendor)),
        ("services".into(), texts(&obs.services)),
        ("category".into(), text(cls.category)),
        ("score".into(), Value::int(cls.score)),
        ("reasons".into(), texts(&cls.reasons)),
        (
            "isolated".into(),
            Value::Bool(isolated.contains(obs.mac.as_str())),
        ),
        (
            "trusted".into(),
            Value::Bool(view.trusted_macs.contains(&obs.mac)),
        ),
    ]))
}

/// One scan at time `now` (seconds since the epoch).
pub fn run_scan(view: &View, io: &mut impl ScanIo, now: f64) -> Result<ScanResult, Crash> {
    let mut messages: Vec<String> = Vec::new();
    if !view.enabled {
        messages.push("IoT discovery is disabled (iot.enabled: false)".into());
        return Ok(ScanResult {
            devices: Vec::new(),
            isolated: Vec::new(),
            messages,
            state: None,
        });
    }

    let mut leases = Vec::new();
    match io.leases() {
        Ok(response) => {
            let response = dict(&response)?;
            if response.get("ok").is_some_and(Value::truthy) {
                leases = list_or_empty(response, "leases")?;
            } else {
                messages.push(format!(
                    "warning: DHCP leases unavailable: {}",
                    str_get(response, "message")
                ));
            }
        }
        Err(HelperError::Transport(text)) => {
            messages.push(format!("warning: DHCP leases unavailable: {text}"));
        }
        Err(HelperError::Raised(name)) => return Err(Crash(name)),
    }

    let addresses: Vec<String> = view
        .interfaces
        .iter()
        .filter_map(|i| i.address.map(|a| a.ip_text()))
        .collect();
    let mut mdns_results = MdnsResults::new();
    if addresses.is_empty() {
        messages.push(
            "warning: no IoT-zone interface has a static address; mDNS discovery skipped".into(),
        );
    } else {
        match io.mdns(&addresses) {
            Ok(found) => mdns_results = found,
            Err(text) => messages.push(format!("warning: mDNS discovery skipped: {text}")),
        }
    }

    let arp_entries = io.arp_table()?;
    let vendor_db = io.vendor_db()?;
    if vendor_db.is_empty() {
        messages.push(format!(
            "note: no OUI vendor database at {} (install the 'ieee-data' package)",
            io.oui_path()
        ));
    }

    let observations = gather_observations(view, &leases, &arp_entries, &vendor_db, &mdns_results)?;
    let known: HashSet<&str> = observations
        .iter()
        .filter_map(|o| o.ip.as_deref())
        .collect();
    let orphans: Vec<Value> = mdns_results
        .keys()
        .filter(|ip| !known.contains(ip.as_str()))
        .map(|ip| Value::Str(ip.clone()))
        .collect();
    if !orphans.is_empty() {
        messages.push(format!(
            "note: {} mDNS responder(s) with no known MAC, not enforceable: {}",
            orphans.len(),
            pytext::repr(&Value::List(orphans))
        ));
    }

    let classified: Vec<(Observation, Classification)> = observations
        .into_iter()
        .map(|o| {
            let c = classify(&o);
            (o, c)
        })
        .collect();
    let wanted = decide_isolation(
        view,
        classified
            .iter()
            .filter(|(_, c)| c.category == CATEGORY_IOT)
            .map(|(o, _)| o.mac.as_str()),
    );

    let isolated = match io.sync(&wanted) {
        Ok(response) => {
            let response = dict(&response)?;
            if response.get("ok").is_some_and(Value::truthy) {
                let isolated = list_or_empty(response, "isolated")?;
                messages.push(format!(
                    "{} device(s) isolated ({})",
                    isolated.len(),
                    view.isolation_mode
                ));
                isolated
            } else {
                messages.push(format!(
                    "error: isolation not applied: {}",
                    str_get(response, "message")
                ));
                Vec::new()
            }
        }
        Err(HelperError::Transport(text)) => {
            messages.push(format!("error: isolation not applied: {text}"));
            Vec::new()
        }
        Err(HelperError::Raised(name)) => return Err(Crash(name)),
    };

    // set(isolated): a list or dict in the reply is unhashable.
    if isolated
        .iter()
        .any(|v| matches!(v, Value::List(_) | Value::Dict(_)))
    {
        return Err(TYPE_ERROR);
    }
    let isolated_set: HashSet<&str> = isolated
        .iter()
        .filter_map(|v| match v {
            Value::Str(s) => Some(s.as_str()),
            _ => None,
        })
        .collect();
    let devices: Vec<Value> = classified
        .iter()
        .map(|(o, c)| device_record(o, c, view, &isolated_set))
        .collect();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, c) in &classified {
        *counts.entry(c.category).or_default() += 1;
    }
    let summary = if devices.is_empty() {
        "0 device(s) found in the IoT zones".to_owned()
    } else {
        let parts: Vec<String> = counts.iter().map(|(cat, n)| format!("{n} {cat}")).collect();
        format!("{} device(s) found: {}", devices.len(), parts.join(", "))
    };
    messages.insert(0, summary);

    let scanned_at = pyjson::py_int(&Value::Float(now)).map_err(|e| match e {
        PyError::OverflowError => Crash("OverflowError"),
        _ => Crash("ValueError"),
    })?;
    let state = Value::Dict(Dict(vec![
        ("scanned_at".into(), Value::Int(scanned_at)),
        ("auto_isolate".into(), Value::Bool(view.auto_isolate)),
        (
            "isolation_mode".into(),
            Value::Str(view.isolation_mode.clone()),
        ),
        ("devices".into(), Value::List(devices.clone())),
        ("isolated".into(), Value::List(isolated.clone())),
        (
            "messages".into(),
            Value::List(messages.iter().map(|m| Value::Str(m.clone())).collect()),
        ),
    ]));
    Ok(ScanResult {
        devices,
        isolated,
        messages,
        state: Some(pyjson::dumps_indent_sorted(&state)),
    })
}

/// The MACs to isolate from the last scan's inventory without
/// rescanning (after an admin trusts or isolates a device in the
/// webUI): 1.x's `resync_from_inventory` before it calls the helper.
pub fn resync_wanted(view: &View, inventory: Option<&Value>) -> Result<Vec<String>, Crash> {
    let devices = match inventory {
        Some(v) if v.truthy() => match dict(v)?.get("devices") {
            Some(devices) => py_iter(devices)?,
            None => Vec::new(),
        },
        _ => Vec::new(),
    };
    let mut iot = Vec::new();
    for device in &devices {
        let d = dict(device)?;
        let Some(mac) = mac_of(d) else {
            continue;
        };
        if str_get(d, "category") == CATEGORY_IOT {
            iot.push(mac);
        }
    }
    Ok(decide_isolation(view, iot.iter().map(String::as_str)))
}
