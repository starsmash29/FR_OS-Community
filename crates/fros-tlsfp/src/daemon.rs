//! What `fr-tls-fp` does with the ClientHello segments it reads (1.x's
//! `frfw.tlsfp.daemon.TlsFingerprintDaemon`): reassemble each flow's
//! hello, fingerprint it, keep the inventory, report a JA4 never seen on
//! the network (after the learning period) and a blocklisted one,
//! quarantining that client through the apply-helper when the config
//! says so, and write the inventory to its state file. Held to 1.x's
//! recorded daemon (tests/daemon.rs, testdata/reference/tlsfpd.jsonl).
//!
//! The settings come from the sensors' JSON view of the config, which
//! the Go apply writes (`apply.SensorView`), never from the YAML copy.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use fros_sensor::helper::HelperError;
use fros_sensor::pyjson::{self, Dict, LoadError, Value};
use fros_sensor::pytext::str_of;
use fros_sensor::statefile::{put_aside, read_limited, universal_newlines, write_atomic};

use crate::inventory::FingerprintInventory;
use crate::reassembly::Reassembler;
use crate::{ja3, ja4, parse_client_hello};

/// A blocklisted client is quarantined at most this often.
pub const QUARANTINE_REPEAT_SECONDS: f64 = 600.0;

/// How often the state file is written, and the view read again.
pub const FLUSH_SECONDS: f64 = 30.0;

/// The state file's path.
pub const STATE_PATH: &str = "/etc/fr_os/sensors/tls_fingerprints.json";

/// Past this the state file is put aside unread (1.x reads any size;
/// at its limits the inventory writes about 6 MiB).
pub const STATE_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// The daemon's part of the sensors' view (`tls_fingerprint`).
#[derive(Debug, Clone, PartialEq)]
pub struct View {
    pub enabled: bool,
    /// (fingerprint, label), in config order.
    pub blocklist: Vec<(String, String)>,
    pub quarantine_on_match: bool,
    pub quarantine_duration_seconds: i64,
}

impl View {
    /// The view file's object: `None` when the config it was written from
    /// was refused (`config_error`) or the file isn't the view; 1.x's
    /// daemon then keeps the settings it has, or stays idle at start.
    pub fn from_json(value: &Value) -> Option<View> {
        let Value::Dict(top) = value else { return None };
        let Some(Value::Dict(t)) = top.get("tls_fingerprint") else {
            return None;
        };
        let flag = |key: &str| match t.get(key) {
            Some(Value::Bool(b)) => Some(*b),
            _ => None,
        };
        let Some(Value::List(entries)) = t.get("blocklist") else {
            return None;
        };
        let mut blocklist = Vec::with_capacity(entries.len());
        for e in entries {
            let Value::Dict(e) = e else { return None };
            match (e.get("fingerprint"), e.get("label")) {
                (Some(Value::Str(f)), Some(Value::Str(l))) => {
                    blocklist.push((f.clone(), l.clone()))
                }
                _ => return None,
            }
        }
        let duration = match t.get("quarantine_duration_seconds") {
            Some(Value::Int(n)) => n.parse().ok()?,
            _ => return None,
        };
        Some(View {
            enabled: flag("enabled")?,
            blocklist,
            quarantine_on_match: flag("quarantine_on_match")?,
            quarantine_duration_seconds: duration,
        })
    }

    /// The view file at `path` (at most 1 MiB), as `from_json` reads it.
    pub fn read(path: &Path) -> Option<View> {
        let raw = read_limited(path, 1 << 20).ok()??;
        View::from_json(&pyjson::loads(&raw).ok()?)
    }
}

/// One ClientHello segment from the `hello_pkts` ring buffer.
pub struct Segment<'a> {
    pub saddr: &'a str,
    pub sport: u16,
    pub daddr: &'a str,
    pub dport: u16,
    pub seq: u32,
    pub first: bool,
    pub payload: &'a [u8],
}

/// Asks the apply-helper to quarantine an address for so many seconds.
pub type QuarantineFn<'a> = dyn FnMut(&str, i64) -> Result<Value, HelperError> + 'a;

type FlowKey = (String, u16, String, u16);

pub struct Daemon {
    reassembler: Reassembler<FlowKey>,
    pub inventory: FingerprintInventory,
    quarantined_at: HashMap<String, f64>,
    hellos: u64,
    parse_errors: u64,
    view: View,
    blocklist: HashMap<String, String>,
}

impl Daemon {
    pub fn new(view: View, inventory: FingerprintInventory) -> Self {
        let mut d = Daemon {
            reassembler: Reassembler::default(),
            inventory,
            quarantined_at: HashMap::new(),
            hellos: 0,
            parse_errors: 0,
            view: view.clone(),
            blocklist: HashMap::new(),
        };
        d.update_view(view);
        d
    }

    pub fn update_view(&mut self, view: View) {
        // `{e.fingerprint: e.label for e in ...}`: a later entry wins.
        self.blocklist = view.blocklist.iter().cloned().collect();
        self.view = view;
    }

    pub fn view(&self) -> &View {
        &self.view
    }

    /// `(hellos, parse_errors)`.
    pub fn stats(&self) -> (u64, u64) {
        (self.hellos, self.parse_errors)
    }

    pub fn handle_segment(&mut self, seg: &Segment, now: f64, quarantine: &mut QuarantineFn) {
        let key = (
            seg.saddr.to_string(),
            seg.sport,
            seg.daddr.to_string(),
            seg.dport,
        );
        let message = match self
            .reassembler
            .add(&key, seg.seq, seg.payload, now, seg.first)
        {
            Ok(Some(m)) => m,
            Ok(None) => return,
            Err(_) => {
                self.parse_errors += 1;
                return;
            }
        };
        let Ok(hello) = parse_client_hello(&message) else {
            self.parse_errors += 1;
            return;
        };
        self.hellos += 1;
        let (ja4_fp, ja3_fp) = (ja4(&hello, "t"), ja3(&hello));
        self.handle_hello(
            seg.saddr,
            &ja4_fp,
            &ja3_fp,
            hello.server_name.as_deref(),
            now,
            quarantine,
        );
    }

    fn handle_hello(
        &mut self,
        client: &str,
        ja4_fp: &str,
        ja3_fp: &str,
        sni: Option<&str>,
        now: f64,
        quarantine: &mut QuarantineFn,
    ) {
        let is_new = self.inventory.observe(client, ja4_fp, ja3_fp, sni, now);
        let base = |kind: &str| {
            Dict(vec![
                ("ts".into(), Value::Float(now)),
                ("client".into(), Value::Str(client.into())),
                ("ja4".into(), Value::Str(ja4_fp.into())),
                ("ja3".into(), Value::Str(ja3_fp.into())),
                (
                    "sni".into(),
                    sni.map_or(Value::Null, |s| Value::Str(s.into())),
                ),
                ("type".into(), Value::Str(kind.into())),
            ])
        };
        if is_new {
            self.inventory.add_event(base("new_fingerprint"));
        }
        // `blocklist.get(ja4, blocklist.get(ja3))`: ja4's label first.
        let Some(label) = self
            .blocklist
            .get(ja4_fp)
            .or_else(|| self.blocklist.get(ja3_fp))
        else {
            return;
        };
        let mut event = base("blocklist");
        event.insert("label".into(), Value::Str(label.clone()));
        let action = if self.view.quarantine_on_match {
            self.quarantine(client, now, quarantine)
        } else {
            "reported".into()
        };
        event.insert("action".into(), Value::Str(action));
        self.inventory.add_event(event);
    }

    fn quarantine(&mut self, client: &str, now: f64, quarantine: &mut QuarantineFn) -> String {
        if let Some(last) = self.quarantined_at.get(client)
            && now - last < QUARANTINE_REPEAT_SECONDS
        {
            return "already quarantined".into();
        }
        self.quarantined_at.insert(client.into(), now);
        match quarantine(client, self.view.quarantine_duration_seconds) {
            Err(e) => format!("quarantine failed: {e}"),
            // 1.x's daemon dies on a reply that isn't an object
            // (AttributeError); FR_OS 2 reports it (decisions.md).
            Ok(Value::Dict(reply)) => {
                if reply.get("ok").is_some_and(Value::truthy) {
                    "quarantined".into()
                } else {
                    let message = reply.get("message").map_or_else(|| "None".into(), str_of);
                    format!("quarantine failed: {message}")
                }
            }
            Ok(other) => format!(
                "quarantine failed: the apply-helper's reply is not an object: {}",
                fros_sensor::pytext::repr(&other)
            ),
        }
    }

    /// The state file's text: the inventory's snapshot and the stats.
    pub fn state_text(&self, now: f64) -> String {
        let mut snapshot = self.inventory.snapshot(now);
        snapshot.insert(
            "stats".into(),
            Value::Dict(Dict(vec![
                ("hellos".into(), Value::Int(self.hellos.to_string())),
                (
                    "parse_errors".into(),
                    Value::Int(self.parse_errors.to_string()),
                ),
            ])),
        );
        pyjson::dumps(&Value::Dict(snapshot))
    }
}

/// Writes `text` to `path` through `path` with the extension `.tmp`
/// (1.x's `with_suffix(".tmp")`), creating the directory.
pub fn write_state(path: &Path, text: &str) -> io::Result<()> {
    write_atomic(path, text)
}

/// What starting on the state file found.
pub struct Restored {
    pub inventory: FingerprintInventory,
    /// The file couldn't be restored and was put aside here, and why
    /// (decisions.md, "phase 4e-1": 1.x dies on such a file at every
    /// start, or starts afresh where the file isn't JSON).
    pub broken: Option<(PathBuf, String)>,
}

/// The inventory from the state file at `path`, as 1.x's start restores
/// it; a file that can't be restored is renamed to `<path>.broken` and
/// the inventory starts afresh.
pub fn restore_state(path: &Path, now: f64) -> Restored {
    let why = match read_limited(path, STATE_MAX_BYTES) {
        Ok(None) => {
            return Restored {
                inventory: FingerprintInventory::new(now),
                broken: None,
            };
        }
        Err(e) => e.to_string(),
        Ok(Some(raw)) => match pyjson::loads(&universal_newlines(&raw)) {
            Ok(value) => match FingerprintInventory::restore_checked(Some(&value), now) {
                Some(inventory) => {
                    return Restored {
                        inventory,
                        broken: None,
                    };
                }
                None => "not an inventory 1.x could restore".into(),
            },
            Err(LoadError::Invalid) => "not JSON".into(),
            Err(LoadError::Crash(name)) => format!("unreadable ({name})"),
        },
    };
    Restored {
        inventory: FingerprintInventory::new(now),
        broken: Some(put_aside(path, why)),
    }
}

/// 1.x's `helper_client.quarantine_ip`: the request the daemon sends.
pub fn quarantine_ip(socket: &Path, ip: &str, duration_seconds: i64) -> Result<Value, HelperError> {
    let cmd = Dict(vec![
        ("cmd".into(), Value::Str("quarantine_ip".into())),
        ("ip".into(), Value::Str(ip.into())),
        ("duration_seconds".into(), Value::int(duration_seconds)),
    ]);
    fros_sensor::helper::send_command(
        &cmd,
        socket,
        fros_sensor::helper::TIMEOUT,
        fros_sensor::helper::MAX_LINE_BYTES,
    )
}
