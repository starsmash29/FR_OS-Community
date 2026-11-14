//! `fr-iot-scan`: one IoT scan (systemd/fr-iot-scan.service, started
//! by fr-iot-scan.timer and by the webUI's "Scan now"; 1.x's
//! `frfw.iot.scanner.main`).
//!
//! Runs as fr_os-sensor with no capability: it parses mDNS answers and
//! DHCP hostnames, which any LAN host shapes, so reading Kea's leases
//! and changing the kernel's `iot_isolated` set go through the
//! apply-helper. It reads the IoT part of the sensors' view, never
//! config.yaml (ROADMAP SEC-11), prints the scan's messages and exits
//! 1 when one of them is an error.
//!
//! Where 1.x's scan dies on a helper reply (decided, phase 4e-3) this
//! prints `error: scan failed: <exception>`, exits 1 and leaves the
//! last inventory as it was.
//!
//! ```text
//! fr-iot-scan [--view FILE] [--state FILE] [--socket FILE] [--arp FILE] [--oui FILE]
//!             [--mdns-target IP:PORT] [--mdns-port PORT] [--mdns-timeout SECONDS]
//! ```
//!
//! The defaults are the router's; the options are for tests.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fros_iot::scan::{View, run_scan};
use fros_iot::system::{INVENTORY_PATH, SystemIo, write_inventory};
use fros_sensor::pyjson::{self, Value};
use fros_sensor::statefile::read_limited;

const VIEW_PATH: &str = "/etc/fr_os/sensor-view.json";
const VIEW_MAX_BYTES: u64 = 1024 * 1024;

fn error(why: String) -> ExitCode {
    println!("error: {why}");
    ExitCode::from(1)
}

/// The view's `iot` member.
fn read_view(path: &Path) -> Result<View, String> {
    let raw = match read_limited(path, VIEW_MAX_BYTES) {
        Ok(Some(raw)) => raw,
        Ok(None) => return Err(format!("no sensor view at {}", path.display())),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let top = pyjson::loads(&raw).map_err(|_| format!("{} is not JSON", path.display()))?;
    let Value::Dict(top) = top else {
        return Err(format!("{} is not a JSON object", path.display()));
    };
    if let Some(Value::Str(message)) = top.get("config_error") {
        return Err(format!("the configuration was refused: {message}"));
    }
    let iot = top
        .get("iot")
        .ok_or_else(|| format!("{} has no iot member", path.display()))?;
    View::from_json(iot).map_err(|e| format!("{}: bad iot.{}", path.display(), e.0))
}

fn main() -> ExitCode {
    let mut view = PathBuf::from(VIEW_PATH);
    let mut state = PathBuf::from(INVENTORY_PATH);
    let mut io = SystemIo::default();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let value = args.next();
        match (a.as_str(), value) {
            ("--view", Some(v)) => view = v.into(),
            ("--state", Some(v)) => state = v.into(),
            ("--socket", Some(v)) => io.socket = v.into(),
            ("--arp", Some(v)) => io.arp = v.into(),
            ("--oui", Some(v)) => io.oui = v.into(),
            ("--mdns-target", Some(v)) => match v.parse() {
                Ok(t) => io.mdns.target = t,
                Err(_) => return error(format!("--mdns-target: not IP:PORT: {v:?}")),
            },
            ("--mdns-port", Some(v)) => match v.parse() {
                Ok(p) => io.mdns.bind_port = p,
                Err(_) => return error(format!("--mdns-port: not a port: {v:?}")),
            },
            ("--mdns-timeout", Some(v)) => match v.parse::<f64>() {
                Ok(s) if s > 0.0 && s < 600.0 => io.mdns.timeout = Duration::from_secs_f64(s),
                _ => return error(format!("--mdns-timeout: not a number of seconds: {v:?}")),
            },
            _ => {
                return error(format!(
                    "usage: fr-iot-scan [--view FILE] [--state FILE] [--socket FILE] [--arp FILE] \
                     [--oui FILE] [--mdns-target IP:PORT] [--mdns-port PORT] [--mdns-timeout SECONDS] \
                     ({a:?})"
                ));
            }
        }
    }

    let view = match read_view(&view) {
        Ok(v) => v,
        Err(why) => return error(why),
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64());
    let result = match run_scan(&view, &mut io, now) {
        Ok(r) => r,
        Err(crash) => return error(format!("scan failed: {}", crash.0)),
    };
    let written = match &result.state {
        Some(text) => write_inventory(&state, text),
        None => Ok(()),
    };
    for message in &result.messages {
        println!("{message}");
    }
    if let Err(e) = written {
        return error(format!("writing {}: {e}", state.display()));
    }
    if result.messages.iter().any(|m| m.starts_with("error:")) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
