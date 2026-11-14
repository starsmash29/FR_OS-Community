//! `fr-xdp-sni-logger`: the XDP SNI filter's event logger
//! (systemd/fr-xdp-sni-logger.service; 1.x's `frfw.xdp.run_event_logger`).
//!
//! Opens the event file the webUI and the sensor daemons read (ROADMAP
//! SEC-4) while still root, so the file is root's and only this process
//! can write it; waits until the filter's pinned `events` ring buffer
//! exists (only once an apply has turned the filter on); opens it
//! (CAP_BPF) and becomes fr_os-sensor for good before the first event
//! (security-lessons I1); then logs every event, one JSON line each, to
//! the file and to stdout (the journal). It exits when the ring buffer
//! can't be read, and systemd starts it again, on the program an apply
//! replaced too.
//!
//! ```text
//! fr-xdp-sni-logger [--map PIN] [--events FILE]
//! ```
//!
//! The defaults are the router's paths; the options are for tests.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fros_xdp::events::{EventFile, SNI_EVENTS_MAX_BYTES, SniEvent, format_event_json};
use fros_xdp::privdrop::{SENSOR_USER, drop_privileges, is_root};
use fros_xdp::ring::Reader;

const EVENTS_PIN: &str = "/sys/fs/bpf/fr_os_xdp/maps/events";
const EVENTS_PATH: &str = "/var/log/fr_os-sni/events.jsonl";

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

fn fail(why: String) -> ExitCode {
    eprintln!("fr-xdp-sni-logger: {why}");
    ExitCode::from(1)
}

fn main() -> ExitCode {
    let mut map = PathBuf::from(EVENTS_PIN);
    let mut events = PathBuf::from(EVENTS_PATH);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let value = args.next().map(PathBuf::from);
        match (a.as_str(), value) {
            ("--map", Some(v)) => map = v,
            ("--events", Some(v)) => events = v,
            _ => {
                return fail(format!(
                    "usage: fr-xdp-sni-logger [--map PIN] [--events FILE] ({a:?})"
                ));
            }
        }
    }

    let mut file = match EventFile::open(&events, SNI_EVENTS_MAX_BYTES) {
        Ok(f) => f,
        Err(e) => return fail(format!("{}: {e}", events.display())),
    };
    while !map.exists() {
        sleep(Duration::from_secs(2));
    }
    let mut reader = match Reader::open(&map) {
        Ok(r) => r,
        Err(e) => return fail(e),
    };
    // Opening the pinned map needed root (CAP_BPF); reading it doesn't.
    if is_root()
        && let Err(e) = drop_privileges(SENSOR_USER)
    {
        return fail(e);
    }
    let stdout = std::io::stdout();
    loop {
        let mut failed = None;
        let polled = reader.poll(500, |raw| {
            let Ok(event) = SniEvent::from_bytes(raw) else {
                return; // 1.x's reader drops a record it can't decode
            };
            let line = format_event_json(&event, now());
            if let Err(e) = file.write_line(&line) {
                failed = Some(format!("{}: {e}", events.display()));
            }
            let mut out = stdout.lock();
            let _ = writeln!(out, "{line}").and_then(|()| out.flush());
        });
        if let Some(e) = failed {
            return fail(e);
        }
        if let Err(e) = polled {
            return fail(e);
        }
    }
}
