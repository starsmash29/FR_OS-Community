//! `fr-tls-fp`: the TLS client fingerprinting daemon
//! (systemd/fr-tls-fp.service; 1.x's `frfw.tlsfp.daemon.main`).
//!
//! As root, it waits until the sensors' view turns fingerprinting on and
//! the XDP program's `hello_pkts` ring buffer is pinned; it opens that
//! (CAP_BPF) and becomes fr_os-sensor for good before reading a byte of
//! packet data (security-lessons I1). Then it fingerprints every
//! ClientHello the program copies (crate::daemon), writes the inventory
//! every 30 seconds, and reads the view again: off, it exits. A replaced
//! program can't be reopened without root, so an apply restarts it.
//!
//! ```text
//! fr-tls-fp [--map PIN] [--view FILE] [--state FILE] [--socket PATH] [--flush SECONDS]
//! ```
//!
//! The defaults are the router's paths; the options are for tests.

use std::path::PathBuf;
use std::process::ExitCode;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fros_sensor::helper::APPLY_SOCKET_PATH;
use fros_tlsfp::daemon::{self, Daemon, FLUSH_SECONDS, STATE_PATH, Segment, View, restore_state};
use fros_xdp::events::HelloSegment;
use fros_xdp::privdrop::{SENSOR_USER, drop_privileges, is_root};
use fros_xdp::ring::Reader;

const HELLO_PIN: &str = "/sys/fs/bpf/fr_os_xdp/maps/hello_pkts";
const VIEW_PATH: &str = "/etc/fr_os/sensor-view.json";
const VIEW_POLL: Duration = Duration::from_secs(30);

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

fn fail(why: String) -> ExitCode {
    eprintln!("fr-tls-fp: {why}");
    ExitCode::from(1)
}

fn main() -> ExitCode {
    let mut map = PathBuf::from(HELLO_PIN);
    let mut view_path = PathBuf::from(VIEW_PATH);
    let mut state = PathBuf::from(STATE_PATH);
    let mut socket = PathBuf::from(APPLY_SOCKET_PATH);
    let mut flush = FLUSH_SECONDS;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let value = args.next();
        match (a.as_str(), value) {
            ("--map", Some(v)) => map = v.into(),
            ("--view", Some(v)) => view_path = v.into(),
            ("--state", Some(v)) => state = v.into(),
            ("--socket", Some(v)) => socket = v.into(),
            ("--flush", Some(v)) => match v.parse::<f64>() {
                Ok(s) if s > 0.0 && s.is_finite() => flush = s,
                _ => return fail(format!("--flush: not a number of seconds: {v:?}")),
            },
            _ => {
                return fail(format!(
                    "usage: fr-tls-fp [--map PIN] [--view FILE] [--state FILE] [--socket PATH] [--flush SECONDS] ({a:?})"
                ));
            }
        }
    }

    // As root: wait until fingerprinting is on and the buffer exists.
    // Nothing untrusted is read here.
    let mut announced = false;
    let view = loop {
        if let Some(v) = View::read(&view_path).filter(|v| v.enabled)
            && map.exists()
        {
            break v;
        }
        if !announced {
            println!("fr-tls-fp: idle until tls_fingerprint.enabled and the XDP filter is loaded");
            announced = true;
        }
        sleep(VIEW_POLL);
    };
    let mut reader = match Reader::open(&map) {
        Ok(r) => r,
        Err(e) => return fail(e),
    };
    // No privileges from here on.
    if is_root() {
        match drop_privileges(SENSOR_USER) {
            Ok(_) => {}
            Err(e) => return fail(e),
        }
    }
    let restored = restore_state(&state, now());
    if let Some((aside, why)) = &restored.broken {
        eprintln!(
            "fr-tls-fp: {} could not be restored ({why}); put aside as {}, starting afresh",
            state.display(),
            aside.display()
        );
    }
    let mut d = Daemon::new(view, restored.inventory);
    println!(
        "fr-tls-fp: running as uid {}, fingerprinting ClientHellos",
        nix::unistd::getuid()
    );

    let mut quarantine = |ip: &str, duration: i64| daemon::quarantine_ip(&socket, ip, duration);
    let mut next_flush = Instant::now() + Duration::from_secs_f64(flush);
    loop {
        let polled = reader.poll(500, |raw| {
            let Ok(seg) = HelloSegment::from_bytes(raw) else {
                return; // 1.x's reader drops a record it can't decode
            };
            let seg = Segment {
                saddr: &seg.saddr,
                sport: seg.sport,
                daddr: &seg.daddr,
                dport: seg.dport,
                seq: seg.seq,
                first: seg.first,
                payload: &seg.payload,
            };
            d.handle_segment(&seg, now(), &mut quarantine);
        });
        if let Err(e) = polled {
            return fail(e);
        }
        if Instant::now() >= next_flush {
            if let Err(e) = daemon::write_state(&state, &d.state_text(now())) {
                // 1.x dies here and loses what it held; this keeps it
                // and tries again at the next flush (decisions.md).
                eprintln!("fr-tls-fp: writing {}: {e}", state.display());
            }
            next_flush = Instant::now() + Duration::from_secs_f64(flush);
            if let Some(fresh) = View::read(&view_path) {
                if !fresh.enabled {
                    println!("fr-tls-fp: disabled in config; exiting");
                    return ExitCode::SUCCESS;
                }
                d.update_view(fresh);
            }
        }
    }
}
