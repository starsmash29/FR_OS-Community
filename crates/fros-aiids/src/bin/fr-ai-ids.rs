//! `fr-ai-ids`: the AI-IDS daemon (systemd/fr-ai-ids.service; 1.x's
//! `frfw.ai_ids.daemon.main`).
//!
//! Runs as fr_os-sensor from the start. It follows the XDP filter's
//! event file and, when the resolver writes it, its query log; every 5
//! seconds it asks the apply-helper for a conntrack sample, and once a
//! window it scores every host and asks the apply-helper to quarantine
//! the flagged ones. With `ai_ids.enabled` off it exits, as 1.x does.
//!
//! Unlike 1.x, which reads its configuration once at start, it reads
//! the sensors' view again at every window and, when its part has
//! changed, starts over as a new process (decisions.md, "phase 4e-2"):
//! a changed exclusion or quarantine time takes effect without a
//! restart by hand.
//!
//! ```text
//! fr-ai-ids [--view FILE] [--events FILE] [--dns-log FILE] [--sni-events FILE]
//!           [--socket FILE] [--route FILE] [--resolv FILE] [--window SECONDS] [--tick SECONDS]
//! ```
//!
//! The defaults are the router's paths; the options are for tests.

use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fros_aiids::AnomalyEngine;
use fros_aiids::daemon::{
    DNS_QUERY_LOG_PATH, IdsDaemon, IdsView, Paths, SNI_EVENTS_PATH, SocketHelper, Stream,
    TICK_SECONDS,
};
use fros_aiids::engine::{WINDOW_SECONDS, ZSCORE_THRESHOLD};
use fros_sensor::follow::Follower;
use fros_sensor::helper::APPLY_SOCKET_PATH;

const VIEW_PATH: &str = "/etc/fr_os/sensor-view.json";
const POLL: Duration = Duration::from_millis(500);

fn wall() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

fn fail(why: String) -> ExitCode {
    eprintln!("fr-ai-ids: {why}");
    ExitCode::from(1)
}

fn seconds(name: &str, v: &str) -> Result<f64, String> {
    match v.parse::<f64>() {
        Ok(s) if s > 0.0 && s.is_finite() => Ok(s),
        _ => Err(format!("{name}: not a number of seconds: {v:?}")),
    }
}

fn flush_log(d: &mut IdsDaemon) {
    for (stream, line) in d.take_log() {
        match stream {
            Stream::Out => println!("{line}"),
            Stream::Err => eprintln!("{line}"),
        }
    }
}

fn main() -> ExitCode {
    let mut view_path = PathBuf::from(VIEW_PATH);
    let mut paths = Paths::default();
    let mut dns_log = PathBuf::from(DNS_QUERY_LOG_PATH);
    let mut sni_events = PathBuf::from(SNI_EVENTS_PATH);
    let mut socket = PathBuf::from(APPLY_SOCKET_PATH);
    let mut window = WINDOW_SECONDS;
    let mut tick = TICK_SECONDS;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let value = args.next();
        match (a.as_str(), value) {
            ("--view", Some(v)) => view_path = v.into(),
            ("--events", Some(v)) => paths.events = v.into(),
            ("--dns-log", Some(v)) => dns_log = v.into(),
            ("--sni-events", Some(v)) => sni_events = v.into(),
            ("--socket", Some(v)) => socket = v.into(),
            ("--route", Some(v)) => paths.route = v.into(),
            ("--resolv", Some(v)) => paths.resolv = v.into(),
            ("--window", Some(v)) => match seconds("--window", &v) {
                Ok(s) => window = s,
                Err(why) => return fail(why),
            },
            ("--tick", Some(v)) => match seconds("--tick", &v) {
                Ok(s) => tick = s,
                Err(why) => return fail(why),
            },
            _ => {
                return fail(format!(
                    "usage: fr-ai-ids [--view FILE] [--events FILE] [--dns-log FILE] [--sni-events FILE] \
                     [--socket FILE] [--route FILE] [--resolv FILE] [--window SECONDS] [--tick SECONDS] ({a:?})"
                ));
            }
        }
    }

    // A missing view, or one written from a refused config, is 1.x's
    // "cannot load": exit, and systemd tries again.
    let Some(view) = IdsView::read(&view_path) else {
        return fail(format!(
            "cannot load the ai_ids settings from {}",
            view_path.display()
        ));
    };
    if !view.enabled {
        println!("fr-ai-ids: ai_ids.enabled is false in config.yaml; exiting");
        return ExitCode::SUCCESS;
    }
    let mut followers: Vec<(&'static str, Follower)> = vec![("sni", Follower::new(&sni_events))];
    if view.query_log {
        followers.push(("dns", Follower::new(&dns_log)));
    }
    let mut d = IdsDaemon::new(view, AnomalyEngine::new(window, ZSCORE_THRESHOLD), paths);
    let mut helper = SocketHelper(&socket);
    let started = Instant::now();
    let clock = || started.elapsed().as_secs_f64();

    let mut next_tick = clock() + tick;
    let mut next_eval = clock() + window;
    loop {
        for (source, follower) in &mut followers {
            for line in follower.poll() {
                match *source {
                    "sni" => d.handle_sni_event_line(&line, clock()),
                    _ => d.handle_dns_log_line(&line, clock()),
                }
            }
        }
        if clock() >= next_tick {
            d.poll_conntrack(&mut helper, clock());
            next_tick = clock() + tick;
            if clock() >= next_eval {
                d.evaluate_and_enforce(&mut helper, clock(), wall());
                next_eval = clock() + window;
                // Kept as it is while the view is missing or refused.
                if let Some(fresh) = IdsView::read(&view_path)
                    && fresh != *d.view()
                {
                    flush_log(&mut d);
                    println!("fr-ai-ids: ai_ids settings changed; restarting");
                    let err = std::process::Command::new(
                        std::env::current_exe().unwrap_or_else(|_| "fr-ai-ids".into()),
                    )
                    .args(std::env::args_os().skip(1))
                    .exec();
                    return fail(format!("restarting: {err}"));
                }
            }
            flush_log(&mut d);
        }
        sleep(POLL);
    }
}
