//! `fr-appid`: the application identification daemon
//! (systemd/fr-appid.service; 1.x's `frfw.appid.daemon.main`).
//!
//! Runs as fr_os-sensor from the start: it reads two log files, never
//! the network. While the sensors' view turns on no source it reads the
//! view again every 30 seconds; then it follows the resolver's query log
//! and/or the XDP filter's event file, counts each name of the catalog
//! per app and client, writes the usage file every 30 seconds and reads
//! the view again: when its sources change it starts over as a new
//! process, as 1.x re-executes itself.
//!
//! ```text
//! fr-appid [--view FILE] [--usage FILE] [--dns-log FILE] [--sni-events FILE] [--flush SECONDS]
//! ```
//!
//! The defaults are the router's paths; the options are for tests.

use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fros_appid::daemon::{
    self, AppIdDaemon, CONFIG_POLL_SECONDS, DNS_QUERY_LOG_PATH, FLUSH_SECONDS, SNI_EVENTS_PATH,
    USAGE_PATH, bundled_catalog, restore_usage, view_sources,
};
use fros_sensor::follow::Follower;
use fros_sensor::pyjson;
use fros_sensor::statefile::read_limited;

const VIEW_PATH: &str = "/etc/fr_os/sensor-view.json";
const VIEW_MAX_BYTES: u64 = 1024 * 1024;
const POLL: Duration = Duration::from_millis(500);

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

fn fail(why: String) -> ExitCode {
    eprintln!("fr-appid: {why}");
    ExitCode::from(1)
}

/// The view's sources; `None` while there is no view, or the config
/// was refused (then the sources stay as they are).
fn read_sources(path: &Path) -> Option<Vec<String>> {
    let raw = read_limited(path, VIEW_MAX_BYTES).ok()??;
    view_sources(&pyjson::loads(&raw).ok()?)
}

fn main() -> ExitCode {
    let mut view = PathBuf::from(VIEW_PATH);
    let mut usage = PathBuf::from(USAGE_PATH);
    let mut dns_log = PathBuf::from(DNS_QUERY_LOG_PATH);
    let mut sni_events = PathBuf::from(SNI_EVENTS_PATH);
    let mut flush = FLUSH_SECONDS;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let value = args.next();
        match (a.as_str(), value) {
            ("--view", Some(v)) => view = v.into(),
            ("--usage", Some(v)) => usage = v.into(),
            ("--dns-log", Some(v)) => dns_log = v.into(),
            ("--sni-events", Some(v)) => sni_events = v.into(),
            ("--flush", Some(v)) => match v.parse::<f64>() {
                Ok(s) if s > 0.0 && s.is_finite() => flush = s,
                _ => return fail(format!("--flush: not a number of seconds: {v:?}")),
            },
            _ => {
                return fail(format!(
                    "usage: fr-appid [--view FILE] [--usage FILE] [--dns-log FILE] [--sni-events FILE] \
                     [--flush SECONDS] ({a:?})"
                ));
            }
        }
    }

    let mut announced = false;
    let sources = loop {
        if let Some(s) = read_sources(&view).filter(|s| !s.is_empty()) {
            break s;
        }
        if !announced {
            println!(
                "fr-appid: idle -- needs app_control.enabled plus adblocker.query_logging \
                 and/or app_control.observe_sni; re-checking the configuration periodically"
            );
            announced = true;
        }
        sleep(Duration::from_secs_f64(CONFIG_POLL_SECONDS.min(flush)));
    };
    let restored = restore_usage(&usage);
    if let Some((aside, why)) = &restored.broken {
        eprintln!(
            "fr-appid: {} could not be restored ({why}); put aside as {}, starting afresh",
            usage.display(),
            aside.display()
        );
    }
    let mut d = AppIdDaemon::new(&bundled_catalog(), restored.tracker, sources.clone());
    let mut followers: Vec<(&'static str, Follower)> = Vec::new();
    for source in &sources {
        match source.as_str() {
            "dns" => followers.push(("dns", Follower::new(&dns_log))),
            _ => followers.push(("sni", Follower::new(&sni_events))),
        }
    }
    let names: Vec<String> = followers
        .iter()
        .map(|(_, f)| f.path().display().to_string())
        .collect();
    println!("fr-appid: following {}", names.join(", "));

    let mut next_flush = Instant::now() + Duration::from_secs_f64(flush);
    loop {
        for (source, follower) in &mut followers {
            for line in follower.poll() {
                d.handle_line(source, &line, now());
            }
        }
        if Instant::now() >= next_flush {
            if let Err(e) = daemon::write_usage(&usage, &d.usage_text(now())) {
                // 1.x dies here; this tries again at the next flush.
                eprintln!("fr-appid: writing {}: {e}", usage.display());
            }
            next_flush = Instant::now() + Duration::from_secs_f64(flush);
            if let Some(fresh) = read_sources(&view)
                && fresh != sources
            {
                println!("fr-appid: observation sources changed; restarting");
                let err = std::process::Command::new(
                    std::env::current_exe().unwrap_or_else(|_| "fr-appid".into()),
                )
                .args(std::env::args_os().skip(1))
                .exec();
                return fail(format!("restarting: {err}"));
            }
        }
        sleep(POLL);
    }
}
