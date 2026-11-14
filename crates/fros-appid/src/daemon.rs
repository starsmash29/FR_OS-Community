//! 1.x's `fr-appid` daemon (`frfw.appid.daemon.AppIdDaemon`, phase 16)
//! without its threads: the sources the sensors' view turns on, each
//! line handed to the observer, the usage file restored at start and
//! written every flush. `fr-appid` (src/bin) runs it on the router;
//! tests/daemon.rs replays 1.x's recorded runs (sensord.jsonl).

use std::io;
use std::path::{Path, PathBuf};

use fros_sensor::pyjson::{self, LoadError, Value};
use fros_sensor::statefile::{put_aside, read_limited, universal_newlines, write_atomic};

use crate::catalog::{Catalog, parse_catalog};
use crate::observer::{AppIdObserver, parse_dns_query_line, parse_sni_event_line};
use crate::usage::UsageTracker;

/// How often the usage file is written and the view read again.
pub const FLUSH_SECONDS: f64 = 30.0;
/// How often an idle daemon reads the view again.
pub const CONFIG_POLL_SECONDS: f64 = 30.0;

pub const USAGE_PATH: &str = "/etc/fr_os/sensors/appid_usage.json";
pub const DNS_QUERY_LOG_PATH: &str = "/var/log/fr_os-dns/queries.log";
pub const SNI_EVENTS_PATH: &str = "/var/log/fr_os-sni/events.jsonl";

/// A usage file past this is put aside unread: 1.x writes at most 512
/// clients per app.
pub const USAGE_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// The bundled catalog (1.x's `frfw/appid/signatures.json`, the same
/// file the Go side reads).
pub fn bundled_catalog() -> Catalog {
    let raw = include_bytes!("../../../appid/signatures.json");
    let value = pyjson::loads(raw).expect("the bundled catalog is JSON");
    parse_catalog(&value).expect("the bundled catalog parses")
}

/// fr-appid's part of the sensors' view: the sources it follows, "dns"
/// and/or "sni" (1.x's `source_units`); `None` if the view has none.
pub fn view_sources(view: &Value) -> Option<Vec<String>> {
    let Value::Dict(top) = view else { return None };
    let Some(Value::Dict(app)) = top.get("app_control") else {
        return None;
    };
    let Some(Value::List(sources)) = app.get("sources") else {
        return None;
    };
    Some(
        sources
            .iter()
            .filter_map(|s| match s {
                Value::Str(s) if s == "dns" || s == "sni" => Some(s.clone()),
                _ => None,
            })
            .collect(),
    )
}

pub struct AppIdDaemon {
    observer: AppIdObserver,
    sources: Vec<String>,
}

impl AppIdDaemon {
    pub fn new(catalog: &Catalog, tracker: UsageTracker, sources: Vec<String>) -> Self {
        Self {
            observer: AppIdObserver::new(catalog, tracker),
            sources,
        }
    }

    pub fn sources(&self) -> &[String] {
        &self.sources
    }

    /// One line of `source`'s log ("dns": the resolver's query log,
    /// "sni": the XDP filter's event file); a source the view doesn't
    /// turn on isn't read. The app it was attributed to, if any.
    pub fn handle_line(&mut self, source: &str, line: &str, now: f64) -> Option<String> {
        if !self.sources.iter().any(|s| s == source) {
            return None;
        }
        let observation = match source {
            "dns" => parse_dns_query_line(line)?,
            _ => parse_sni_event_line(line)?,
        };
        self.observer.observe_line(&observation, now)
    }

    /// The usage file's text at `now` (1.x's `json.dumps(snapshot)`).
    pub fn usage_text(&mut self, now: f64) -> String {
        pyjson::dumps(&self.observer.tracker.snapshot(now))
    }
}

pub fn write_usage(path: &Path, text: &str) -> io::Result<()> {
    write_atomic(path, text)
}

/// What starting on the usage file found.
pub struct Restored {
    pub tracker: UsageTracker,
    /// The file couldn't be restored and was put aside here, and why
    /// (decisions.md, "phase 4e-2": 1.x dies on such a file at every
    /// start).
    pub broken: Option<(PathBuf, String)>,
}

/// The usage counts in the file at `path`, as 1.x's start restores
/// them: a file that isn't JSON, or holds no usage, starts empty (as in
/// 1.x); one 1.x dies on, or one past the size limit, is renamed to
/// `<path>.broken` and the counts start empty.
pub fn restore_usage(path: &Path) -> Restored {
    let why = match read_limited(path, USAGE_MAX_BYTES) {
        Ok(None) => {
            return Restored {
                tracker: UsageTracker::new(),
                broken: None,
            };
        }
        Err(e) => e.to_string(),
        Ok(Some(raw)) => {
            let value = match pyjson::loads(&universal_newlines(&raw)) {
                Ok(v) => Ok(Some(v)),
                Err(LoadError::Invalid) => Ok(None),
                Err(LoadError::Crash(name)) => Err(format!("unreadable ({name})")),
            };
            match value.and_then(|v| {
                UsageTracker::restore(v.as_ref())
                    .map_err(|c| format!("not usage 1.x could restore ({})", c.0))
            }) {
                Ok(tracker) => {
                    return Restored {
                        tracker,
                        broken: None,
                    };
                }
                Err(why) => why,
            }
        }
    };
    Restored {
        tracker: UsageTracker::new(),
        broken: Some(put_aside(path, why)),
    }
}
