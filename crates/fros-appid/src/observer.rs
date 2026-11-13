//! What 1.x's `fr-appid` daemon does with each log line
//! (`frfw.appid.daemon.AppIdDaemon`), without the threads and files:
//! read a name out of a resolver query line or an XDP SNI event, match
//! it, and count it once per client, name and source within ten seconds.

use std::collections::HashMap;

use fros_sensor::dnsmasq::dnsmasq_message;
use fros_sensor::pyjson::{self, LoadError, Value};
use fros_sensor::pytext::{self, is_decimal, is_space};

use crate::catalog::{AppMatcher, Catalog};
use crate::usage::UsageTracker;

/// Repeated observations of one name by one client through one source
/// within this many seconds count once: a browser asks for the A, AAAA
/// and HTTPS records of every name at the same moment.
pub const DEDUP_SECONDS: f64 = 10.0;
const DEDUP_MAX_ENTRIES: usize = 20_000;

/// Record types that say nothing about which app a client is about to use.
const IGNORED_QTYPES: [&str; 5] = ["PTR", "SOA", "NS", "SRV", "TXT"];

/// One name seen in a log: who asked, what, and through which source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub client: String,
    pub name: String,
    pub source: &'static str,
}

struct Scan<'a> {
    s: &'a str,
    pos: usize,
}

impl<'a> Scan<'a> {
    fn new(s: &'a str) -> Self {
        Self { s, pos: 0 }
    }

    /// One or more characters `ok` accepts; the run, or `None`.
    fn run(&mut self, ok: impl Fn(char) -> bool) -> Option<&'a str> {
        let rest = &self.s[self.pos..];
        let len = rest.find(|c: char| !ok(c)).unwrap_or(rest.len());
        if len == 0 {
            return None;
        }
        self.pos += len;
        Some(&rest[..len])
    }

    fn lit(&mut self, text: &str) -> Option<()> {
        if self.s[self.pos..].starts_with(text) {
            self.pos += text.len();
            Some(())
        } else {
            None
        }
    }

    /// Python's `$`: the end, or a final newline.
    fn end(&self) -> bool {
        matches!(&self.s[self.pos..], "" | "\n")
    }
}

fn non_space(c: char) -> bool {
    !is_space(c)
}

fn address_char(c: char) -> bool {
    c.is_ascii_hexdigit() || c == ':' || c == '.'
}

/// A dnsmasq `log-queries=extra` query line (with or without its
/// timestamp prefix), as 1.x's
/// `^\d+ (client)/\d+ query\[(qtype)\] (name) from \S+$`:
/// `2 10.0.0.5/46381 query[A] www.netflix.com from 10.0.0.5`.
/// `None` for any other line, and for record types that name no app.
pub fn parse_dns_query_line(line: &str) -> Option<Observation> {
    let mut s = Scan::new(dnsmasq_message(line));
    s.run(is_decimal)?;
    s.lit(" ")?;
    let client = s.run(address_char)?;
    s.lit("/")?;
    s.run(is_decimal)?;
    s.lit(" query[")?;
    let qtype = s.run(|c| c.is_ascii_alphanumeric())?;
    s.lit("] ")?;
    let name = s.run(non_space)?;
    s.lit(" from ")?;
    s.run(non_space)?;
    if !s.end() || IGNORED_QTYPES.contains(&qtype.to_ascii_uppercase().as_str()) {
        return None;
    }
    Some(Observation {
        client: client.to_owned(),
        name: name.to_owned(),
        source: "dns",
    })
}

/// One line of the XDP SNI logger's event file: both passes and drops
/// count (a dropped connection is still an attempt to use the app).
/// Malformed lines are `None`; so is one nested too deep for Python's
/// recursion limit, which ended 1.x's reader thread (decisions.md).
pub fn parse_sni_event_line(line: &str) -> Option<Observation> {
    let event = match pyjson::loads(line.as_bytes()) {
        Ok(Value::Dict(d)) => d,
        Ok(_) | Err(LoadError::Invalid | LoadError::Crash(_)) => return None,
    };
    match event.get("action") {
        Some(Value::Str(a)) if a == "pass" || a == "drop" => {}
        _ => return None,
    }
    match (event.get("saddr"), event.get("sni")) {
        (Some(Value::Str(client)), Some(Value::Str(sni)))
            if !client.is_empty() && !sni.is_empty() =>
        {
            Some(Observation {
                client: client.clone(),
                name: sni.clone(),
                source: "sni",
            })
        }
        _ => None,
    }
}

/// The matcher, the usage tracker and the de-duplication table.
pub struct AppIdObserver {
    pub matcher: AppMatcher,
    pub tracker: UsageTracker,
    recent: HashMap<(String, String, &'static str), f64>,
}

impl AppIdObserver {
    pub fn new(catalog: &Catalog, tracker: UsageTracker) -> Self {
        Self {
            matcher: AppMatcher::new(catalog),
            tracker,
            recent: HashMap::new(),
        }
    }

    /// How many (client, name, source) keys the table remembers.
    pub fn remembered(&self) -> usize {
        self.recent.len()
    }

    /// Attribute one observed name at `now`; the app id, if any.
    pub fn observe(
        &mut self,
        client: &str,
        name: &str,
        source: &'static str,
        now: f64,
    ) -> Option<String> {
        let app_id = self.matcher.matches(name)?.to_owned();
        let key = (client.to_owned(), pytext::lower(name), source);
        if let Some(&last) = self.recent.get(&key)
            && now - last < DEDUP_SECONDS
        {
            return Some(app_id);
        }
        self.recent.insert(key, now);
        if self.recent.len() > DEDUP_MAX_ENTRIES {
            self.recent.retain(|_, &mut t| now - t < DEDUP_SECONDS);
        }
        self.tracker.record(&app_id, client, source, now);
        Some(app_id)
    }

    pub fn observe_line(&mut self, observation: &Observation, now: f64) -> Option<String> {
        self.observe(
            &observation.client,
            &observation.name,
            observation.source,
            now,
        )
    }
}
