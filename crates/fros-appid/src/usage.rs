//! Per-app, per-client usage accounting (1.x's `frfw.appid.usage`).
//!
//! A hit is one observation that a client used an app: one lookup of one
//! of its names, or one TLS connection whose SNI was one. Counts are
//! kept in hourly buckets for a day, so the summary survives a restart
//! through the state file and never grows without bound.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use fros_sensor::ordered::{OrderedMap, py_max, py_min_by};
use fros_sensor::pyfloat::{cmp_int_float, floor_div, to_i128};
use fros_sensor::pyjson::{Dict, PyError, Value, py_float, py_int};

pub const BUCKET_SECONDS: f64 = 3600.0;
pub const RETENTION_SECONDS: f64 = 24.0 * 3600.0;
pub const ACTIVE_WINDOW_SECONDS: f64 = 15.0 * 60.0;

/// Upper bound on distinct clients tracked per app; beyond it the least
/// recently seen client is forgotten (a flood of spoofed sources must
/// not grow the daemon's memory without limit).
pub const MAX_CLIENTS_PER_APP: usize = 512;

pub const SOURCES: [&str; 2] = ["dns", "sni"];

#[derive(Debug, Clone)]
struct ClientUsage {
    first_seen: f64,
    last_seen: f64,
    /// Bucket start -> hits. 1.x's ints are unbounded; the ones a state
    /// file can hold here are i128 (decisions.md).
    buckets: BTreeMap<i128, i128>,
    sources: BTreeSet<String>,
}

impl ClientUsage {
    fn hits(&self) -> i128 {
        self.buckets
            .values()
            .fold(0i128, |sum, &n| sum.saturating_add(n))
    }
}

/// What 1.x's `UsageTracker.restore` would raise instead of skipping a
/// row: its daemon does not start then.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreCrash(pub &'static str);

#[derive(Debug, Clone, Default)]
pub struct UsageTracker {
    apps: OrderedMap<String, OrderedMap<String, ClientUsage>>,
}

impl UsageTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// One hit. `now` comes from the clock; a non-finite one (1.x would
    /// raise) is ignored.
    pub fn record(&mut self, app_id: &str, client: &str, source: &str, now: f64) {
        if !now.is_finite() {
            return;
        }
        if !self.apps.contains_key(&app_id.to_owned()) {
            self.apps.insert(app_id.to_owned(), OrderedMap::new());
        }
        let Some(clients) = self.apps.get_mut(&app_id.to_owned()) else {
            return;
        };
        let key = client.to_owned();
        if !clients.contains_key(&key) {
            if clients.len() >= MAX_CLIENTS_PER_APP
                && let Some(oldest) = py_min_by(clients.iter(), |u| u.last_seen)
            {
                let oldest = oldest.clone();
                clients.remove(&oldest);
            }
            clients.insert(
                key.clone(),
                ClientUsage {
                    first_seen: now,
                    last_seen: now,
                    buckets: BTreeMap::new(),
                    sources: BTreeSet::new(),
                },
            );
        }
        let Some(usage) = clients.get_mut(&key) else {
            return;
        };
        // Python's max(a, b): b only if it is greater.
        if now > usage.last_seen {
            usage.last_seen = now;
        }
        let bucket = to_i128(floor_div(now, BUCKET_SECONDS))
            .unwrap_or(0)
            .saturating_mul(3600);
        let n = usage.buckets.entry(bucket).or_insert(0);
        *n = n.saturating_add(1);
        usage.sources.insert(source.to_owned());
    }

    pub fn prune(&mut self, now: f64) {
        // A bucket is kept while any part of it is inside the window.
        let cutoff = now - RETENTION_SECONDS - BUCKET_SECONDS;
        let app_ids: Vec<String> = self.apps.keys().cloned().collect();
        for app_id in app_ids {
            let Some(clients) = self.apps.get_mut(&app_id) else {
                continue;
            };
            let names: Vec<String> = clients.keys().cloned().collect();
            for client in names {
                let Some(usage) = clients.get_mut(&client) else {
                    continue;
                };
                usage
                    .buckets
                    .retain(|&b, _| cmp_int_float(b, cutoff) == Some(Ordering::Greater));
                if usage.buckets.is_empty() {
                    clients.remove(&client);
                }
            }
            if clients.is_empty() {
                self.apps.remove(&app_id);
            }
        }
    }

    /// The summary, also the state file (`pyjson::dumps` of it is what
    /// 1.x writes). Prunes first, as 1.x does.
    pub fn snapshot(&mut self, now: f64) -> Value {
        self.prune(now);
        let mut app_ids: Vec<&String> = self.apps.keys().collect();
        app_ids.sort();
        let mut apps = Dict::default();
        for app_id in app_ids {
            let Some(clients) = self.apps.get(app_id) else {
                continue;
            };
            let mut names: Vec<(&String, &ClientUsage)> = clients.iter().collect();
            names.sort_by(|a, b| a.0.cmp(b.0));
            let mut rows = Dict::default();
            let mut hits: i128 = 0;
            let mut active_clients: i64 = 0;
            let mut last_seen: Vec<f64> = Vec::new();
            for (client, usage) in names {
                let active = now - usage.last_seen <= ACTIVE_WINDOW_SECONDS;
                hits = hits.saturating_add(usage.hits());
                active_clients += i64::from(active);
                last_seen.push(usage.last_seen);
                let mut buckets = Dict::default();
                for (b, n) in &usage.buckets {
                    buckets.insert(b.to_string(), Value::Int(n.to_string()));
                }
                let row = Dict(vec![
                    ("hits_24h".into(), Value::Int(usage.hits().to_string())),
                    ("first_seen".into(), Value::Float(usage.first_seen)),
                    ("last_seen".into(), Value::Float(usage.last_seen)),
                    ("active".into(), Value::Bool(active)),
                    (
                        "sources".into(),
                        Value::List(
                            usage
                                .sources
                                .iter()
                                .map(|s| Value::Str(s.clone()))
                                .collect(),
                        ),
                    ),
                    ("buckets".into(), Value::Dict(buckets)),
                ]);
                rows.insert(client.clone(), Value::Dict(row));
            }
            let app = Dict(vec![
                ("hits_24h".into(), Value::Int(hits.to_string())),
                ("active_clients".into(), Value::int(active_clients)),
                (
                    "last_seen".into(),
                    Value::Float(py_max(last_seen.into_iter()).unwrap_or(f64::NAN)),
                ),
                ("clients".into(), Value::Dict(rows)),
            ]);
            apps.insert(app_id.clone(), Value::Dict(app));
        }
        Value::Dict(Dict(vec![
            ("generated".into(), Value::Float(now)),
            ("apps".into(), Value::Dict(apps)),
        ]))
    }

    /// Rebuild from a previous snapshot (`None`: no file, or not JSON).
    /// Anything malformed is skipped, as in 1.x; the exceptions 1.x does
    /// not catch are `Err`, so the caller can tell (it starts empty).
    pub fn restore(data: Option<&Value>) -> Result<Self, RestoreCrash> {
        let mut tracker = Self::new();
        let Some(Value::Dict(data)) = data else {
            return Ok(tracker);
        };
        let Some(Value::Dict(apps)) = data.get("apps") else {
            return Ok(tracker);
        };
        for (app_id, app) in &apps.0 {
            let Value::Dict(app) = app else { continue };
            let Some(Value::Dict(clients)) = app.get("clients") else {
                continue;
            };
            for (client, row) in &clients.0 {
                match restore_row(row)? {
                    Some(usage) if !usage.buckets.is_empty() => {
                        if !tracker.apps.contains_key(app_id) {
                            tracker.apps.insert(app_id.clone(), OrderedMap::new());
                        }
                        if let Some(rows) = tracker.apps.get_mut(app_id) {
                            rows.insert(client.clone(), usage);
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(tracker)
    }
}

/// Python's conversion errors in 1.x's restore: Type/ValueError skip the
/// row, OverflowError is not caught.
fn caught<T>(r: Result<T, PyError>) -> Result<Option<T>, RestoreCrash> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(PyError::OverflowError) => Err(RestoreCrash("OverflowError")),
        Err(_) => Ok(None),
    }
}

/// One client row, in the order 1.x evaluates it; `Ok(None)` skips it.
fn restore_row(row: &Value) -> Result<Option<ClientUsage>, RestoreCrash> {
    let Value::Dict(row) = row else {
        return Ok(None); // TypeError
    };
    let (Some(first), Some(last)) = (row.get("first_seen"), row.get("last_seen")) else {
        // KeyError -- but a first_seen that overflows raises first.
        if let Some(first) = row.get("first_seen") {
            caught(py_float(first))?;
        }
        return Ok(None);
    };
    let Some(first_seen) = caught(py_float(first))? else {
        return Ok(None);
    };
    let Some(last_seen) = caught(py_float(last))? else {
        return Ok(None);
    };
    let mut buckets = BTreeMap::new();
    match row.get("buckets") {
        None => {}
        Some(Value::Dict(d)) => {
            for (b, n) in &d.0 {
                let Some(b) = caught(py_int(&Value::Str(b.clone())))? else {
                    return Ok(None);
                };
                let Some(n) = caught(py_int(n))? else {
                    return Ok(None);
                };
                // Past i128 (Python would keep it): skipped, decisions.md.
                let (Ok(b), Ok(n)) = (b.parse::<i128>(), n.parse::<i128>()) else {
                    return Ok(None);
                };
                buckets.insert(b, n);
            }
        }
        Some(_) => return Ok(None), // AttributeError: no .items()
    }
    let keep = |v: &str| SOURCES.contains(&v);
    let sources: BTreeSet<String> = match row.get("sources") {
        None => BTreeSet::new(),
        Some(Value::List(items)) => items
            .iter()
            .filter_map(|v| match v {
                Value::Str(s) if keep(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        Some(Value::Dict(d)) => {
            d.0.iter()
                .filter(|(k, _)| keep(k))
                .map(|(k, _)| k.clone())
                .collect()
        }
        // A str iterates as characters, none of which is a source.
        Some(Value::Str(_)) => BTreeSet::new(),
        Some(_) => return Ok(None), // TypeError: not iterable
    };
    Ok(Some(ClientUsage {
        first_seen,
        last_seen,
        buckets,
        sources,
    }))
}
