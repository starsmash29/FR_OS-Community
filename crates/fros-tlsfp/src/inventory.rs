//! Which TLS client fingerprints each device presented (1.x's
//! `frfw.tlsfp.inventory`, phase 19).
//!
//! Per client address: every JA4 seen, the JA3 values that went with it
//! (several per JA4 for browsers that shuffle extensions), a few server
//! names, counts and first/last-seen times. Network-wide: when each JA4
//! was first seen, which drives the "new fingerprint" event after a
//! learning period. Everything is bounded so a noisy or hostile network
//! can't grow it without limit, and it round-trips through the JSON
//! state file, byte for byte as 1.x writes it.

use fros_sensor::ordered::{OrderedMap, py_max, py_min_by};
use fros_sensor::pyjson::{Dict, PyError, Value, int_plus_one, py_float, py_int, py_str};

/// No "new fingerprint" events until the inventory is this old: at
/// first every fingerprint is new.
pub const LEARNING_SECONDS: f64 = 24.0 * 3600.0;

pub const MAX_CLIENTS: usize = 1024;
pub const MAX_FINGERPRINTS_PER_CLIENT: usize = 32;
pub const MAX_NETWORK_FINGERPRINTS: usize = 10000;
pub const MAX_JA3_PER_FINGERPRINT: usize = 8;
pub const MAX_SNI_PER_FINGERPRINT: usize = 5;
pub const MAX_EVENTS: usize = 200;

#[derive(Debug, Clone, PartialEq)]
pub struct Seen {
    pub first_seen: f64,
    pub last_seen: f64,
    /// An int of any size, as decimal text: 1.x's restore takes any
    /// int the state file holds.
    pub count: String,
    pub ja3: Vec<String>,
    pub sni: Vec<String>,
}

fn remember(values: &mut Vec<String>, value: Option<&str>, limit: usize) {
    let Some(value) = value.filter(|v| !v.is_empty()) else {
        return;
    };
    if let Some(i) = values.iter().position(|v| v == value) {
        values.remove(i);
    }
    values.push(value.to_string());
    keep_last(values, limit);
}

fn keep_last<T>(values: &mut Vec<T>, limit: usize) {
    let excess = values.len().saturating_sub(limit);
    values.drain(..excess);
}

type Fingerprints = OrderedMap<String, Seen>;

pub struct FingerprintInventory {
    pub started: f64,
    clients: OrderedMap<String, Fingerprints>,
    network_first_seen: OrderedMap<String, f64>,
    events: Vec<Dict>,
}

/// Restoring found what makes 1.x's restore raise an exception it
/// doesn't catch (the daemon then dies and is restarted, on the same
/// file). FR_OS 2 starts from an empty inventory instead
/// (testdata/reference/decisions.md).
struct Unreadable;

impl FingerprintInventory {
    pub fn new(started: f64) -> Self {
        Self {
            started,
            clients: OrderedMap::new(),
            network_first_seen: OrderedMap::new(),
            events: Vec::new(),
        }
    }

    pub fn client_count(&self) -> usize {
        self.clients.len()
    }

    /// The fingerprints one client presented, by JA4.
    pub fn client(&self, client: &str) -> Option<Vec<(&str, &Seen)>> {
        let fps = self.clients.get(&client.to_string())?;
        Some(fps.iter().map(|(k, v)| (k.as_str(), v)).collect())
    }

    /// Record one fingerprinted ClientHello. True if this JA4 has never
    /// been seen on the network before and the learning period is over.
    pub fn observe(
        &mut self,
        client: &str,
        ja4: &str,
        ja3: &str,
        sni: Option<&str>,
        now: f64,
    ) -> bool {
        let ja4_key = ja4.to_string();
        let is_new = !self.network_first_seen.contains_key(&ja4_key);
        if is_new {
            if self.network_first_seen.len() >= MAX_NETWORK_FINGERPRINTS
                && let Some(oldest) = py_min_by(self.network_first_seen.iter(), |t| *t)
            {
                let oldest = oldest.clone();
                self.network_first_seen.remove(&oldest);
            }
            self.network_first_seen.insert(ja4_key.clone(), now);
        }

        let client_key = client.to_string();
        if !self.clients.contains_key(&client_key) {
            if self.clients.len() >= MAX_CLIENTS {
                let stalest = py_min_by(self.clients.iter(), |fps| {
                    py_max(fps.iter().map(|(_, s)| s.last_seen)).unwrap_or(f64::NEG_INFINITY)
                });
                if let Some(stalest) = stalest {
                    let stalest = stalest.clone();
                    self.clients.remove(&stalest);
                }
            }
            self.clients.insert(client_key.clone(), OrderedMap::new());
        }
        let Some(fingerprints) = self.clients.get_mut(&client_key) else {
            return false;
        };
        if !fingerprints.contains_key(&ja4_key) {
            if fingerprints.len() >= MAX_FINGERPRINTS_PER_CLIENT
                && let Some(oldest) = py_min_by(fingerprints.iter(), |s| s.last_seen)
            {
                let oldest = oldest.clone();
                fingerprints.remove(&oldest);
            }
            fingerprints.insert(
                ja4_key.clone(),
                Seen {
                    first_seen: now,
                    last_seen: now,
                    count: "0".into(),
                    ja3: Vec::new(),
                    sni: Vec::new(),
                },
            );
        }
        if let Some(seen) = fingerprints.get_mut(&ja4_key) {
            seen.last_seen = now;
            seen.count = int_plus_one(&seen.count);
            remember(&mut seen.ja3, Some(ja3), MAX_JA3_PER_FINGERPRINT);
            remember(&mut seen.sni, sni, MAX_SNI_PER_FINGERPRINT);
        }
        is_new && now - self.started >= LEARNING_SECONDS
    }

    pub fn add_event(&mut self, event: Dict) {
        self.events.push(event);
        keep_last(&mut self.events, MAX_EVENTS);
    }

    pub fn learning(&self, now: f64) -> bool {
        now - self.started < LEARNING_SECONDS
    }

    /// The state as 1.x's `snapshot` builds it; `pyjson::dumps` of it
    /// is the state file's text.
    pub fn snapshot(&self, now: f64) -> Dict {
        let mut clients: Vec<(&String, &Fingerprints)> = self.clients.iter().collect();
        clients.sort_by(|a, b| a.0.cmp(b.0));
        let clients = clients
            .into_iter()
            .map(|(client, fps)| {
                let mut fps: Vec<(&String, &Seen)> = fps.iter().collect();
                fps.sort_by(|a, b| a.0.cmp(b.0));
                let rows = fps
                    .into_iter()
                    .map(|(ja4, s)| {
                        let strings =
                            |v: &[String]| Value::List(v.iter().cloned().map(Value::Str).collect());
                        let row = Dict(vec![
                            ("first_seen".into(), Value::Float(s.first_seen)),
                            ("last_seen".into(), Value::Float(s.last_seen)),
                            ("count".into(), Value::Int(s.count.clone())),
                            ("ja3".into(), strings(&s.ja3)),
                            ("sni".into(), strings(&s.sni)),
                        ]);
                        (ja4.clone(), Value::Dict(row))
                    })
                    .collect();
                (client.clone(), Value::Dict(Dict(rows)))
            })
            .collect();
        Dict(vec![
            ("generated".into(), Value::Float(now)),
            ("started".into(), Value::Float(self.started)),
            ("learning".into(), Value::Bool(self.learning(now))),
            ("clients".into(), Value::Dict(Dict(clients))),
            (
                "network_first_seen".into(),
                Value::Dict(Dict(
                    self.network_first_seen
                        .iter()
                        .map(|(k, t)| (k.clone(), Value::Float(*t)))
                        .collect(),
                )),
            ),
            (
                "events".into(),
                Value::List(self.events.iter().cloned().map(Value::Dict).collect()),
            ),
        ])
    }

    /// Rebuild from what the state file held (`None`: no file, or not
    /// JSON); anything malformed is dropped, as in 1.x. Where 1.x would
    /// raise an exception it doesn't catch, this starts empty.
    pub fn restore(data: Option<&Value>, now: f64) -> Self {
        Self::try_restore(data, now).unwrap_or_else(|Unreadable| Self::new(now))
    }

    /// `restore`, or `None` where 1.x's restore raises an exception it
    /// doesn't catch: the daemon puts such a file aside.
    pub fn restore_checked(data: Option<&Value>, now: f64) -> Option<Self> {
        Self::try_restore(data, now).ok()
    }

    fn try_restore(data: Option<&Value>, now: f64) -> Result<Self, Unreadable> {
        let Some(Value::Dict(data)) = data else {
            return Ok(Self::new(now));
        };
        let started = match data.get("started").map(py_float) {
            None => now,
            Some(Ok(started)) => started,
            Some(Err(PyError::OverflowError)) => return Err(Unreadable),
            Some(Err(_)) => return Ok(Self::new(now)),
        };
        let mut inventory = Self::new(started);

        // `(data.get(...) or {}).items()`: a value that is true but not
        // a dict has no .items(), an AttributeError 1.x doesn't catch.
        let mapping = |key: &str| -> Result<Option<&Dict>, Unreadable> {
            match data.get(key) {
                Some(v) if v.truthy() => match v {
                    Value::Dict(d) => Ok(Some(d)),
                    _ => Err(Unreadable),
                },
                _ => Ok(None),
            }
        };

        for (client, fps) in mapping("clients")?
            .map(|d| d.0.as_slice())
            .unwrap_or_default()
        {
            let Value::Dict(fps) = fps else {
                continue;
            };
            for (ja4, row) in &fps.0 {
                if let Some(seen) = restore_row(row)? {
                    if !inventory.clients.contains_key(client) {
                        inventory.clients.insert(client.clone(), OrderedMap::new());
                    }
                    if let Some(fingerprints) = inventory.clients.get_mut(client) {
                        fingerprints.insert(ja4.clone(), seen);
                    }
                }
            }
        }
        for (ja4, ts) in mapping("network_first_seen")?
            .map(|d| d.0.as_slice())
            .unwrap_or_default()
        {
            if matches!(ts, Value::Int(_) | Value::Float(_) | Value::Bool(_)) {
                let ts = py_float(ts).map_err(|_| Unreadable)?;
                inventory.network_first_seen.insert(ja4.clone(), ts);
            }
        }
        // `(data.get("events") or [])`, iterated: a list keeps its
        // dicts; a dict or string iterates to keys or characters, never
        // dicts; a true number or `true` can't be iterated (TypeError).
        let mut events: Vec<Dict> = match data.get("events") {
            Some(v) if v.truthy() => match v {
                Value::List(items) => items
                    .iter()
                    .filter_map(|e| match e {
                        Value::Dict(d) => Some(d.clone()),
                        _ => None,
                    })
                    .collect(),
                Value::Dict(_) | Value::Str(_) => Vec::new(),
                _ => return Err(Unreadable),
            },
            _ => Vec::new(),
        };
        keep_last(&mut events, MAX_EVENTS);
        inventory.events = events;
        Ok(inventory)
    }
}

/// One row of the state file, as 1.x's `Seen(...)` builds it: `None`
/// where 1.x catches the error and skips the row, `Err` where it
/// doesn't catch it.
fn restore_row(row: &Value) -> Result<Option<Seen>, Unreadable> {
    // A row that isn't a dict: `row["first_seen"]` raises TypeError.
    let Value::Dict(row) = row else {
        return Ok(None);
    };
    let float_field = |key: &str| -> Result<Option<f64>, Unreadable> {
        match row.get(key).map(py_float) {
            None => Ok(None), // KeyError
            Some(Ok(f)) => Ok(Some(f)),
            Some(Err(PyError::OverflowError)) => Err(Unreadable),
            Some(Err(_)) => Ok(None),
        }
    };
    let Some(first_seen) = float_field("first_seen")? else {
        return Ok(None);
    };
    let Some(last_seen) = float_field("last_seen")? else {
        return Ok(None);
    };
    let count = match row.get("count").map(py_int) {
        None => "0".to_string(),
        Some(Ok(count)) => count,
        Some(Err(PyError::OverflowError)) => return Err(Unreadable),
        Some(Err(_)) => return Ok(None),
    };
    let Some(ja3) = string_list(row.get("ja3"), MAX_JA3_PER_FINGERPRINT) else {
        return Ok(None);
    };
    let Some(sni) = string_list(row.get("sni"), MAX_SNI_PER_FINGERPRINT) else {
        return Ok(None);
    };
    Ok(Some(Seen {
        first_seen,
        last_seen,
        count,
        ja3,
        sni,
    }))
}

/// `[str(v) for v in value][-limit:]`. `None` where 1.x raises
/// TypeError (the value can't be iterated) or, as decided, where an
/// item is a list or dict.
fn string_list(value: Option<&Value>, limit: usize) -> Option<Vec<String>> {
    let mut out: Vec<String> = match value {
        None => Vec::new(),
        Some(Value::List(items)) => items.iter().map(py_str).collect::<Option<_>>()?,
        Some(Value::Dict(d)) => d.0.iter().map(|(k, _)| k.clone()).collect(),
        Some(Value::Str(s)) => s.chars().map(String::from).collect(),
        Some(_) => return None,
    };
    keep_last(&mut out, limit);
    Some(out)
}
