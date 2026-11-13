//! Sliding-window anomaly scoring (1.x's `frfw.ai_ids.engine`).
//!
//! For each source, six counters over the last `window_seconds`: new
//! connections per second, distinct destinations per connection (a scan
//! approaches 1.0), SNI-blocklist drops, distinct NXDOMAIN names,
//! distinct random-looking NXDOMAIN names, and lookups blocked as
//! malware/phishing. Each `evaluate` compares every counter with that
//! source's own last 30 windows by z-score -- "unusual for this host" --
//! or, until it has 5 of them, with a generous fixed floor; then adds
//! the window to the history. The mean and standard deviation are
//! Python's `statistics` ones, exact and correctly rounded
//! (fros_sensor::pyfloat), so a score near a threshold decides alike.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};

use fros_sensor::ordered::OrderedMap;
use fros_sensor::pyfloat;

/// The window, and how often the daemon calls `evaluate`.
pub const WINDOW_SECONDS: f64 = 60.0;
/// Past windows that make up a source's own baseline.
pub const BASELINE_SAMPLES: usize = 30;
/// Below this many past windows, a source is held to the floors instead.
pub const MIN_BASELINE_SAMPLES: usize = 5;
pub const ZSCORE_THRESHOLD: f64 = 3.0;

pub const ABS_CONN_RATE_FLOOR: f64 = 5.0;
pub const ABS_UNIQUE_DST_RATIO_FLOOR: f64 = 0.8;
pub const ABS_SNI_BLOCK_COUNT_FLOOR: f64 = 3.0;
pub const ABS_NXDOMAIN_FLOOR: f64 = 30.0;
pub const ABS_DGA_NXDOMAIN_FLOOR: f64 = 10.0;
pub const ABS_DNS_THREAT_FLOOR: f64 = 3.0;

/// Below this many connections in a window the destination ratio means
/// nothing; it is neither scored nor added to the history.
pub const MIN_CONNS_FOR_RATIO: usize = 5;

/// Every this many observations, sources silent for STALE_IP_SECONDS go.
pub const SWEEP_INTERVAL: usize = 200;
pub const STALE_IP_SECONDS: f64 = 3600.0;

#[derive(Debug, Clone, Default)]
struct IpWindow {
    new_conn_ts: VecDeque<f64>,
    /// Destination -> when last seen.
    dst_ips_seen: HashMap<String, f64>,
    sni_block_ts: VecDeque<f64>,
    nxdomain_ts: VecDeque<(f64, String)>,
    dga_nxdomain_ts: VecDeque<(f64, String)>,
    dns_threat_ts: VecDeque<f64>,
    conn_rate_history: VecDeque<f64>,
    dst_ratio_history: VecDeque<f64>,
    sni_block_history: VecDeque<f64>,
    nxdomain_history: VecDeque<f64>,
    dga_nxdomain_history: VecDeque<f64>,
    dns_threat_history: VecDeque<f64>,
    last_seen: f64,
}

/// One flagged source from one `evaluate`. `score` is the highest
/// z-score among the features that tripped (or `value / floor` for a
/// source still without a baseline): a rough severity, not a probability.
#[derive(Debug, Clone, PartialEq)]
pub struct AnomalyEvent {
    pub ip: String,
    pub score: f64,
    pub reasons: Vec<&'static str>,
    pub conn_rate: f64,
    pub unique_dst_ratio: f64,
    pub sni_block_count: usize,
    pub nxdomain_count: usize,
    pub dga_nxdomain_count: usize,
    pub dns_threat_count: usize,
}

#[derive(Debug, Clone)]
pub struct AnomalyEngine {
    window_seconds: f64,
    zscore_threshold: f64,
    ips: OrderedMap<String, IpWindow>,
    calls_since_sweep: usize,
}

impl Default for AnomalyEngine {
    fn default() -> Self {
        Self::new(WINDOW_SECONDS, ZSCORE_THRESHOLD)
    }
}

impl AnomalyEngine {
    pub fn new(window_seconds: f64, zscore_threshold: f64) -> Self {
        Self {
            window_seconds,
            zscore_threshold,
            ips: OrderedMap::new(),
            calls_since_sweep: 0,
        }
    }

    pub fn window_seconds(&self) -> f64 {
        self.window_seconds
    }

    /// One new connection from `src` to `dst` (the caller counts only
    /// flows new since its last conntrack sample).
    pub fn observe_connection(&mut self, src: &str, dst: &str, now: f64) {
        let window_seconds = self.window_seconds;
        let w = self.window(src, now);
        w.new_conn_ts.push_back(now);
        w.dst_ips_seen.insert(dst.to_owned(), now);
        prune(w, now, window_seconds);
    }

    /// One XDP SNI-blocklist drop attributed to `src`.
    pub fn observe_sni_block(&mut self, src: &str, now: f64) {
        let window_seconds = self.window_seconds;
        let w = self.window(src, now);
        w.sni_block_ts.push_back(now);
        prune(w, now, window_seconds);
    }

    /// One NXDOMAIN answer for `name` to `src`; `generated` is the DGA
    /// verdict on the name.
    pub fn observe_dns_nxdomain(&mut self, src: &str, name: &str, generated: bool, now: f64) {
        let window_seconds = self.window_seconds;
        let w = self.window(src, now);
        w.nxdomain_ts.push_back((now, name.to_owned()));
        if generated {
            w.dga_nxdomain_ts.push_back((now, name.to_owned()));
        }
        prune(w, now, window_seconds);
    }

    /// One lookup by `src` answered from a malware/phishing category.
    pub fn observe_dns_threat_block(&mut self, src: &str, now: f64) {
        let window_seconds = self.window_seconds;
        let w = self.window(src, now);
        w.dns_threat_ts.push_back(now);
        prune(w, now, window_seconds);
    }

    /// Every tracked source, in the order first seen.
    pub fn tracked_ips(&self) -> Vec<String> {
        self.ips.keys().cloned().collect()
    }

    fn window(&mut self, ip: &str, now: f64) -> &mut IpWindow {
        self.calls_since_sweep += 1;
        if self.calls_since_sweep >= SWEEP_INTERVAL {
            self.calls_since_sweep = 0;
            // Stale when `now - last_seen > STALE_IP_SECONDS`; NaN stays.
            self.ips.retain(|_, w| {
                (now - w.last_seen).partial_cmp(&STALE_IP_SECONDS) != Some(Ordering::Greater)
            });
        }
        let key = ip.to_owned();
        if !self.ips.contains_key(&key) {
            self.ips.insert(key.clone(), IpWindow::default());
        }
        let w = self.ips.get_mut(&key).expect("inserted just above");
        w.last_seen = now;
        w
    }

    /// Score `ip`'s current window against its own history, then add the
    /// window to that history. Once per window per tracked source.
    pub fn evaluate(&mut self, ip: &str, now: f64) -> Option<AnomalyEvent> {
        let window_seconds = self.window_seconds;
        let threshold = self.zscore_threshold;
        let w = self.ips.get_mut(&ip.to_owned())?;
        prune(w, now, window_seconds);

        let total_conns = w.new_conn_ts.len();
        let conn_rate = total_conns as f64 / window_seconds;
        let unique_dst_ratio = if total_conns > 0 {
            w.dst_ips_seen.len() as f64 / total_conns as f64
        } else {
            0.0
        };
        let distinct = |series: &VecDeque<(f64, String)>| {
            series
                .iter()
                .map(|(_, n)| n.as_str())
                .collect::<HashSet<&str>>()
                .len()
        };
        let sni_block_count = w.sni_block_ts.len();
        let nxdomain_count = distinct(&w.nxdomain_ts);
        let dga_nxdomain_count = distinct(&w.dga_nxdomain_ts);
        let dns_threat_count = w.dns_threat_ts.len();

        let mut features: Vec<(&'static str, f64, &mut VecDeque<f64>, f64)> = vec![
            (
                "connection-rate spike",
                conn_rate,
                &mut w.conn_rate_history,
                ABS_CONN_RATE_FLOOR,
            ),
            (
                "SNI-blocklist beacon",
                sni_block_count as f64,
                &mut w.sni_block_history,
                ABS_SNI_BLOCK_COUNT_FLOOR,
            ),
            (
                "NXDOMAIN burst",
                nxdomain_count as f64,
                &mut w.nxdomain_history,
                ABS_NXDOMAIN_FLOOR,
            ),
            (
                "DGA-like NXDOMAIN lookups",
                dga_nxdomain_count as f64,
                &mut w.dga_nxdomain_history,
                ABS_DGA_NXDOMAIN_FLOOR,
            ),
            (
                "malware/phishing DNS lookups",
                dns_threat_count as f64,
                &mut w.dns_threat_history,
                ABS_DNS_THREAT_FLOOR,
            ),
        ];
        if total_conns >= MIN_CONNS_FOR_RATIO {
            features.push((
                "destination-scan pattern",
                unique_dst_ratio,
                &mut w.dst_ratio_history,
                ABS_UNIQUE_DST_RATIO_FLOOR,
            ));
        }
        let mut reasons = Vec::new();
        let mut best = 0.0f64;
        for (label, value, history, floor) in features {
            if let Some(score) = score(value, history, floor, threshold) {
                reasons.push(label);
                // Python's max(best, score): score only if greater.
                if score > best {
                    best = score;
                }
            }
            if history.len() == BASELINE_SAMPLES {
                history.pop_front();
            }
            history.push_back(value);
        }
        if reasons.is_empty() {
            return None;
        }
        Some(AnomalyEvent {
            ip: ip.to_owned(),
            score: pyfloat::round(best, 2),
            reasons,
            conn_rate: pyfloat::round(conn_rate, 3),
            unique_dst_ratio: pyfloat::round(unique_dst_ratio, 3),
            sni_block_count,
            nxdomain_count,
            dga_nxdomain_count,
            dns_threat_count,
        })
    }
}

/// Whether one feature trips, and its score.
fn score(value: f64, history: &VecDeque<f64>, floor: f64, threshold: f64) -> Option<f64> {
    if history.len() >= MIN_BASELINE_SAMPLES {
        let values: Vec<f64> = history.iter().copied().collect();
        let mean = pyfloat::mean(&values);
        let mut stdev = pyfloat::pstdev(&values);
        if stdev == 0.0 {
            stdev = 1e-6;
        }
        let z = (value - mean) / stdev;
        // Still at least half the floor, so a host whose baseline is
        // near zero isn't flagged for its second connection.
        (z >= threshold && value > floor / 2.0).then_some(z)
    } else {
        (value >= floor).then(|| value / floor)
    }
}

fn prune(w: &mut IpWindow, now: f64, window_seconds: f64) {
    let cutoff = now - window_seconds;
    for series in [
        &mut w.new_conn_ts,
        &mut w.sni_block_ts,
        &mut w.dns_threat_ts,
    ] {
        while series.front().is_some_and(|&t| t < cutoff) {
            series.pop_front();
        }
    }
    for series in [&mut w.nxdomain_ts, &mut w.dga_nxdomain_ts] {
        while series.front().is_some_and(|(t, _)| *t < cutoff) {
            series.pop_front();
        }
    }
    w.dst_ips_seen
        .retain(|_, &mut t| t.partial_cmp(&cutoff) != Some(Ordering::Less));
}
