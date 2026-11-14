//! Anomaly scoring for FR_OS 2's `fr-ai-ids` daemon, held to FR_OS 1.x's
//! `frfw.ai_ids` (phases 11 and 15) case for case (tests/reference.rs
//! replays testdata/reference/aiids.jsonl).
//!
//! Each internal host is scored against its own history: connection
//! rate, destination diversity, SNI-blocklist hits, NXDOMAIN bursts,
//! random-looking NXDOMAIN names and lookups of malware/phishing names,
//! counted over a sliding window and compared with that host's past
//! windows by z-score (or a fixed floor while it has no baseline yet).
//! The inputs are log lines any LAN host can shape, so every function is
//! total over its input (tests/props.rs).

pub mod daemon;
pub mod dga;
pub mod engine;
pub mod lines;

pub use dga::{common_bigram_ratio, looks_generated, registered_label, shannon_entropy};
pub use engine::{AnomalyEngine, AnomalyEvent};
pub use lines::{DnsLogEvent, parse_dns_log_line, parse_sni_drop_line};
