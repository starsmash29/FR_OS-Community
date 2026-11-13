//! Coarse application identification for FR_OS 2's `fr-appid` daemon,
//! held to FR_OS 1.x's `frfw.appid` (phase 16) case for case
//! (tests/reference.rs replays testdata/reference/appid.jsonl).
//!
//! Nothing here looks inside traffic: a name a client looked up (the
//! resolver's query log) or sent as its TLS SNI (the XDP filter's event
//! file) is matched against a catalog of per-app domains and counted
//! per app and client. Both logs carry text any LAN host can shape, so
//! every function is total over its input (tests/props.rs).

pub mod catalog;
pub mod observer;
pub mod usage;

pub use catalog::{AppMatcher, AppSignature, Catalog, CatalogError, blocking_names, parse_catalog};
pub use observer::{AppIdObserver, Observation, parse_dns_query_line, parse_sni_event_line};
pub use usage::UsageTracker;
