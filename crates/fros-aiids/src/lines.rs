//! What 1.x's AI-IDS daemon reads out of its two logs
//! (`IDSDaemon.handle_dns_log_line`, `handle_sni_event_line`). Which
//! sources are scored at all (internal networks, IPv6 hosts by MAC) is
//! the daemon's business; these only parse.

use std::collections::HashSet;

use fros_sensor::dnsmasq::dnsmasq_message;
use fros_sensor::pyjson::{self, Value};
use fros_sensor::pytext::{self, is_decimal, is_space};

use crate::dga::looks_generated;

/// What one resolver log line tells the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsLogEvent {
    /// An NXDOMAIN answer for `name` (lowercased) to `client`, and
    /// whether the name looks machine-generated.
    Nxdomain {
        client: String,
        name: String,
        generated: bool,
    },
    /// A lookup answered from one of the malware/phishing category files.
    ThreatBlock { client: String },
}

fn run(s: &str, ok: impl Fn(char) -> bool) -> Option<(&str, &str)> {
    let len = s.find(|c: char| !ok(c)).unwrap_or(s.len());
    (len > 0).then(|| s.split_at(len))
}

fn non_space(c: char) -> bool {
    !is_space(c)
}

/// The client address and the rest of a log line, as 1.x's
/// `^\d+ ([0-9A-Fa-f:.]+)/\d+ (.+)$`.
fn split_line(message: &str) -> Option<(&str, &str)> {
    let (_, s) = run(message, is_decimal)?;
    let s = s.strip_prefix(' ')?;
    let (client, s) = run(s, |c| c.is_ascii_hexdigit() || c == ':' || c == '.')?;
    let s = s.strip_prefix('/')?;
    let (_, s) = run(s, is_decimal)?;
    let rest = s.strip_prefix(' ')?;
    // `.+$`: no newline inside, one allowed at the very end.
    let rest = rest.strip_suffix('\n').unwrap_or(rest);
    (!rest.is_empty() && !rest.contains('\n')).then_some((client, rest))
}

/// `(reply|cached) (name) is NXDOMAIN`
fn nxdomain_name(rest: &str) -> Option<&str> {
    let s = rest
        .strip_prefix("reply ")
        .or_else(|| rest.strip_prefix("cached "))?;
    let (name, s) = run(s, non_space)?;
    (s == " is NXDOMAIN").then_some(name)
}

/// `(/file) (name) is (0.0.0.0|::)`: the file a blocked answer came from.
fn hosts_file(rest: &str) -> Option<&str> {
    let after_slash = rest.strip_prefix('/')?;
    let (tail, s) = run(after_slash, non_space)?;
    let file = &rest[..1 + tail.len()];
    let s = s.strip_prefix(' ')?;
    let (_, s) = run(s, non_space)?;
    matches!(s, " is 0.0.0.0" | " is ::").then_some(file)
}

/// One line of the resolver's query log, with or without dnsmasq's
/// timestamp prefix. Everything but an NXDOMAIN answer and an answer
/// from one of `threat_files` is `None`.
pub fn parse_dns_log_line(line: &str, threat_files: &HashSet<String>) -> Option<DnsLogEvent> {
    let (client, rest) = split_line(dnsmasq_message(line))?;
    if let Some(name) = nxdomain_name(rest) {
        let name = pytext::lower(name);
        let generated = looks_generated(&name);
        return Some(DnsLogEvent::Nxdomain {
            client: client.to_owned(),
            name,
            generated,
        });
    }
    let file = hosts_file(rest)?;
    threat_files
        .contains(file)
        .then(|| DnsLogEvent::ThreatBlock {
            client: client.to_owned(),
        })
}

/// The source address of an XDP SNI-blocklist drop event; `None` for
/// any other line. A line nested too deep for Python's recursion limit,
/// which ended 1.x's reader thread, is `None` too (decisions.md).
pub fn parse_sni_drop_line(line: &str) -> Option<String> {
    let Ok(Value::Dict(event)) = pyjson::loads(line.as_bytes()) else {
        return None;
    };
    match (event.get("action"), event.get("saddr")) {
        (Some(Value::Str(a)), Some(Value::Str(saddr))) if a == "drop" => Some(saddr.clone()),
        _ => None,
    }
}
