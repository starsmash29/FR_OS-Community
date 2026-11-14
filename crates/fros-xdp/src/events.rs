//! What the kernel program reports, decoded as 1.x's `frfw.xdp` decodes
//! it: a match (or, while observing, a pass) from the `events` ring
//! buffer (`SniEvent`), a ClientHello segment from `hello_pkts`
//! (`HelloSegment`), the JSON line the event logger writes for an event
//! (`format_event_json`) and the event file it appends that line to
//! (`EventFile`). Held to 1.x's answers for every recorded record
//! (`testdata/reference/xdpuser.jsonl`, tests/xdpuser.rs).
//!
//! Every record comes from a program FR_OS loaded, but is still read as
//! untrusted bytes: a short record is refused, every length is bounded
//! by the record itself, and the name is decoded as 1.x does (ASCII,
//! each other byte as U+FFFD), so nothing in it can break the JSON line.

use std::fs::{File, OpenOptions, Permissions};
use std::io::{self, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

use fros_sensor::pyjson::{self, Dict, Value};

use crate::{HELLO_SNAP, MAX_SNI_LEN};

/// `struct sni_event`: saddr(16) daddr(16) sport(2) dport(2) action(1),
/// one byte of padding, sni_len(2), then MAX_SNI_LEN name bytes.
pub const EVENT_SIZE: usize = 40 + MAX_SNI_LEN;

/// `struct hello_pkt`'s header: saddr(16) daddr(16) sport(2) dport(2)
/// seq(4) len(2) first(1) pad(1); HELLO_SNAP data bytes follow.
pub const HELLO_HEADER: usize = 44;

/// Past this size the event file is emptied and starts over (1.x's
/// SNI_EVENTS_MAX_BYTES): a router's log partition is small, and the
/// readers only follow new lines.
pub const SNI_EVENTS_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// A 16-byte address from the program as text: an IPv4-mapped one as
/// plain IPv4 ("10.0.0.5"), as the readers always got it; any other as
/// IPv6, written as Python's `ipaddress` writes it (lower-case hex, the
/// longest run of two or more zero groups, the first of equal runs,
/// as "::"; no dotted tail for any other address).
pub fn address_text(raw: &[u8; 16]) -> String {
    if raw[..10].iter().all(|&b| b == 0) && raw[10] == 0xff && raw[11] == 0xff {
        return format!("{}.{}.{}.{}", raw[12], raw[13], raw[14], raw[15]);
    }
    let groups: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    let (mut best_start, mut best_len) = (0usize, 0usize);
    let mut i = 0;
    while i < groups.len() {
        if groups[i] == 0 {
            let start = i;
            while i < groups.len() && groups[i] == 0 {
                i += 1;
            }
            if i - start > best_len {
                (best_start, best_len) = (start, i - start);
            }
        } else {
            i += 1;
        }
    }
    let hex = |g: &[u16]| {
        g.iter()
            .map(|x| format!("{x:x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    if best_len < 2 {
        return hex(&groups);
    }
    format!(
        "{}::{}",
        hex(&groups[..best_start]),
        hex(&groups[best_start + best_len..])
    )
}

fn address(raw: &[u8], at: usize) -> String {
    let mut a = [0u8; 16];
    a.copy_from_slice(&raw[at..at + 16]);
    address_text(&a)
}

fn le16(raw: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([raw[at], raw[at + 1]])
}

/// One record of the `events` ring buffer. `action` is "drop" for a
/// blocklist match, "pass" for a name that matched nothing (reported
/// only while observing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniEvent {
    pub saddr: String,
    pub daddr: String,
    pub sport: u16,
    pub dport: u16,
    pub hostname: String,
    pub action: &'static str,
}

impl SniEvent {
    /// 1.x's `SniEvent.from_bytes`: the error is its XdpError's text.
    pub fn from_bytes(raw: &[u8]) -> Result<SniEvent, String> {
        if raw.len() < EVENT_SIZE {
            return Err(format!(
                "short ring buffer record: {} < {EVENT_SIZE} bytes",
                raw.len()
            ));
        }
        let sni_len = usize::from(le16(raw, 38)).min(MAX_SNI_LEN);
        // bytes.decode("ascii", errors="replace"): one U+FFFD per byte
        // that isn't ASCII.
        let hostname = raw[40..40 + sni_len]
            .iter()
            .map(|&b| if b < 0x80 { char::from(b) } else { '\u{fffd}' })
            .collect();
        Ok(SniEvent {
            saddr: address(raw, 0),
            daddr: address(raw, 16),
            sport: le16(raw, 32),
            dport: le16(raw, 34),
            hostname,
            action: if raw[36] == 1 { "drop" } else { "pass" },
        })
    }
}

/// One TCP segment of a ClientHello from the `hello_pkts` ring buffer.
/// `first` marks the segment the hello starts in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloSegment {
    pub saddr: String,
    pub daddr: String,
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub first: bool,
    pub payload: Vec<u8>,
}

impl HelloSegment {
    /// 1.x's `HelloSegment.from_bytes`. The whole record is required, not
    /// just its header: the previous release's (IPv4 addresses only,
    /// 2068 bytes) read with this layout would turn its bytes into
    /// made-up addresses.
    pub fn from_bytes(raw: &[u8]) -> Result<HelloSegment, String> {
        if raw.len() < HELLO_HEADER + HELLO_SNAP {
            return Err(format!("short hello record: {} bytes", raw.len()));
        }
        let len = usize::from(le16(raw, 40))
            .min(HELLO_SNAP)
            .min(raw.len() - HELLO_HEADER);
        Ok(HelloSegment {
            saddr: address(raw, 0),
            daddr: address(raw, 16),
            sport: le16(raw, 32),
            dport: le16(raw, 34),
            seq: u32::from_le_bytes([raw[36], raw[37], raw[38], raw[39]]),
            first: raw[42] != 0,
            payload: raw[HELLO_HEADER..HELLO_HEADER + len].to_vec(),
        })
    }
}

/// The event logger's line for `event` at `ts` (seconds since the
/// epoch, `time.time()`): one JSON object, as `json.dumps` writes it,
/// which the webUI's live log and the sensor daemons read.
pub fn format_event_json(event: &SniEvent, ts: f64) -> String {
    let mut d = Dict::default();
    d.insert("ts".into(), Value::Float(ts));
    d.insert("action".into(), Value::Str(event.action.into()));
    d.insert("saddr".into(), Value::Str(event.saddr.clone()));
    d.insert("sport".into(), Value::int(i64::from(event.sport)));
    d.insert("daddr".into(), Value::Str(event.daddr.clone()));
    d.insert("dport".into(), Value::int(i64::from(event.dport)));
    d.insert("sni".into(), Value::Str(event.hostname.clone()));
    pyjson::dumps(&Value::Dict(d))
}

/// The SNI event file, opened once for appending (1.x's `EventFile`,
/// ROADMAP SEC-4): mode 0640 on every open, each line one write() with
/// O_APPEND so a reader never sees half of one, emptied once the next
/// line would take it past `max_bytes` (readers follow with `tail -F`,
/// which notices and starts again from the top). Opened by the logger
/// while still root, the file is root's, so only this open file can
/// write it after the logger becomes the readers' account.
pub struct EventFile {
    file: File,
    max_bytes: u64,
}

impl EventFile {
    pub fn open(path: &Path, max_bytes: u64) -> io::Result<EventFile> {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o640)
            .open(path)?;
        // The group is the process's own (the unit's Group=, the
        // readers'), set on every open, so a file an earlier version
        // made with another group is moved over too (ROADMAP SEC-11).
        if nix::unistd::geteuid().is_root() {
            nix::unistd::fchown(&file, None, Some(nix::unistd::getegid()))
                .map_err(io::Error::from)?;
        }
        file.set_permissions(Permissions::from_mode(0o640))?;
        Ok(EventFile { file, max_bytes })
    }

    pub fn write_line(&mut self, line: &str) -> io::Result<()> {
        let mut data = Vec::with_capacity(line.len() + 1);
        data.extend_from_slice(line.as_bytes());
        data.push(b'\n');
        if self.file.metadata()?.len() + data.len() as u64 > self.max_bytes {
            self.file.set_len(0)?;
        }
        // One write() of the whole line, as Python's os.write.
        let n = self.file.write(&data)?;
        if n != data.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short write to the event file",
            ));
        }
        Ok(())
    }
}
