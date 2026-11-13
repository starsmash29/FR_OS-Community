//! mDNS service discovery (RFC 6762 / RFC 6763): the one query a scan
//! sends and the parser of the answers, held to 1.x's
//! `frfw.iot.mdns`. The socket that sends and listens is the daemon's
//! (phase 4e); everything it hands here is untrusted LAN input.
//!
//! The parser is bounded wherever it could loop or allocate: label and
//! name lengths (63/255 bytes, the DNS maximums), at most 32
//! compression-pointer jumps per name (a pointer loop can't spin), at
//! most 256 records per packet, and only names shaped like a DNS-SD
//! service type (`_name._tcp` / `_name._udp`) are kept.

use std::collections::BTreeSet;

pub const MDNS_GROUP: &str = "224.0.0.251";
pub const MDNS_PORT: u16 = 5353;
pub const SERVICES_META_QUERY: &str = "_services._dns-sd._udp.local";

const TYPE_PTR: u16 = 12;
const CLASS_IN: u16 = 1;
const MAX_NAME: usize = 255;
const MAX_POINTER_JUMPS: usize = 32;
const MAX_RECORDS: usize = 256;

/// The largest datagram a scan reads (1.x's `_MAX_PACKET`).
pub const MAX_PACKET: usize = 9000;
/// At most this many service types are kept per responding host.
pub const MAX_SERVICES_PER_HOST: usize = 64;

/// The `_services._dns-sd._udp.local PTR` query, with the given id
/// (the daemon picks it at random).
pub fn build_query(query_id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(46);
    for word in [query_id, 0, 1, 0, 0, 0] {
        out.extend_from_slice(&word.to_be_bytes());
    }
    for label in SERVICES_META_QUERY.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&TYPE_PTR.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out
}

struct Malformed;

/// A name at `offset`: its text (labels decoded as ASCII, other bytes
/// as U+FFFD), and the offset just past it where it starts, i.e. after
/// the first pointer of a compressed name.
fn decode_name(packet: &[u8], offset: usize) -> Result<(String, usize), Malformed> {
    let mut labels: Vec<String> = Vec::new();
    let mut total = 0;
    let mut jumps = 0;
    let mut end_offset = None;
    let mut pos = offset;
    loop {
        let &length = packet.get(pos).ok_or(Malformed)?;
        if length & 0xC0 == 0xC0 {
            let &low = packet.get(pos + 1).ok_or(Malformed)?;
            jumps += 1;
            if jumps > MAX_POINTER_JUMPS {
                return Err(Malformed);
            }
            end_offset.get_or_insert(pos + 2);
            pos = (usize::from(length & 0x3F) << 8) | usize::from(low);
            continue;
        }
        if length & 0xC0 != 0 {
            return Err(Malformed); // label types 0x40 and 0x80
        }
        pos += 1;
        if length == 0 {
            break;
        }
        let length = usize::from(length);
        let label = packet.get(pos..pos + length).ok_or(Malformed)?;
        total += length + 1;
        if total > MAX_NAME {
            return Err(Malformed);
        }
        labels.push(
            label
                .iter()
                .map(|&b| {
                    if b.is_ascii() {
                        char::from(b)
                    } else {
                        '\u{FFFD}'
                    }
                })
                .collect(),
        );
        pos += length;
    }
    Ok((labels.join("."), end_offset.unwrap_or(pos)))
}

/// `^_[a-z0-9][a-z0-9-]{0,62}\._(tcp|udp)\Z`
fn is_service_type(name: &str) -> bool {
    let Some(head) = name
        .strip_suffix("._tcp")
        .or_else(|| name.strip_suffix("._udp"))
    else {
        return false;
    };
    let Some(body) = head.strip_prefix('_') else {
        return false;
    };
    let b = body.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && matches!(b[0], b'a'..=b'z' | b'0'..=b'9')
        && b.iter()
            .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

fn strip_local(name: &str) -> String {
    let name = name.to_lowercase();
    match name.strip_suffix(".local") {
        Some(stripped) => stripped.to_owned(),
        None => name,
    }
}

fn be16(packet: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([packet[at], packet[at + 1]])
}

/// The DNS-SD service types one mDNS response advertises; empty (never
/// an error) for a query or anything malformed.
pub fn parse_services(packet: &[u8]) -> BTreeSet<String> {
    parse(packet).unwrap_or_default()
}

fn parse(packet: &[u8]) -> Result<BTreeSet<String>, Malformed> {
    if packet.len() < 12 {
        return Err(Malformed);
    }
    let flags = be16(packet, 2);
    if flags & 0x8000 == 0 {
        return Ok(BTreeSet::new()); // a query, not a response
    }
    let [qd, an, ns, ar] = [4, 6, 8, 10].map(|at| usize::from(be16(packet, at)));
    if qd + an + ns + ar > MAX_RECORDS {
        return Err(Malformed);
    }
    let mut offset = 12;
    for _ in 0..qd {
        offset = decode_name(packet, offset)?.1 + 4;
    }
    let mut services = BTreeSet::new();
    for _ in 0..an + ns + ar {
        let (owner, next) = decode_name(packet, offset)?;
        offset = next;
        if offset + 10 > packet.len() {
            return Err(Malformed);
        }
        let rtype = be16(packet, offset);
        let rdlength = usize::from(be16(packet, offset + 8));
        offset += 10;
        let rdata_offset = offset;
        offset += rdlength;
        if offset > packet.len() {
            return Err(Malformed);
        }
        if rtype != TYPE_PTR {
            continue;
        }
        let owner = owner.to_lowercase();
        let candidate = if owner == SERVICES_META_QUERY {
            strip_local(&decode_name(packet, rdata_offset)?.0)
        } else {
            // Instance enumeration ("<name>._hap._tcp.local PTR ..."):
            // the owner itself is the service type.
            strip_local(&owner)
        };
        if is_service_type(&candidate) {
            services.insert(candidate);
        }
    }
    Ok(services)
}
