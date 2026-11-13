//! The kernel's IPv4 neighbour table, `/proc/net/arp`, held to 1.x's
//! `frfw.iot.arp`: world-readable, and the only inventory source for a
//! device with a static IP that never asks the DHCP server.

use std::io::Read;
use std::path::Path;

use fros_sensor::pytext;

use crate::Crash;
use crate::oui::normalize_mac;

pub const ARP_PATH: &str = "/proc/net/arp";

/// The kernel caps the table (gc_thresh3, 1024 by default); a read past
/// this is cut here, at a line boundary's worth of slack, rather than
/// held in memory (security-lessons: every read has a size limit).
pub const MAX_ARP_BYTES: u64 = 16 << 20;

/// ATF_COM: the entry is resolved. Incomplete entries have flags 0x0
/// and an all-zero hardware address.
const ATF_COM: u32 = 0x2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpEntry {
    pub ip: String,
    pub mac: String,
    pub device: String,
}

/// `str.splitlines()`: lines end at \n, \r, \r\n, \v, \f, \x1c-\x1e,
/// \x85, U+2028 and U+2029, and a final terminator adds no empty line.
/// (1.x reads the file in universal-newline mode first, which only
/// turns \r\n and \r into \n: the same breaks.)
fn splitlines(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let breaks = matches!(
            c,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if !breaks {
            continue;
        }
        out.push(&text[start..i]);
        let mut next = i + c.len_utf8();
        if c == '\r'
            && let Some(&(j, '\n')) = chars.peek()
        {
            chars.next();
            next = j + 1;
        }
        start = next;
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

/// Bit 1 of Python's `int(text, 16)`, or `None` where that raises
/// ValueError. Python takes a sign, a `0x` prefix (and one `_` after
/// it), single `_` between digits, and any Unicode decimal digit as
/// its ASCII digit.
fn hex_flag_bit1(text: &str) -> Option<bool> {
    // CPython first turns each Unicode decimal digit into its ASCII
    // digit and anything else non-ASCII into '?' (so "\u{ff10}x2" reads
    // as "0x2"), then parses ASCII.
    let ascii: String = pytext::strip(text)
        .chars()
        .map(|c| {
            if c.is_ascii() {
                c
            } else {
                pytext::decimal_value(c)
                    .and_then(|d| char::from_digit(d, 10))
                    .unwrap_or('?')
            }
        })
        .collect();
    let (negative, body) = match ascii.as_bytes().first() {
        Some(b'-') => (true, &ascii[1..]),
        Some(b'+') => (false, &ascii[1..]),
        _ => (false, ascii.as_str()),
    };
    let body = body
        .strip_prefix("0x")
        .or_else(|| body.strip_prefix("0X"))
        .map(|rest| rest.strip_prefix('_').unwrap_or(rest))
        .unwrap_or(body);
    let mut last: Option<u32> = None;
    let mut after_underscore = false;
    for c in body.chars() {
        if c == '_' {
            if last.is_none() || after_underscore {
                return None;
            }
            after_underscore = true;
            continue;
        }
        last = Some(c.to_digit(16)?);
        after_underscore = false;
    }
    if after_underscore {
        return None;
    }
    let low = last? % 4;
    // Two's complement of a negative value, as Python's `&` sees it.
    let low = if negative { (4 - low) % 4 } else { low };
    Some(low & ATF_COM != 0)
}

/// The table's text: the resolved entries with a real MAC, in file
/// order. Not UTF-8 is 1.x's UnicodeDecodeError, which it doesn't catch.
pub fn parse_arp_table(raw: &[u8]) -> Result<Vec<ArpEntry>, Crash> {
    let text = std::str::from_utf8(raw).map_err(|_| Crash("UnicodeDecodeError"))?;
    let mut entries = Vec::new();
    for line in splitlines(text).into_iter().skip(1) {
        let parts: Vec<&str> = line
            .split(pytext::is_space)
            .filter(|p| !p.is_empty())
            .collect();
        let [ip, _hw_type, flags, hw_addr, _mask, device, ..] = parts[..] else {
            continue;
        };
        if hex_flag_bit1(flags) != Some(true) {
            continue;
        }
        let Some(mac) = normalize_mac(hw_addr) else {
            continue;
        };
        if mac == "00:00:00:00:00:00" {
            continue;
        }
        entries.push(ArpEntry {
            ip: ip.to_owned(),
            mac,
            device: device.to_owned(),
        });
    }
    Ok(entries)
}

/// The table at `path`; empty if it can't be opened or read (1.x's
/// OSError), cut at [`MAX_ARP_BYTES`].
pub fn read_arp_table(path: &Path) -> Result<Vec<ArpEntry>, Crash> {
    let Ok(file) = std::fs::File::open(path) else {
        return Ok(Vec::new());
    };
    let mut raw = Vec::new();
    if file.take(MAX_ARP_BYTES).read_to_end(&mut raw).is_err() {
        return Ok(Vec::new());
    }
    parse_arp_table(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_base_16_as_python() {
        // int(x, 16) & 2 != 0, or ValueError
        for (text, want) in [
            ("0x2", Some(true)),
            ("0X6", Some(true)),
            ("0x_2", Some(true)),
            ("_2", None),
            ("2_", None),
            ("2__0", None),
            ("0x", None),
            ("-0x2", Some(true)),
            ("-0x1", Some(true)),
            ("-0x4", Some(false)),
            ("+3", Some(true)),
            ("\u{662}", Some(true)),
            ("1_0", Some(false)),
            ("0_x2", None),
            ("\u{ff12}", Some(true)),
            ("\u{ff10}x2", Some(true)),
            ("zz", None),
            ("0xffffffffffffffffffffffffffffff", Some(true)),
        ] {
            assert_eq!(hex_flag_bit1(text), want, "{text:?}");
        }
    }

    #[test]
    fn splitlines_as_python() {
        assert_eq!(
            splitlines("a\r\nb\rc\n\nd\x1ce\u{2028}"),
            vec!["a", "b", "c", "", "d", "e"]
        );
        assert_eq!(splitlines(""), Vec::<&str>::new());
    }
}
