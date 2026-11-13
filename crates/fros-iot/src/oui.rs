//! MAC address -> hardware vendor, from the IEEE's MA-L (24-bit OUI)
//! registry as Debian's `ieee-data` package ships it
//! (`/usr/share/ieee-data/oui.csv`, columns `Registry,Assignment,
//! Organization Name,Organization Address`), held to 1.x's
//! `frfw.iot.oui`. Nothing is bundled: without the package the lookup
//! finds no vendor and the scoring leans on the other signals.

use std::io::Read;
use std::path::Path;

use fros_sensor::ordered::OrderedMap;
use fros_sensor::pytext;

use crate::{Crash, csv};

pub const OUI_CSV_PATH: &str = "/usr/share/ieee-data/oui.csv";

/// The registry is about 3 MB today. A file past this is read as
/// missing rather than held in memory (a decided difference: 1.x has no
/// limit; testdata/reference/decisions.md).
pub const MAX_OUI_BYTES: u64 = 64 << 20;

/// `{"AABBCC": "Vendor Name"}` in the order 1.x's dict has it: a prefix
/// listed twice keeps its first place and its last name.
pub type VendorDb = OrderedMap<String, String>;

/// `AA-BB-CC-DD-EE-FF` / ` aa:bb:... ` -> `aa:bb:cc:dd:ee:ff`, or `None`
/// for anything that isn't a MAC address. Python's `strip` and `lower`,
/// then `^([0-9a-f]{2}:){5}[0-9a-f]{2}\Z`.
pub fn normalize_mac(mac: &str) -> Option<String> {
    let mac = pytext::lower(pytext::strip(mac)).replace('-', ":");
    let b = mac.as_bytes();
    let ok = b.len() == 17
        && b.iter().enumerate().all(|(i, &c)| {
            if i % 3 == 2 {
                c == b':'
            } else {
                matches!(c, b'0'..=b'9' | b'a'..=b'f')
            }
        });
    ok.then_some(mac)
}

/// Bit 1 of the first octet of a normalized MAC: set on randomized
/// ("private") addresses of phones and laptops and on virtual NICs,
/// almost never on an embedded device's burned-in address.
pub fn is_locally_administered(mac: &str) -> bool {
    mac.get(..2)
        .and_then(|octet| u8::from_str_radix(octet, 16).ok())
        .is_some_and(|octet| octet & 0x02 != 0)
}

/// The registry's text as 1.x reads it (UTF-8, bad bytes replaced):
/// every `MA-L` row with a six-character assignment, or the
/// `_csv.Error` of a field past the size limit, which 1.x doesn't catch.
pub fn parse_vendor_db(raw: &[u8]) -> Result<VendorDb, Crash> {
    let text = String::from_utf8_lossy(raw);
    let mut db = VendorDb::new();
    csv::read_rows(&text, |row| {
        if row.len() < 3 || row[0] != "MA-L" {
            return;
        }
        let prefix = pytext::strip(&row[1]).to_uppercase();
        if prefix.chars().count() == 6 {
            db.insert(prefix, pytext::strip(&row[2]).to_owned());
        }
    })?;
    Ok(db)
}

/// The registry at `path`; empty if it is missing, unreadable or past
/// [`MAX_OUI_BYTES`].
pub fn load_vendor_db(path: &Path) -> Result<VendorDb, Crash> {
    let Ok(file) = std::fs::File::open(path) else {
        return Ok(VendorDb::new());
    };
    let mut raw = Vec::new();
    match file.take(MAX_OUI_BYTES + 1).read_to_end(&mut raw) {
        Ok(n) if (n as u64) <= MAX_OUI_BYTES => parse_vendor_db(&raw),
        _ => Ok(VendorDb::new()),
    }
}

/// The vendor of a normalized MAC; none for a randomized address,
/// whose prefix names no real vendor.
pub fn vendor_for<'a>(mac: &str, db: &'a VendorDb) -> Option<&'a str> {
    if is_locally_administered(mac) {
        return None;
    }
    let prefix: String = mac
        .chars()
        .filter(|&c| c != ':')
        .take(6)
        .collect::<String>()
        .to_uppercase();
    db.get(&prefix).map(String::as_str)
}
