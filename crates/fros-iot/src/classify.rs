//! "Is this an IoT device?", held to 1.x's `frfw.iot.classify`: a
//! transparent point system, not a model, so an admin can predict and
//! override it (`iot.trusted_macs` / `iot.isolated_macs`). Every signal
//! adds or subtracts points and is kept as a reason the webUI shows.
//!
//! Signals, all cheaply observable and none needing decryption: the
//! IEEE vendor of the MAC, the mDNS service types the device
//! advertises, the DHCP hostname it announced, and the locally
//! administered ("randomized") MAC bit phones and laptops use.

use std::collections::BTreeSet;

use fros_sensor::pytext;

use crate::oui::is_locally_administered;

pub const CATEGORY_IOT: &str = "iot";
pub const CATEGORY_GENERAL: &str = "general";
pub const CATEGORY_UNKNOWN: &str = "unknown";

pub const IOT_THRESHOLD: i64 = 3;
pub const GENERAL_THRESHOLD: i64 = -2;

/// Vendors whose OUIs are, in practice, almost only on IoT hardware
/// (lowercase substrings of the IEEE organization name).
const STRONG_IOT_VENDORS: &[&str] = &[
    "espressif",
    "tuya",
    "allterco",
    "itead",
    "signify",
    "philips lighting",
    "sonos",
    "roku",
    "ecobee",
    "wyze",
    "hikvision",
    "dahua",
    "ring llc",
    "nest labs",
    "arlo",
    "chamberlain",
    "lifx",
    "meross",
    "govee",
    "nanoleaf",
    "yeelight",
];

/// Vendors of IoT gear *and* phones, PCs and network kit: a weak hint.
const MIXED_VENDORS: &[&str] = &[
    "amazon technologies",
    "google",
    "xiaomi",
    "tp-link",
    "belkin",
    "raspberry pi",
];

const IOT_SERVICES: &[(&str, &str)] = &[
    ("_hap._tcp", "HomeKit accessory"),
    ("_hap._udp", "HomeKit accessory (Thread)"),
    ("_homekit._tcp", "HomeKit"),
    ("_googlecast._tcp", "Google Cast device"),
    ("_hue._tcp", "Philips Hue bridge"),
    ("_sonos._tcp", "Sonos speaker"),
    ("_spotify-connect._tcp", "Spotify Connect speaker"),
    ("_matter._tcp", "Matter device"),
    ("_matterc._udp", "Matter commissionable device"),
    ("_esphomelib._tcp", "ESPHome firmware"),
    ("_shelly._tcp", "Shelly device"),
    ("_amzn-wplay._tcp", "Amazon Fire TV / Echo"),
    ("_ipp._tcp", "network printer"),
    ("_ipps._tcp", "network printer"),
    ("_printer._tcp", "network printer"),
    ("_pdl-datastream._tcp", "network printer"),
    ("_miio._udp", "Xiaomi Mi Home device"),
    ("_arduino._tcp", "Arduino board"),
];

const GENERAL_SERVICES: &[(&str, &str)] = &[
    ("_workstation._tcp", "workstation"),
    ("_smb._tcp", "file sharing (SMB)"),
    ("_afpovertcp._tcp", "file sharing (AFP)"),
    ("_ssh._tcp", "SSH server"),
    ("_sftp-ssh._tcp", "SFTP server"),
    ("_companion-link._tcp", "Apple phone/tablet/computer"),
    ("_rdlink._tcp", "Apple phone/tablet/computer"),
];

const IOT_HOSTNAME_HINTS: &[&str] = &[
    "esp_",
    "esp-",
    "espressif",
    "tasmota",
    "shelly",
    "sonoff",
    "tuya",
    "wled",
    "chromecast",
    "echo-",
    "kasa",
    "hs100",
    "hs103",
    "hs105",
    "hs110",
    "philips-hue",
    "sonos",
    "roku",
    "ring-",
    "nest-",
    "wyze",
    "ipcam",
    "camera",
    "doorbell",
    "thermostat",
    "smartplug",
    "smart-plug",
    "bulb",
    "yeelink",
    "miio",
    "printer",
];

const GENERAL_HOSTNAME_HINTS: &[&str] = &[
    "desktop",
    "laptop",
    "macbook",
    "imac",
    "iphone",
    "ipad",
    "android-",
    "galaxy",
    "pixel",
    "thinkpad",
    "workstation",
    "-pc",
];

/// What a scan knows about one MAC.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Observation {
    pub mac: String,
    pub ip: Option<String>,
    pub hostname: String,
    pub interface: String,
    pub vendor: Option<String>,
    /// Sorted, as 1.x builds the tuple.
    pub services: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    pub category: &'static str,
    pub score: i64,
    pub reasons: Vec<String>,
}

fn described(services: &[String], table: &[(&str, &str)]) -> Option<String> {
    let names: BTreeSet<&str> = services
        .iter()
        .filter_map(|s| table.iter().find(|(k, _)| k == s).map(|(_, v)| *v))
        .collect();
    (!names.is_empty()).then(|| names.into_iter().collect::<Vec<_>>().join(", "))
}

pub fn classify(obs: &Observation) -> Classification {
    let mut score = 0;
    let mut reasons = Vec::new();

    let vendor = obs.vendor.as_deref().unwrap_or("");
    let vendor_l = pytext::lower(vendor);
    if !vendor_l.is_empty() {
        if STRONG_IOT_VENDORS.iter().any(|v| vendor_l.contains(v)) {
            score += 3;
            reasons.push(format!("+3 vendor '{vendor}' ships mostly IoT hardware"));
        } else if MIXED_VENDORS.iter().any(|v| vendor_l.contains(v)) {
            score += 1;
            reasons.push(format!(
                "+1 vendor '{vendor}' ships IoT and general devices"
            ));
        }
    }

    if let Some(names) = described(&obs.services, IOT_SERVICES) {
        score += 3;
        reasons.push(format!("+3 advertises IoT services via mDNS ({names})"));
    }
    if let Some(names) = described(&obs.services, GENERAL_SERVICES) {
        score -= 3;
        reasons.push(format!(
            "-3 advertises computer services via mDNS ({names})"
        ));
    }

    let host_l = pytext::lower(&obs.hostname);
    if !host_l.is_empty() {
        if IOT_HOSTNAME_HINTS.iter().any(|h| host_l.contains(h)) {
            score += 2;
            reasons.push(format!(
                "+2 DHCP hostname '{}' looks like an IoT device",
                obs.hostname
            ));
        } else if GENERAL_HOSTNAME_HINTS.iter().any(|h| host_l.contains(h)) {
            score -= 2;
            reasons.push(format!(
                "-2 DHCP hostname '{}' looks like a phone/computer",
                obs.hostname
            ));
        }
    }

    if is_locally_administered(&obs.mac) {
        score -= 2;
        reasons.push("-2 randomized (locally administered) MAC, typical of phones/laptops".into());
    }

    let category = if score >= IOT_THRESHOLD {
        CATEGORY_IOT
    } else if score <= GENERAL_THRESHOLD {
        CATEGORY_GENERAL
    } else {
        CATEGORY_UNKNOWN
    };
    if reasons.is_empty() {
        reasons
            .push("no identifying signal (unknown vendor, no mDNS services, no hostname)".into());
    }
    Classification {
        category,
        score,
        reasons,
    }
}
