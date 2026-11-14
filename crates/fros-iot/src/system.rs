//! What `fr-iot-scan` reads and asks on the router: the apply-helper's
//! two calls, the mDNS socket, the neighbour table, the OUI registry
//! and the inventory file. [`SystemIo`] is the [`ScanIo`] the scan runs
//! with; held to 1.x's `frfw.helper.client` and `frfw.iot.mdns.discover`
//! (sensord.jsonl, ops `iotscan` and `mdns`).
//!
//! The mDNS socket is the one place this process touches the network,
//! and what comes back is any LAN host's: a datagram is read into a
//! [`MAX_PACKET`] buffer (longer ones are cut), at most `max_packets`
//! are read before the deadline, the router's own answers and any not
//! from the mDNS port are dropped, and each host keeps at most
//! [`MAX_SERVICES_PER_HOST`] service types.

use std::collections::BTreeSet;
use std::fs;
use std::hash::{BuildHasher as _, Hasher as _};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fros_sensor::helper::{self, HelperError, os_error_text};
use fros_sensor::pyjson::{Dict, Value};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::Crash;
use crate::arp::{ArpEntry, read_arp_table};
use crate::mdns::{MAX_PACKET, MAX_SERVICES_PER_HOST, MDNS_PORT, build_query, parse_services};
use crate::oui::{VendorDb, load_vendor_db};
use crate::scan::{MdnsResults, ScanIo};

/// Where the scan writes the inventory the webUI shows (1.x's
/// `paths.IOT_INVENTORY_PATH`).
pub const INVENTORY_PATH: &str = "/etc/fr_os/sensors/iot_inventory.json";

/// The port discovery sends from and hears the answers on (1.x's
/// `IOT_MDNS_REPLY_PORT`): the ruleset lets unicast answers to it in
/// from the IoT zones, and only to it (RFC 6762 section 6.7).
pub const IOT_MDNS_REPLY_PORT: u16 = 53530;

/// `helper_client.dhcp_leases`.
pub fn dhcp_leases(socket: &Path) -> Result<Value, HelperError> {
    let cmd = Dict(vec![("cmd".into(), Value::Str("dhcp_leases".into()))]);
    helper::send_command(&cmd, socket, helper::TIMEOUT, helper::MAX_LINE_BYTES)
}

/// `helper_client.iot_sync_isolation`.
pub fn iot_sync_isolation(socket: &Path, macs: &[String]) -> Result<Value, HelperError> {
    let cmd = Dict(vec![
        ("cmd".into(), Value::Str("iot_sync_isolation".into())),
        (
            "macs".into(),
            Value::List(macs.iter().map(|m| Value::Str(m.clone())).collect()),
        ),
    ]);
    helper::send_command(&cmd, socket, helper::TIMEOUT, helper::MAX_LINE_BYTES)
}

/// Where and how discovery asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsOptions {
    /// The multicast group and port (a unicast address in tests).
    pub target: SocketAddrV4,
    pub bind_port: u16,
    pub timeout: Duration,
    pub max_packets: usize,
}

impl Default for MdnsOptions {
    fn default() -> Self {
        Self {
            target: SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), MDNS_PORT),
            bind_port: IOT_MDNS_REPLY_PORT,
            timeout: Duration::from_secs(2),
            max_packets: 512,
        }
    }
}

/// A random query id, as 1.x's `random.randrange(0, 0x10000)`; it only
/// has to differ from scan to scan.
fn query_id() -> u16 {
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64),
    );
    (h.finish() & 0xffff) as u16
}

/// `mdns.discover`: the query sent once out of each of the router's
/// own addresses (`IP_MULTICAST_IF`), then every answer until the
/// deadline. An error is 1.x's MdnsError text.
pub fn discover(addresses: &[String], options: &MdnsOptions) -> Result<MdnsResults, String> {
    let mut results = MdnsResults::new();
    if addresses.is_empty() {
        return Ok(results);
    }
    let query = build_query(query_id());
    let own: BTreeSet<&str> = addresses.iter().map(String::as_str).collect();
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| format!("cannot create UDP socket: {}", os_error_text(&e)))?;
    let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, options.bind_port));
    sock.bind(&SockAddr::from(bind)).map_err(|e| {
        format!(
            "cannot bind UDP port {} ({}) -- is another IoT scan already running?",
            options.bind_port,
            os_error_text(&e)
        )
    })?;
    // 1.x lets a failure here through; it can't fail on a UDP socket.
    let _ = sock.set_multicast_ttl_v4(255);
    let target = SockAddr::from(SocketAddr::V4(options.target));
    let mut sent = 0;
    for address in addresses {
        let Ok(ip) = address.parse::<Ipv4Addr>() else {
            continue;
        };
        if sock.set_multicast_if_v4(&ip).is_ok() && sock.send_to(&query, &target).is_ok() {
            sent += 1;
        }
    }
    if sent == 0 {
        return Ok(results);
    }

    let sock: UdpSocket = sock.into();
    let deadline = Instant::now() + options.timeout;
    let mut buf = vec![0u8; MAX_PACKET];
    for _ in 0..options.max_packets {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        if sock.set_read_timeout(Some(remaining)).is_err() {
            break;
        }
        let Ok((n, SocketAddr::V4(src))) = sock.recv_from(&mut buf) else {
            break;
        };
        let src_ip = src.ip().to_string();
        if src.port() != options.target.port() || own.contains(src_ip.as_str()) {
            continue;
        }
        let found = parse_services(&buf[..n]);
        if !found.is_empty() {
            let bucket = results.entry(src_ip).or_default();
            for service in found {
                if bucket.len() >= MAX_SERVICES_PER_HOST {
                    break;
                }
                bucket.insert(service);
            }
        }
    }
    Ok(results)
}

/// The router's own: the helper's socket, the mDNS socket, the files.
#[derive(Debug, Clone)]
pub struct SystemIo {
    pub socket: PathBuf,
    pub mdns: MdnsOptions,
    pub arp: PathBuf,
    pub oui: PathBuf,
}

impl Default for SystemIo {
    fn default() -> Self {
        Self {
            socket: helper::APPLY_SOCKET_PATH.into(),
            mdns: MdnsOptions::default(),
            arp: crate::arp::ARP_PATH.into(),
            oui: crate::oui::OUI_CSV_PATH.into(),
        }
    }
}

impl ScanIo for SystemIo {
    fn leases(&mut self) -> Result<Value, HelperError> {
        dhcp_leases(&self.socket)
    }
    fn mdns(&mut self, addresses: &[String]) -> Result<MdnsResults, String> {
        discover(addresses, &self.mdns)
    }
    fn arp_table(&mut self) -> Result<Vec<ArpEntry>, Crash> {
        read_arp_table(&self.arp)
    }
    fn vendor_db(&mut self) -> Result<VendorDb, Crash> {
        load_vendor_db(&self.oui)
    }
    fn oui_path(&self) -> String {
        self.oui.display().to_string()
    }
    fn sync(&mut self, macs: &[String]) -> Result<Value, HelperError> {
        iot_sync_isolation(&self.socket, macs)
    }
}

/// 1.x's `_write_state`: the directory made, the text written to
/// `<path>.tmp` and moved over `path`, so the webUI never reads half a
/// file.
pub fn write_inventory(path: &Path, text: &str) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    fs::write(&tmp, text)?;
    fs::rename(&tmp, path)
}
