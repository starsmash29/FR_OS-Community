//! Replays FR_OS 1.x's IoT scan through its helper client and its mDNS
//! discovery on a real socket (testdata/reference/sensord.jsonl, ops
//! `iotscan` and `mdns`, written by reference/test_fros_sensord_cases.py).
//!
//! `iotscan`: with the same view, neighbour table and OUI registry,
//! asking a fake apply-helper on a real Unix socket that answers the
//! same bytes, the scan must send the same requests, give the same
//! messages and write the same inventory, or die on the same exception.
//!
//! `mdns`: discovery on a real UDP socket, aimed at a fake responder on
//! loopback that sends the same answers from the same addresses and
//! ports, must send the same query (less its random id) the same number
//! of times and find the same services, or give the same error.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use fros_iot::Crash;
use fros_iot::arp::{ArpEntry, read_arp_table};
use fros_iot::oui::{VendorDb, load_vendor_db};
use fros_iot::scan::{MdnsResults, ScanIo, View, run_scan};
use fros_iot::system::{self, MdnsOptions, write_inventory};
use fros_sensor::helper::HelperError;
use fros_sensor::pyjson::{self, Dict, Value};
use fros_sensor::reference::{cases, clip, field, int, list, number, report, strs, text};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fros-iot-sys-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// One connection to a fake apply-helper on `sock` answering `answer`
/// (hex), or a regular file there ("file"), or nothing (null): the
/// request line it got.
fn serve_once<T>(sock: &Path, answer: &Value, call: impl FnOnce() -> T) -> (Option<String>, T) {
    let _ = fs::remove_file(sock);
    let server = match answer {
        Value::Null => None,
        Value::Str(s) if s == "file" => {
            fs::write(sock, "").expect("file");
            None
        }
        Value::Str(h) => {
            let bytes = hex(h);
            let listener = UnixListener::bind(sock).expect("bind");
            Some(thread::spawn(move || {
                let (mut conn, _) = listener.accept().expect("accept");
                let mut request = Vec::new();
                conn.read_to_end(&mut request).expect("read");
                let _ = conn.write_all(&bytes);
                String::from_utf8_lossy(&request).into_owned()
            }))
        }
        other => panic!("answer {other:?}"),
    };
    let reply = call();
    let request = server.map(|t| t.join().expect("server"));
    let _ = fs::remove_file(sock);
    (request, reply)
}

/// The real helper calls, to a fake helper answering the recording's
/// bytes in turn (then `{"ok": true}`), with the recorded mDNS answers
/// and the real file readers.
struct Replay<'a> {
    sock: &'a Path,
    answers: Vec<Value>,
    requests: Vec<Value>,
    mdns: MdnsResults,
    arp: PathBuf,
    oui: PathBuf,
}

impl Replay<'_> {
    fn helper(
        &mut self,
        call: impl FnOnce(&Path) -> Result<Value, HelperError>,
    ) -> Result<Value, HelperError> {
        let answer = if self.answers.is_empty() {
            Value::Str(hex_of(b"{\"ok\": true}\n"))
        } else {
            self.answers.remove(0)
        };
        let sock = self.sock;
        let (request, reply) = serve_once(sock, &answer, || call(sock));
        self.requests.push(request.map_or(Value::Null, Value::Str));
        reply
    }
}

impl ScanIo for Replay<'_> {
    fn leases(&mut self) -> Result<Value, HelperError> {
        self.helper(system::dhcp_leases)
    }
    fn mdns(&mut self, _addresses: &[String]) -> Result<MdnsResults, String> {
        Ok(self.mdns.clone())
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
        self.helper(|s| system::iot_sync_isolation(s, macs))
    }
}

fn check_scan(case: &Dict, dir: &Path) -> Result<(), String> {
    let sock = dir.join("apply.sock");
    let arp = dir.join("arp");
    let oui = dir.join("oui.csv");
    fs::write(&arp, text(field(case, "arp"))).expect("arp");
    fs::write(&oui, hex(text(field(case, "oui")))).expect("oui");
    let Value::Dict(mdns) = field(case, "mdns") else {
        panic!("mdns")
    };
    let view = View::from_json(field(case, "view")).map_err(|e| format!("view refused: {e:?}"))?;
    let recorded = list(field(case, "helper"));
    let pick = |key: &str| -> Vec<Value> {
        recorded
            .iter()
            .map(|c| match c {
                Value::Dict(c) => field(c, key).clone(),
                _ => panic!("call"),
            })
            .collect()
    };
    let mut io = Replay {
        sock: &sock,
        answers: pick("answer"),
        requests: Vec::new(),
        mdns: mdns
            .0
            .iter()
            .map(|(ip, s)| (ip.clone(), strs(s).into_iter().collect()))
            .collect(),
        arp,
        oui,
    };
    let result = run_scan(&view, &mut io, number(field(case, "now")));
    let sock_text = sock.display().to_string();
    let requests: Vec<Value> = io
        .requests
        .iter()
        .map(|r| match r {
            Value::Str(s) => Value::Str(s.replace(&sock_text, "@SOCK@")),
            other => other.clone(),
        })
        .collect();
    let want = pick("request");
    if requests != want {
        return Err(format!("requests\n got {requests:?}\nwant {want:?}"));
    }
    match (result, case.get("crash")) {
        (Err(Crash(name)), Some(want)) if name == text(want) => Ok(()),
        (Err(crash), want) => Err(format!("died of {crash:?}, want {want:?}")),
        (Ok(_), Some(want)) => Err(format!("ran to the end; 1.x died of {want:?}")),
        (Ok(r), None) => {
            let messages: Vec<String> = r
                .messages
                .iter()
                .map(|m| m.replace(&sock_text, "@SOCK@"))
                .collect();
            let want = strs(field(case, "messages"));
            if messages != want {
                return Err(format!("messages\n got {messages:?}\nwant {want:?}"));
            }
            let state = r.state.map(|s| s.replace(&sock_text, "@SOCK@"));
            let want = match field(case, "state") {
                Value::Str(s) => Some(s.clone()),
                _ => None,
            };
            if state != want {
                return Err(format!(
                    "inventory\n got {:?}\nwant {:?}",
                    state.as_deref().map(clip),
                    want.as_deref().map(clip)
                ));
            }
            Ok(())
        }
    }
}

#[test]
fn reference_iot_scan_through_the_helper() {
    let dir = temp_dir("scan");
    let mut failures = Vec::new();
    let mut seen = 0;
    for case in cases(env!("CARGO_MANIFEST_DIR"), "sensord.jsonl") {
        if text(field(&case, "op")) != "iotscan" {
            continue;
        }
        seen += 1;
        if let Err(e) = check_scan(&case, &dir) {
            failures.push(format!("{}: {e}", text(field(&case, "name"))));
        }
    }
    let _ = fs::remove_dir_all(&dir);
    assert!(seen >= 10, "only {seen} iotscan cases");
    report(&failures);
}

fn check_mdns(case: &Dict) -> Result<(), String> {
    let responder_ip: Ipv4Addr = text(field(case, "responder")).parse().expect("ip");
    let port = int(field(case, "port")) as u16;
    let bind = int(field(case, "bind")) as u16;
    let responder = SocketAddrV4::new(responder_ip, port);
    let answers: Vec<(SocketAddrV4, Vec<u8>)> = list(field(case, "answers"))
        .iter()
        .map(|a| {
            let a = list(a);
            (
                SocketAddrV4::new(text(&a[0]).parse().expect("ip"), int(&a[1]) as u16),
                hex(text(&a[2])),
            )
        })
        .collect();
    let handle = respond(responder, answers);
    let blocker = matches!(field(case, "taken"), Value::Bool(true))
        .then(|| UdpSocket::bind(("0.0.0.0", bind)).expect("bind blocker"));
    let options = MdnsOptions {
        target: responder,
        bind_port: bind,
        timeout: Duration::from_secs_f64(number(field(case, "timeout"))),
        max_packets: int(field(case, "max_packets")) as usize,
    };
    let addresses = strs(field(case, "addresses"));
    let got = system::discover(&addresses, &options);
    drop(blocker);
    let queries = handle.finish(responder);

    let want_queries = strs(field(case, "queries"));
    let got_queries: Vec<String> = queries
        .iter()
        .map(|q| hex_of(&q[2.min(q.len())..]))
        .collect();
    if got_queries != want_queries {
        return Err(format!(
            "queries\n got {got_queries:?}\nwant {want_queries:?}"
        ));
    }
    match (got, case.get("error")) {
        (Err(e), Some(want)) if e == text(want) => Ok(()),
        (Err(e), want) => Err(format!("error {e:?}, want {want:?}")),
        (Ok(found), Some(want)) => Err(format!("found {found:?}; want the error {want:?}")),
        (Ok(found), None) => {
            let got = pyjson::dumps(&Value::Dict(Dict(
                found
                    .into_iter()
                    .map(|(ip, s)| (ip, Value::List(s.into_iter().map(Value::Str).collect())))
                    .collect(),
            )));
            let want = pyjson::dumps(field(case, "found"));
            if got != want {
                return Err(format!("found\n got {}\nwant {}", clip(&got), clip(&want)));
            }
            Ok(())
        }
    }
}

/// The responder, with every socket it binds kept until the case ends.
struct Responder {
    main: UdpSocket,
    thread: thread::JoinHandle<Option<Vec<u8>>>,
}

impl Responder {
    /// Every query the responder got: the one it answered, then any
    /// still queued.
    fn finish(self, at: SocketAddrV4) -> Vec<Vec<u8>> {
        let mut queries = Vec::new();
        if !self.thread.is_finished() {
            // Nothing was sent: end the responder's wait.
            let kick = UdpSocket::bind("127.0.0.1:0").expect("bind");
            let _ = kick.send_to(b"", SocketAddr::V4(at));
        }
        if let Ok(Some(first)) = self.thread.join() {
            queries.push(first);
        }
        self.main.set_nonblocking(true).expect("nonblocking");
        let mut buf = vec![0u8; 65536];
        while let Ok(n) = self.main.recv(&mut buf) {
            queries.push(buf[..n].to_vec());
        }
        queries.retain(|q| !q.is_empty());
        queries
    }
}

/// The fake responder: sockets at each answer's source; once the first
/// query reaches the responder's own socket, every answer is sent from
/// its source to where the query came from, in order.
fn respond(responder: SocketAddrV4, answers: Vec<(SocketAddrV4, Vec<u8>)>) -> Responder {
    let mut socks: BTreeMap<SocketAddrV4, UdpSocket> = BTreeMap::new();
    for src in answers.iter().map(|(src, _)| *src).chain([responder]) {
        socks
            .entry(src)
            .or_insert_with(|| UdpSocket::bind(src).expect("bind answer source"));
    }
    let main = socks[&responder].try_clone().expect("clone");
    let listen = socks[&responder].try_clone().expect("clone");
    let thread = thread::spawn(move || {
        listen.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
        let mut buf = vec![0u8; 65536];
        let (n, peer) = listen.recv_from(&mut buf).ok()?;
        for (src, packet) in &answers {
            let _ = socks[src].send_to(packet, peer);
        }
        Some(buf[..n].to_vec())
    });
    Responder { main, thread }
}

#[test]
fn reference_mdns_discovery_on_a_real_socket() {
    let mut failures = Vec::new();
    let mut seen = 0;
    for case in cases(env!("CARGO_MANIFEST_DIR"), "sensord.jsonl") {
        if text(field(&case, "op")) != "mdns" {
            continue;
        }
        seen += 1;
        if let Err(e) = check_mdns(&case) {
            failures.push(format!("{}: {e}", text(field(&case, "name"))));
        }
    }
    assert!(seen >= 10, "only {seen} mdns cases");
    report(&failures);
}

/// The inventory is moved into place whole, its directory made first.
#[test]
fn inventory_written_whole() {
    let dir = temp_dir("inventory");
    let path = dir.join("sensors").join("iot_inventory.json");
    write_inventory(&path, "{}\n").expect("write");
    assert_eq!(fs::read_to_string(&path).expect("read"), "{}\n");
    write_inventory(&path, "{\"a\": 1}\n").expect("write");
    assert_eq!(fs::read_to_string(&path).expect("read"), "{\"a\": 1}\n");
    assert!(!dir.join("sensors").join("iot_inventory.json.tmp").exists());
    let _ = fs::remove_dir_all(&dir);
}
