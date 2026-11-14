//! The real `fr-iot-scan` binary on real files, a real Unix-socket fake
//! apply-helper and a real UDP fake mDNS responder on loopback: one
//! scan finds a device by its lease, hears its services, asks the
//! helper to isolate it, prints the messages and writes the inventory;
//! a refused configuration, discovery switched off and a helper reply
//! 1.x dies on each end as decided (phase 4e-3).

use std::fs;
use std::io::{Read as _, Write as _};
use std::net::UdpSocket;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_fr-iot-scan");
/// Each test's own mDNS ports (responder, bind): the tests run at once.
const SCAN: (&str, &str) = ("127.0.0.2:45363", "45540");
const CRASH: (&str, &str) = ("127.0.0.2:45364", "45541");
const REFUSED: (&str, &str) = ("127.0.0.2:45365", "45542");
const OFF: (&str, &str) = ("127.0.0.2:45366", "45543");
const CONFIG: (&str, &str) = ("127.0.0.2:45367", "45544");

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fros-iot-e2e-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// A fake apply-helper answering each connection with the next answer:
/// the requests it got.
fn helper(sock: &Path, answers: Vec<Vec<u8>>) -> thread::JoinHandle<Vec<String>> {
    let _ = fs::remove_file(sock);
    let listener = UnixListener::bind(sock).expect("bind");
    thread::spawn(move || {
        let mut requests = Vec::new();
        for answer in answers {
            let Ok((mut conn, _)) = listener.accept() else {
                break;
            };
            let mut request = Vec::new();
            conn.read_to_end(&mut request).expect("read");
            requests.push(String::from_utf8_lossy(&request).into_owned());
            let _ = conn.write_all(&answer);
        }
        requests
    })
}

fn name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// An mDNS response advertising `services`.
fn ptrs(services: &[&str]) -> Vec<u8> {
    let mut out = vec![0, 0, 0x84, 0, 0, 0, 0, services.len() as u8, 0, 0, 0, 0];
    for s in services {
        let target = name(s);
        out.extend(name("_services._dns-sd._udp.local"));
        out.extend([0, 12, 0x80, 1, 0, 0, 0x11, 0x94, 0, target.len() as u8]);
        out.extend(target);
    }
    out
}

/// A fake mDNS responder: answers the first query with `services`.
fn responder(at: &str, services: &'static [&'static str]) -> thread::JoinHandle<Option<Vec<u8>>> {
    let sock = UdpSocket::bind(at).expect("bind responder");
    thread::spawn(move || {
        sock.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        let mut buf = vec![0u8; 9000];
        let (n, peer) = sock.recv_from(&mut buf).ok()?;
        sock.send_to(&ptrs(services), peer).ok()?;
        Some(buf[..n].to_vec())
    })
}

fn view(dir: &Path, iot: &str) -> PathBuf {
    let path = dir.join("sensor-view.json");
    fs::write(&path, format!("{{\"iot\": {iot}}}\n")).expect("view");
    path
}

const IOT_ON: &str = r#"{"enabled": true, "interfaces": [{"device": "lo", "address": "127.0.0.1/8"}],
    "trusted_macs": [], "isolated_macs": [], "auto_isolate": true, "isolation_mode": "block"}"#;

fn run(dir: &Path, view: &Path, (target, bind): (&str, &str)) -> Output {
    let arp = dir.join("arp");
    fs::write(
        &arp,
        "IP address       HW type     Flags       HW address            Mask     Device\n",
    )
    .expect("arp");
    let oui = dir.join("oui.csv");
    fs::write(
        &oui,
        "Registry,Assignment,Organization Name,Organization Address\nMA-L,240AC4,Espressif Inc.,CN\n",
    )
    .expect("oui");
    Command::new(BIN)
        .args(["--view".as_ref(), view.as_os_str()])
        .args([
            "--state".as_ref(),
            dir.join("sensors/iot_inventory.json").as_os_str(),
        ])
        .args(["--socket".as_ref(), dir.join("apply.sock").as_os_str()])
        .args(["--arp".as_ref(), arp.as_os_str()])
        .args(["--oui".as_ref(), oui.as_os_str()])
        .args([
            "--mdns-target",
            target,
            "--mdns-port",
            bind,
            "--mdns-timeout",
            "0.5",
        ])
        .output()
        .expect("run fr-iot-scan")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn a_scan_finds_hears_isolates_and_records() {
    let dir = temp_dir("scan");
    let leases = br#"{"ok": true, "leases": [{"mac": "24:0A:C4:11:22:33", "ip": "127.0.0.2", "hostname": "esp-plug"}]}"#;
    let helper = helper(
        &dir.join("apply.sock"),
        vec![
            [&leases[..], b"\n"].concat(),
            b"{\"ok\": true, \"isolated\": [\"24:0a:c4:11:22:33\"]}\n".to_vec(),
        ],
    );
    let responder = responder(SCAN.0, &["_hap._tcp.local", "_matter._tcp.local"]);
    let out = run(&dir, &view(&dir, IOT_ON), SCAN);
    let requests = helper.join().expect("helper");
    let query = responder.join().expect("responder").expect("a query");

    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        stdout(&out),
        "1 device(s) found: 1 iot\n1 device(s) isolated (block)\n"
    );
    assert_eq!(
        requests,
        [
            "{\"cmd\": \"dhcp_leases\"}\n",
            "{\"cmd\": \"iot_sync_isolation\", \"macs\": [\"24:0a:c4:11:22:33\"]}\n"
        ]
    );
    assert_eq!(&query[2..4], &[0, 0], "a query, not a response");
    let inventory = fs::read_to_string(dir.join("sensors/iot_inventory.json")).expect("inventory");
    for want in [
        "\"_hap._tcp\"",
        "\"_matter._tcp\"",
        "\"esp-plug\"",
        "\"Espressif Inc.\"",
        "\"isolated\": true",
    ] {
        assert!(inventory.contains(want), "{want} not in {inventory}");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_reply_1x_dies_on_keeps_the_last_inventory() {
    let dir = temp_dir("crash");
    fs::create_dir_all(dir.join("sensors")).expect("dir");
    fs::write(dir.join("sensors/iot_inventory.json"), "{\"last\": 1}\n").expect("last");
    let helper = helper(
        &dir.join("apply.sock"),
        vec![b"{\"ok\": true, \"leases\": [\"\xff\"]}\n".to_vec()],
    );
    let out = run(&dir, &view(&dir, IOT_ON), CRASH);
    helper.join().expect("helper");
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_eq!(stdout(&out), "error: scan failed: UnicodeDecodeError\n");
    assert_eq!(
        fs::read_to_string(dir.join("sensors/iot_inventory.json")).expect("inventory"),
        "{\"last\": 1}\n"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn isolation_refused_is_an_error() {
    let dir = temp_dir("refused");
    let helper = helper(
        &dir.join("apply.sock"),
        vec![
            b"{\"ok\": true, \"leases\": []}\n".to_vec(),
            b"{\"ok\": false, \"message\": \"nft failed\"}\n".to_vec(),
        ],
    );
    let out = run(&dir, &view(&dir, IOT_ON), REFUSED);
    helper.join().expect("helper");
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_eq!(
        stdout(&out),
        "0 device(s) found in the IoT zones\nerror: isolation not applied: nft failed\n"
    );
    assert!(dir.join("sensors/iot_inventory.json").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn switched_off_writes_nothing() {
    let dir = temp_dir("off");
    let off = IOT_ON.replace("\"enabled\": true", "\"enabled\": false");
    let out = run(&dir, &view(&dir, &off), OFF);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        stdout(&out),
        "IoT discovery is disabled (iot.enabled: false)\n"
    );
    assert!(!dir.join("sensors/iot_inventory.json").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_refused_configuration_is_an_error() {
    let dir = temp_dir("refused-config");
    let path = dir.join("sensor-view.json");
    fs::write(&path, "{\"config_error\": \"zones: missing\"}\n").expect("view");
    let out = run(&dir, &path, CONFIG);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_eq!(
        stdout(&out),
        "error: the configuration was refused: zones: missing\n"
    );
    let out = run(&dir, &dir.join("no-such-view.json"), CONFIG);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(stdout(&out).starts_with("error: no sensor view at "));
    let _ = fs::remove_dir_all(&dir);
}
