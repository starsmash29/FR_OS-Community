//! `fr-ai-ids` itself, end to end on real files and a real Unix socket:
//! a fake apply-helper answers its conntrack samples with a scan from
//! one LAN host and every quarantine with ok; the XDP filter's event
//! file, which appears after the daemon started, reports SNI-blocklist
//! drops from another. Both hosts must be quarantined through the
//! socket and written to the event log; a gateway and an address
//! outside the LAN must not be. Then the view turns ai_ids off: the
//! daemon starts over and exits, as 1.x does when it is off.

use std::fs;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fros-aiids-e2e-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn view(path: &Path, enabled: bool) {
    fs::write(
        path,
        format!(
            r#"{{"tls_fingerprint": {{}}, "ai_ids": {{"enabled": {enabled}, "excluded_macs": [], "excluded_ips": [],
              "internal_networks": ["10.0.0.0/24"], "infrastructure": ["10.0.0.1"], "threat_categories": [],
              "query_log": false, "quarantine_duration_seconds": 600}}}}"#
        ),
    )
    .expect("view");
}

fn scan() -> String {
    let flows: Vec<String> = (1..=60)
        .map(|i| format!(r#"{{"proto": "tcp", "src": "10.0.0.7", "sport": {}, "dst": "198.51.100.{i}", "dport": 443}}"#, 30000 + i))
        .chain([r#"{"proto": "tcp", "src": "192.0.2.9", "sport": 1, "dst": "10.0.0.7", "dport": 22}"#.to_owned()])
        .collect();
    format!("{{\"ok\": true, \"flows\": [{}]}}\n", flows.join(", "))
}

/// The fake apply-helper: every request it got, in order.
fn serve(sock: &Path) -> Arc<Mutex<Vec<String>>> {
    let listener = UnixListener::bind(sock).expect("bind");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&requests);
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { break };
            let mut request = String::new();
            if conn.read_to_string(&mut request).is_err() {
                continue;
            }
            let answer = if request.contains("conntrack_sample") {
                scan()
            } else {
                "{\"ok\": true}\n".into()
            };
            let _ = conn.write_all(answer.as_bytes());
            seen.lock().expect("lock").push(request);
        }
    });
    requests
}

/// Kills the daemon when the test ends, however it ends.
struct Reap(std::process::Child);

impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_until(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if ok() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn samples_scores_quarantines_and_restarts() {
    let dir = temp_dir("run");
    let p = |n: &str| dir.join(n);
    let (view_path, events, sni, sock) = (
        p("view.json"),
        p("events.json"),
        p("events.jsonl"),
        p("apply.sock"),
    );
    view(&view_path, true);
    // 10.0.0.2 is the default gateway; 192.0.2.53 the resolver.
    fs::write(
        p("route"),
        "Iface\tDestination\tGateway\neth1\t00000000\t0200000A\t0003\n",
    )
    .expect("route");
    fs::write(p("resolv.conf"), "nameserver 192.0.2.53\n").expect("resolv");
    let requests = serve(&sock);
    let path = |q: &Path| q.to_str().expect("path").to_owned();
    let child = Command::new(env!("CARGO_BIN_EXE_fr-ai-ids"))
        .args([
            "--view",
            &path(&view_path),
            "--events",
            &path(&events),
            "--sni-events",
            &path(&sni),
        ])
        .args([
            "--socket",
            &path(&sock),
            "--route",
            &path(&p("route")),
            "--resolv",
            &path(&p("resolv.conf")),
        ])
        .args([
            "--dns-log",
            &path(&p("queries.log")),
            "--window",
            "2",
            "--tick",
            "0.5",
        ])
        .stdout(Stdio::piped())
        .stderr(fs::File::create(p("stderr")).expect("stderr"))
        .spawn()
        .expect("fr-ai-ids");
    let mut child = Reap(child);
    let out = child.0.stdout.take().expect("stdout");
    let printed = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&printed);
    thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            sink.lock().expect("lock").push(line);
        }
    });
    let mut drops = String::new();
    for src in ["10.0.0.5", "10.0.0.2", "192.0.2.9"] {
        for _ in 0..4 {
            drops.push_str(&format!(
                "{{\"ts\": 1.0, \"action\": \"drop\", \"saddr\": \"{src}\", \"sport\": 1, \"daddr\": \"203.0.113.1\", \
                 \"dport\": 443, \"sni\": \"evil.test\"}}\n"
            ));
        }
    }
    // Written once the daemon follows the file (it has asked for a
    // sample): a file there before that is read from its end, as `tail
    // -n 0 -F` reads it.
    wait_until("the first conntrack sample", || {
        !requests.lock().expect("lock").is_empty()
    });
    fs::write(&sni, drops).expect("events");

    wait_until("both quarantines in the event log", || {
        fs::read_to_string(&events)
            .is_ok_and(|t| t.contains("\"10.0.0.7\"") && t.contains("\"10.0.0.5\""))
    });
    let log = fs::read_to_string(&events).expect("events");
    assert!(
        log.contains("connection-rate spike") && log.contains("SNI-blocklist beacon"),
        "{log}"
    );
    assert!(
        !log.contains("10.0.0.2") && !log.contains("192.0.2.9"),
        "{log}"
    );
    {
        let requests = requests.lock().expect("lock");
        assert!(
            requests
                .iter()
                .any(|r| r == "{\"cmd\": \"conntrack_sample\"}\n"),
            "{requests:?}"
        );
        for ip in ["10.0.0.7", "10.0.0.5"] {
            let want = format!(
                "{{\"cmd\": \"quarantine_ip\", \"ip\": \"{ip}\", \"duration_seconds\": 600}}\n"
            );
            assert!(requests.contains(&want), "{requests:?}");
        }
        assert!(
            !requests
                .iter()
                .any(|r| r.contains("10.0.0.2") || r.contains("192.0.2.9")),
            "{requests:?}"
        );
    }
    wait_until("the gateway reported as infrastructure", || {
        printed
            .lock()
            .expect("lock")
            .iter()
            .any(|l| l.contains("10.0.0.2 scored") && l.contains("infrastructure"))
    });

    view(&view_path, false);
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.0.try_wait().expect("wait") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "fr-ai-ids still running: {:?}",
            printed.lock().expect("lock")
        );
        thread::sleep(Duration::from_millis(100));
    };
    assert!(status.success(), "{status}");
    wait_until("the restart and the exit printed", || {
        let printed = printed.lock().expect("lock");
        printed
            .iter()
            .any(|l| l == "fr-ai-ids: ai_ids settings changed; restarting")
            && printed
                .iter()
                .any(|l| l == "fr-ai-ids: ai_ids.enabled is false in config.yaml; exiting")
    });
    let _ = fs::remove_dir_all(&dir);
}
