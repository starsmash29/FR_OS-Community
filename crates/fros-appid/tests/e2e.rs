//! `fr-appid` itself, end to end on real files: started with no source
//! turned on it idles; with "dns" it follows a query log that doesn't
//! exist yet, writes the usage file every flush, and when the view's
//! sources change it starts over as a new process.

use std::fs;
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fros-appid-e2e-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn view(path: &Path, sources: &[&str]) {
    let list: Vec<String> = sources.iter().map(|s| format!("\"{s}\"")).collect();
    fs::write(
        path,
        format!(
            "{{\"app_control\": {{\"sources\": [{}]}}}}",
            list.join(", ")
        ),
    )
    .expect("view");
}

fn append(path: &Path, text: &str) {
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("log");
    f.write_all(text.as_bytes()).expect("append");
}

/// The process's stdout, line by line.
fn lines(child: &mut Child) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    let out = child.stdout.take().expect("stdout");
    thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

fn wait_for(rx: &mpsc::Receiver<String>, want: &str, seen: &mut Vec<String>) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Ok(line) = rx.recv_timeout(Duration::from_millis(200)) {
            let hit = line.contains(want);
            seen.push(line);
            if hit {
                return;
            }
        }
    }
    panic!("no {want:?} in {seen:?}");
}

fn wait_until(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if ok() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn follows_writes_and_restarts() {
    let dir = temp_dir("run");
    let (view_path, usage, dns_log) = (
        dir.join("view.json"),
        dir.join("usage.json"),
        dir.join("queries.log"),
    );
    view(&view_path, &[]);
    let mut child = Command::new(env!("CARGO_BIN_EXE_fr-appid"))
        .args([
            "--view",
            view_path.to_str().unwrap(),
            "--usage",
            usage.to_str().unwrap(),
        ])
        .args([
            "--dns-log",
            dns_log.to_str().unwrap(),
            "--sni-events",
            dir.join("events.jsonl").to_str().unwrap(),
        ])
        .args(["--flush", "0.5"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("fr-appid");
    let rx = lines(&mut child);
    let mut seen = Vec::new();
    wait_for(&rx, "fr-appid: idle", &mut seen);
    view(&view_path, &["dns"]);
    wait_for(&rx, "fr-appid: following", &mut seen);
    // The log appears after the daemon started: read from its start.
    append(
        &dns_log,
        "Nov 14 08:00:00 dnsmasq[1]: 1 10.0.0.5/40000 query[A] www.netflix.com from 10.0.0.5\n",
    );
    wait_until("the usage file", || {
        fs::read_to_string(&usage).is_ok_and(|t| t.contains("netflix") && t.contains("10.0.0.5"))
    });
    view(&view_path, &["dns", "sni"]);
    wait_for(&rx, "observation sources changed; restarting", &mut seen);
    wait_for(&rx, "fr-appid: following", &mut seen);
    assert!(
        child.try_wait().expect("wait").is_none(),
        "fr-appid exited: {seen:?}"
    );
    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_dir_all(&dir);
}
