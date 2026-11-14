//! Replays FR_OS 1.x's AI-IDS daemon (testdata/reference/sensord.jsonl,
//! op "aiids", written by reference/test_fros_sensord_cases.py): with the
//! same view, routing table, resolv.conf and event log, fed the same
//! lines, conntrack samples and evaluations at the same clocks, asking a
//! fake apply-helper on a real Unix socket that answers the same bytes,
//! the daemon must send the same requests, print the same lines, flag
//! the same events and write the same event log, byte for byte.
//!
//! Decided (testdata/reference/decisions.md, "phase 4e-2"): where 1.x
//! dies (a reply that isn't an object, flows that are a number, an
//! event log that isn't UTF-8) FR_OS 2 logs it and goes on, so there
//! the recording is a prefix of what it does; a lone surrogate in the
//! event log is written as U+FFFD.

use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::thread;

use fros_aiids::AnomalyEngine;
use fros_aiids::daemon::{self, Helper, IdsDaemon, IdsView, Paths, event_fields};
use fros_aiids::engine::ZSCORE_THRESHOLD;
use fros_sensor::helper::HelperError;
use fros_sensor::pyjson::{self, Dict, Value};
use fros_sensor::reference::{cases, clip, field, list, number, report, text};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fros-aiidsd-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// One connection to a fake apply-helper on `sock` answering `answer`
/// (hex), or a regular file there ("file"), or nothing (null): the
/// request line it got.
fn serve_once(
    sock: &Path,
    answer: &Value,
    call: impl FnOnce() -> Result<Value, HelperError>,
) -> (Option<String>, Result<Value, HelperError>) {
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

/// Answers each call with the recording's next answer, then `{"ok": true}`
/// (as the recorder does once its answers run out).
struct Fake<'a> {
    sock: &'a Path,
    answers: Vec<Value>,
    requests: Vec<Value>,
}

impl Fake<'_> {
    fn next(
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

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Helper for Fake<'_> {
    fn conntrack_sample(&mut self) -> Result<Value, HelperError> {
        self.next(daemon::conntrack_sample)
    }
    fn quarantine_ip(&mut self, ip: &str, duration_seconds: i64) -> Result<Value, HelperError> {
        self.next(|s| daemon::quarantine_ip(s, ip, duration_seconds))
    }
}

/// The case's event log after a decided difference: a lone surrogate
/// escape is written as U+FFFD.
fn decided_file(name: &str, want: Vec<u8>) -> Vec<u8> {
    if name == "event log odd values" {
        return String::from_utf8(want)
            .expect("text")
            .replace("\\ud800", "\\ufffd")
            .into_bytes();
    }
    want
}

fn check(case: &Dict, dir: &Path) -> Result<(), String> {
    let name = text(field(case, "name"));
    let sock = dir.join("apply.sock");
    let paths = Paths {
        events: dir.join("ai_ids_events.json"),
        adblock_category_dir: "/etc/fr_os/adblock.d".into(),
        route: dir.join("route"),
        resolv: dir.join("resolv.conf"),
    };
    let _ = fs::remove_file(&paths.events);
    fs::write(&paths.route, text(field(case, "route"))).expect("route");
    fs::write(&paths.resolv, text(field(case, "resolv"))).expect("resolv");
    if let Value::Str(events) = field(case, "events") {
        fs::write(&paths.events, hex(events)).expect("events");
    }
    let top = Value::Dict(Dict(vec![("ai_ids".into(), field(case, "view").clone())]));
    let view = IdsView::from_json(&top).ok_or("the view doesn't read")?;
    let engine = AnomalyEngine::new(number(field(case, "window")), ZSCORE_THRESHOLD);
    let mut d = IdsDaemon::new(view, engine, paths.clone());
    let sock_text = sock.display().to_string();
    for (n, step) in list(field(case, "steps")).iter().enumerate() {
        let Value::Dict(step) = step else {
            panic!("step")
        };
        let now = number(field(step, "now"));
        let recorded = list(field(step, "helper"));
        let mut fake = Fake {
            sock: &sock,
            answers: recorded
                .iter()
                .map(|c| match c {
                    Value::Dict(c) => field(c, "answer").clone(),
                    _ => panic!("call"),
                })
                .collect(),
            requests: Vec::new(),
        };
        let mut flagged = None;
        if let Some(Value::Str(line)) = step.get("sni") {
            d.handle_sni_event_line(line, now);
        } else if let Some(Value::Str(line)) = step.get("dns") {
            d.handle_dns_log_line(line, now);
        } else if step.get("conntrack").is_some() {
            d.poll_conntrack(&mut fake, now);
        } else {
            let wall = number(field(step, "wall"));
            flagged = Some(d.evaluate_and_enforce(&mut fake, now, wall));
        }
        let want_requests: Vec<Value> = recorded
            .iter()
            .map(|c| match c {
                Value::Dict(c) => field(c, "request").clone(),
                _ => panic!("call"),
            })
            .collect();
        let log: String = d
            .take_log()
            .into_iter()
            .map(|(_, l)| l.replace(&sock_text, "@SOCK@") + "\n")
            .collect();
        let want_log = text(field(step, "log"));
        if step.get("crash").is_some() {
            // 1.x died here; FR_OS 2 logs it and goes on.
            if !fake.requests.starts_with(&want_requests) {
                return Err(format!(
                    "step {n}: requests\n got {:?}\nwant {want_requests:?}…",
                    fake.requests
                ));
            }
            if !log.starts_with(want_log) || log == want_log && !name.contains("not utf-8") {
                return Err(format!(
                    "step {n}: 1.x died; log\n got {log:?}\nwant {want_log:?} and more"
                ));
            }
            return Ok(());
        }
        if fake.requests != want_requests {
            return Err(format!(
                "step {n}: requests\n got {:?}\nwant {want_requests:?}",
                fake.requests
            ));
        }
        if log != want_log {
            return Err(format!("step {n}: log\n got {log:?}\nwant {want_log:?}"));
        }
        if let Some(flagged) = flagged {
            let got = pyjson::dumps(&Value::List(
                flagged
                    .iter()
                    .map(|e| Value::Dict(Dict(event_fields(e))))
                    .collect(),
            ));
            let want = pyjson::dumps(field(step, "flagged"));
            if got != want {
                return Err(format!(
                    "step {n}: flagged\n got {}\nwant {}",
                    clip(&got),
                    clip(&want)
                ));
            }
            let got = fs::read(&paths.events).ok();
            let want = match field(step, "file") {
                Value::Str(h) => Some(decided_file(name, hex(h))),
                _ => None,
            };
            if got != want {
                let show =
                    |b: &Option<Vec<u8>>| b.as_ref().map(|b| clip(&String::from_utf8_lossy(b)));
                return Err(format!(
                    "step {n}: event log\n got {:?}\nwant {:?}",
                    show(&got),
                    show(&want)
                ));
            }
        }
    }
    Ok(())
}

#[test]
fn reference_aiids_daemon() {
    let dir = temp_dir("replay");
    let mut failures = Vec::new();
    let mut seen = 0;
    for case in cases(env!("CARGO_MANIFEST_DIR"), "sensord.jsonl") {
        if text(field(&case, "op")) != "aiids" {
            continue;
        }
        seen += 1;
        if let Err(e) = check(&case, &dir) {
            failures.push(format!("{}: {e}", text(field(&case, "name"))));
        }
    }
    let _ = fs::remove_dir_all(&dir);
    assert!(seen > 20, "only {seen} aiids cases");
    report(&failures);
}

/// An event log that isn't UTF-8, where 1.x dies, reads as empty: the
/// new event is all the log then holds.
#[test]
fn event_log_not_utf8_starts_afresh() {
    let dir = temp_dir("utf8");
    let events = dir.join("events.json");
    fs::write(&events, b"[\xff]").expect("events");
    assert!(daemon::load_events(&events).is_empty());
    fs::write(&events, vec![b'['; 20_000]).expect("events");
    assert!(daemon::load_events(&events).is_empty());
    let _ = fs::remove_dir_all(&dir);
}
