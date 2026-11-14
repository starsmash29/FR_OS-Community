//! Replays FR_OS 1.x's TLS fingerprinting daemon
//! (testdata/reference/tlsfpd.jsonl, written by
//! reference/test_fros_tlsfpd_cases.py): started on the same state file
//! with the same view, fed the same ring buffer records at the same
//! clocks, asking a fake apply-helper that answers the same bytes, the
//! daemon must send the same requests, count the same, and write the
//! same state file, byte for byte. And the helper client alone must
//! send the same line and get the same reply or error text.
//!
//! Decided (testdata/reference/decisions.md, "phase 4e-1"): a state
//! file 1.x dies on at start is put aside and the daemon starts afresh,
//! which the recording's steps (those of 1.x started without the file)
//! check; a reply 1.x dies on mid-run is reported as a failed
//! quarantine.

use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::thread;

use fros_sensor::helper::{self, HelperError};
use fros_sensor::pyjson::{self, Dict, Value};
use fros_sensor::reference::{cases, clip, field, int, list, number, report, text};
use fros_tlsfp::daemon::{self, Daemon, Segment, View, restore_state};
use fros_xdp::events::HelloSegment;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fros-tlsfpd-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// A fake apply-helper on `sock` answering one connection with
/// `answer` (hex), or a regular file there ("file"), or nothing (null).
struct Fake {
    thread: Option<thread::JoinHandle<String>>,
}

impl Fake {
    fn start(sock: &Path, answer: &Value) -> Fake {
        let _ = fs::remove_file(sock);
        match answer {
            Value::Null => Fake { thread: None },
            Value::Str(s) if s == "file" => {
                fs::write(sock, "").expect("file");
                Fake { thread: None }
            }
            Value::Str(h) => {
                let bytes = hex(h);
                let listener = UnixListener::bind(sock).expect("bind");
                let thread = thread::spawn(move || {
                    let (mut conn, _) = listener.accept().expect("accept");
                    let mut request = Vec::new();
                    conn.read_to_end(&mut request).expect("read");
                    let _ = conn.write_all(&bytes);
                    String::from_utf8_lossy(&request).into_owned()
                });
                Fake {
                    thread: Some(thread),
                }
            }
            other => panic!("answer {other:?}"),
        }
    }

    /// The request line it got (`None`: no server).
    fn finish(self, sock: &Path) -> Option<String> {
        let request = self.thread.map(|t| t.join().expect("server"));
        let _ = fs::remove_file(sock);
        request
    }
}

fn opt_text(v: Option<&String>) -> Value {
    v.map_or(Value::Null, |s| Value::Str(s.clone()))
}

fn view_of(case: &Dict) -> View {
    let top = Value::Dict(Dict(vec![(
        "tls_fingerprint".into(),
        field(case, "view").clone(),
    )]));
    View::from_json(&top).expect("view")
}

fn check_daemon(case: &Dict, dir: &Path) -> Result<(), String> {
    let path = dir.join("tls_fingerprints.json");
    let sock = dir.join("apply.sock");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(dir.join("tls_fingerprints.json.broken"));
    if let Value::Str(state) = field(case, "state") {
        fs::write(&path, hex(state)).expect("state");
    }
    let start = number(field(case, "start"));
    let restored = restore_state(&path, start);
    if case.get("crash").is_some() && restored.broken.is_none() {
        return Err("1.x died on the state file; it wasn't put aside".into());
    }
    let mut d = Daemon::new(view_of(case), restored.inventory);
    for (n, step) in list(field(case, "steps")).iter().enumerate() {
        let Value::Dict(step) = step else {
            panic!("step")
        };
        if let Some(view) = step.get("view") {
            let top = Value::Dict(Dict(vec![("tls_fingerprint".into(), view.clone())]));
            d.update_view(View::from_json(&top).expect("view"));
            continue;
        }
        if let Some(now) = step.get("write") {
            let got = d.state_text(number(now));
            daemon::write_state(&path, &got).map_err(|e| format!("step {n}: write: {e}"))?;
            let written = fs::read_to_string(&path)
                .expect("state")
                .replace(&sock.display().to_string(), "@SOCK@");
            let want = text(field(step, "file"));
            if written != want {
                return Err(format!(
                    "step {n}: state file\n got {}\nwant {}",
                    clip(&written),
                    clip(want)
                ));
            }
            continue;
        }
        let raw = hex(text(field(step, "record")));
        let now = number(field(step, "now"));
        let expected = list(field(step, "quarantine"));
        let mut asked: Vec<Option<String>> = Vec::new();
        let mut i = 0;
        if let Ok(seg) = HelloSegment::from_bytes(&raw) {
            let seg = Segment {
                saddr: &seg.saddr,
                sport: seg.sport,
                daddr: &seg.daddr,
                dport: seg.dport,
                seq: seg.seq,
                first: seg.first,
                payload: &seg.payload,
            };
            let mut quarantine = |ip: &str, duration: i64| -> Result<Value, HelperError> {
                let Some(Value::Dict(call)) = expected.get(i) else {
                    asked.push(Some(format!("an extra quarantine of {ip}")));
                    return Ok(Value::Dict(Dict(vec![("ok".into(), Value::Bool(true))])));
                };
                i += 1;
                let fake = Fake::start(&sock, field(call, "answer"));
                let reply = daemon::quarantine_ip(&sock, ip, duration);
                asked.push(fake.finish(&sock));
                reply
            };
            d.handle_segment(&seg, now, &mut quarantine);
        }
        let want: Vec<Value> = expected
            .iter()
            .map(|c| match c {
                Value::Dict(c) => c.get("request").cloned().unwrap_or(Value::Null),
                _ => Value::Null,
            })
            .collect();
        let got: Vec<Value> = asked.iter().map(|r| opt_text(r.as_ref())).collect();
        if got != want {
            return Err(format!("step {n}: requests\n got {got:?}\nwant {want:?}"));
        }
        if step.get("crash").is_some() {
            // 1.x died here; FR_OS 2 reports the quarantine as failed.
            let state = d.state_text(now);
            if !state.contains("quarantine failed: the apply-helper's reply is not an object") {
                return Err(format!(
                    "step {n}: 1.x died on the reply; no failed quarantine reported"
                ));
            }
            return Ok(());
        }
        let Value::Dict(stats) = field(step, "stats") else {
            panic!("stats")
        };
        let (hellos, errors) = d.stats();
        let want = (
            int(field(stats, "hellos")) as u64,
            int(field(stats, "parse_errors")) as u64,
        );
        if (hellos, errors) != want {
            return Err(format!(
                "step {n}: stats ({hellos}, {errors}), want {want:?}"
            ));
        }
    }
    Ok(())
}

fn check_client(case: &Dict, dir: &Path) -> Result<(), String> {
    let sock = dir.join("client.sock");
    let Value::Dict(cmd) = field(case, "cmd") else {
        panic!("cmd")
    };
    let max = case
        .get("max_bytes")
        .map_or(helper::MAX_LINE_BYTES, |m| int(m) as usize);
    let fake = Fake::start(&sock, field(case, "answer"));
    let got = helper::send_command(cmd, &sock, helper::TIMEOUT, max);
    let request = fake.finish(&sock);
    if opt_text(request.as_ref()) != *field(case, "request") {
        return Err(format!(
            "request {request:?}, want {:?}",
            field(case, "request")
        ));
    }
    let sock_text = sock.display().to_string();
    match (
        got,
        case.get("reply"),
        case.get("error"),
        case.get("raised"),
    ) {
        (Ok(v), Some(want), _, _) if pyjson::dumps(&v) == pyjson::dumps(want) => Ok(()),
        (Err(HelperError::Transport(e)), _, Some(want), _)
            if e.replace(&sock_text, "@SOCK@") == text(want) =>
        {
            Ok(())
        }
        (Err(HelperError::Raised(name)), _, _, Some(want)) if name == text(want) => Ok(()),
        (got, reply, error, raised) => Err(format!(
            "got {got:?}, want reply {reply:?} error {error:?} raised {raised:?}"
        )),
    }
}

#[test]
fn reference_tlsfpd() {
    let all = cases(env!("CARGO_MANIFEST_DIR"), "tlsfpd.jsonl");
    assert!(!all.is_empty(), "no tlsfpd cases");
    let dir = temp_dir("replay");
    let mut failures = Vec::new();
    for case in &all {
        let result = match text(field(case, "op")) {
            "daemon" => check_daemon(case, &dir),
            "client" => check_client(case, &dir),
            other => Err(format!("unknown op {other}")),
        };
        if let Err(e) = result {
            failures.push(format!(
                "{} {}: {e}",
                text(field(case, "op")),
                text(field(case, "name"))
            ));
        }
    }
    let _ = fs::remove_dir_all(&dir);
    report(&failures);
}

/// A state file past the size limit is put aside unread.
#[test]
fn oversized_state_put_aside() {
    let dir = temp_dir("big");
    let path = dir.join("tls_fingerprints.json");
    let f = fs::File::create(&path).expect("create");
    f.set_len(daemon::STATE_MAX_BYTES + 1).expect("size");
    let restored = restore_state(&path, 1.0);
    let (aside, why) = restored.broken.expect("put aside");
    assert_eq!(aside, dir.join("tls_fingerprints.json.broken"));
    assert!(why.contains("larger than"), "{why}");
    assert!(!path.exists());
    assert_eq!(restored.inventory.client_count(), 0);
    let _ = fs::remove_dir_all(&dir);
}
