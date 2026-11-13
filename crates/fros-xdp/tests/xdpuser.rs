//! Replays what FR_OS 1.x's `frfw.xdp` does with the filter's ring
//! buffer records and its event file (testdata/reference/xdpuser.jsonl,
//! written by reference/test_fros_xdpuser_cases.py): every event record
//! must decode to the same fields and the same JSON line, every hello
//! copy to the same segment, the same records must be refused with the
//! same text, and the event file must hold the same bytes, with the same
//! mode, after the same lines. (The blocklist keys are built by the Go
//! apply and replayed there.)

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use fros_sensor::pyjson::{Dict, Value};
use fros_sensor::reference::{boolean, cases, field, int, list, number, opt_text, report, text};
use fros_xdp::events::{EventFile, HelloSegment, SniEvent, format_event_json};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The recorded error, without 1.x's exception class.
fn error_of(case: &Dict) -> Option<&str> {
    case.get("error")
        .map(|e| text(e).strip_prefix("XdpError: ").expect("an XdpError"))
}

fn check_event(case: &Dict) -> Result<(), String> {
    let raw = hex(text(field(case, "raw")));
    let got = SniEvent::from_bytes(&raw);
    if let Some(want) = error_of(case) {
        return match got {
            Err(e) if e == want => Ok(()),
            other => Err(format!("want error {want:?}, got {other:?}")),
        };
    }
    let event = got.map_err(|e| format!("refused: {e}"))?;
    let want = field(case, "event");
    let Value::Dict(want) = want else {
        panic!("not a dict")
    };
    let fields = [
        (
            "saddr",
            event.saddr.clone(),
            text(field(want, "saddr")).to_owned(),
        ),
        (
            "daddr",
            event.daddr.clone(),
            text(field(want, "daddr")).to_owned(),
        ),
        (
            "sport",
            event.sport.to_string(),
            int(field(want, "sport")).to_string(),
        ),
        (
            "dport",
            event.dport.to_string(),
            int(field(want, "dport")).to_string(),
        ),
        (
            "hostname",
            event.hostname.clone(),
            text(field(want, "hostname")).to_owned(),
        ),
        (
            "action",
            event.action.to_owned(),
            text(field(want, "action")).to_owned(),
        ),
    ];
    for (name, got, want) in fields {
        if got != want {
            return Err(format!("{name}: got {got:?}, want {want:?}"));
        }
    }
    let line = format_event_json(&event, number(field(case, "ts")));
    let want = text(field(case, "line"));
    if line != want {
        return Err(format!("line:\n got {line}\nwant {want}"));
    }
    Ok(())
}

fn check_hello(case: &Dict) -> Result<(), String> {
    let raw = hex(text(field(case, "raw")));
    let got = HelloSegment::from_bytes(&raw);
    if let Some(want) = error_of(case) {
        return match got {
            Err(e) if e == want => Ok(()),
            Err(e) => Err(format!("want error {want:?}, got {e:?}")),
            Ok(_) => Err(format!("want error {want:?}, got a segment")),
        };
    }
    let hello = got.map_err(|e| format!("refused: {e}"))?;
    let Value::Dict(want) = field(case, "hello") else {
        panic!("not a dict")
    };
    let fields = [
        (
            "saddr",
            hello.saddr.clone(),
            text(field(want, "saddr")).to_owned(),
        ),
        (
            "daddr",
            hello.daddr.clone(),
            text(field(want, "daddr")).to_owned(),
        ),
        (
            "sport",
            hello.sport.to_string(),
            int(field(want, "sport")).to_string(),
        ),
        (
            "dport",
            hello.dport.to_string(),
            int(field(want, "dport")).to_string(),
        ),
        (
            "seq",
            hello.seq.to_string(),
            int(field(want, "seq")).to_string(),
        ),
        (
            "first",
            hello.first.to_string(),
            boolean(field(want, "first")).to_string(),
        ),
        (
            "payload",
            to_hex(&hello.payload),
            text(field(want, "payload")).to_owned(),
        ),
    ];
    for (name, got, want) in fields {
        if got != want {
            return Err(format!("{name}: got {got:?}, want {want:?}"));
        }
    }
    Ok(())
}

fn check_eventfile(case: &Dict, dir: &Path) -> Result<(), String> {
    let path = dir.join(text(field(case, "id")));
    if let Some(initial) = opt_text(field(case, "initial")) {
        fs::write(&path, hex(initial)).expect("initial");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
    }
    let max = u64::try_from(int(field(case, "max_bytes"))).expect("max_bytes");
    let mut file = EventFile::open(&path, max).map_err(|e| format!("open: {e}"))?;
    for line in list(field(case, "lines")) {
        file.write_line(text(line))
            .map_err(|e| format!("write: {e}"))?;
    }
    drop(file);
    let content = to_hex(&fs::read(&path).expect("read"));
    let want = text(field(case, "content"));
    if content != want {
        return Err(format!("content:\n got {content}\nwant {want}"));
    }
    let mode = format!(
        "0o{:o}",
        fs::metadata(&path).expect("stat").permissions().mode() & 0o7777
    );
    let want = text(field(case, "mode"));
    if mode != want {
        return Err(format!("mode {mode}, want {want}"));
    }
    Ok(())
}

#[test]
fn reference_xdpuser() {
    let all = cases(env!("CARGO_MANIFEST_DIR"), "xdpuser.jsonl");
    let dir = std::env::temp_dir().join(format!("fros-xdpuser-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("temp dir");
    let mut failures = Vec::new();
    let mut seen = 0;
    for case in &all {
        let result = match text(field(case, "kind")) {
            "event" => check_event(case),
            "hello" => check_hello(case),
            "eventfile" => check_eventfile(case, &dir),
            "key" => continue, // the Go apply's (apply/reference_xdp_keys_test.go)
            other => Err(format!("unknown kind {other}")),
        };
        seen += 1;
        if let Err(e) = result {
            failures.push(format!("{}: {e}", text(field(case, "id"))));
        }
    }
    let _ = fs::remove_dir_all(&dir);
    assert!(seen > 0, "no xdpuser cases");
    report(&failures);
}
