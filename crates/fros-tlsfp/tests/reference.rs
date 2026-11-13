//! Replays FR_OS 1.x's recorded answers (testdata/reference/tlsfp.jsonl,
//! written by reference/test_fros_tlsfp_cases.py through
//! reference/generate.sh): every case must come out the same, byte for
//! byte -- parsed fields, fingerprints, error texts, reassembled
//! messages, and the inventory's state file.
//!
//! The file is read with this crate's own Python-dialect JSON reader
//! (1.x's json.dumps writes NaN and Infinity), which this also tests.

use fros_tlsfp::pyjson::{self, Dict, Value};
use fros_tlsfp::{
    FingerprintInventory, Reassembler, handshake_from_records, is_grease, ja3, ja3_string, ja4,
    ja4_parts, parse_client_hello,
};

fn cases() -> Vec<Dict> {
    let raw = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/reference/tlsfp.jsonl"
    ))
    .expect("testdata/reference/tlsfp.jsonl (reference/generate.sh writes it)");
    raw.split(|&b| b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| match pyjson::loads(line) {
            Ok(Value::Dict(d)) => d,
            other => panic!("not a case: {other:?}"),
        })
        .collect()
}

fn field<'a>(case: &'a Dict, key: &str) -> &'a Value {
    case.get(key)
        .unwrap_or_else(|| panic!("case without {key}: {case:?}"))
}

fn text(v: &Value) -> &str {
    match v {
        Value::Str(s) => s,
        other => panic!("not a string: {other:?}"),
    }
}

fn opt_text(v: &Value) -> Option<&str> {
    match v {
        Value::Null => None,
        other => Some(text(other)),
    }
}

fn number(v: &Value) -> f64 {
    match v {
        Value::Float(f) => *f,
        Value::Int(s) => s.parse().expect("int"),
        other => panic!("not a number: {other:?}"),
    }
}

fn int(v: &Value) -> i64 {
    match v {
        Value::Int(s) => s.parse().expect("int"),
        other => panic!("not an int: {other:?}"),
    }
}

fn boolean(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        other => panic!("not a bool: {other:?}"),
    }
}

fn list(v: &Value) -> &[Value] {
    match v {
        Value::List(items) => items,
        other => panic!("not a list: {other:?}"),
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn ints(values: &[u16]) -> Value {
    Value::List(values.iter().map(|&v| Value::int(i64::from(v))).collect())
}

fn check_hello(case: &Dict) -> Result<(), String> {
    let input = unhex(text(field(case, "input")));
    let got = parse_client_hello(&input);
    if !boolean(field(case, "ok")) {
        let want = text(field(case, "error"));
        return match got {
            Err(e) if e.0 == want => Ok(()),
            other => Err(format!("want error {want:?}, got {other:?}")),
        };
    }
    let hello = got.map_err(|e| format!("unexpected error {e}"))?;
    let Value::Dict(want) = field(case, "hello") else {
        return Err("hello is not a dict".into());
    };
    let fields = Dict(vec![
        (
            "legacy_version".into(),
            Value::int(i64::from(hello.legacy_version)),
        ),
        ("ciphers".into(), ints(&hello.ciphers)),
        ("extensions".into(), ints(&hello.extensions)),
        ("supported_groups".into(), ints(&hello.supported_groups)),
        (
            "ec_point_formats".into(),
            Value::List(
                hello
                    .ec_point_formats
                    .iter()
                    .map(|&v| Value::int(i64::from(v)))
                    .collect(),
            ),
        ),
        (
            "signature_algorithms".into(),
            ints(&hello.signature_algorithms),
        ),
        ("supported_versions".into(), ints(&hello.supported_versions)),
        (
            "alpn".into(),
            Value::List(hello.alpn.iter().map(|p| Value::Str(hex(p))).collect()),
        ),
        (
            "server_name".into(),
            hello.server_name.clone().map_or(Value::Null, Value::Str),
        ),
    ]);
    if fields != *want {
        return Err(format!("fields differ:\n got {fields:?}\nwant {want:?}"));
    }
    let checks = [
        (
            "ja3_string",
            ja3_string(&hello),
            text(field(case, "ja3_string")).to_string(),
        ),
        ("ja3", ja3(&hello), text(field(case, "ja3")).to_string()),
    ];
    for (name, got, want) in checks {
        if got != want {
            return Err(format!("{name}: got {got}, want {want}"));
        }
    }
    let (a, b, c) = ja4_parts(&hello, "t");
    let want_parts: Vec<&str> = list(field(case, "ja4_parts")).iter().map(text).collect();
    if [a.as_str(), b.as_str(), c.as_str()] != want_parts[..] {
        return Err(format!(
            "ja4_parts: got {:?}, want {want_parts:?}",
            (a, b, c)
        ));
    }
    let Value::Dict(want_ja4) = field(case, "ja4") else {
        return Err("ja4 is not a dict".into());
    };
    for (transport, want) in &want_ja4.0 {
        let got = ja4(&hello, transport);
        if got != text(want) {
            return Err(format!("ja4 {transport}: got {got}, want {}", text(want)));
        }
    }
    Ok(())
}

fn check_records(case: &Dict) -> Result<(), String> {
    let input = unhex(text(field(case, "input")));
    let got = handshake_from_records(&input);
    if boolean(field(case, "ok")) {
        let want = opt_text(field(case, "message")).map(unhex);
        match got {
            Ok(m) if m == want => Ok(()),
            other => Err(format!("want {want:?}, got {other:?}")),
        }
    } else {
        let want = text(field(case, "error"));
        match got {
            Err(e) if e.0 == want => Ok(()),
            other => Err(format!("want error {want:?}, got {other:?}")),
        }
    }
}

type FlowKey = (String, i64, String, i64);

fn check_reassembly(case: &Dict) -> Result<(), String> {
    let mut r: Reassembler<FlowKey> = Reassembler::new(
        usize::try_from(int(field(case, "max_flows"))).map_err(|e| e.to_string())?,
        number(field(case, "timeout")),
    );
    for (i, step) in list(field(case, "steps")).iter().enumerate() {
        let Value::Dict(step) = step else {
            return Err("step is not a dict".into());
        };
        let key = list(field(step, "key"));
        let key: FlowKey = (
            text(&key[0]).to_string(),
            int(&key[1]),
            text(&key[2]).to_string(),
            int(&key[3]),
        );
        let seq = u32::try_from(int(field(step, "seq"))).map_err(|e| e.to_string())?;
        let payload = unhex(text(field(step, "payload")));
        let got = r.add(
            &key,
            seq,
            &payload,
            number(field(step, "now")),
            boolean(field(step, "first")),
        );
        let ok = match (step.get("error"), &got) {
            (Some(want), Err(e)) => e.0 == text(want),
            (None, Ok(m)) => *m == opt_text(field(step, "result")).map(unhex),
            _ => false,
        };
        let want_len = usize::try_from(int(field(step, "len"))).map_err(|e| e.to_string())?;
        if !ok || r.len() != want_len {
            return Err(format!(
                "step {i}: got {:?} (len {}), want {:?} (len {want_len})",
                got.map(|m| m.map(|m| hex(&m))),
                r.len(),
                step.get("error").or(step.get("result")),
            ));
        }
    }
    Ok(())
}

fn check_inventory(case: &Dict) -> Result<(), String> {
    let mut inv = FingerprintInventory::new(number(field(case, "started")));
    for (i, step) in list(field(case, "steps")).iter().enumerate() {
        let Value::Dict(step) = step else {
            return Err("step is not a dict".into());
        };
        if let Some(args) = step.get("observe") {
            let a = list(args);
            let got = inv.observe(
                text(&a[0]),
                text(&a[1]),
                text(&a[2]),
                opt_text(&a[3]),
                number(&a[4]),
            );
            if got != boolean(field(step, "result")) {
                return Err(format!("step {i}: observe gave {got}"));
            }
        } else if let Some(event) = step.get("event") {
            let Value::Dict(event) = event else {
                return Err("event is not a dict".into());
            };
            inv.add_event(event.clone());
        } else if let Some(now) = step.get("learning") {
            let got = inv.learning(number(now));
            if got != boolean(field(step, "result")) {
                return Err(format!("step {i}: learning gave {got}"));
            }
        } else {
            let now = number(field(step, "snapshot"));
            let got = pyjson::dumps(&Value::Dict(inv.snapshot(now)));
            let want = text(field(step, "json"));
            if got != want {
                return Err(format!(
                    "step {i}: snapshot differs:\n got {}\nwant {}",
                    clip(&got),
                    clip(want)
                ));
            }
        }
    }
    Ok(())
}

/// A long text cut down for a failure message.
fn clip(s: &str) -> String {
    if s.len() <= 600 {
        s.to_string()
    } else {
        let mut end = 600;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}... ({} bytes)", &s[..end], s.len())
    }
}

fn check_restore(case: &Dict) -> Result<(), String> {
    let raw = unhex(text(field(case, "file")));
    let now = number(field(case, "now"));
    let data = pyjson::loads(&raw).ok();
    let inv = FingerprintInventory::restore(data.as_ref(), now);
    let got = pyjson::dumps(&Value::Dict(inv.snapshot(now)));
    let want = match case.get("json") {
        Some(want) => text(want).to_string(),
        // 1.x raised an exception it doesn't catch; FR_OS 2 starts empty
        // (decisions.md).
        None => pyjson::dumps(&Value::Dict(FingerprintInventory::new(now).snapshot(now))),
    };
    if got == want {
        Ok(())
    } else {
        Err(format!(
            "restored differs:\n got {}\nwant {}",
            clip(&got),
            clip(&want)
        ))
    }
}

/// Cases where FR_OS 2 decided to differ from 1.x
/// (testdata/reference/decisions.md, "Phase 4a"), by their name.
const DECIDED: &[&str] = &[
    // A list or dict inside a row's "ja3" or "sni": 1.x writes its repr
    // ("[]", "{'k': 'v'}") into the list; FR_OS 2 skips the row.
    "ja3 item list",
    "ja3 item empty list",
    "ja3 item dict",
    "ja3 item empty dict",
    "ja3 nested",
    // A number written with non-ASCII decimal digits ("\u{669}"): Python
    // reads it, FR_OS 2 doesn't.
    "started '\u{669}'",
    "first_seen '\u{669}'",
    "count '\u{669}'",
    // A lone surrogate escape becomes U+FFFD.
    "lone high in key",
];

#[test]
fn replays_every_recorded_case() {
    let cases = cases();
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    let mut failures = Vec::new();
    for case in &cases {
        let op = text(field(case, "op"));
        *counts.entry(op.to_string()).or_default() += 1;
        let result = match op {
            "grease" => {
                let want: Vec<i64> = list(field(case, "values")).iter().map(int).collect();
                let got: Vec<i64> = (0..=u16::MAX)
                    .filter(|&v| is_grease(v))
                    .map(i64::from)
                    .collect();
                if got == want {
                    Ok(())
                } else {
                    Err(format!("grease: got {got:?}"))
                }
            }
            "hello" => check_hello(case),
            "records" => check_records(case),
            "reassembly" => check_reassembly(case),
            "inventory" => check_inventory(case),
            "restore" => check_restore(case),
            other => Err(format!("unknown op {other}")),
        };
        let name = case.get("name").map(text).unwrap_or_default();
        match result {
            Ok(()) if DECIDED.contains(&name) => {
                failures.push(format!("{op} {name:?}: listed as decided but matches 1.x"));
            }
            Ok(()) => {}
            Err(_) if op == "restore" && DECIDED.contains(&name) => {}
            Err(e) => failures.push(format!(
                "{op} {name:?} {}: {e}",
                case.get("input")
                    .or(case.get("file"))
                    .map(|v| clip(text(v)))
                    .unwrap_or_default()
            )),
        }
    }
    // Every kind is there, in numbers (a short file is a broken regen).
    for (op, at_least) in [
        ("grease", 1),
        ("hello", 3000),
        ("records", 500),
        ("reassembly", 50),
        ("inventory", 8),
        ("restore", 400),
    ] {
        assert!(
            counts.get(op).copied().unwrap_or_default() >= at_least,
            "too few {op} cases: {counts:?}"
        );
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases differ from 1.x:\n{}",
        failures.len(),
        cases.len(),
        failures
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
