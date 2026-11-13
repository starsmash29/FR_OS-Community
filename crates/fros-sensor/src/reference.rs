//! Reading the recorded 1.x reference (testdata/reference/*.jsonl) in
//! the sensor crates' differential tests: one case per line, read with
//! [`crate::pyjson`] because 1.x's json.dumps writes NaN and Infinity.
//! A malformed file is a broken regeneration, so these panic.

use crate::pyjson::{self, Dict, Value};

/// Every case of `testdata/reference/<file>`, from a crate two levels
/// below the repository root.
pub fn cases(manifest_dir: &str, file: &str) -> Vec<Dict> {
    let path = format!("{manifest_dir}/../../testdata/reference/{file}");
    let raw = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("{path} (reference/generate.sh writes it): {e}"));
    raw.split(|&b| b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| match pyjson::loads(line) {
            Ok(Value::Dict(d)) => d,
            other => panic!("not a case: {other:?}"),
        })
        .collect()
}

pub fn field<'a>(case: &'a Dict, key: &str) -> &'a Value {
    case.get(key).unwrap_or_else(|| {
        panic!(
            "case without {key}: {}",
            clip(&pyjson::dumps(&Value::Dict(case.clone())))
        )
    })
}

pub fn text(v: &Value) -> &str {
    match v {
        Value::Str(s) => s,
        other => panic!("not a string: {other:?}"),
    }
}

pub fn opt_text(v: &Value) -> Option<&str> {
    match v {
        Value::Null => None,
        other => Some(text(other)),
    }
}

pub fn number(v: &Value) -> f64 {
    match v {
        Value::Float(f) => *f,
        Value::Int(s) => s.parse().expect("int"),
        other => panic!("not a number: {other:?}"),
    }
}

pub fn int(v: &Value) -> i64 {
    match v {
        Value::Int(s) => s.parse().expect("int"),
        other => panic!("not an int: {other:?}"),
    }
}

pub fn boolean(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        other => panic!("not a bool: {other:?}"),
    }
}

pub fn list(v: &Value) -> &[Value] {
    match v {
        Value::List(items) => items,
        other => panic!("not a list: {other:?}"),
    }
}

pub fn strs(v: &Value) -> Vec<String> {
    list(v).iter().map(|s| text(s).to_owned()).collect()
}

/// The start of a long text, for a failure message.
pub fn clip(s: &str) -> String {
    let short: String = s.chars().take(160).collect();
    if short.len() < s.len() {
        format!("{short}...")
    } else {
        short
    }
}

/// Fail with every mismatch at once; `decided` cases must differ.
pub fn report(failures: &[String]) {
    if !failures.is_empty() {
        let shown: Vec<&String> = failures.iter().take(40).collect();
        panic!(
            "{} case(s) differ from 1.x:\n{}",
            failures.len(),
            shown
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}
