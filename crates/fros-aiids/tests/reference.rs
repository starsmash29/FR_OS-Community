//! Replays FR_OS 1.x's recorded answers (testdata/reference/aiids.jsonl,
//! written by reference/test_fros_aiids_cases.py through
//! reference/generate.sh): the DGA heuristic, Python's exact
//! statistics and rounding, every evaluate() of the anomaly engine, and
//! the daemon's two line readers. Floats are compared by their repr.

use std::collections::{HashMap, HashSet};

use fros_aiids::engine::{WINDOW_SECONDS, ZSCORE_THRESHOLD};
use fros_aiids::{
    AnomalyEngine, AnomalyEvent, DnsLogEvent, common_bigram_ratio, looks_generated,
    parse_dns_log_line, parse_sni_drop_line, registered_label, shannon_entropy,
};
use fros_sensor::pyfloat;
use fros_sensor::pyjson::{self, Dict, Value, float_repr};
use fros_sensor::reference::{
    boolean, cases, clip, field, int, list, number, opt_text, report, strs, text,
};

/// Cases where FR_OS 2 answers differently on purpose
/// (testdata/reference/decisions.md, "phase 4b"); a trailing `*` matches
/// any rest.
const DECIDED: &[&str] = &[
    // A lone surrogate escape becomes U+FFFD (as in phase 4a).
    "sni_line {\"action\": \"drop\", \"saddr\": \"\\udc00\"}",
    // An event line nested past Python's recursion limit: the
    // RecursionError ended 1.x's reader thread; FR_OS 2 skips the line.
    "sni_line [[[[[[[[*",
];

fn decided(key: &str) -> bool {
    DECIDED.iter().any(|d| match d.strip_suffix('*') {
        Some(prefix) => key.starts_with(prefix),
        None => key == *d,
    })
}

fn same_float(got: f64, want: &Value) -> Result<(), String> {
    let want = number(want);
    if float_repr(got) == float_repr(want) {
        Ok(())
    } else {
        Err(format!(
            "got {}, want {}",
            float_repr(got),
            float_repr(want)
        ))
    }
}

fn check_dga(case: &Dict) -> Result<(), String> {
    let input = text(field(case, "input"));
    let label = registered_label(input);
    if label.as_deref() != opt_text(field(case, "label")) {
        return Err(format!("label {label:?}"));
    }
    if looks_generated(input) != boolean(field(case, "generated")) {
        return Err("verdict".into());
    }
    if let Some(label) = label {
        let compact = label.replace('-', "");
        same_float(shannon_entropy(&compact), field(case, "entropy"))
            .map_err(|e| format!("entropy: {e}"))?;
        same_float(common_bigram_ratio(&compact), field(case, "bigram_ratio"))
            .map_err(|e| format!("ratio: {e}"))?;
    }
    Ok(())
}

fn check_dga_parts(case: &Dict) -> Result<(), String> {
    let input = text(field(case, "input"));
    same_float(shannon_entropy(input), field(case, "entropy"))
        .map_err(|e| format!("entropy: {e}"))?;
    same_float(common_bigram_ratio(input), field(case, "bigram_ratio"))
        .map_err(|e| format!("ratio: {e}"))
}

fn check_stats(case: &Dict) -> Result<(), String> {
    let values: Vec<f64> = list(field(case, "values")).iter().map(number).collect();
    same_float(pyfloat::mean(&values), field(case, "mean")).map_err(|e| format!("mean: {e}"))?;
    same_float(pyfloat::pstdev(&values), field(case, "pstdev")).map_err(|e| format!("pstdev: {e}"))
}

fn check_round(case: &Dict) -> Result<(), String> {
    let digits = u32::try_from(int(field(case, "n"))).expect("digits");
    same_float(
        pyfloat::round(number(field(case, "x")), digits),
        field(case, "result"),
    )
}

fn event_value(e: &AnomalyEvent) -> Value {
    let count = |n: usize| Value::int(i64::try_from(n).unwrap_or(i64::MAX));
    Value::Dict(Dict(vec![
        ("ip".into(), Value::Str(e.ip.clone())),
        ("score".into(), Value::Float(e.score)),
        (
            "reasons".into(),
            Value::List(e.reasons.iter().map(|r| Value::Str((*r).into())).collect()),
        ),
        ("conn_rate".into(), Value::Float(e.conn_rate)),
        ("unique_dst_ratio".into(), Value::Float(e.unique_dst_ratio)),
        ("sni_block_count".into(), count(e.sni_block_count)),
        ("nxdomain_count".into(), count(e.nxdomain_count)),
        ("dga_nxdomain_count".into(), count(e.dga_nxdomain_count)),
        ("dns_threat_count".into(), count(e.dns_threat_count)),
    ]))
}

fn check_engine(case: &Dict) -> Result<(), String> {
    let Value::Dict(args) = field(case, "args") else {
        panic!("args")
    };
    let mut engine = AnomalyEngine::new(
        args.get("window_seconds")
            .map(number)
            .unwrap_or(WINDOW_SECONDS),
        args.get("zscore_threshold")
            .map(number)
            .unwrap_or(ZSCORE_THRESHOLD),
    );
    for (i, step) in list(field(case, "steps")).iter().enumerate() {
        let Value::Dict(s) = step else { panic!("step") };
        let now = number(field(s, "now"));
        let src = || text(field(s, "src"));
        match text(field(s, "do")) {
            "conn" => engine.observe_connection(src(), text(field(s, "dst")), now),
            "sni" => engine.observe_sni_block(src(), now),
            "nx" => engine.observe_dns_nxdomain(
                src(),
                text(field(s, "name")),
                boolean(field(s, "generated")),
                now,
            ),
            "threat" => engine.observe_dns_threat_block(src(), now),
            "evaluate" => {
                let got = engine.evaluate(text(field(s, "ip")), now);
                let got = pyjson::dumps(&got.as_ref().map(event_value).unwrap_or(Value::Null));
                let want = pyjson::dumps(field(s, "event"));
                if got != want {
                    return Err(format!("step {i}: got {got}, want {want}"));
                }
            }
            "tracked" => {
                let (got, want) = (engine.tracked_ips(), strs(field(s, "ips")));
                if got != want {
                    return Err(format!("step {i}: tracked {got:?}, want {want:?}"));
                }
            }
            other => panic!("step {other}"),
        }
    }
    Ok(())
}

fn check_dns_line(case: &Dict) -> Result<(), String> {
    let threat: HashSet<String> = strs(field(case, "threat_files")).into_iter().collect();
    let got = match parse_dns_log_line(text(field(case, "line")), &threat) {
        None => Value::List(vec![]),
        Some(DnsLogEvent::Nxdomain {
            client,
            name,
            generated,
        }) => Value::List(vec![Value::List(vec![
            Value::Str("nx".into()),
            Value::Str(client),
            Value::Str(name),
            Value::Bool(generated),
        ])]),
        Some(DnsLogEvent::ThreatBlock { client }) => Value::List(vec![Value::List(vec![
            Value::Str("threat".into()),
            Value::Str(client),
        ])]),
    };
    let (got, want) = (pyjson::dumps(&got), pyjson::dumps(field(case, "calls")));
    if got == want {
        Ok(())
    } else {
        Err(format!("got {got}, want {want}"))
    }
}

fn check_sni_line(case: &Dict) -> Result<(), String> {
    let got = Value::List(
        parse_sni_drop_line(text(field(case, "line")))
            .into_iter()
            .map(|s| Value::List(vec![Value::Str("sni".into()), Value::Str(s)]))
            .collect(),
    );
    let got = pyjson::dumps(&got);
    match case.get("calls") {
        Some(want) if text(want) == got => Ok(()),
        want => Err(format!(
            "got {got}, want {want:?} / crash {:?}",
            case.get("crash")
        )),
    }
}

fn case_name(case: &Dict) -> String {
    ["name", "line", "input"]
        .iter()
        .find_map(|k| case.get(k).map(|v| text(v).to_owned()))
        .unwrap_or_default()
}

#[test]
fn replays_1x() {
    let all = cases(env!("CARGO_MANIFEST_DIR"), "aiids.jsonl");
    let mut failures = Vec::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    for case in &all {
        let op = text(field(case, "op"));
        *counts.entry(op.to_owned()).or_default() += 1;
        let name = case_name(case);
        let result = match op {
            "dga" => check_dga(case),
            "dga_parts" => check_dga_parts(case),
            "stats" => check_stats(case),
            "round" => check_round(case),
            "engine" => check_engine(case),
            "dns_line" => check_dns_line(case),
            "sni_line" => check_sni_line(case),
            other => panic!("unknown op {other}"),
        };
        let key = format!("{op} {name}");
        match result {
            Ok(()) if decided(&key) => {
                failures.push(format!("{key:?}: listed as decided but matches 1.x"))
            }
            Err(e) if !decided(&key) => failures.push(format!("{}: {e}", clip(&key))),
            _ => {}
        }
    }
    for (op, at_least) in [
        ("dga", 600),
        ("dga_parts", 10),
        ("stats", 300),
        ("round", 800),
        ("engine", 30),
        ("dns_line", 30),
        ("sni_line", 15),
    ] {
        let n = counts.get(op).copied().unwrap_or(0);
        if n < at_least {
            failures.push(format!("only {n} {op} cases (at least {at_least})"));
        }
    }
    report(&failures);
}
