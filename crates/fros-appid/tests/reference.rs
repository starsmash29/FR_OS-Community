//! Replays FR_OS 1.x's recorded answers (testdata/reference/appid.jsonl,
//! written by reference/test_fros_appid_cases.py through
//! reference/generate.sh): the catalog parser, name matching, blocking
//! lists, the usage tracker and its state file byte for byte, the
//! daemon's de-duplication and its two line readers.

use std::collections::HashMap;

use fros_appid::{
    AppIdObserver, AppMatcher, Catalog, UsageTracker, blocking_names, parse_catalog,
    parse_dns_query_line, parse_sni_event_line,
};
use fros_sensor::pyjson::{self, Dict, LoadError, Value};
use fros_sensor::reference::{cases, clip, field, int, list, number, opt_text, report, strs, text};

/// Cases where FR_OS 2 answers differently on purpose
/// (testdata/reference/decisions.md, "phase 4b"); a trailing `*` matches
/// any rest.
const DECIDED: &[&str] = &[
    // A lone surrogate escape becomes U+FFFD (as in phase 4a).
    "usage lone surrogate key",
    "sni_line {\"action\": \"pass\", \"saddr\": \"a\", \"sni\": \"\\ud800x\"}",
    // A number written with non-ASCII decimal digits: Python reads it,
    // FR_OS 2 doesn't (as in phase 4a), so the row is skipped.
    "usage first_seen \"\\u0661\"",
    "usage last_seen \"\\u0661\"",
    "usage bucket count \"\\u0661\"",
    // A hit count past i128 (int(1e308)): Python keeps the 309-digit
    // int, FR_OS 2 skips the row.
    "usage bucket count 1e+308",
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

fn catalog_value(c: &Catalog) -> Value {
    let strings = |v: &[String]| Value::List(v.iter().map(|s| Value::Str(s.clone())).collect());
    Value::Dict(Dict(vec![
        (
            "apps".into(),
            Value::List(
                c.apps
                    .iter()
                    .map(|a| {
                        Value::Dict(Dict(vec![
                            ("id".into(), Value::Str(a.id.clone())),
                            ("name".into(), Value::Str(a.name.clone())),
                            ("category".into(), Value::Str(a.category.clone())),
                            ("domains".into(), strings(&a.domains)),
                            ("exact".into(), strings(&a.exact)),
                        ]))
                    })
                    .collect(),
            ),
        ),
        ("source".into(), Value::Str(c.source.clone())),
        ("license".into(), Value::Str(c.license.clone())),
        ("ref".into(), Value::Str(c.reference.clone())),
        ("generated".into(), Value::Str(c.generated.clone())),
        ("categories".into(), strings(&c.categories())),
    ]))
}

fn load(input: &str) -> Value {
    pyjson::loads(input.as_bytes()).expect("a recorded catalog is JSON")
}

fn check_catalog(case: &Dict) -> Result<(), String> {
    let got = parse_catalog(&load(text(field(case, "input"))));
    match (got, case.get("error"), case.get("catalog")) {
        (Err(e), Some(want), _) if e.0 == text(want) => Ok(()),
        (Ok(c), _, Some(want)) => {
            let (got, want) = (pyjson::dumps(&catalog_value(&c)), pyjson::dumps(want));
            if got == want {
                Ok(())
            } else {
                Err(format!("got {}, want {}", clip(&got), clip(&want)))
            }
        }
        (got, error, _) => Err(format!("got {got:?}, want error {error:?}")),
    }
}

fn check_match(case: &Dict, catalogs: &HashMap<String, Catalog>) -> Result<(), String> {
    let matcher = AppMatcher::new(&catalogs[text(field(case, "catalog"))]);
    for (name, want) in list(field(case, "names"))
        .iter()
        .zip(list(field(case, "apps")))
    {
        let got = matcher.matches(text(name));
        if got != opt_text(want) {
            return Err(format!("{:?}: got {got:?}, want {want:?}", text(name)));
        }
    }
    Ok(())
}

fn check_blocking(case: &Dict, catalogs: &HashMap<String, Catalog>) -> Result<(), String> {
    let got = blocking_names(&strs(field(case, "app_ids")), &catalogs["bundled"]);
    let want = strs(field(case, "names"));
    if got == want {
        Ok(())
    } else {
        Err(format!("got {} names, want {}", got.len(), want.len()))
    }
}

fn run_usage(tracker: &mut UsageTracker, steps: &[Value]) -> Result<(), String> {
    for (i, step) in steps.iter().enumerate() {
        let Value::Dict(step) = step else {
            panic!("step")
        };
        let now = number(field(step, "now"));
        match text(field(step, "do")) {
            "record" => tracker.record(
                text(field(step, "app")),
                text(field(step, "client")),
                text(field(step, "source")),
                now,
            ),
            "prune" => tracker.prune(now),
            "snapshot" => {
                let got = pyjson::dumps(&tracker.snapshot(now));
                let want = text(field(step, "json"));
                if got != want {
                    return Err(format!("step {i}: got {}, want {}", clip(&got), clip(want)));
                }
            }
            other => panic!("step {other}"),
        }
    }
    Ok(())
}

fn check_usage(case: &Dict) -> Result<(), String> {
    let mut tracker = match case.get("restore") {
        None => UsageTracker::new(),
        Some(file) => {
            let data = match pyjson::loads(text(file).as_bytes()) {
                Ok(v) => Some(v),
                Err(LoadError::Invalid) => None,
                Err(LoadError::Crash(kind)) => {
                    return match case.get("crash") {
                        Some(want) if text(want) == kind => Ok(()),
                        want => Err(format!("load crashed {kind}, want {want:?}")),
                    };
                }
            };
            match (UsageTracker::restore(data.as_ref()), case.get("crash")) {
                (Err(e), Some(want)) if e.0 == text(want) => return Ok(()),
                (Ok(t), None) => t,
                (got, want) => return Err(format!("restore: got {got:?}, want crash {want:?}")),
            }
        }
    };
    run_usage(&mut tracker, list(field(case, "steps")))
}

fn observer(catalogs: &HashMap<String, Catalog>) -> AppIdObserver {
    AppIdObserver::new(&catalogs["bundled"], UsageTracker::new())
}

fn check_observe(case: &Dict, catalogs: &HashMap<String, Catalog>) -> Result<(), String> {
    let mut o = observer(catalogs);
    let mut now = 0.0;
    if let Some(Value::Dict(flood)) = case.get("flood") {
        let (count, start, step) = (
            int(field(flood, "count")),
            number(field(flood, "start")),
            number(field(flood, "step")),
        );
        for i in 0..count {
            now = start + i as f64 * step;
            o.observe(
                &format!("10.{}.{}.{}", i / 65536, i / 256 % 256, i % 256),
                "www.netflix.com",
                "dns",
                now,
            );
        }
        for probe in list(field(case, "probes")) {
            let Value::Dict(p) = probe else {
                panic!("probe")
            };
            now = number(field(p, "now"));
            let got = o.observe(text(field(p, "client")), "www.netflix.com", "dns", now);
            if got.as_deref() != opt_text(field(p, "app"))
                || o.remembered() as i64 != int(field(p, "recent"))
            {
                return Err(format!(
                    "probe {}: got {got:?} with {} remembered",
                    text(field(p, "client")),
                    o.remembered()
                ));
            }
        }
    } else {
        for (i, step) in list(field(case, "steps")).iter().enumerate() {
            let Value::Dict(s) = step else { panic!("step") };
            now = number(field(s, "now"));
            let source = if text(field(s, "source")) == "dns" {
                "dns"
            } else {
                "sni"
            };
            let got = o.observe(
                text(field(s, "client")),
                text(field(s, "name")),
                source,
                now,
            );
            if got.as_deref() != opt_text(field(s, "app")) {
                return Err(format!("step {i}: got {got:?}"));
            }
        }
    }
    let got = pyjson::dumps(&o.tracker.snapshot(now));
    let want = text(field(case, "json"));
    if got == want {
        Ok(())
    } else {
        Err(format!("got {}, want {}", clip(&got), clip(want)))
    }
}

fn observed(o: Option<fros_appid::Observation>) -> Value {
    Value::List(
        o.into_iter()
            .map(|o| {
                Value::List(vec![
                    Value::Str(o.client),
                    Value::Str(o.name),
                    Value::Str(o.source.into()),
                ])
            })
            .collect(),
    )
}

fn check_dns_line(case: &Dict) -> Result<(), String> {
    let got = pyjson::dumps(&observed(parse_dns_query_line(text(field(case, "line")))));
    let want = pyjson::dumps(field(case, "observed"));
    if got == want {
        Ok(())
    } else {
        Err(format!("got {got}, want {want}"))
    }
}

fn check_sni_line(case: &Dict) -> Result<(), String> {
    let got = pyjson::dumps(&observed(parse_sni_event_line(text(field(case, "line")))));
    match case.get("observed") {
        Some(want) if text(want) == got => Ok(()),
        want => Err(format!(
            "got {got}, want {want:?} / crash {:?}",
            case.get("crash")
        )),
    }
}

fn case_name(case: &Dict) -> String {
    ["name", "line"]
        .iter()
        .find_map(|k| case.get(k).map(|v| text(v).to_owned()))
        .unwrap_or_default()
}

#[test]
fn replays_1x() {
    let all = cases(env!("CARGO_MANIFEST_DIR"), "appid.jsonl");
    let mut catalogs: HashMap<String, Catalog> = HashMap::new();
    for case in &all {
        if text(field(case, "op")) == "catalog"
            && let Ok(c) = parse_catalog(&load(text(field(case, "input"))))
        {
            catalogs.insert(text(field(case, "name")).to_owned(), c);
        }
    }
    let mut failures = Vec::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    for case in &all {
        let op = text(field(case, "op"));
        *counts.entry(op.to_owned()).or_default() += 1;
        let name = case_name(case);
        let result = match op {
            "catalog" => check_catalog(case),
            "match" => check_match(case, &catalogs),
            "blocking" => check_blocking(case, &catalogs),
            "usage" => check_usage(case),
            "observe" => check_observe(case, &catalogs),
            "dns_line" => check_dns_line(case),
            "sni_line" => check_sni_line(case),
            other => panic!("unknown op {other}"),
        };
        let decided = decided(&format!("{op} {name}"));
        match result {
            Ok(()) if decided => {
                failures.push(format!("{op} {name:?}: listed as decided but matches 1.x"))
            }
            Err(e) if !decided => failures.push(format!("{op} {:?}: {e}", clip(&name))),
            _ => {}
        }
    }
    for (op, at_least) in [
        ("catalog", 200),
        ("match", 2),
        ("blocking", 20),
        ("usage", 200),
        ("observe", 2),
        ("dns_line", 30),
        ("sni_line", 20),
    ] {
        let n = counts.get(op).copied().unwrap_or(0);
        if n < at_least {
            failures.push(format!("only {n} {op} cases (at least {at_least})"));
        }
    }
    report(&failures);
}
