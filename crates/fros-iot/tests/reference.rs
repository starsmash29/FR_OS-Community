//! Replays FR_OS 1.x's recorded answers (testdata/reference/iot.jsonl,
//! written by reference/test_fros_iot_cases.py through
//! reference/generate.sh): MAC normalization and vendor lookups, the
//! IEEE registry and the neighbour table read in every shape, the mDNS
//! query and parser, the IoT scoring, whole scans (messages, devices,
//! the helper calls and the inventory file byte for byte) and the
//! resync from an inventory.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use fros_iot::scan::MdnsResults;
use fros_iot::{
    ArpEntry, Crash, Observation, ScanIo, VendorDb, View, build_query, classify, load_vendor_db,
    normalize_mac, parse_arp_table, parse_services, parse_vendor_db, read_arp_table, resync_wanted,
    run_scan, vendor_for,
};
use fros_sensor::pyjson::{self, Dict, Value};
use fros_sensor::reference::{cases, clip, field, int, number, opt_text, report, strs, text};

/// Cases where FR_OS 2 answers differently on purpose
/// (testdata/reference/decisions.md, "phase 4c").
const DECIDED: &[&str] = &[];

fn hex(v: &Value) -> Vec<u8> {
    let s = text(v);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn same(what: &str, got: &Value, want: &Value) -> Result<(), String> {
    let (got, want) = (pyjson::dumps(got), pyjson::dumps(want));
    if got == want {
        Ok(())
    } else {
        Err(format!("{what}: got {} want {}", clip(&got), clip(&want)))
    }
}

fn strings(items: impl IntoIterator<Item = impl Into<String>>) -> Value {
    Value::List(items.into_iter().map(|s| Value::Str(s.into())).collect())
}

fn db_value(db: &VendorDb) -> Value {
    Value::List(
        db.iter()
            .map(|(k, v)| strings([k.clone(), v.clone()]))
            .collect(),
    )
}

fn crash_or(case: &Dict, got: Result<Value, Crash>, key: &str) -> Result<(), String> {
    match (got, case.get("crash"), case.get(key)) {
        (Err(Crash(c)), Some(want), _) if c == text(want) => Ok(()),
        (Ok(v), None, Some(want)) => same(key, &v, want),
        (got, crash, _) => Err(format!("got {got:?}, 1.x crashed with {crash:?}")),
    }
}

fn check_mac(case: &Dict) -> Result<(), String> {
    let got = match field(case, "input") {
        Value::Str(s) => normalize_mac(s),
        _ => None,
    };
    let want = opt_text(field(case, "mac"));
    if got.as_deref() == want {
        Ok(())
    } else {
        Err(format!("got {got:?} want {want:?}"))
    }
}

fn check_vendor(case: &Dict) -> Result<(), String> {
    let Value::Dict(d) = field(case, "db") else {
        panic!("db")
    };
    let mut db = VendorDb::new();
    for (k, v) in &d.0 {
        db.insert(k.clone(), text(v).to_owned());
    }
    let got = vendor_for(text(field(case, "mac")), &db);
    let want = opt_text(field(case, "vendor"));
    if got == want {
        Ok(())
    } else {
        Err(format!("got {got:?} want {want:?}"))
    }
}

fn check_oui(case: &Dict) -> Result<(), String> {
    let got = match case.get("path") {
        Some(path) => load_vendor_db(Path::new(text(path))),
        None => parse_vendor_db(&hex(field(case, "file"))),
    };
    crash_or(case, got.map(|db| db_value(&db)), "db")
}

fn arp_value(entries: &[ArpEntry]) -> Value {
    Value::List(
        entries
            .iter()
            .map(|e| strings([e.ip.clone(), e.mac.clone(), e.device.clone()]))
            .collect(),
    )
}

fn check_arp(case: &Dict) -> Result<(), String> {
    let got = match case.get("path") {
        Some(path) => read_arp_table(Path::new(text(path))),
        None => parse_arp_table(&hex(field(case, "file"))),
    };
    crash_or(case, got.map(|e| arp_value(&e)), "entries")
}

fn check_mdns_query(case: &Dict) -> Result<(), String> {
    let id = u16::try_from(int(field(case, "query_id"))).expect("u16");
    let got = to_hex(&build_query(id));
    let want = text(field(case, "packet"));
    if got == want {
        Ok(())
    } else {
        Err(format!("got {got} want {want}"))
    }
}

fn check_mdns(case: &Dict) -> Result<(), String> {
    let got = parse_services(&hex(field(case, "packet")));
    same("services", &strings(got), field(case, "services"))
}

fn check_classify(case: &Dict) -> Result<(), String> {
    let Value::Dict(o) = field(case, "observation") else {
        panic!("observation")
    };
    let obs = Observation {
        mac: text(field(o, "mac")).to_owned(),
        ip: opt_text(field(o, "ip")).map(str::to_owned),
        hostname: text(field(o, "hostname")).to_owned(),
        interface: text(field(o, "interface")).to_owned(),
        vendor: opt_text(field(o, "vendor")).map(str::to_owned),
        services: strs(field(o, "services")),
    };
    let c = classify(&obs);
    let got = Value::List(vec![
        Value::Str(c.category.to_owned()),
        Value::int(c.score),
        strings(c.reasons),
    ]);
    let want = Value::List(vec![
        field(case, "category").clone(),
        field(case, "score").clone(),
        field(case, "reasons").clone(),
    ]);
    same("classification", &got, &want)
}

/// A helper answer as recorded: `{"raise": text}` is the HelperError.
fn answer(spec: &Value) -> Result<Value, String> {
    match spec {
        Value::Dict(d) if d.get("raise").is_some() => Err(text(field(d, "raise")).to_owned()),
        other => Ok(other.clone()),
    }
}

struct Recorded<'a> {
    case: &'a Dict,
    sync_calls: Vec<Value>,
}

impl ScanIo for Recorded<'_> {
    fn leases(&mut self) -> Result<Value, String> {
        answer(field(self.case, "leases"))
    }

    fn mdns(&mut self, _addresses: &[String]) -> Result<MdnsResults, String> {
        let Value::Dict(d) = field(self.case, "mdns") else {
            panic!("mdns")
        };
        if let Some(raise) = d.get("raise") {
            return Err(text(raise).to_owned());
        }
        Ok(d.0
            .iter()
            .map(|(ip, s)| (ip.clone(), strs(s).into_iter().collect::<BTreeSet<_>>()))
            .collect::<BTreeMap<_, _>>())
    }

    fn arp_table(&mut self) -> Result<Vec<ArpEntry>, Crash> {
        parse_arp_table(&hex(field(self.case, "arp")))
    }

    fn vendor_db(&mut self) -> Result<VendorDb, Crash> {
        match field(self.case, "oui") {
            Value::Null => Ok(VendorDb::new()),
            raw => parse_vendor_db(&hex(raw)),
        }
    }

    fn oui_path(&self) -> String {
        text(field(self.case, "oui_path")).to_owned()
    }

    fn sync(&mut self, macs: &[String]) -> Result<Value, String> {
        self.sync_calls.push(strings(macs.iter().cloned()));
        match field(self.case, "sync") {
            Value::Null => Ok(Value::Dict(Dict(vec![
                ("ok".into(), Value::Bool(true)),
                ("isolated".into(), strings(macs.iter().cloned())),
            ]))),
            spec => answer(spec),
        }
    }
}

fn check_scan(case: &Dict) -> Result<(), String> {
    let view = View::from_json(field(case, "view")).map_err(|e| format!("view refused: {e:?}"))?;
    let mut io = Recorded {
        case,
        sync_calls: Vec::new(),
    };
    let result = run_scan(&view, &mut io, number(field(case, "now")))
        .map_err(|c| format!("crashed: {c:?}"))?;
    same(
        "messages",
        &strings(result.messages),
        field(case, "messages"),
    )?;
    same(
        "isolated",
        &Value::List(result.isolated),
        field(case, "isolated"),
    )?;
    same(
        "devices",
        &Value::List(result.devices),
        field(case, "devices"),
    )?;
    same(
        "sync calls",
        &Value::List(io.sync_calls),
        field(case, "sync_calls"),
    )?;
    let want = opt_text(field(case, "state"));
    if result.state.as_deref() != want {
        return Err(format!(
            "state: got {:?} want {:?}",
            result.state.as_deref().map(clip),
            want.map(clip)
        ));
    }
    Ok(())
}

fn check_resync(case: &Dict) -> Result<(), String> {
    let view = View::from_json(field(case, "view")).map_err(|e| format!("view refused: {e:?}"))?;
    let inventory = match field(case, "inventory") {
        Value::Null => None,
        v => Some(v),
    };
    // 1.x's sync here answers {"ok": True, "isolated": macs}.
    let got = resync_wanted(&view, inventory).map(|macs| {
        let macs = strings(macs);
        Value::List(vec![
            Value::Dict(Dict(vec![
                ("ok".into(), Value::Bool(true)),
                ("isolated".into(), macs.clone()),
            ])),
            Value::List(vec![macs]),
        ])
    });
    match (got, case.get("crash")) {
        (Err(Crash(c)), Some(want)) if c == text(want) => Ok(()),
        (Ok(v), None) => same(
            "reply and sync calls",
            &v,
            &Value::List(vec![
                field(case, "reply").clone(),
                field(case, "sync_calls").clone(),
            ]),
        ),
        (got, crash) => Err(format!("got {got:?}, 1.x crashed with {crash:?}")),
    }
}

#[test]
fn replays_1x() {
    let all = cases(env!("CARGO_MANIFEST_DIR"), "iot.jsonl");
    let mut failures = Vec::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    for case in &all {
        let op = text(field(case, "op"));
        *counts.entry(op.to_owned()).or_default() += 1;
        let name = case
            .get("name")
            .map(|n| text(n).to_owned())
            .unwrap_or_else(|| text(field(case, "id")).to_owned());
        let result = match op {
            "mac" => check_mac(case),
            "vendor" => check_vendor(case),
            "oui" => check_oui(case),
            "arp" => check_arp(case),
            "mdns_query" => check_mdns_query(case),
            "mdns" => check_mdns(case),
            "classify" => check_classify(case),
            "scan" => check_scan(case),
            "resync" => check_resync(case),
            other => panic!("unknown op {other}"),
        };
        let key = format!("{op} {name}");
        let decided = DECIDED.contains(&key.as_str());
        match result {
            Ok(()) if decided => {
                failures.push(format!("{key:?}: listed as decided but matches 1.x"))
            }
            Err(e) if !decided => failures.push(format!("{key:?}: {e}")),
            _ => {}
        }
    }
    for (op, at_least) in [
        ("mac", 20),
        ("vendor", 8),
        ("oui", 100),
        ("arp", 50),
        ("mdns_query", 4),
        ("mdns", 800),
        ("classify", 700),
        ("scan", 60),
        ("resync", 16),
    ] {
        let n = counts.get(op).copied().unwrap_or(0);
        if n < at_least {
            failures.push(format!("only {n} {op} cases (at least {at_least})"));
        }
    }
    report(&failures);
}
