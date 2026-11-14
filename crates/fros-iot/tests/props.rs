//! Properties over random input: mDNS answers, DHCP hostnames, the
//! neighbour table and the registry can be shaped by any LAN host or
//! damaged on disk, so nothing may panic or grow without bound, and
//! every name kept or decision made has the shape the rest of FR_OS
//! relies on (a service type, a normalized MAC, trusted never isolated).

use std::collections::BTreeSet;

use fros_iot::scan::{MdnsResults, decide_isolation};
use fros_iot::{
    ArpEntry, Crash, Observation, ScanIo, VendorDb, View, build_query, classify, normalize_mac,
    parse_arp_table, parse_services, parse_vendor_db, run_scan,
};
use fros_sensor::helper::HelperError;
use fros_sensor::pyjson::{self, Dict, Value};
use proptest::prelude::*;

fn is_service_type(s: &str) -> bool {
    let Some(head) = s.strip_suffix("._tcp").or_else(|| s.strip_suffix("._udp")) else {
        return false;
    };
    let Some(body) = head.strip_prefix('_') else {
        return false;
    };
    (1..=63).contains(&body.len())
        && !body.starts_with('-')
        && body
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

fn is_mac(s: &str) -> bool {
    s.len() == 17
        && s.bytes().enumerate().all(|(i, c)| {
            if i % 3 == 2 {
                c == b':'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
}

/// A real answer advertising three service types, then damaged.
fn packet() -> impl Strategy<Value = Vec<u8>> {
    let base = hex(concat!(
        "000084000000000300000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c8001",
        "000011940011045f686170045f746370056c6f63616c00c00c000c8001000011940018",
        "0b5f676f6f676c6563617374045f746370056c6f63616c00c00c000c8001000011940014",
        "075f6d6174746572045f746370056c6f63616c00",
    ));
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..600),
        prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..8).prop_map(
            move |edits| {
                let mut p = base.clone();
                for (at, b) in edits {
                    let i = at.index(p.len());
                    p[i] = b;
                }
                p
            }
        ),
    ]
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn text() -> impl Strategy<Value = String> {
    let alphabet = prop::sample::select(vec![
        'M', 'A', '-', 'L', ',', '"', '\n', '\r', ' ', '0', '2', '4', 'a', 'C', 'x', ':', '\t',
        '\u{3000}', '\u{2028}', '\x1c', '\u{662}', '\u{e9}', '\0', '*', '.', '1',
    ]);
    prop::collection::vec(alphabet, 0..200).prop_map(|c| c.into_iter().collect())
}

fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::int),
        any::<f64>().prop_map(Value::Float),
        "[0-9a-f:.-]{0,20}".prop_map(Value::Str),
        prop::sample::select(vec!["10.0.0.5", "24:0a:c4:11:22:33", "esp_1", "iphone"])
            .prop_map(|s| Value::Str(s.into())),
    ];
    leaf.prop_recursive(3, 24, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::List),
            prop::collection::vec(
                (
                    prop::sample::select(vec![
                        "ok", "leases", "isolated", "ip", "mac", "hostname", "message"
                    ]),
                    inner
                ),
                0..6
            )
            .prop_map(|kv| {
                let mut d = Dict::default();
                for (k, v) in kv {
                    d.insert(k.to_owned(), v);
                }
                Value::Dict(d)
            }),
        ]
    })
}

fn view(auto_isolate: bool, trusted: Vec<String>, isolated: Vec<String>) -> View {
    let raw = format!(
        r#"{{"enabled": true, "interfaces": [{{"device": "eth1", "address": "10.0.0.1/24"}}, {{"device": "eth3", "address": null}}],
            "trusted_macs": {}, "isolated_macs": {}, "auto_isolate": {auto_isolate}, "isolation_mode": "internet_only"}}"#,
        pyjson::dumps(&Value::List(trusted.into_iter().map(Value::Str).collect())),
        pyjson::dumps(&Value::List(isolated.into_iter().map(Value::Str).collect())),
    );
    View::from_json(&pyjson::loads(raw.as_bytes()).expect("json")).expect("view")
}

struct Random {
    leases: Value,
    sync: Value,
    mdns: MdnsResults,
}

impl ScanIo for Random {
    fn leases(&mut self) -> Result<Value, HelperError> {
        Ok(self.leases.clone())
    }
    fn mdns(&mut self, _addresses: &[String]) -> Result<MdnsResults, String> {
        Ok(self.mdns.clone())
    }
    fn arp_table(&mut self) -> Result<Vec<ArpEntry>, Crash> {
        Ok(Vec::new())
    }
    fn vendor_db(&mut self) -> Result<VendorDb, Crash> {
        Ok(VendorDb::new())
    }
    fn oui_path(&self) -> String {
        "/usr/share/ieee-data/oui.csv".into()
    }
    fn sync(&mut self, _macs: &[String]) -> Result<Value, HelperError> {
        Ok(self.sync.clone())
    }
}

fn mac() -> impl Strategy<Value = String> {
    prop::sample::select(vec![
        "24:0a:c4:11:22:33",
        "3a:11:22:33:44:55",
        "00:11:22:33:44:66",
        "aa:aa:aa:aa:aa:aa",
    ])
    .prop_map(str::to_owned)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn mdns_parser_is_total_and_bounded(p in packet()) {
        let services = parse_services(&p);
        prop_assert!(services.len() <= 256);
        for s in &services {
            prop_assert!(is_service_type(s), "{s:?}");
        }
    }

    #[test]
    fn our_query_is_no_answer(id in any::<u16>()) {
        let q = build_query(id);
        prop_assert_eq!(&q[..2], &id.to_be_bytes());
        prop_assert!(parse_services(&q).is_empty());
    }

    #[test]
    fn registry_reader_is_total(t in text()) {
        if let Ok(db) = parse_vendor_db(t.as_bytes()) {
            for (k, _) in db.iter() {
                prop_assert_eq!(k.chars().count(), 6);
            }
        }
    }

    #[test]
    fn neighbour_table_keeps_real_macs(t in text(), raw in prop::collection::vec(any::<u8>(), 0..200)) {
        for input in [t.into_bytes(), raw] {
            if let Ok(entries) = parse_arp_table(&input) {
                for e in entries {
                    prop_assert!(is_mac(&e.mac) && e.mac != "00:00:00:00:00:00", "{:?}", e.mac);
                }
            }
        }
    }

    #[test]
    fn normalized_macs_are_fixed_points(s in "[ \\-:0-9a-fA-FgK\\u{212a}]{0,20}") {
        if let Some(m) = normalize_mac(&s) {
            prop_assert!(is_mac(&m));
            prop_assert_eq!(normalize_mac(&m), Some(m.clone()));
        }
    }

    #[test]
    fn verdict_follows_the_score(
        m in mac(),
        hostname in "[a-zA-Z_\\- \\u{130}]{0,16}",
        vendor in prop::option::of("[a-zA-Z .,]{0,20}"),
        services in prop::collection::btree_set(
            prop::sample::select(vec!["_hap._tcp", "_ssh._tcp", "_ipp._tcp", "_x._tcp"]), 0..4),
    ) {
        let c = classify(&Observation {
            mac: m, hostname, vendor,
            services: services.into_iter().map(str::to_owned).collect(),
            ..Observation::default()
        });
        prop_assert!(!c.reasons.is_empty());
        let want = if c.score >= 3 { "iot" } else if c.score <= -2 { "general" } else { "unknown" };
        prop_assert_eq!(c.category, want);
    }

    #[test]
    fn trusted_always_wins(
        trusted in prop::collection::vec(mac(), 0..3),
        isolated in prop::collection::vec(mac(), 0..4),
        iot in prop::collection::vec(mac(), 0..4),
        auto in any::<bool>(),
    ) {
        let v = view(auto, trusted.clone(), isolated);
        let out = decide_isolation(&v, iot.iter().map(String::as_str));
        let sorted: BTreeSet<&String> = out.iter().collect();
        prop_assert_eq!(sorted.len(), out.len());
        prop_assert!(out.windows(2).all(|w| w[0] < w[1]));
        prop_assert!(out.iter().all(|m| !trusted.contains(m)));
    }

    #[test]
    fn a_scan_never_panics(leases in json_value(), sync in json_value(), auto in any::<bool>()) {
        let mut io = Random {
            leases,
            sync,
            mdns: MdnsResults::from([("10.0.0.5".into(), BTreeSet::from(["_hap._tcp".to_owned()]))]),
        };
        if let Ok(r) = run_scan(&view(auto, Vec::new(), Vec::new()), &mut io, 1_700_000_000.5) {
            let state = r.state.expect("an enabled scan writes its inventory");
            prop_assert!(pyjson::loads(state.as_bytes()).is_ok());
        }
    }
}
