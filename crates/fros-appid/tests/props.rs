//! Properties over random input: log lines and state files can be
//! shaped by any LAN host or damaged on disk, so nothing may panic or
//! grow without bound, and a state file written is read back the same.

use fros_appid::usage::MAX_CLIENTS_PER_APP;
use fros_appid::{
    AppIdObserver, AppMatcher, UsageTracker, parse_catalog, parse_dns_query_line,
    parse_sni_event_line,
};
use fros_sensor::pyjson;
use proptest::prelude::*;

fn catalog() -> fros_appid::Catalog {
    let text = br#"{"apps": [{"id": "a", "name": "A", "category": "c", "domains": ["a.example", "x"], "exact": ["e.b.example"]},
                             {"id": "b", "name": "B", "category": "c", "domains": ["b.example"]}]}"#;
    parse_catalog(&pyjson::loads(text).expect("json")).expect("catalog")
}

/// Lines close to the real ones, then damaged.
fn line() -> impl Strategy<Value = String> {
    let alphabet = prop::sample::select(vec![
        '0', '1', '9', ' ', '.', ':', '/', 'a', 'f', 'q', 'u', 'e', 'r', 'y', '[', ']', 'A', '\n',
        '\t', '"', '{', '}', ',', '\u{661}', '\u{e9}', '\u{3000}', '\x1c', 'x', 'm', 'p', 'l',
    ]);
    prop_oneof![
        prop::collection::vec(alphabet, 0..80).prop_map(|c| c.into_iter().collect()),
        (0usize..60, any::<char>()).prop_map(|(at, c)| {
            let mut s: Vec<char> =
                "Nov 13 10:00:00 dnsmasq[9]: 2 10.0.0.5/53 query[A] a.example from 10.0.0.5"
                    .chars()
                    .collect();
            let at = at.min(s.len() - 1);
            s[at] = c;
            s.into_iter().collect()
        }),
        (0usize..50, any::<char>()).prop_map(|(at, c)| {
            let mut s: Vec<char> = r#"{"action": "pass", "saddr": "10.0.0.5", "sni": "a.example"}"#
                .chars()
                .collect();
            let at = at.min(s.len() - 1);
            s[at] = c;
            s.into_iter().collect()
        }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn line_readers_are_total(line in line()) {
        let _ = parse_dns_query_line(&line);
        let _ = parse_sni_event_line(&line);
        if let Some(o) = parse_dns_query_line(&line) {
            prop_assert!(!o.client.is_empty() && !o.name.is_empty());
        }
    }

    #[test]
    fn matching_is_total_and_case_blind(name in "\\PC{0,40}") {
        let m = AppMatcher::new(&catalog());
        let got = m.matches(&name).map(str::to_owned);
        prop_assert_eq!(got, m.matches(&name.to_ascii_uppercase()).map(str::to_owned));
    }

    #[test]
    fn restore_never_panics(raw in prop::collection::vec(any::<u8>(), 0..300)) {
        if let Ok(v) = pyjson::loads(&raw) {
            let _ = UsageTracker::restore(Some(&v));
        }
    }

    #[test]
    fn state_file_round_trips(hits in prop::collection::vec((0u8..3, 0u16..700, 0u8..2, 0u32..200_000), 0..400)) {
        let mut t = UsageTracker::new();
        let t0 = 1_700_000_000.0;
        for (app, client, source, dt) in &hits {
            t.record(["a", "b", "c"][*app as usize], &format!("10.0.{}.{}", client / 256, client % 256),
                     ["dns", "sni"][*source as usize], t0 + f64::from(*dt));
        }
        let now = t0 + 200_000.0;
        let first = t.snapshot(now);
        let text = pyjson::dumps(&first);
        let mut back = UsageTracker::restore(Some(&pyjson::loads(text.as_bytes()).expect("reads back"))).expect("no crash");
        prop_assert_eq!(pyjson::dumps(&back.snapshot(now)), text.clone());
        // Bounded: no app holds more clients than the limit.
        if let fros_sensor::pyjson::Value::Dict(top) = &first
            && let Some(fros_sensor::pyjson::Value::Dict(apps)) = top.get("apps") {
            for (_, app) in &apps.0 {
                if let fros_sensor::pyjson::Value::Dict(app) = app
                    && let Some(fros_sensor::pyjson::Value::Dict(clients)) = app.get("clients") {
                    prop_assert!(clients.0.len() <= MAX_CLIENTS_PER_APP);
                }
            }
        }
    }

    #[test]
    fn dedup_table_stays_bounded(steps in prop::collection::vec((0u32..30_000, 0u32..100), 0..300)) {
        let mut o = AppIdObserver::new(&catalog(), UsageTracker::new());
        let mut now = 0.0;
        for (client, dt) in steps {
            now += f64::from(dt) / 10.0;
            o.observe(&client.to_string(), "a.example", "dns", now);
            prop_assert!(o.remembered() <= 20_001);
        }
    }
}
