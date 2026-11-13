//! Properties over random input: the lines and names scored here come
//! from any LAN host, so nothing may panic, whatever arrives; and the
//! exact arithmetic keeps the identities it must.

use std::collections::HashSet;

use fros_aiids::{
    AnomalyEngine, looks_generated, parse_dns_log_line, parse_sni_drop_line, registered_label,
};
use fros_sensor::pyfloat;
use proptest::prelude::*;

fn finite() -> impl Strategy<Value = f64> {
    prop_oneof![
        any::<f64>().prop_filter("finite", |f| f.is_finite()),
        (0u32..100).prop_map(|n| f64::from(n) / 60.0),
        (0u32..50).prop_map(f64::from),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn readers_are_total(line in "\\PC{0,80}", name in "[a-z0-9.\\-]{0,40}") {
        let threat: HashSet<String> = ["/x".to_owned()].into_iter().collect();
        let _ = parse_dns_log_line(&line, &threat);
        let _ = parse_dns_log_line(&format!("5 10.0.0.5/1 reply {name} is NXDOMAIN"), &threat);
        let _ = parse_sni_drop_line(&line);
        let _ = looks_generated(&line);
        if let Some(label) = registered_label(&name) {
            prop_assert!(!label.is_empty());
        }
    }

    #[test]
    fn mean_and_pstdev(values in prop::collection::vec(finite(), 1..30), x in finite(), n in 1usize..30) {
        let m = pyfloat::mean(&values);
        let lo = values.iter().copied().fold(f64::INFINITY, f64::min);
        let hi = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        prop_assert!(lo <= m && m <= hi, "{} not in [{}, {}]", m, lo, hi);
        prop_assert!(pyfloat::pstdev(&values) >= 0.0);
        let same = vec![x; n];
        prop_assert_eq!(pyfloat::mean(&same), x);
        prop_assert_eq!(pyfloat::pstdev(&same), 0.0);
    }

    #[test]
    fn rounding(x in finite(), digits in 0u32..6) {
        let r = pyfloat::round(x, digits);
        prop_assert_eq!(pyfloat::round(r, digits).to_bits(), r.to_bits());
        if x.abs() < 1e15 {
            prop_assert!((r - x).abs() <= 0.5 * 10f64.powi(-(digits as i32)) * (1.0 + 1e-9) + x.abs() * 1e-15);
        }
    }

    #[test]
    fn engine_is_total(steps in prop::collection::vec((0u8..5, 0u8..4, prop_oneof![finite(), Just(f64::NAN), Just(f64::INFINITY)]), 0..400),
                       window in prop_oneof![Just(60.0), Just(0.0), Just(1e-300), finite()]) {
        let mut e = AnomalyEngine::new(window, 3.0);
        for (op, ip, now) in steps {
            let ip = ["a", "b", "c", "d"][ip as usize];
            match op {
                0 => e.observe_connection(ip, &format!("{now}"), now),
                1 => e.observe_sni_block(ip, now),
                2 => e.observe_dns_nxdomain(ip, &format!("{now}"), now > 0.0, now),
                3 => e.observe_dns_threat_block(ip, now),
                _ => {
                    if let Some(event) = e.evaluate(ip, now) {
                        prop_assert!(!event.reasons.is_empty());
                    }
                }
            }
        }
        prop_assert!(e.tracked_ips().len() <= 4);
    }
}
