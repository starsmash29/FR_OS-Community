//! Properties over random input: the bytes this crate reads come from
//! strangers, so nothing may panic or grow without bound, whatever
//! arrives, and the same input always gives the same answer.

use fros_tlsfp::pyjson::{self, Value};
use fros_tlsfp::{
    FingerprintInventory, MAX_HELLO_BYTES, Reassembler, handshake_from_records, ja3, ja4,
    parse_client_hello,
};
use proptest::prelude::*;

/// A well-formed hello to damage: random bytes rarely get past the
/// first length check, mutations of a real one reach every extension.
fn base_hello() -> Vec<u8> {
    fn ext(t: u16, body: &[u8]) -> Vec<u8> {
        let mut out = t.to_be_bytes().to_vec();
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }
    let mut exts = Vec::new();
    exts.extend(ext(0x0000, b"\x00\x0e\x00\x00\x0bexample.com"));
    exts.extend(ext(0x000A, b"\x00\x04\x00\x1d\x00\x17"));
    exts.extend(ext(0x000B, b"\x01\x00"));
    exts.extend(ext(0x000D, b"\x00\x04\x04\x03\x08\x04"));
    exts.extend(ext(0x0010, b"\x00\x0c\x02h2\x08http/1.1"));
    exts.extend(ext(0x002B, b"\x04\x03\x04\x03\x03"));
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[7u8; 32]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x00, 0x2f, 0x01, 0x00]);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend(exts);
    let mut hello = vec![0x01];
    hello.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hello.extend(body);
    hello
}

fn mutated() -> impl Strategy<Value = Vec<u8>> {
    let base = base_hello();
    let len = base.len();
    (prop::collection::vec((0..len, any::<u8>()), 1..8), 0..=len).prop_map(move |(edits, keep)| {
        let mut data = base.clone();
        for (at, byte) in edits {
            if let Some(slot) = data.get_mut(at) {
                *slot = byte;
            }
        }
        data.truncate(keep.max(1));
        data
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn parsing_random_bytes_is_total(data in prop::collection::vec(any::<u8>(), 0..600)) {
        let first = parse_client_hello(&data);
        prop_assert_eq!(&first, &parse_client_hello(&data));
        if let Ok(hello) = first {
            prop_assert_eq!(ja3(&hello), ja3(&hello));
            prop_assert_eq!(ja4(&hello, "t"), ja4(&hello, "t"));
        }
    }

    #[test]
    fn damaged_hellos_are_total(data in mutated()) {
        if let Ok(hello) = parse_client_hello(&data) {
            let fp = ja4(&hello, "t");
            prop_assert_eq!(fp.len(), 36);
            prop_assert!(hello.extensions.len() <= 256);
        }
    }

    #[test]
    fn records_are_total_and_bounded(data in prop::collection::vec(any::<u8>(), 0..2000)) {
        let mut stream = vec![0x16, 0x03, 0x01];
        stream.extend(data);
        if let Ok(Some(message)) = handshake_from_records(&stream) {
            prop_assert!(message.len() <= MAX_HELLO_BYTES);
        }
    }

    #[test]
    fn reassembly_is_total_and_bounded(
        steps in prop::collection::vec(
            (0u8..4, any::<u32>(), prop::collection::vec(any::<u8>(), 0..300), 0.0f64..20.0, any::<bool>()),
            0..60,
        )
    ) {
        let mut r: Reassembler<u8> = Reassembler::new(3, 5.0);
        for (key, seq, payload, now, first) in steps {
            let _ = r.add(&key, seq, &payload, now, first);
            prop_assert!(r.len() <= 3);
        }
    }

    #[test]
    fn json_reading_is_total(data in prop::collection::vec(any::<u8>(), 0..300)) {
        let _ = pyjson::loads(&data);
    }

    #[test]
    fn json_written_reads_back_the_same(text in r#"[\[\]{}",:0-9a-zA-Z .eE+\-\\u]{0,80}"#) {
        if let Ok(value) = pyjson::loads(text.as_bytes()) {
            let once = pyjson::dumps(&value);
            let again = pyjson::loads(once.as_bytes()).expect("dumps output reads back");
            prop_assert_eq!(once, pyjson::dumps(&again));
        }
    }

    #[test]
    fn restoring_any_json_is_total(text in r#"\{"(started|clients|network_first_seen|events)": [\[\]{}",:0-9a-z .\-]{0,60}\}"#) {
        if let Ok(value) = pyjson::loads(text.as_bytes()) {
            let inv = FingerprintInventory::restore(Some(&value), 0.0);
            let _ = pyjson::dumps(&Value::Dict(inv.snapshot(0.0)));
        }
    }
}
