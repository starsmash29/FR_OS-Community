//! The shared wire-format vectors; `ipc` (Go) runs the same file.

use std::io::{BufReader, Cursor, Read};

use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    name: String,
    hex: String,
    max: usize,
    want: String,
}

#[derive(Deserialize)]
struct File {
    vectors: Vec<Vector>,
}

#[test]
fn shared_vectors() {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/ipc/vectors.json"
    ))
    .unwrap();
    let file: File = serde_json::from_str(&raw).unwrap();
    assert!(file.vectors.len() >= 20);
    let mut failed = Vec::new();
    for v in &file.vectors {
        let data = hex::decode(&v.hex).unwrap();
        let mut r = BufReader::with_capacity(16, Cursor::new(data));
        let got = match fros_ipc::read::<_, serde_json::Value>(&mut r, v.max) {
            Ok(_) => "ok",
            Err(e) => e.kind(),
        };
        if got != v.want {
            failed.push(format!("{}: got {got}, want {}", v.name, v.want));
        }
    }
    assert!(failed.is_empty(), "{failed:#?}");
}

#[test]
fn too_long_stops_reading() {
    let data = vec![b'x'; 1 << 20];
    let mut src = Cursor::new(data);
    let mut r = BufReader::with_capacity(4096, (&mut src).take(u64::MAX));
    assert_eq!(
        fros_ipc::read_line(&mut r, 1024),
        Err(fros_ipc::Error::TooLong)
    );
    drop(r);
    assert!(src.position() <= 8192, "read {} bytes", src.position());
}

#[test]
fn write_read_round_trip() {
    let mut buf = Vec::new();
    let msg = serde_json::json!({"cmd": "apply", "args": {"confirm": true}});
    fros_ipc::write(&mut buf, fros_ipc::MAX_LINE_BYTES, &msg).unwrap();
    let back: serde_json::Value =
        fros_ipc::read(&mut Cursor::new(buf), fros_ipc::MAX_LINE_BYTES).unwrap();
    assert_eq!(back, msg);
}

#[test]
fn write_refuses_non_objects_and_long_lines() {
    assert_eq!(
        fros_ipc::write(&mut Vec::new(), 1024, &[1, 2]),
        Err(fros_ipc::Error::NotObject)
    );
    let long = serde_json::json!({"k": "long value"});
    assert_eq!(
        fros_ipc::write(&mut Vec::new(), 8, &long),
        Err(fros_ipc::Error::TooLong)
    );
}
