//! Replays FR_OS 1.x's application identification daemon
//! (testdata/reference/sensord.jsonl, op "appid", written by
//! reference/test_fros_sensord_cases.py): started on the same usage
//! file with the same sources, fed the same log lines at the same
//! clocks, the daemon must write the same usage files, byte for byte.
//!
//! Decided (testdata/reference/decisions.md, "phase 4e-2"): a usage
//! file 1.x dies on at start is put aside and the daemon starts afresh,
//! which the recording's steps (those of 1.x started without the file)
//! check.

use std::fs;
use std::path::PathBuf;

use fros_appid::daemon::{AppIdDaemon, bundled_catalog, restore_usage, view_sources, write_usage};
use fros_sensor::pyjson::{Dict, Value};
use fros_sensor::reference::{cases, clip, field, list, number, report, text};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fros-appidd-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn check(case: &Dict, dir: &std::path::Path) -> Result<(), String> {
    let path = dir.join("appid_usage.json");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(dir.join("appid_usage.json.broken"));
    if let Value::Str(state) = field(case, "state") {
        fs::write(&path, hex(state)).expect("state");
    }
    let view = Value::Dict(Dict(vec![(
        "app_control".into(),
        field(case, "view").clone(),
    )]));
    let sources = view_sources(&view).ok_or("no sources in the view")?;
    let restored = restore_usage(&path);
    match (case.get("crash"), &restored.broken) {
        (Some(_), None) => return Err("1.x died on the usage file; it wasn't put aside".into()),
        (None, Some((_, why))) => return Err(format!("put aside ({why}), where 1.x read it")),
        _ => {}
    }
    let catalog = bundled_catalog();
    let mut d = AppIdDaemon::new(&catalog, restored.tracker, sources);
    for (n, step) in list(field(case, "steps")).iter().enumerate() {
        let Value::Dict(step) = step else {
            panic!("step")
        };
        if let Some(now) = step.get("write") {
            write_usage(&path, &d.usage_text(number(now))).map_err(|e| format!("step {n}: {e}"))?;
            let got = fs::read_to_string(&path).expect("usage");
            let want = text(field(step, "file"));
            if got != want {
                return Err(format!(
                    "step {n}: usage file\n got {}\nwant {}",
                    clip(&got),
                    clip(want)
                ));
            }
            continue;
        }
        let now = number(field(step, "now"));
        for source in ["dns", "sni"] {
            if let Some(line) = step.get(source) {
                d.handle_line(source, text(line), now);
            }
        }
    }
    Ok(())
}

#[test]
fn reference_appid_daemon() {
    let all: Vec<Dict> = cases(env!("CARGO_MANIFEST_DIR"), "sensord.jsonl")
        .into_iter()
        .filter(|c| matches!(c.get("op"), Some(Value::Str(op)) if op == "appid"))
        .collect();
    assert!(all.len() >= 10, "only {} appid daemon cases", all.len());
    let dir = temp_dir("replay");
    let mut failures = Vec::new();
    for case in &all {
        if let Err(e) = check(case, &dir) {
            failures.push(format!("appid {}: {e}", text(field(case, "name"))));
        }
    }
    let _ = fs::remove_dir_all(&dir);
    report(&failures);
}

/// A usage file past the size limit is put aside unread.
#[test]
fn oversized_usage_put_aside() {
    let dir = temp_dir("big");
    let path = dir.join("appid_usage.json");
    let f = fs::File::create(&path).expect("create");
    f.set_len(fros_appid::daemon::USAGE_MAX_BYTES + 1)
        .expect("size");
    let restored = restore_usage(&path);
    let (aside, why) = restored.broken.expect("put aside");
    assert_eq!(aside, dir.join("appid_usage.json.broken"));
    assert!(why.contains("larger than"), "{why}");
    assert!(!path.exists());
    let _ = fs::remove_dir_all(&dir);
}
