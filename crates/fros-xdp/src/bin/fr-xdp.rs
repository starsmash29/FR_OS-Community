//! `fr-xdp`: the XDP SNI filter's pins, for the apply-helper (root). It
//! runs what 1.x's `frfw.xdp` ran `bpftool` for (crate::pins says why
//! bpftool can't), one command per run, with fixed argv:
//!
//! ```text
//! fr-xdp load -- OBJECT PROG_DIR MAP_DIR    load, fill split_prog, pin
//! fr-xdp prog-id -- PROG_PIN                {"id": N}
//! fr-xdp blocklist -- MAP_PIN               stdin: the keys, one hex line each
//! fr-xdp settings -- MAP_PIN FLAGS          the switch bits, decimal
//! fr-xdp stats -- MAP_PIN                   [{"key": 0, "value": N}, ...]
//! ```
//!
//! Every path is absolute and comes after `--` (security-lessons F1);
//! stdin is read up to the most the blocklist can hold. Exit 0 on
//! success; 1 with the failure on stderr; 2 for a usage error.

use std::collections::BTreeSet;
use std::io::{self, Read as _, Write as _};
use std::path::Path;
use std::process::ExitCode;

use fros_xdp::pins::{self, LpmKey};
use fros_xdp::{BLOCKLIST_MAX_ENTRIES, LPM_KEY_SIZE};

/// One key per line: 80 hex digits and a newline.
const STDIN_LIMIT: u64 = (BLOCKLIST_MAX_ENTRIES * (LPM_KEY_SIZE * 2 + 1)) as u64;

fn usage(why: &str) -> ExitCode {
    eprintln!("fr-xdp: {why}");
    eprintln!(
        "usage: fr-xdp load -- OBJECT PROG_DIR MAP_DIR | prog-id -- PROG_PIN | \
         blocklist -- MAP_PIN | settings -- MAP_PIN FLAGS | stats -- MAP_PIN"
    );
    ExitCode::from(2)
}

fn done(result: Result<String, String>) -> ExitCode {
    match result {
        Ok(out) => {
            let mut stdout = io::stdout().lock();
            if stdout
                .write_all(out.as_bytes())
                .and_then(|()| stdout.flush())
                .is_err()
            {
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        Err(mut e) => {
            // The message as it is, one line end: the apply-helper
            // reports it.
            if !e.ends_with('\n') {
                e.push('\n');
            }
            let _ = io::stderr().write_all(e.as_bytes());
            ExitCode::from(1)
        }
    }
}

/// The blocklist keys from stdin, refused whole if any line is not one.
fn read_keys() -> Result<BTreeSet<LpmKey>, String> {
    let mut raw = Vec::new();
    io::stdin()
        .take(STDIN_LIMIT + 1)
        .read_to_end(&mut raw)
        .map_err(|e| format!("reading the keys: {e}\n"))?;
    if raw.len() as u64 > STDIN_LIMIT {
        return Err(format!("more than {BLOCKLIST_MAX_ENTRIES} keys on stdin\n"));
    }
    let text = std::str::from_utf8(&raw).map_err(|_| "the keys are not text\n".to_string())?;
    let mut keys = BTreeSet::new();
    for line in text.split_terminator('\n') {
        if line.len() != LPM_KEY_SIZE * 2 {
            return Err(format!("not a key: {line:?}\n"));
        }
        let mut key = [0u8; LPM_KEY_SIZE];
        for (i, b) in key.iter_mut().enumerate() {
            let pair = &line[i * 2..i * 2 + 2];
            if !pair
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            {
                return Err(format!("not a key: {line:?}\n"));
            }
            *b = u8::from_str_radix(pair, 16).map_err(|_| format!("not a key: {line:?}\n"))?;
        }
        keys.insert(key);
    }
    Ok(keys)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(cmd), Some(sep)) = (args.first(), args.get(1)) else {
        return usage("missing command");
    };
    if sep != "--" {
        return usage("`--` must come before the paths");
    }
    let rest = &args[2..];
    // Every argument is a path but the settings' flags.
    let paths = if cmd == "settings" {
        &rest[..rest.len().min(1)]
    } else {
        rest
    };
    if let Some(p) = paths.iter().find(|p| !Path::new(p).is_absolute()) {
        return usage(&format!("not an absolute path: {p:?}"));
    }
    let path = |i: usize| Path::new(&rest[i]);
    match (cmd.as_str(), rest.len()) {
        ("load", 3) => done(pins::load_and_pin(path(0), path(1), path(2)).map(|()| String::new())),
        ("prog-id", 1) => done(pins::prog_id(path(0)).map(|id| format!("{{\"id\": {id}}}\n"))),
        ("blocklist", 1) => done(
            read_keys()
                .and_then(|keys| pins::sync_blocklist(path(0), &keys))
                .map(|()| String::new()),
        ),
        ("settings", 2) => {
            let Some(flags) = rest[1]
                .parse::<u32>()
                .ok()
                .filter(|_| rest[1].bytes().all(|c| c.is_ascii_digit()))
            else {
                return usage(&format!("not a number: {:?}", rest[1]));
            };
            done(pins::set_settings(path(0), flags).map(|()| String::new()))
        }
        ("stats", 1) => done(pins::stats(path(0)).map(|values| {
            let entries: Vec<String> = values
                .iter()
                .enumerate()
                .map(|(i, v)| format!("{{\"key\": {i}, \"value\": {v}}}"))
                .collect();
            format!("[{}]\n", entries.join(", "))
        })),
        _ => usage(&format!("unknown command or wrong arguments: {cmd}")),
    }
}
