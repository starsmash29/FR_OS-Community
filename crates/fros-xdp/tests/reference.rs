//! Replays FR_OS 1.x's XDP program (testdata/reference/xdp.jsonl, written
//! by reference/test_fros_xdp_cases.py through reference/generate-xdp.sh):
//! the kernel runs the aya program (crates/fros-xdp-ebpf) on every frame
//! it ran 1.x's C program on, with the same blocklist and settings, and
//! each frame must get the same verdict, move the same counters, report
//! the same events and hello copies, and leave the same flows behind.
//!
//! Loading a BPF program needs root, so without root, or without the
//! built object, this skips; FROS_XDP_REQUIRED=1 (CI's XDP job) makes
//! either a failure instead.

use std::collections::HashMap as Counts;
use std::path::PathBuf;

use aya::Ebpf;
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Array, HashMap, MapData, ProgramArray, RingBuf};
use aya::programs::{TestRun, TestRunOptions, Xdp};
use fros_sensor::pyjson::{self, Dict, Value};
use fros_sensor::reference::{cases, clip, field, int, list, report, text};
use fros_xdp::{PROGRAMS, STATS};

/// Cases where FR_OS 2 answers differently on purpose
/// (testdata/reference/decisions.md, "phase 4d").
const DECIDED: &[&str] = &[];

fn object() -> PathBuf {
    match std::env::var_os("FROS_XDP_OBJECT") {
        Some(p) => PathBuf::from(p),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../fros-xdp-ebpf/target/bpfel-unknown-none/release/fros-xdp"),
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn u16_at(b: &[u8], i: usize) -> i64 {
    i64::from(u16::from_le_bytes([b[i], b[i + 1]]))
}

fn u32_at(b: &[u8], i: usize) -> i64 {
    i64::from(u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]))
}

/// The program, loaded once; its maps emptied for every case.
struct Filter {
    ebpf: Ebpf,
    blocklist: LpmTrie<MapData, [u8; 36], u8>,
    stats: Array<MapData, u64>,
    settings: Array<MapData, u32>,
    hello_flows: HashMap<MapData, [u8; 36], u32>,
    sni_flows: HashMap<MapData, [u8; 36], [u8; 88]>,
    events: RingBuf<MapData>,
    hello_pkts: RingBuf<MapData>,
    _split_prog: ProgramArray<MapData>,
}

impl Filter {
    fn load(path: &PathBuf) -> Filter {
        let mut ebpf = Ebpf::load_file(path).expect("load the object");
        for name in PROGRAMS {
            let prog: &mut Xdp = ebpf
                .program_mut(name)
                .unwrap_or_else(|| panic!("no program {name}"))
                .try_into()
                .expect("an XDP program");
            prog.load().unwrap_or_else(|e| panic!("{name}: {e:?}"));
        }
        let mut split_prog =
            ProgramArray::try_from(ebpf.take_map("split_prog").expect("split_prog"))
                .expect("prog array");
        for (index, name) in [(0, "xdp_sni_split"), (1, "xdp_sni_filter6")] {
            let prog: &Xdp = ebpf.program(name).expect(name).try_into().expect("xdp");
            split_prog
                .set(index, prog.fd().expect("fd"), 0)
                .expect("fill split_prog");
        }
        let mut take = |name: &str| {
            ebpf.take_map(name)
                .unwrap_or_else(|| panic!("no map {name}"))
        };
        let blocklist = LpmTrie::try_from(take("sni_blocklist")).expect("sni_blocklist");
        let stats = Array::try_from(take("stats")).expect("stats");
        let settings = Array::try_from(take("settings")).expect("settings");
        let hello_flows = HashMap::try_from(take("hello_flows")).expect("hello_flows");
        let sni_flows = HashMap::try_from(take("sni_flows")).expect("sni_flows");
        let events = RingBuf::try_from(take("events")).expect("events");
        let hello_pkts = RingBuf::try_from(take("hello_pkts")).expect("hello_pkts");
        Filter {
            ebpf,
            blocklist,
            stats,
            settings,
            hello_flows,
            sni_flows,
            events,
            hello_pkts,
            _split_prog: split_prog,
        }
    }

    fn reset(&mut self, blocklist: &[Vec<u8>], settings: u32) {
        let keys: Vec<Key<[u8; 36]>> = self.blocklist.keys().map(|k| k.expect("key")).collect();
        for k in keys {
            self.blocklist.remove(&k).expect("remove");
        }
        let keys: Vec<[u8; 36]> = self.hello_flows.keys().map(|k| k.expect("key")).collect();
        for k in keys {
            let _ = self.hello_flows.remove(&k);
        }
        let keys: Vec<[u8; 36]> = self.sni_flows.keys().map(|k| k.expect("key")).collect();
        for k in keys {
            let _ = self.sni_flows.remove(&k);
        }
        for i in 0..STATS.len() as u32 {
            self.stats.set(i, 0, 0).expect("stats");
        }
        self.settings.set(0, settings, 0).expect("settings");
        for raw in blocklist {
            let prefix = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            let data: [u8; 36] = raw[4..40].try_into().expect("40-byte key");
            self.blocklist
                .insert(&Key::new(prefix, data), 1, 0)
                .expect("insert");
        }
        self.drain();
    }

    fn stats(&self) -> Vec<i64> {
        (0..STATS.len() as u32)
            .map(|i| i64::try_from(self.stats.get(&i, 0).expect("stat")).expect("i64"))
            .collect()
    }

    fn drain(&mut self) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let mut events = Vec::new();
        while let Some(item) = self.events.next() {
            events.push(item.to_vec());
        }
        let mut hellos = Vec::new();
        while let Some(item) = self.hello_pkts.next() {
            hellos.push(item.to_vec());
        }
        (events, hellos)
    }

    fn run(&self, frame: &[u8]) -> u32 {
        let prog: &Xdp = self
            .ebpf
            .program("xdp_sni_filter")
            .expect("filter")
            .try_into()
            .expect("xdp");
        prog.test_run(TestRunOptions {
            data_in: Some(frame),
            ..TestRunOptions::default()
        })
        .expect("test run")
        .return_value
    }

    /// sni_flows as the recorder lists them (born left out: a clock).
    fn flows(&self) -> Value {
        let mut out: Vec<(String, Value)> = Vec::new();
        for item in self.sni_flows.iter() {
            let (k, v) = item.expect("flow");
            let carry_len = u32::from_le_bytes([v[24], v[25], v[26], v[27]]) as usize;
            let row = Value::List(vec![
                Value::Str(to_hex(&k)),
                Value::int(u32_at(&v, 8)),
                Value::int(u32_at(&v, 12)),
                Value::int(u32_at(&v, 16)),
                Value::int(u32_at(&v, 20)),
                Value::int(u32_at(&v, 24)),
                Value::int(u32_at(&v, 28)),
                Value::int(u32_at(&v, 32)),
                Value::Str(to_hex(&v[36..36 + carry_len.min(48)])),
            ]);
            out.push((pyjson::dumps(&row), row));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Value::List(out.into_iter().map(|(_, v)| v).collect())
    }

    fn hello_flows(&self) -> Value {
        let mut out: Vec<(String, Value)> = Vec::new();
        for item in self.hello_flows.iter() {
            let (k, v) = item.expect("hello flow");
            let row = Value::List(vec![Value::Str(to_hex(&k)), Value::int(i64::from(v))]);
            out.push((pyjson::dumps(&row), row));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Value::List(out.into_iter().map(|(_, v)| v).collect())
    }

    /// Every followed flow made older than SPLIT_TTL_NS.
    fn expire(&mut self) {
        let flows: Vec<([u8; 36], [u8; 88])> =
            self.sni_flows.iter().map(|i| i.expect("flow")).collect();
        for (k, mut v) in flows {
            v[0..8].copy_from_slice(&1u64.to_le_bytes());
            self.sni_flows.insert(k, v, 0).expect("expire");
        }
    }
}

fn event(raw: &[u8]) -> Value {
    Value::List(vec![
        Value::Str(to_hex(&raw[0..16])),
        Value::Str(to_hex(&raw[16..32])),
        Value::int(u16_at(raw, 32)),
        Value::int(u16_at(raw, 34)),
        Value::int(i64::from(raw[36])),
        Value::int(u16_at(raw, 38)),
        Value::Str(to_hex(&raw[40..72])),
    ])
}

fn hello(raw: &[u8]) -> Value {
    let len = u16::from_le_bytes([raw[40], raw[41]]) as usize;
    Value::List(vec![
        Value::Str(to_hex(&raw[0..16])),
        Value::Str(to_hex(&raw[16..32])),
        Value::int(u16_at(raw, 32)),
        Value::int(u16_at(raw, 34)),
        Value::int(u32_at(raw, 36)),
        Value::int(len as i64),
        Value::int(i64::from(raw[42])),
        Value::int(i64::from(raw[43])),
        Value::Str(to_hex(&raw[44..44 + len.min(2048)])),
    ])
}

fn same(what: &str, step: usize, got: &Value, want: &Value) -> Result<(), String> {
    let (got, want) = (pyjson::dumps(got), pyjson::dumps(want));
    if got == want {
        Ok(())
    } else {
        Err(format!(
            "step {step} {what}: got {} want {}",
            clip(&got),
            clip(&want)
        ))
    }
}

fn check(filter: &mut Filter, case: &Dict) -> Result<(), String> {
    let blocklist: Vec<Vec<u8>> = list(field(case, "blocklist"))
        .iter()
        .map(|k| hex(text(k)))
        .collect();
    filter.reset(
        &blocklist,
        u32::try_from(int(field(case, "settings"))).expect("u32"),
    );
    let steps = list(field(case, "steps"));
    let results = list(field(case, "results"));
    for (i, (step, want)) in steps.iter().zip(results).enumerate() {
        let Value::Dict(step) = step else {
            panic!("step")
        };
        if step.get("expire").is_some() {
            filter.expire();
            continue;
        }
        let Value::Dict(want) = want else {
            panic!("result")
        };
        let before = filter.stats();
        let verdict = filter.run(&hex(text(field(step, "frame"))));
        let after = filter.stats();
        let (events, hellos) = filter.drain();
        same(
            "verdict",
            i,
            &Value::int(i64::from(verdict)),
            field(want, "verdict"),
        )?;
        let delta = Value::List(
            after
                .iter()
                .zip(&before)
                .map(|(a, b)| Value::int(a - b))
                .collect(),
        );
        same("stats", i, &delta, field(want, "stats"))?;
        same(
            "events",
            i,
            &Value::List(events.iter().map(|e| event(e)).collect()),
            field(want, "events"),
        )?;
        same(
            "hellos",
            i,
            &Value::List(hellos.iter().map(|h| hello(h)).collect()),
            field(want, "hellos"),
        )?;
        same("flows", i, &filter.flows(), field(want, "flows"))?;
        same(
            "hello flows",
            i,
            &filter.hello_flows(),
            field(want, "hello_flows"),
        )?;
    }
    Ok(())
}

fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .map(|l| l.split_whitespace().nth(2) == Some("0"))
        })
        .unwrap_or(false)
}

#[test]
fn replays_1x() {
    let required = std::env::var_os("FROS_XDP_REQUIRED").is_some();
    let path = object();
    if !is_root() || !path.exists() {
        let why = format!("needs root and the built program at {}", path.display());
        assert!(!required, "{why}");
        eprintln!("skipped: {why}");
        return;
    }
    let mut filter = Filter::load(&path);
    let all = cases(env!("CARGO_MANIFEST_DIR"), "xdp.jsonl");
    let mut failures = Vec::new();
    let mut counts: Counts<String, usize> = Counts::new();
    for case in &all {
        let name = text(field(case, "name")).to_owned();
        let kind = name.split(' ').next().unwrap_or("").to_owned();
        *counts.entry(kind).or_default() += 1;
        let decided = DECIDED.contains(&name.as_str());
        match check(&mut filter, case) {
            Ok(()) if decided => {
                failures.push(format!("{name:?}: listed as decided but matches 1.x"))
            }
            Err(e) if !decided => failures.push(format!("{name:?}: {e}")),
            _ => {}
        }
    }
    for (kind, at_least) in [
        ("name", 200),
        ("field", 150),
        ("cut", 400),
        ("layer", 100),
        ("split", 380),
        ("copies", 6),
        ("damaged", 700),
        ("random", 400),
    ] {
        let n = counts.get(kind).copied().unwrap_or(0);
        if n < at_least {
            failures.push(format!("only {n} {kind} cases (at least {at_least})"));
        }
    }
    report(&failures);
}
