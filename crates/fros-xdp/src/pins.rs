//! The program and its maps on bpffs, where 1.x's `frfw.xdp` keeps them
//! (`/sys/fs/bpf/fr_os_xdp/{prog,maps}/<name>`), so the apply-helper,
//! the event logger and the fingerprinting daemon all see one instance
//! however many devices run it.
//!
//! 1.x does this with `bpftool`; FR_OS 2 cannot: bpftool loads through
//! libbpf, which no longer reads the legacy `maps` section aya-ebpf's
//! maps are declared in, and its map dumps decode values only through
//! BTF the aya maps don't carry. So the same operations are here, over
//! the bpf() syscall (aya), and the `fr-xdp` binary runs them for the
//! Go apply-helper. The messages are 1.x's, so an apply says the same
//! when one of them fails.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::Path;

use aya::Ebpf;
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Array, Map, MapData, ProgramArray};
use aya::programs::{ProgramInfo, Xdp};

use crate::{BLOCKLIST_MAX_ENTRIES, LPM_KEY_SIZE, PROGRAMS};

/// A blocklist key as the map stores it (`struct lpm_sni_key`).
pub type LpmKey = [u8; LPM_KEY_SIZE];

/// An error and every cause under it, one line: what aya reports is
/// often only the outer step ("the BPF_PROG_LOAD syscall failed").
fn chain(e: &dyn Error) -> String {
    let mut text = e.to_string();
    let mut cause = e.source();
    while let Some(c) = cause {
        let next = c.to_string();
        if !text.contains(&next) {
            text.push_str(": ");
            text.push_str(&next);
        }
        cause = c.source();
    }
    text
}

/// Loads `object`, fills the tail-call array (`split_prog`: 0 the split
/// ClientHello follower, 1 the IPv6 path), and pins each program under
/// `prog_dir` and each map under `map_dir`, by name. The tail calls
/// stay filled while the map is pinned. Nothing is attached.
pub fn load_and_pin(object: &Path, prog_dir: &Path, map_dir: &Path) -> Result<(), String> {
    let mut ebpf = Ebpf::load_file(object).map_err(|e| chain(&e))?;
    for name in PROGRAMS {
        let prog: &mut Xdp = ebpf
            .program_mut(name)
            .ok_or_else(|| format!("the object has no program {name}"))?
            .try_into()
            .map_err(|e| format!("{name}: {}", chain(&e)))?;
        prog.load().map_err(|e| format!("{name}: {}", chain(&e)))?;
    }
    {
        let mut fds = Vec::new();
        for name in ["xdp_sni_split", "xdp_sni_filter6"] {
            let prog: &Xdp = ebpf
                .program(name)
                .ok_or_else(|| format!("the object has no program {name}"))?
                .try_into()
                .map_err(|e| format!("{name}: {}", chain(&e)))?;
            fds.push(
                prog.fd()
                    .map_err(|e| format!("{name}: {}", chain(&e)))?
                    .try_clone()
                    .map_err(|e| format!("{name}: {e}"))?,
            );
        }
        let map = ebpf
            .map_mut("split_prog")
            .ok_or("the object has no map split_prog")?;
        let mut split = ProgramArray::try_from(map).map_err(|e| chain(&e))?;
        for (index, fd) in (0u32..).zip(&fds) {
            split
                .set(index, fd, 0)
                .map_err(|e| format!("split_prog[{index}]: {}", chain(&e)))?;
        }
    }
    fs::create_dir_all(prog_dir).map_err(|e| format!("{}: {e}", prog_dir.display()))?;
    fs::create_dir_all(map_dir).map_err(|e| format!("{}: {e}", map_dir.display()))?;
    for name in PROGRAMS {
        let prog: &mut Xdp = ebpf
            .program_mut(name)
            .ok_or_else(|| format!("the object has no program {name}"))?
            .try_into()
            .map_err(|e| format!("{name}: {}", chain(&e)))?;
        prog.pin(prog_dir.join(name))
            .map_err(|e| format!("pinning {name}: {}", chain(&e)))?;
    }
    for (name, map) in ebpf.maps() {
        // A section the compiler names (.rodata, .bss) is no map of
        // ours, and bpffs refuses a dot in a name.
        if name.contains('.') {
            continue;
        }
        map.pin(map_dir.join(name))
            .map_err(|e| format!("pinning {name}: {}", chain(&e)))?;
    }
    Ok(())
}

/// The id the kernel gave the program pinned at `pin`.
pub fn prog_id(pin: &Path) -> Result<u32, String> {
    let info = ProgramInfo::from_pin(pin).map_err(|e| chain(&e))?;
    Ok(info.id())
}

/// Makes the pinned blocklist hold exactly `desired`: removes what is
/// no longer wanted, then adds what is missing, and touches nothing
/// else, so an apply never empties a filter that is running. The
/// message of a failure is 1.x's, naming the map and the step.
pub fn sync_blocklist(map: &Path, desired: &BTreeSet<LpmKey>) -> Result<(), String> {
    let at = map.display();
    if desired.len() > BLOCKLIST_MAX_ENTRIES {
        return Err(format!(
            "Updating {at} failed:\n{} keys, more than the map's {BLOCKLIST_MAX_ENTRIES}\n",
            desired.len()
        ));
    }
    let dump = |e: &dyn Error| format!("Dumping {at} failed:\n{}\n", chain(e));
    let data = MapData::from_pin(map).map_err(|e| dump(&e))?;
    let mut trie: LpmTrie<MapData, [u8; LPM_KEY_SIZE - 4], u8> =
        LpmTrie::try_from(Map::from_map_data(data).map_err(|e| dump(&e))?).map_err(|e| dump(&e))?;
    let mut existing = BTreeSet::new();
    for key in trie.keys() {
        let key = key.map_err(|e| dump(&e))?;
        existing.insert(to_bytes(&key));
    }
    for key in existing.difference(desired) {
        trie.remove(&to_key(key))
            .map_err(|e| format!("Deleting from {at} failed:\n{}\n", chain(&e)))?;
    }
    for key in desired.difference(&existing) {
        trie.insert(&to_key(key), 1, 0)
            .map_err(|e| format!("Updating {at} failed:\n{}\n", chain(&e)))?;
    }
    Ok(())
}

fn to_key(raw: &LpmKey) -> Key<[u8; LPM_KEY_SIZE - 4]> {
    let mut data = [0u8; LPM_KEY_SIZE - 4];
    data.copy_from_slice(&raw[4..]);
    Key::new(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]), data)
}

fn to_bytes(key: &Key<[u8; LPM_KEY_SIZE - 4]>) -> LpmKey {
    let mut raw = [0u8; LPM_KEY_SIZE];
    raw[..4].copy_from_slice(&key.prefix_len().to_le_bytes());
    raw[4..].copy_from_slice(&key.data());
    raw
}

/// Writes the `settings` map's switch bits (SETTING_REPORT_*). The
/// error is the cause alone: the apply puts 1.x's "Updating ... failed"
/// before it.
pub fn set_settings(map: &Path, flags: u32) -> Result<(), String> {
    let data = MapData::from_pin(map).map_err(|e| chain(&e))?;
    let mut settings: Array<MapData, u32> =
        Array::try_from(Map::from_map_data(data).map_err(|e| chain(&e))?).map_err(|e| chain(&e))?;
    settings.set(0, flags, 0).map_err(|e| chain(&e))
}

/// The `stats` map's counters, by index.
pub fn stats(map: &Path) -> Result<Vec<u64>, String> {
    let data = MapData::from_pin(map).map_err(|e| chain(&e))?;
    let stats: Array<MapData, u64> =
        Array::try_from(Map::from_map_data(data).map_err(|e| chain(&e))?).map_err(|e| chain(&e))?;
    stats.iter().map(|v| v.map_err(|e| chain(&e))).collect()
}
