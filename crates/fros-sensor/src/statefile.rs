//! The sensor daemons' state files: read with a size limit, as 1.x's
//! `read_text()` reads them, written whole through a temporary file and
//! a rename, and put aside when they can't be restored
//! (testdata/reference/decisions.md, phases 4e-1 and 4e-2).

use std::fs;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

/// The file's bytes, `None` when it doesn't exist, an error past `max`.
pub fn read_limited(path: &Path, max: u64) -> io::Result<Option<Vec<u8>>> {
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut raw = Vec::new();
    file.take(max + 1).read_to_end(&mut raw)?;
    if raw.len() as u64 > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("larger than {max} bytes"),
        ));
    }
    Ok(Some(raw))
}

/// 1.x's `read_text()`: text mode turns "\r\n" and "\r" into "\n".
pub fn universal_newlines(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\r' {
            out.push(b'\n');
            if raw.get(i + 1) == Some(&b'\n') {
                i += 1;
            }
        } else {
            out.push(raw[i]);
        }
        i += 1;
    }
    out
}

/// 1.x's `tmp = path.with_suffix(".tmp"); tmp.write_text(text);
/// tmp.replace(path)`, creating the directory first.
pub fn write_atomic(path: &Path, text: &str) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, text)?;
    fs::rename(&tmp, path)
}

/// Renames `path` to `<path>.broken`: where it went, and `why` (with
/// the rename's error if it failed).
pub fn put_aside(path: &Path, why: String) -> (PathBuf, String) {
    let mut aside = path.as_os_str().to_owned();
    aside.push(".broken");
    let aside = PathBuf::from(aside);
    match fs::rename(path, &aside) {
        Ok(()) => (aside, why),
        Err(e) => (
            path.to_path_buf(),
            format!("{why}; could not put it aside: {e}"),
        ),
    }
}
