//! Following a log file as 1.x's daemons do with `tail -n 0 -F`
//! (`frfw.journal.follow_file_forever`), without a child process: new
//! lines only, a file that doesn't exist yet waited for, and a file
//! emptied (the SNI event file at its size limit) or replaced (log
//! rotation) read again from its start. Polled from the daemon's own
//! loop, so a daemon is one thread.
//!
//! Every read has a limit (AGENTS.md): at most `READ_CHUNK` bytes per
//! poll, and a line longer than `MAX_LINE_BYTES` is dropped whole, where
//! `tail` would hand it over however long. Bytes that aren't UTF-8 are
//! read as U+FFFD, where 1.x's reader thread dies on them
//! (testdata/reference/decisions.md, phase 4e-2).

use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use crate::pytext;

/// The longest line handed over; the event file's and the query log's
/// lines are a few hundred bytes.
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// The most read from the file in one poll.
pub const READ_CHUNK: usize = 1024 * 1024;

pub struct Follower {
    path: PathBuf,
    file: Option<(File, u64, u64)>, // the file, its device and inode
    offset: u64,
    /// A line read up to here, without its newline yet.
    partial: Vec<u8>,
    /// The current line is past MAX_LINE_BYTES: drop it to its newline.
    skipping: bool,
    /// Whether the file existed when following began: then only lines
    /// written after that are read.
    started: bool,
}

impl Follower {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_owned(),
            file: None,
            offset: 0,
            partial: Vec::new(),
            skipping: false,
            started: false,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn reopen(&mut self, at_end: bool) {
        self.file = None;
        self.partial.clear();
        self.skipping = false;
        self.offset = 0;
        let Ok(mut f) = File::open(&self.path) else {
            return;
        };
        let Ok(meta) = f.metadata() else {
            return;
        };
        if at_end {
            match f.seek(SeekFrom::End(0)) {
                Ok(end) => self.offset = end,
                Err(_) => return,
            }
        }
        self.file = Some((f, meta.dev(), meta.ino()));
    }

    /// The lines written since the last poll, each stripped of the
    /// whitespace around it (1.x's `line.strip()`).
    pub fn poll(&mut self) -> Vec<String> {
        if !self.started {
            self.started = true;
            self.reopen(true);
        }
        // Replaced or gone: what is at the path now, from its start.
        let now = std::fs::metadata(&self.path)
            .ok()
            .map(|m| (m.dev(), m.ino(), m.len()));
        match (&self.file, now) {
            (Some((_, dev, ino)), Some((d, i, _))) if *dev == d && *ino == i => {}
            (None, None) => return Vec::new(),
            (_, Some(_)) => self.reopen(false),
            (Some(_), None) => {
                self.file = None;
                return Vec::new();
            }
        }
        let Some((file, _, _)) = self.file.as_mut() else {
            return Vec::new();
        };
        // Emptied in place: from its start again.
        if now.is_some_and(|(_, _, len)| len < self.offset) {
            self.offset = 0;
            self.partial.clear();
            self.skipping = false;
        }
        if file.seek(SeekFrom::Start(self.offset)).is_err() {
            return Vec::new();
        }
        let mut buf = Vec::new();
        let Ok(n) = file.take(READ_CHUNK as u64).read_to_end(&mut buf) else {
            return Vec::new();
        };
        self.offset += n as u64;
        let mut lines = Vec::new();
        for chunk in buf.split_inclusive(|&b| b == b'\n') {
            let complete = chunk.ends_with(b"\n");
            if !self.skipping {
                self.partial.extend_from_slice(chunk);
                if self.partial.len() > MAX_LINE_BYTES + 1 {
                    self.partial.clear();
                    self.skipping = true;
                }
            }
            if complete {
                if !self.skipping {
                    let text = String::from_utf8_lossy(&self.partial);
                    lines.push(pytext::strip(&text).to_owned());
                }
                self.partial.clear();
                self.skipping = false;
            }
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fros-follow-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn append(path: &Path, text: &[u8]) {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .unwrap();
        f.write_all(text).unwrap();
    }

    #[test]
    fn new_lines_only_then_truncation_and_replacement() {
        let d = dir("tail");
        let path = d.join("log");
        append(&path, b"old line\n");
        let mut f = Follower::new(&path);
        assert!(f.poll().is_empty());
        append(&path, b"one\n  two  \nthr");
        assert_eq!(f.poll(), ["one", "two"]);
        append(&path, b"ee\n\xffx\n");
        assert_eq!(f.poll(), ["three", "\u{fffd}x"]);
        // Emptied, then written again.
        std::fs::write(&path, b"").unwrap();
        assert!(f.poll().is_empty());
        append(&path, b"after\n");
        assert_eq!(f.poll(), ["after"]);
        // Replaced by a new file.
        let new = d.join("log.new");
        std::fs::write(&new, b"fresh\n").unwrap();
        std::fs::rename(&new, &path).unwrap();
        assert_eq!(f.poll(), ["fresh"]);
        // Gone, then back.
        std::fs::remove_file(&path).unwrap();
        assert!(f.poll().is_empty());
        append(&path, b"back\n");
        assert_eq!(f.poll(), ["back"]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn missing_at_start_is_read_from_its_start() {
        let d = dir("missing");
        let path = d.join("log");
        let mut f = Follower::new(&path);
        assert!(f.poll().is_empty());
        append(&path, b"first\n");
        assert_eq!(f.poll(), ["first"]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn long_lines_are_dropped() {
        let d = dir("long");
        let path = d.join("log");
        std::fs::write(&path, b"").unwrap();
        let mut f = Follower::new(&path);
        f.poll();
        let mut long = vec![b'a'; MAX_LINE_BYTES + 10];
        long.extend_from_slice(b"\nshort\n");
        append(&path, &long);
        assert_eq!(f.poll(), ["short"]);
        let exact = vec![b'b'; MAX_LINE_BYTES];
        append(&path, &exact);
        append(&path, b"\n");
        assert_eq!(f.poll().len(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }
}
