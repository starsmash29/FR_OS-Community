//! The wire format between FR_OS processes on a Unix socket, the Rust
//! side of `ipc` (Go): one JSON object per line, at most `max`
//! bytes up to the newline, UTF-8, valid JSON, an object at the top, and
//! no name twice in any object (RFC 7493). Both sides make the same call
//! on every case in `testdata/ipc/vectors.json`.
//!
//! `serde_json` on its own keeps the last of two equal names; Go's
//! `encoding/json/v2` refuses them. A peer that sends
//! `{"cmd":"status","cmd":"apply"}` must not be read as two different
//! commands, so [`check`] refuses duplicates here too.

use std::collections::HashSet;
use std::fmt;
use std::io::BufRead;

use serde::de::{self, DeserializeOwned, Deserializer, MapAccess, SeqAccess, Visitor};

/// `frfw.helper.protocol.MAX_LINE_BYTES`.
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// Why a line was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Eof,
    Truncated,
    TooLong,
    InvalidUtf8,
    InvalidJson,
    NotObject,
    DuplicateKey,
    Io(std::io::ErrorKind),
}

impl Error {
    /// The name the test vectors use.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::Eof => "eof",
            Error::Truncated => "truncated",
            Error::TooLong => "too_long",
            Error::InvalidUtf8 => "invalid_utf8",
            Error::InvalidJson => "invalid_json",
            Error::NotObject => "not_object",
            Error::DuplicateKey => "duplicate_key",
            Error::Io(_) => "io",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ipc: {}", self.kind())
    }
}

impl std::error::Error for Error {}

/// Reads one line (without its newline) of at most `max` bytes. Bytes
/// past the limit are not read: after `TooLong` the stream is out of
/// step and the connection must be closed.
pub fn read_line<R: BufRead>(r: &mut R, max: usize) -> Result<Vec<u8>, Error> {
    let mut line = Vec::new();
    loop {
        let buf = r.fill_buf().map_err(|e| Error::Io(e.kind()))?;
        if buf.is_empty() {
            return Err(if line.is_empty() {
                Error::Eof
            } else {
                Error::Truncated
            });
        }
        let (take, done) = match buf.iter().position(|&b| b == b'\n') {
            Some(i) => (i, true),
            None => (buf.len(), false),
        };
        if line.len() + take > max {
            return Err(Error::TooLong);
        }
        line.extend_from_slice(&buf[..take]);
        r.consume(if done { take + 1 } else { take });
        if done {
            return Ok(line);
        }
    }
}

/// Whether `line` is one acceptable message, and why not.
pub fn check(line: &[u8]) -> Result<(), Error> {
    let text = std::str::from_utf8(line).map_err(|_| Error::InvalidUtf8)?;
    let value: serde_json::Value = serde_json::from_str(text).map_err(|_| Error::InvalidJson)?;
    if !value.is_object() {
        return Err(Error::NotObject);
    }
    let mut de = serde_json::Deserializer::from_str(text);
    <NoDuplicates as serde::Deserialize>::deserialize(&mut de).map_err(|_| Error::DuplicateKey)?;
    Ok(())
}

/// Reads, checks and decodes one message.
pub fn read<R: BufRead, T: DeserializeOwned>(r: &mut R, max: usize) -> Result<T, Error> {
    let line = read_line(r, max)?;
    check(&line)?;
    serde_json::from_slice(&line).map_err(|_| Error::InvalidJson)
}

/// Encodes `msg` as one line; refuses anything that is not a JSON object
/// or is longer than `max`, so a peer never has to.
pub fn write<W: std::io::Write, T: serde::Serialize>(
    w: &mut W,
    max: usize,
    msg: &T,
) -> Result<(), Error> {
    let mut b = serde_json::to_vec(msg).map_err(|_| Error::InvalidJson)?;
    check(&b)?;
    if b.len() > max {
        return Err(Error::TooLong);
    }
    b.push(b'\n');
    w.write_all(&b).map_err(|e| Error::Io(e.kind()))
}

/// Walks a JSON document and fails on the first object with a name twice.
struct NoDuplicates;

impl<'de> serde::Deserialize<'de> for NoDuplicates {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(NoDuplicatesVisitor)
    }
}

struct NoDuplicatesVisitor;

impl<'de> Visitor<'de> for NoDuplicatesVisitor {
    type Value = NoDuplicates;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON without duplicate names")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<NoDuplicates, A::Error> {
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key) {
                return Err(de::Error::custom("duplicate name"));
            }
            map.next_value::<NoDuplicates>()?;
        }
        Ok(NoDuplicates)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<NoDuplicates, A::Error> {
        while seq.next_element::<NoDuplicates>()?.is_some() {}
        Ok(NoDuplicates)
    }

    fn visit_bool<E>(self, _: bool) -> Result<NoDuplicates, E> {
        Ok(NoDuplicates)
    }
    fn visit_i64<E>(self, _: i64) -> Result<NoDuplicates, E> {
        Ok(NoDuplicates)
    }
    fn visit_u64<E>(self, _: u64) -> Result<NoDuplicates, E> {
        Ok(NoDuplicates)
    }
    fn visit_f64<E>(self, _: f64) -> Result<NoDuplicates, E> {
        Ok(NoDuplicates)
    }
    fn visit_str<E>(self, _: &str) -> Result<NoDuplicates, E> {
        Ok(NoDuplicates)
    }
    fn visit_unit<E>(self) -> Result<NoDuplicates, E> {
        Ok(NoDuplicates)
    }
}
