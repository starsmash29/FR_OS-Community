//! Asking the apply-helper something, as 1.x's sensor daemons do
//! (`frfw.helper.client.send_command`): one JSON request line on the
//! helper's Unix socket, the write side shut, the reply read to the end
//! (at most a size limit), and its JSON returned. A failure to talk to
//! the helper is an error with 1.x's text; what the helper says (an
//! `{"ok": false, ...}` reply) is a reply. The daemons only ever reach
//! the commands `frfw.helper.peer` lets their account send.

use std::fmt;
use std::io::{self, Read as _, Write as _};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::pyjson::{self, Dict, LoadError, Value};

/// The apply-helper's socket.
pub const APPLY_SOCKET_PATH: &str = "/run/fr_os/apply.sock";

/// The most a reply may hold (1.x's `MAX_LINE_BYTES`).
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// 1.x's default for every call.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// Why there is no reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperError {
    /// 1.x's `HelperError`, with its text.
    Transport(String),
    /// A reply 1.x's client lets an exception through for (not UTF-8:
    /// `UnicodeDecodeError`; too deeply nested: `RecursionError`), by the
    /// exception's name.
    Raised(&'static str),
}

impl fmt::Display for HelperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HelperError::Transport(text) => f.write_str(text),
            HelperError::Raised(name) => write!(f, "{name} reading the apply-helper's reply"),
        }
    }
}

/// Python's text for an OSError: `[Errno N] strerror`, or "timed out".
pub fn os_error_text(e: &io::Error) -> String {
    if matches!(
        e.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        return "timed out".into();
    }
    match e.raw_os_error() {
        Some(n) => {
            let text = io::Error::from_raw_os_error(n).to_string();
            let suffix = format!(" (os error {n})");
            format!(
                "[Errno {n}] {}",
                text.strip_suffix(&suffix).unwrap_or(&text)
            )
        }
        None => e.to_string(),
    }
}

/// Python's `repr(b)` of bytes.
pub fn repr_bytes(b: &[u8]) -> String {
    let quote = if b.contains(&b'\'') && !b.contains(&b'"') {
        b'"'
    } else {
        b'\''
    };
    let mut out = String::with_capacity(b.len() + 3);
    out.push('b');
    out.push(char::from(quote));
    for &c in b {
        match c {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(char::from(c));
            }
            c if !(0x20..0x7f).contains(&c) => out.push_str(&format!("\\x{c:02x}")),
            c => out.push(char::from(c)),
        }
    }
    out.push(char::from(quote));
    out
}

/// Python's `bytes.strip()`: ASCII whitespace off both ends.
fn strip(b: &[u8]) -> &[u8] {
    let ws = |c: &u8| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
    let start = b.iter().position(|c| !ws(c)).unwrap_or(b.len());
    let end = b.iter().rposition(|c| !ws(c)).map_or(start, |i| i + 1);
    &b[start..end]
}

/// `json.loads(bytes)` decodes them first, guessing the encoding
/// (`json.detect_encoding`): a UTF-8, UTF-16 or UTF-32 byte order mark,
/// or the zero bytes ASCII text has in UTF-16 and UTF-32. A lone
/// surrogate (Python's "surrogatepass") becomes U+FFFD, as everywhere
/// in FR_OS 2 (decisions.md); bytes that don't decode raise
/// UnicodeDecodeError.
fn decode(b: &[u8]) -> Result<String, &'static str> {
    const ERR: &str = "UnicodeDecodeError";
    let units16 = |b: &[u8], be: bool| -> Result<String, &'static str> {
        if !b.len().is_multiple_of(2) {
            return Err(ERR);
        }
        let units = b.chunks_exact(2).map(|c| {
            if be {
                u16::from_be_bytes([c[0], c[1]])
            } else {
                u16::from_le_bytes([c[0], c[1]])
            }
        });
        Ok(char::decode_utf16(units)
            .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect())
    };
    let units32 = |b: &[u8], be: bool| -> Result<String, &'static str> {
        if !b.len().is_multiple_of(4) {
            return Err(ERR);
        }
        b.chunks_exact(4)
            .map(|c| {
                let n = if be {
                    u32::from_be_bytes([c[0], c[1], c[2], c[3]])
                } else {
                    u32::from_le_bytes([c[0], c[1], c[2], c[3]])
                };
                match n {
                    0xD800..=0xDFFF => Ok(char::REPLACEMENT_CHARACTER),
                    n => char::from_u32(n).ok_or(ERR),
                }
            })
            .collect()
    };
    let utf8 = |b: &[u8]| String::from_utf8(b.to_vec()).map_err(|_| ERR);
    if let Some(rest) = b.strip_prefix(&[0x00, 0x00, 0xfe, 0xff]) {
        return units32(rest, true);
    }
    if let Some(rest) = b.strip_prefix(&[0xff, 0xfe, 0x00, 0x00]) {
        return units32(rest, false);
    }
    if let Some(rest) = b.strip_prefix(&[0xfe, 0xff]) {
        return units16(rest, true);
    }
    if let Some(rest) = b.strip_prefix(&[0xff, 0xfe]) {
        return units16(rest, false);
    }
    if let Some(rest) = b.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        return utf8(rest);
    }
    if b.len() >= 4 {
        if b[0] == 0 {
            return if b[1] != 0 {
                units16(b, true)
            } else {
                units32(b, true)
            };
        }
        if b[1] == 0 {
            return if b[2] != 0 || b[3] != 0 {
                units16(b, false)
            } else {
                units32(b, false)
            };
        }
    } else if b.len() == 2 {
        if b[0] == 0 {
            return units16(b, true);
        }
        if b[1] == 0 {
            return units16(b, false);
        }
    }
    utf8(b)
}

/// `send_command(cmd, socket_path, timeout, max_bytes)`.
pub fn send_command(
    cmd: &Dict,
    socket: &Path,
    timeout: Duration,
    max_bytes: usize,
) -> Result<Value, HelperError> {
    let unreachable = |e: &io::Error| {
        HelperError::Transport(format!(
            "cannot reach apply-helper at {}: {}",
            socket.display(),
            os_error_text(e)
        ))
    };
    let mut stream = UnixStream::connect(socket).map_err(|e| unreachable(&e))?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|e| unreachable(&e))?;
    let mut line = pyjson::dumps(&Value::Dict(cmd.clone())).into_bytes();
    line.push(b'\n');
    stream.write_all(&line).map_err(|e| unreachable(&e))?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|e| unreachable(&e))?;

    let mut reply = Vec::new();
    let mut chunk = vec![0u8; 65536];
    loop {
        let n = stream.read(&mut chunk).map_err(|e| unreachable(&e))?;
        if n == 0 {
            break;
        }
        reply.extend_from_slice(&chunk[..n]);
        if reply.len() > max_bytes {
            return Err(HelperError::Transport(
                "response from apply-helper exceeded size limit".into(),
            ));
        }
    }
    let raw = strip(&reply);
    if raw.is_empty() {
        return Err(HelperError::Transport(
            "apply-helper closed the connection without a response".into(),
        ));
    }
    let text = match decode(raw) {
        Ok(text) => text,
        Err(name) => return Err(HelperError::Raised(name)),
    };
    match pyjson::loads(text.as_bytes()) {
        Ok(v) => Ok(v),
        Err(LoadError::Invalid) => Err(HelperError::Transport(format!(
            "invalid response from apply-helper: {}",
            repr_bytes(raw)
        ))),
        Err(LoadError::Crash(name)) => Err(HelperError::Raised(name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_repr() {
        assert_eq!(repr_bytes(b""), "b''");
        assert_eq!(repr_bytes(b"'"), "b\"'\"");
        assert_eq!(repr_bytes(b"'\""), "b'\\'\"'");
        assert_eq!(
            repr_bytes(b"\x00\x7f\x80\xff a"),
            "b'\\x00\\x7f\\x80\\xff a'"
        );
    }

    #[test]
    fn errno_text() {
        let e = io::Error::from_raw_os_error(2);
        assert_eq!(os_error_text(&e), "[Errno 2] No such file or directory");
    }
}
