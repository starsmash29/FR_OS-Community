//! Strict, bounded parsing of a TLS ClientHello (1.x's
//! `frfw.tlsfp.clienthello`, phase 19).
//!
//! The input is packet data any LAN host sends, so every length is
//! checked against what is actually there and anything malformed is a
//! [`ParseError`] -- never a panic, never an unbounded loop. Only the
//! fields fingerprinting needs are kept. The error texts are 1.x's,
//! word for word (the differential test compares them).

use std::fmt;

pub const TLS_HANDSHAKE: u8 = 0x16;
pub const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

/// A ClientHello is one handshake message; its 24-bit length allows
/// 16 MiB, but real ones are a few KiB. Anything larger is not worth
/// buffering.
pub const MAX_HELLO_BYTES: usize = 16 * 1024;

pub const EXT_SERVER_NAME: u16 = 0x0000;
pub const EXT_SUPPORTED_GROUPS: u16 = 0x000A;
pub const EXT_EC_POINT_FORMATS: u16 = 0x000B;
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000D;
pub const EXT_ALPN: u16 = 0x0010;
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002B;

/// At most this many extensions: a hello with more is refused, as in 1.x.
const MAX_EXTENSIONS: usize = 256;

/// The largest TLS record body 1.x accepts (2^14 plus the 2048 bytes
/// RFC 8446 allows a compressed or protected record).
const MAX_RECORD_BYTES: usize = 16384 + 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl ParseError {
    fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseError {}

/// RFC 8701 GREASE values: 0x0a0a, 0x1a1a, ... 0xfafa.
pub fn is_grease(value: u16) -> bool {
    (value & 0x0F0F) == 0x0A0A && (value >> 8) == (value & 0xFF)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub ciphers: Vec<u16>,
    /// In wire order.
    pub extensions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub alpn: Vec<Vec<u8>>,
    /// The first host name, each byte outside ASCII read as U+FFFD
    /// (1.x decodes it as ASCII with errors="replace").
    pub server_name: Option<String>,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    what: &'a str,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8], what: &'a str) -> Self {
        Self { data, pos: 0, what }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.data.len())
            .ok_or_else(|| ParseError::new(format!("{}: truncated", self.what)))?;
        let chunk = &self.data[self.pos..end];
        self.pos = end;
        Ok(chunk)
    }

    fn u8(&mut self) -> Result<u8, ParseError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ParseError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Result<usize, ParseError> {
        let b = self.take(3)?;
        Ok((usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]))
    }

    fn vec8(&mut self) -> Result<&'a [u8], ParseError> {
        let n = self.u8()?;
        self.take(usize::from(n))
    }

    fn vec16(&mut self) -> Result<&'a [u8], ParseError> {
        let n = self.u16()?;
        self.take(usize::from(n))
    }

    fn done(&self) -> bool {
        self.pos == self.data.len()
    }
}

fn u16_list(data: &[u8], what: &str) -> Result<Vec<u16>, ParseError> {
    if !data.len().is_multiple_of(2) {
        return Err(ParseError::new(format!("{what}: odd length")));
    }
    Ok(data
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect())
}

/// The first handshake message from the start of a client's TLS byte
/// stream, reassembled across TLS records if it spans several. `None`
/// if more bytes are needed; an error if this isn't a TLS handshake.
pub fn handshake_from_records(stream: &[u8]) -> Result<Option<Vec<u8>>, ParseError> {
    let mut body: Vec<u8> = Vec::new();
    let mut pos = 0usize;
    loop {
        if body.len() >= 4 {
            let needed = 4
                + ((usize::from(body[1]) << 16)
                    | (usize::from(body[2]) << 8)
                    | usize::from(body[3]));
            if needed > MAX_HELLO_BYTES {
                return Err(ParseError::new("handshake message too large"));
            }
            if body.len() >= needed {
                body.truncate(needed);
                return Ok(Some(body));
            }
        }
        let Some(header) = stream.get(pos..pos + 5) else {
            return Ok(None);
        };
        let content_type = header[0];
        let version_major = header[1];
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if content_type != TLS_HANDSHAKE || version_major != 0x03 {
            return Err(ParseError::new("not a TLS handshake record"));
        }
        if length == 0 || length > MAX_RECORD_BYTES {
            return Err(ParseError::new("bad TLS record length"));
        }
        let start = pos + 5;
        let Some(record) = stream.get(start..start + length) else {
            // Take what is there; the rest comes with later segments.
            if body.is_empty()
                && stream
                    .get(start)
                    .is_some_and(|&t| t != HANDSHAKE_CLIENT_HELLO)
            {
                return Err(ParseError::new("not a ClientHello"));
            }
            return Ok(None);
        };
        body.extend_from_slice(record);
        pos = start + length;
        if body.first().is_some_and(|&t| t != HANDSHAKE_CLIENT_HELLO) {
            return Err(ParseError::new("not a ClientHello"));
        }
    }
}

/// Parse one complete handshake message (type byte first). Bytes after
/// the message, or after the extensions block inside it, are ignored,
/// as in 1.x.
pub fn parse_client_hello(message: &[u8]) -> Result<ClientHello, ParseError> {
    let mut r = Reader::new(message, "ClientHello");
    if r.u8()? != HANDSHAKE_CLIENT_HELLO {
        return Err(ParseError::new("not a ClientHello"));
    }
    let length = r.u24()?;
    let mut body = Reader::new(r.take(length)?, "ClientHello body");
    let legacy_version = body.u16()?;
    body.take(32)?; // random
    body.vec8()?; // legacy_session_id
    let ciphers = u16_list(body.vec16()?, "cipher_suites")?;
    body.vec8()?; // legacy_compression_methods
    let mut hello = ClientHello {
        legacy_version,
        ciphers,
        ..ClientHello::default()
    };
    if body.done() {
        // A ClientHello may legally carry no extensions.
        return Ok(hello);
    }
    let mut exts = Reader::new(body.vec16()?, "extensions");
    while !exts.done() {
        let ext_type = exts.u16()?;
        let data = exts.vec16()?;
        hello.extensions.push(ext_type);
        if hello.extensions.len() > MAX_EXTENSIONS {
            return Err(ParseError::new("too many extensions"));
        }
        // The outer structure is intact, only this extension's body may
        // be odd (e.g. empty): keep its type -- it still counts for the
        // fingerprint -- and ignore its contents, as Wireshark does.
        // What was read before the odd part is kept, as in 1.x.
        let _ = parse_extension(&mut hello, ext_type, data);
    }
    Ok(hello)
}

fn ascii_replace(name: &[u8]) -> String {
    name.iter()
        .map(|&b| {
            if b.is_ascii() {
                char::from(b)
            } else {
                '\u{FFFD}'
            }
        })
        .collect()
}

fn parse_extension(hello: &mut ClientHello, ext_type: u16, data: &[u8]) -> Result<(), ParseError> {
    let what = format!("extension 0x{ext_type:04x}");
    match ext_type {
        EXT_SERVER_NAME if !data.is_empty() => {
            let mut names = Reader::new(Reader::new(data, &what).vec16()?, &what);
            while !names.done() {
                let name_type = names.u8()?;
                let name = names.vec16()?;
                if name_type == 0 && hello.server_name.is_none() {
                    hello.server_name = Some(ascii_replace(name));
                }
            }
        }
        EXT_SUPPORTED_GROUPS => {
            hello.supported_groups = u16_list(Reader::new(data, &what).vec16()?, &what)?;
        }
        EXT_EC_POINT_FORMATS => {
            hello.ec_point_formats = Reader::new(data, &what).vec8()?.to_vec();
        }
        EXT_SIGNATURE_ALGORITHMS => {
            hello.signature_algorithms = u16_list(Reader::new(data, &what).vec16()?, &what)?;
        }
        EXT_SUPPORTED_VERSIONS => {
            hello.supported_versions = u16_list(Reader::new(data, &what).vec8()?, &what)?;
        }
        EXT_ALPN if !data.is_empty() => {
            let mut protocols = Reader::new(Reader::new(data, &what).vec16()?, &what);
            while !protocols.done() {
                hello.alpn.push(protocols.vec8()?.to_vec());
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_values() {
        let all: Vec<u16> = (0..=u16::MAX).filter(|&v| is_grease(v)).collect();
        assert_eq!(all.len(), 16);
        assert!(!is_grease(0x0A1A) && !is_grease(0x0B0B));
    }

    #[test]
    fn empty_input_is_truncated() {
        assert_eq!(
            parse_client_hello(&[]).unwrap_err().0,
            "ClientHello: truncated"
        );
        assert_eq!(handshake_from_records(&[]), Ok(None));
    }
}
