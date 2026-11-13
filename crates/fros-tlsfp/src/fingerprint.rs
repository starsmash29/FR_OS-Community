//! JA3 and JA4 TLS client fingerprints (1.x's `frfw.tlsfp.fingerprint`,
//! phase 19).
//!
//! Both summarize *how* a client speaks TLS -- which cipher suites,
//! extensions, groups and signature algorithms its TLS library offers,
//! in what order -- without decrypting anything: all of it is cleartext
//! in the ClientHello.
//!
//! - JA3 (Salesforce, BSD 3-Clause): MD5 of the raw lists *in wire
//!   order*. Browsers shuffle their extension order per connection, so a
//!   browser's JA3 changes constantly -- which is why JA4 exists.
//! - JA4 (FoxIO, BSD 3-Clause -- unlike the other JA4+ methods, which
//!   are under the non-permissive FoxIO License and deliberately not
//!   implemented): sorted lists, so extension shuffling doesn't change
//!   it, plus a readable prefix. Implemented from the published
//!   specification, as 1.x's is, and held to 1.x's output.

use std::fmt::Write as _;

use md5::{Digest as _, Md5};
use sha2::Sha256;

use crate::clienthello::{ClientHello, EXT_ALPN, EXT_SERVER_NAME, is_grease};

fn tls_version(version: u16) -> &'static str {
    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xFEFF => "d1",
        0xFEFD => "d2",
        0xFEFC => "d3",
        _ => "00",
    }
}

fn no_grease(values: &[u16]) -> Vec<u16> {
    values.iter().copied().filter(|&v| !is_grease(v)).collect()
}

fn dashed<T: ToString>(values: &[T]) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("-")
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

pub fn ja3_string(hello: &ClientHello) -> String {
    [
        dashed(&[hello.legacy_version]),
        dashed(&no_grease(&hello.ciphers)),
        dashed(&no_grease(&hello.extensions)),
        dashed(&no_grease(&hello.supported_groups)),
        dashed(&hello.ec_point_formats),
    ]
    .join(",")
}

pub fn ja3(hello: &ClientHello) -> String {
    hex_digest(&Md5::digest(ja3_string(hello).as_bytes()))
}

fn alpn_chars(alpn: &[Vec<u8>]) -> String {
    let Some(first) = alpn.first() else {
        return "00".into();
    };
    let (Some(&a), Some(&b)) = (first.first(), first.last()) else {
        return "00".into();
    };
    if a.is_ascii_alphanumeric() && b.is_ascii_alphanumeric() {
        return [char::from(a), char::from(b)].iter().collect();
    }
    let hexed = hex_digest(first);
    let mut out = String::new();
    out.extend(hexed.chars().next());
    out.extend(hexed.chars().last());
    out
}

fn sha12(text: &str) -> String {
    let mut digest = hex_digest(&Sha256::digest(text.as_bytes()));
    digest.truncate(12);
    digest
}

fn hex4_list(values: impl IntoIterator<Item = u16>) -> String {
    values
        .into_iter()
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// (a, raw cipher list, raw extension+sigalg list) -- `ja4_r` style.
/// `transport` is "t" (TCP), "q" (QUIC) or "d" (DTLS).
pub fn ja4_parts(hello: &ClientHello, transport: &str) -> (String, String, String) {
    let versions = no_grease(&hello.supported_versions);
    let version = versions
        .iter()
        .copied()
        .max()
        .unwrap_or(hello.legacy_version);
    let mut ciphers = no_grease(&hello.ciphers);
    let mut extensions = no_grease(&hello.extensions);
    let a = format!(
        "{transport}{}{}{:02}{:02}{}",
        tls_version(version),
        if extensions.contains(&EXT_SERVER_NAME) {
            'd'
        } else {
            'i'
        },
        ciphers.len().min(99),
        extensions.len().min(99),
        alpn_chars(&hello.alpn),
    );
    ciphers.sort_unstable();
    extensions.sort_unstable();
    let cipher_list = hex4_list(ciphers);
    let ext_list = hex4_list(
        extensions
            .into_iter()
            .filter(|&e| e != EXT_SERVER_NAME && e != EXT_ALPN),
    );
    let sigalgs = hex4_list(no_grease(&hello.signature_algorithms));
    let c = if sigalgs.is_empty() {
        ext_list
    } else {
        format!("{ext_list}_{sigalgs}")
    };
    (a, cipher_list, c)
}

pub fn ja4(hello: &ClientHello, transport: &str) -> String {
    const ZEROS: &str = "000000000000";
    let (a, cipher_list, ext_list) = ja4_parts(hello, transport);
    let b = if cipher_list.is_empty() {
        ZEROS.to_string()
    } else {
        sha12(&cipher_list)
    };
    let extensions_only = ext_list.split('_').next().unwrap_or_default();
    let c = if extensions_only.is_empty() {
        ZEROS.to_string()
    } else {
        sha12(&ext_list)
    };
    format!("{a}_{b}_{c}")
}
