//! Python's `ipaddress` for the text the sensor daemons read: what
//! `IPv4Address(text)` and `IPv6Address(text)` accept, what `str()` of
//! one writes, and `IPv4Network`'s membership test, as the recording
//! Python (3.13) has them.

/// `IPv4Address(text)`: four dot-separated decimal octets of one to
/// three ASCII digits, no leading zero, at most 255.
pub fn parse_ipv4(text: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = text.split('.');
    for slot in &mut out {
        let part = parts.next()?;
        if part.is_empty()
            || part.len() > 3
            || !part.bytes().all(|b| b.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
        {
            return None;
        }
        *slot = part.parse().ok()?;
    }
    parts.next().is_none().then_some(out)
}

pub fn ipv4_text(ip: [u8; 4]) -> String {
    let [a, b, c, d] = ip;
    format!("{a}.{b}.{c}.{d}")
}

/// An IPv6 address and its scope id (`fe80::1%eth1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6 {
    pub groups: [u16; 8],
    pub scope: Option<String>,
}

fn hextet(text: &str) -> Option<u16> {
    if text.is_empty() || text.len() > 4 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u16::from_str_radix(text, 16).ok()
}

/// `IPv6Address(text)` (`_split_scope_id`, `_ip_int_from_string`).
pub fn parse_ipv6(text: &str) -> Option<Ipv6> {
    if text.contains('/') {
        return None;
    }
    let (addr, scope) = match text.split_once('%') {
        None => (text, None),
        Some((_, "")) => return None,
        Some((_, s)) if s.contains('%') => return None,
        Some((a, s)) => (a, Some(s.to_owned())),
    };
    if addr.is_empty() || addr.chars().count() > 45 {
        return None;
    }
    let mut parts: Vec<String> = addr.split(':').map(str::to_owned).collect();
    if parts.len() < 3 {
        return None;
    }
    if parts.last().is_some_and(|p| p.contains('.')) {
        let v4 = parse_ipv4(&parts.pop()?)?;
        parts.push(format!("{:x}", u16::from_be_bytes([v4[0], v4[1]])));
        parts.push(format!("{:x}", u16::from_be_bytes([v4[2], v4[3]])));
    }
    if parts.len() > 9 {
        return None;
    }
    let mut skip = None;
    for (i, p) in parts.iter().enumerate().take(parts.len() - 1).skip(1) {
        if p.is_empty() {
            if skip.is_some() {
                return None;
            }
            skip = Some(i);
        }
    }
    let (hi, lo, skipped) = match skip {
        Some(at) => {
            let mut hi = at;
            let mut lo = parts.len() - at - 1;
            if parts[0].is_empty() {
                hi -= 1;
                if hi != 0 {
                    return None;
                }
            }
            if parts[parts.len() - 1].is_empty() {
                lo -= 1;
                if lo != 0 {
                    return None;
                }
            }
            let skipped = 8i32 - (hi + lo) as i32;
            if skipped < 1 {
                return None;
            }
            (hi, lo, skipped as usize)
        }
        None => {
            if parts.len() != 8 || parts[0].is_empty() || parts[7].is_empty() {
                return None;
            }
            (8, 0, 0)
        }
    };
    let mut groups = [0u16; 8];
    for i in 0..hi {
        groups[i] = hextet(&parts[i])?;
    }
    for j in 0..lo {
        groups[hi + skipped + j] = hextet(&parts[parts.len() - lo + j])?;
    }
    Some(Ipv6 { groups, scope })
}

/// `str(IPv6Address)`: lower-case hex, the longest run of two or more
/// zero groups (the first of equal runs) as "::", an IPv4-mapped
/// address with its dotted tail, then the scope id.
pub fn ipv6_text(ip: &Ipv6) -> String {
    let g = &ip.groups;
    let mut out = if g[..5].iter().all(|&x| x == 0) && g[5] == 0xffff {
        let [a, b] = g[6].to_be_bytes();
        let [c, d] = g[7].to_be_bytes();
        format!("::ffff:{a}.{b}.{c}.{d}")
    } else {
        compressed(g)
    };
    if let Some(scope) = &ip.scope {
        out.push('%');
        out.push_str(scope);
    }
    out
}

fn compressed(groups: &[u16; 8]) -> String {
    let (mut best_start, mut best_len) = (0usize, 0usize);
    let mut i = 0;
    while i < 8 {
        if groups[i] == 0 {
            let start = i;
            while i < 8 && groups[i] == 0 {
                i += 1;
            }
            if i - start > best_len {
                (best_start, best_len) = (start, i - start);
            }
        } else {
            i += 1;
        }
    }
    let hex = |g: &[u16]| {
        g.iter()
            .map(|x| format!("{x:x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    if best_len < 2 {
        return hex(groups);
    }
    format!(
        "{}::{}",
        hex(&groups[..best_start]),
        hex(&groups[best_start + best_len..])
    )
}

/// `str(IPv6Address(text))`, or `None` where Python raises.
pub fn ipv6_str(text: &str) -> Option<String> {
    parse_ipv6(text).map(|ip| ipv6_text(&ip))
}

/// An `IPv4Network` ("10.0.0.0/24").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Net {
    pub addr: u32,
    pub prefix: u8,
}

impl Ipv4Net {
    /// A network as `str(IPv4Network)` writes it.
    pub fn parse(text: &str) -> Option<Self> {
        let (a, p) = text.split_once('/')?;
        let prefix: u8 = p.parse().ok().filter(|&p| p <= 32)?;
        let addr = u32::from_be_bytes(parse_ipv4(a)?);
        let net = Self { addr, prefix };
        (addr & net.mask() == addr).then_some(net)
    }

    fn mask(self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix)
        }
    }

    pub fn contains(self, ip: [u8; 4]) -> bool {
        u32::from_be_bytes(ip) & self.mask() == self.addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_as_python() {
        for (text, want) in [
            ("::ffff:1.2.3.4", Some("::ffff:1.2.3.4")),
            ("::ffff:102:304", Some("::ffff:1.2.3.4")),
            ("fe80::1%eth1", Some("fe80::1%eth1")),
            ("::1.2.3.4", Some("::102:304")),
            ("FD00:0::B", Some("fd00::b")),
            ("1:2:3:4:5:6:7::", Some("1:2:3:4:5:6:7:0")),
            ("::", Some("::")),
            ("1:0:0:2:0:0:0:3", Some("1:0:0:2::3")),
            ("1:0:0:2:0:0:3:4", Some("1::2:0:0:3:4")),
            ("1::2::3", None),
            (":1::", None),
            ("1:2", None),
            ("fe80::1%", None),
            ("fe80::1%a%b", None),
            ("12345::", None),
            ("::g", None),
            ("1:2:3:4:5:6:7:8:9", None),
            ("1::2:3:4:5:6:7:8", None),
            ("::1/128", None),
        ] {
            assert_eq!(ipv6_str(text).as_deref(), want, "{text}");
        }
    }

    #[test]
    fn ipv4_networks() {
        let n = Ipv4Net::parse("10.0.0.128/25").unwrap();
        assert!(n.contains([10, 0, 0, 200]));
        assert!(!n.contains([10, 0, 0, 1]));
        assert!(Ipv4Net::parse("10.0.0.1/24").is_none());
        assert!(Ipv4Net::parse("0.0.0.0/0").unwrap().contains([1, 2, 3, 4]));
        assert_eq!(parse_ipv4("010.0.0.1"), None);
    }
}
