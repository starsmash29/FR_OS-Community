//! dnsmasq's query log (1.x's `frfw.adblock.dns_service.dnsmasq_message`):
//! with `log-facility` set to a file, each line starts with a timestamp
//! and `dnsmasq[pid]: `; the readers want the text after it.

use crate::pytext::is_decimal;

fn digits(chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>, at_least: usize) -> bool {
    let mut n = 0;
    while chars.peek().is_some_and(|&(_, c)| is_decimal(c)) {
        chars.next();
        n += 1;
    }
    n >= at_least
}

fn exactly(chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>, text: &str) -> bool {
    text.chars()
        .all(|want| chars.next().is_some_and(|(_, c)| c == want))
}

fn one(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    ok: impl Fn(char) -> bool,
) -> bool {
    chars.next().is_some_and(|(_, c)| ok(c))
}

/// The line without dnsmasq's `Mon dd hh:mm:ss dnsmasq[pid]: ` prefix,
/// or the line itself when it has none. As 1.x's
/// `^[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d dnsmasq\[\d+\]: (.*)\Z` (re.S),
/// where `\d` is any Unicode decimal digit.
pub fn dnsmasq_message(line: &str) -> &str {
    let mut c = line.char_indices().peekable();
    let d = is_decimal;
    let matched = one(&mut c, |x| x.is_ascii_uppercase())
        && one(&mut c, |x| x.is_ascii_lowercase())
        && one(&mut c, |x| x.is_ascii_lowercase())
        && exactly(&mut c, " ")
        && one(&mut c, |x| x == ' ' || d(x))
        && one(&mut c, d)
        && exactly(&mut c, " ")
        && one(&mut c, d)
        && one(&mut c, d)
        && exactly(&mut c, ":")
        && one(&mut c, d)
        && one(&mut c, d)
        && exactly(&mut c, ":")
        && one(&mut c, d)
        && one(&mut c, d)
        && exactly(&mut c, " dnsmasq[")
        && digits(&mut c, 1)
        && exactly(&mut c, "]: ");
    if !matched {
        return line;
    }
    match c.peek() {
        Some(&(i, _)) => &line[i..],
        None => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix() {
        assert_eq!(dnsmasq_message("Nov  3 10:00:00 dnsmasq[12]: 2 x"), "2 x");
        assert_eq!(dnsmasq_message("Nov 13 10:00:00 dnsmasq[1]: "), "");
        assert_eq!(
            dnsmasq_message("nov 13 10:00:00 dnsmasq[1]: x"),
            "nov 13 10:00:00 dnsmasq[1]: x"
        );
        assert_eq!(
            dnsmasq_message("Nov 13 10:00:00 dnsmasq[]: x"),
            "Nov 13 10:00:00 dnsmasq[]: x"
        );
    }
}
