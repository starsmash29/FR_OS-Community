//! Python's text rules where they differ from Rust's: what counts as
//! whitespace (`str.isspace` includes \x1c-\x1f) and as a digit (`re`'s
//! `\d` is any Unicode decimal digit), and `repr`/`str` of a JSON value
//! (1.x puts both in messages and keys). The Unicode classes come from
//! the Python that records the reference (unicode_tables.rs).

use crate::pyjson::{Value, float_repr};
use crate::unicode_tables::{DECIMAL, NOT_PRINTABLE};

fn in_table(table: &[(u32, u32)], c: char) -> bool {
    let c = u32::from(c);
    table
        .binary_search_by(|&(lo, hi)| {
            if hi < c {
                std::cmp::Ordering::Less
            } else if lo > c {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// `str.isspace()` of one character, which is also `re`'s `\s`.
pub fn is_space(c: char) -> bool {
    matches!(
        c,
        '\t'..='\r'
            | '\x1c'..=' '
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

/// `re`'s `\d`: a Unicode decimal digit (`str.isdecimal()`).
pub fn is_decimal(c: char) -> bool {
    in_table(DECIMAL, c)
}

/// The value of a Unicode decimal digit (`unicodedata.decimal`): every
/// range of the table is whole runs of ten, 0 to 9.
pub fn decimal_value(c: char) -> Option<u32> {
    let code = u32::from(c);
    DECIMAL
        .iter()
        .find(|&&(lo, hi)| lo <= code && code <= hi)
        .map(|&(lo, _)| (code - lo) % 10)
}

/// `str.isprintable()` of one character.
pub fn is_printable(c: char) -> bool {
    !in_table(NOT_PRINTABLE, c)
}

/// `str.strip()` with no argument.
pub fn strip(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// `str.lower()`. Rust's full lowercase mapping, final sigma included,
/// as Python's; the two can differ only on characters newer than the
/// recording Python's Unicode.
pub fn lower(s: &str) -> String {
    s.to_lowercase()
}

/// `repr(s)` of a str.
pub fn repr_str(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if c < ' ' || c == '\x7f' => out.push_str(&format!("\\x{:02x}", u32::from(c))),
            c if c.is_ascii() || is_printable(c) => out.push(c),
            c if u32::from(c) <= 0xff => out.push_str(&format!("\\x{:02x}", u32::from(c))),
            c if u32::from(c) <= 0xffff => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push_str(&format!("\\U{:08x}", u32::from(c))),
        }
    }
    out.push(quote);
    out
}

enum Piece<'a> {
    Value(&'a Value),
    Text(&'static str),
    Key(&'a str),
}

/// `repr(x)` of a JSON value; walked with a stack of its own, so a
/// deeply nested value can't exhaust the thread's stack.
pub fn repr(value: &Value) -> String {
    let mut out = String::new();
    let mut stack = vec![Piece::Value(value)];
    while let Some(piece) = stack.pop() {
        match piece {
            Piece::Text(t) => out.push_str(t),
            Piece::Key(k) => {
                out.push_str(&repr_str(k));
                out.push_str(": ");
            }
            Piece::Value(v) => match v {
                Value::Null => out.push_str("None"),
                Value::Bool(true) => out.push_str("True"),
                Value::Bool(false) => out.push_str("False"),
                Value::Int(s) => out.push_str(s),
                Value::Float(f) => out.push_str(&float_repr(*f)),
                Value::Str(s) => out.push_str(&repr_str(s)),
                Value::List(items) => {
                    out.push('[');
                    stack.push(Piece::Text("]"));
                    for (i, item) in items.iter().enumerate().rev() {
                        stack.push(Piece::Value(item));
                        if i > 0 {
                            stack.push(Piece::Text(", "));
                        }
                    }
                }
                Value::Dict(d) => {
                    out.push('{');
                    stack.push(Piece::Text("}"));
                    for (i, (k, item)) in d.0.iter().enumerate().rev() {
                        stack.push(Piece::Value(item));
                        stack.push(Piece::Key(k));
                        if i > 0 {
                            stack.push(Piece::Text(", "));
                        }
                    }
                }
            },
        }
    }
    out
}

/// `str(x)` of any JSON value: a str as it is, everything else as
/// `repr` writes it.
pub fn str_of(value: &Value) -> String {
    match value {
        Value::Str(s) => s.clone(),
        other => repr(other),
    }
}

/// Python's name for the type of a JSON value, as error texts use it.
pub fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Int(_) => "int",
        Value::Float(_) => "float",
        Value::Str(_) => "str",
        Value::List(_) => "list",
        Value::Dict(_) => "dict",
    }
}

/// `str.splitlines()`: lines end at \n, \r, \r\n, \v, \f, \x1c-\x1e,
/// \x85, U+2028 and U+2029, and a final terminator adds no empty line.
pub fn splitlines(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let breaks = matches!(
            c,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if !breaks {
            continue;
        }
        out.push(&text[start..i]);
        let mut next = i + c.len_utf8();
        if c == '\r'
            && let Some(&(j, '\n')) = chars.peek()
        {
            chars.next();
            next = j + 1;
        }
        start = next;
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

/// `str.split()` with no argument: runs of whitespace separate fields.
pub fn split_fields(text: &str) -> Vec<&str> {
    text.split(is_space).filter(|f| !f.is_empty()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reprs() {
        assert_eq!(repr_str("a'b"), "\"a'b\"");
        assert_eq!(repr_str("a'\"b"), "'a\\'\"b'");
        assert_eq!(
            repr_str("\u{85}\u{e9}\u{200b}\u{1f600}\u{e0001}"),
            "'\\x85\u{e9}\\u200b\u{1f600}\\U000e0001'"
        );
        assert!(is_space('\x1c') && !is_space('\u{200b}'));
        assert!(is_decimal('\u{661}') && !is_decimal('\u{b2}'));
        assert_eq!(
            splitlines("a\r\nb\rc\x1cd\n\ne\n"),
            ["a", "b", "c", "d", "", "e"]
        );
        assert_eq!(split_fields(" a \t b\x1fc "), ["a", "b", "c"]);
    }
}
