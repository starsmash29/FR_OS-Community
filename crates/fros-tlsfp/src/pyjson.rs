//! JSON as 1.x's Python reads and writes it: `json.loads` (NaN and
//! Infinity taken, integers of any size up to Python's 4,300-digit
//! limit, a repeated key's last value kept in its first place) and
//! `json.dumps` with its defaults (", " and ": ", every non-ASCII
//! character escaped, floats as `repr` writes them). The inventory's
//! state file is this JSON, and the differential test compares it
//! byte for byte; serde_json reads and writes another dialect.
//!
//! Plus the Python conversions 1.x's restore applies to what it read
//! (`float(x)`, `int(x)`, `str(x)`, truthiness), with the exception
//! each one raises, because which exception decides whether 1.x skips a
//! row or gives up on the file.

use std::collections::HashMap;
use std::fmt::Write as _;

/// Python's limit on the digits of an int read from text
/// (`sys.int_info.str_digits_check_threshold`).
const MAX_INT_DIGITS: usize = 4300;

/// Containers nested deeper than this are refused as Python's own
/// recursion limit refuses them (a RecursionError 1.x doesn't catch):
/// everything that walks a value here, dropping it included, recurses.
pub const MAX_DEPTH: usize = 10_000;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// An int of any size, as its canonical decimal text ("-12", "0").
    Int(String),
    Float(f64),
    Str(String),
    List(Vec<Value>),
    Dict(Dict),
}

/// A dict in insertion order. Keys are unique.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Dict(pub Vec<(String, Value)>);

impl Dict {
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Like a dict assignment: a key already there keeps its place.
    pub fn insert(&mut self, key: String, value: Value) {
        if let Some(slot) = self.0.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value;
        } else {
            self.0.push((key, value));
        }
    }
}

impl Value {
    pub fn int(n: i64) -> Self {
        Self::Int(n.to_string())
    }

    /// Python's `bool(x)`.
    pub fn truthy(&self) -> bool {
        match self {
            Self::Null => false,
            Self::Bool(b) => *b,
            Self::Int(s) => s != "0",
            Self::Float(f) => *f != 0.0,
            Self::Str(s) => !s.is_empty(),
            Self::List(l) => !l.is_empty(),
            Self::Dict(d) => !d.0.is_empty(),
        }
    }
}

/// Why `json.loads` (or reading the file before it) failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// `json.JSONDecodeError`: 1.x reads the file as missing.
    Invalid,
    /// Not UTF-8 (`UnicodeDecodeError`), an int over 4,300 digits
    /// (`ValueError`), nesting past `MAX_DEPTH` (`RecursionError`):
    /// exceptions 1.x's daemon does not catch.
    Crash(&'static str),
}

/// `json.loads(text)` of a file's bytes. A lone surrogate escape
/// (`"\ud83d"`) becomes U+FFFD: Python keeps it, but a Rust string
/// can't hold one (testdata/reference/decisions.md).
pub fn loads(raw: &[u8]) -> Result<Value, LoadError> {
    let text = std::str::from_utf8(raw).map_err(|_| LoadError::Crash("UnicodeDecodeError"))?;
    let mut p = Parser {
        s: text.as_bytes(),
        pos: 0,
    };
    p.ws();
    let value = p.value()?;
    p.ws();
    if p.pos != p.s.len() {
        return Err(LoadError::Invalid);
    }
    Ok(value)
}

enum Frame {
    List(Vec<Value>),
    /// The dict so far, where each key sits in it (a state file's dicts
    /// hold thousands of keys), and the key whose value comes next.
    Dict(Dict, HashMap<String, usize>, String),
}

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn eat(&mut self, literal: &[u8]) -> bool {
        if self.s.get(self.pos..self.pos + literal.len()) == Some(literal) {
            self.pos += literal.len();
            true
        } else {
            false
        }
    }

    /// One value. Containers are parsed with an explicit stack, not
    /// recursion, and their depth is capped at `MAX_DEPTH`.
    fn value(&mut self) -> Result<Value, LoadError> {
        let mut stack: Vec<Frame> = Vec::new();
        'next: loop {
            // Parse a scalar, or open a container.
            let mut value = match self.peek() {
                Some(b'[' | b'{') if stack.len() >= MAX_DEPTH => {
                    return Err(LoadError::Crash("RecursionError"));
                }
                Some(b'[') => {
                    self.pos += 1;
                    self.ws();
                    if self.peek() == Some(b']') {
                        self.pos += 1;
                        Value::List(Vec::new())
                    } else {
                        stack.push(Frame::List(Vec::new()));
                        continue 'next;
                    }
                }
                Some(b'{') => {
                    self.pos += 1;
                    self.ws();
                    if self.peek() == Some(b'}') {
                        self.pos += 1;
                        Value::Dict(Dict::default())
                    } else {
                        let key = self.key()?;
                        stack.push(Frame::Dict(Dict::default(), HashMap::new(), key));
                        continue 'next;
                    }
                }
                _ => self.scalar()?,
            };
            // Hand the value to the containers it closes.
            loop {
                match stack.last_mut() {
                    None => return Ok(value),
                    Some(Frame::List(items)) => {
                        items.push(value);
                        self.ws();
                        match self.peek() {
                            Some(b',') => {
                                self.pos += 1;
                                self.ws();
                                continue 'next;
                            }
                            Some(b']') => self.pos += 1,
                            _ => return Err(LoadError::Invalid),
                        }
                    }
                    Some(Frame::Dict(dict, index, key)) => {
                        // A repeated key keeps its first place, last value.
                        let key = std::mem::take(key);
                        if let Some(slot) = index.get(&key).and_then(|&i| dict.0.get_mut(i)) {
                            slot.1 = value;
                        } else {
                            index.insert(key.clone(), dict.0.len());
                            dict.0.push((key, value));
                        }
                        self.ws();
                        match self.peek() {
                            Some(b',') => {
                                self.pos += 1;
                                self.ws();
                                let next = self.key()?;
                                if let Some(Frame::Dict(_, _, key)) = stack.last_mut() {
                                    *key = next;
                                }
                                continue 'next;
                            }
                            Some(b'}') => self.pos += 1,
                            _ => return Err(LoadError::Invalid),
                        }
                    }
                }
                value = match stack.pop() {
                    Some(Frame::List(items)) => Value::List(items),
                    Some(Frame::Dict(dict, _, _)) => Value::Dict(dict),
                    None => return Err(LoadError::Invalid),
                };
            }
        }
    }

    /// `"key"`, whitespace, `:`, whitespace.
    fn key(&mut self) -> Result<String, LoadError> {
        if self.peek() != Some(b'"') {
            return Err(LoadError::Invalid);
        }
        self.pos += 1;
        let key = self.string()?;
        self.ws();
        if self.peek() != Some(b':') {
            return Err(LoadError::Invalid);
        }
        self.pos += 1;
        self.ws();
        Ok(key)
    }

    fn scalar(&mut self) -> Result<Value, LoadError> {
        match self.peek() {
            Some(b'"') => {
                self.pos += 1;
                Ok(Value::Str(self.string()?))
            }
            Some(b'n') if self.eat(b"null") => Ok(Value::Null),
            Some(b't') if self.eat(b"true") => Ok(Value::Bool(true)),
            Some(b'f') if self.eat(b"false") => Ok(Value::Bool(false)),
            Some(b'N') if self.eat(b"NaN") => Ok(Value::Float(f64::NAN)),
            Some(b'I') if self.eat(b"Infinity") => Ok(Value::Float(f64::INFINITY)),
            Some(b'-') if self.eat(b"-Infinity") => Ok(Value::Float(f64::NEG_INFINITY)),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(LoadError::Invalid),
        }
    }

    /// `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?`, as Python's
    /// scanner matches it: a fraction or exponent that doesn't complete
    /// is left unread (and then fails as extra data).
    fn number(&mut self) -> Result<Value, LoadError> {
        let start = self.pos;
        let digits = |s: &[u8], mut i: usize| {
            while s.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
            i
        };
        let mut i = start;
        if self.s.get(i) == Some(&b'-') {
            i += 1;
        }
        match self.s.get(i) {
            Some(b'0') => i += 1,
            Some(b'1'..=b'9') => i = digits(self.s, i),
            _ => return Err(LoadError::Invalid),
        }
        let int_end = i;
        let mut is_float = false;
        if self.s.get(i) == Some(&b'.') && self.s.get(i + 1).is_some_and(u8::is_ascii_digit) {
            i = digits(self.s, i + 1);
            is_float = true;
        }
        if matches!(self.s.get(i), Some(b'e' | b'E')) {
            let mut j = i + 1;
            if matches!(self.s.get(j), Some(b'+' | b'-')) {
                j += 1;
            }
            if self.s.get(j).is_some_and(u8::is_ascii_digit) {
                i = digits(self.s, j);
                is_float = true;
            }
        }
        self.pos = i;
        let text = std::str::from_utf8(&self.s[start..i]).map_err(|_| LoadError::Invalid)?;
        if is_float {
            return text
                .parse::<f64>()
                .map(Value::Float)
                .map_err(|_| LoadError::Invalid);
        }
        let negative = text.starts_with('-');
        if int_end - start - usize::from(negative) > MAX_INT_DIGITS {
            return Err(LoadError::Crash("ValueError"));
        }
        Ok(Value::Int(canonical_int(
            negative,
            text.trim_start_matches('-'),
        )))
    }

    /// The rest of a string whose opening quote was read.
    fn string(&mut self) -> Result<String, LoadError> {
        let mut out = String::new();
        loop {
            let start = self.pos;
            while self
                .peek()
                .is_some_and(|b| b != b'"' && b != b'\\' && b >= 0x20)
            {
                self.pos += 1;
            }
            // The input is valid UTF-8 and the stop bytes are ASCII, so
            // the run is too.
            out.push_str(
                std::str::from_utf8(&self.s[start..self.pos]).map_err(|_| LoadError::Invalid)?,
            );
            match self.peek() {
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    let escape = self.peek().ok_or(LoadError::Invalid)?;
                    self.pos += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        _ => return Err(LoadError::Invalid),
                    }
                }
                // An unescaped control character, or the end of the text.
                _ => return Err(LoadError::Invalid),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, LoadError> {
        let digits = self
            .s
            .get(self.pos..self.pos + 4)
            .ok_or(LoadError::Invalid)?;
        let mut value = 0u32;
        for &d in digits {
            value = value * 16 + char::from(d).to_digit(16).ok_or(LoadError::Invalid)?;
        }
        self.pos += 4;
        Ok(value)
    }

    /// After `\u`: one code point, joining a surrogate pair written as
    /// two escapes, as Python's scanner does.
    fn unicode_escape(&mut self) -> Result<char, LoadError> {
        let c = self.hex4()?;
        if (0xD800..=0xDBFF).contains(&c) && self.s.get(self.pos..self.pos + 2) == Some(b"\\u") {
            let save = self.pos;
            self.pos += 2;
            let low = self.hex4()?;
            if (0xDC00..=0xDFFF).contains(&low) {
                let joined = 0x10000 + ((c - 0xD800) << 10) + (low - 0xDC00);
                return Ok(char::from_u32(joined).unwrap_or('\u{FFFD}'));
            }
            self.pos = save;
        }
        Ok(char::from_u32(c).unwrap_or('\u{FFFD}'))
    }
}

fn canonical_int(negative: bool, digits: &str) -> String {
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        "0".into()
    } else if negative {
        format!("-{digits}")
    } else {
        digits.to_string()
    }
}

/// `json.dumps(value)` with Python's defaults.
pub fn dumps(value: &Value) -> String {
    let mut out = String::new();
    dump_into(&mut out, value);
    out
}

fn dump_into(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(s) => out.push_str(s),
        Value::Float(f) => {
            if f.is_nan() {
                out.push_str("NaN");
            } else if f.is_infinite() {
                out.push_str(if *f > 0.0 { "Infinity" } else { "-Infinity" });
            } else {
                out.push_str(&float_repr(*f));
            }
        }
        Value::Str(s) => dump_str(out, s),
        Value::List(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                dump_into(out, item);
            }
            out.push(']');
        }
        Value::Dict(dict) => {
            out.push('{');
            for (i, (k, v)) in dict.0.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                dump_str(out, k);
                out.push_str(": ");
                dump_into(out, v);
            }
            out.push('}');
        }
    }
}

/// A string as `json.dumps` writes it with `ensure_ascii`: everything
/// outside space..'~' escaped, astral characters as surrogate pairs.
fn dump_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
}

/// Python's `repr(float)` (and `str(float)`): the shortest digits that
/// read back to the same float, written in fixed notation unless the
/// exponent is below -4 or at least 16.
pub fn float_repr(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf".into() } else { "-inf".into() };
    }
    // Rust's `{:e}` gives the same shortest round-trip digits: "1.5e-5".
    let sci = format!("{:e}", f.abs());
    let (mantissa, exponent) = sci.split_once('e').unwrap_or((&sci, "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let exponent: i64 = exponent.parse().unwrap_or(0);
    let sign = if f.is_sign_negative() { "-" } else { "" };
    // Python's decpt: the decimal point sits after `decpt` digits.
    let decpt = exponent + 1;
    let n = digits.len() as i64;
    if (-4 < decpt) && decpt <= 16 {
        if decpt <= 0 {
            format!("{sign}0.{}{digits}", "0".repeat((-decpt) as usize))
        } else if decpt < n {
            let (a, b) = digits.split_at(decpt as usize);
            format!("{sign}{a}.{b}")
        } else {
            format!("{sign}{digits}{}.0", "0".repeat((decpt - n) as usize))
        }
    } else {
        let (first, rest) = digits.split_at(1);
        let dot = if rest.is_empty() {
            String::new()
        } else {
            format!(".{rest}")
        };
        let e = decpt - 1;
        let esign = if e < 0 { '-' } else { '+' };
        format!("{sign}{first}{dot}e{esign}{:02}", e.abs())
    }
}

/// The exception a Python conversion raised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PyError {
    TypeError,
    ValueError,
    OverflowError,
}

/// The whitespace Python's `int(text)` and `float(text)` strip: ASCII
/// space and \t..\r (not \x1c-\x1f, which `str.isspace()` counts), and
/// the non-ASCII characters `str.isspace()` counts.
fn py_isspace(c: char) -> bool {
    matches!(
        c,
        '\t'..='\r'
            | ' '
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

/// Drop underscores that sit between two ASCII digits; `None` if any
/// other underscore is there (Python refuses the text then).
fn without_underscores(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    for (i, &c) in b.iter().enumerate() {
        if c == b'_' {
            let before = i.checked_sub(1).and_then(|j| b.get(j));
            let after = b.get(i + 1);
            if !(before.is_some_and(u8::is_ascii_digit) && after.is_some_and(u8::is_ascii_digit)) {
                return None;
            }
        } else {
            out.push(char::from(c));
        }
    }
    Some(out)
}

/// Python's `float(text)`. Digits other than ASCII ones are refused
/// here; Python takes any Unicode decimal digit (decisions.md).
fn float_from_text(text: &str) -> Result<f64, PyError> {
    let t = text.trim_matches(py_isspace);
    if !t.is_ascii() {
        return Err(PyError::ValueError);
    }
    let t = without_underscores(t).ok_or(PyError::ValueError)?;
    let body = t.strip_prefix(['+', '-']).unwrap_or(&t);
    let lower = body.to_ascii_lowercase();
    if matches!(lower.as_str(), "inf" | "infinity" | "nan") {
        return t.parse::<f64>().map_err(|_| PyError::ValueError);
    }
    // digits [. digits] | . digits, then an optional exponent.
    let b = body.as_bytes();
    let mut i = 0;
    let int_digits = b.iter().take_while(|c| c.is_ascii_digit()).count();
    i += int_digits;
    let mut frac_digits = 0;
    if b.get(i) == Some(&b'.') {
        i += 1;
        frac_digits = b[i..].iter().take_while(|c| c.is_ascii_digit()).count();
        i += frac_digits;
    }
    if int_digits + frac_digits == 0 {
        return Err(PyError::ValueError);
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let exp_digits = b[i.min(b.len())..]
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .count();
        if exp_digits == 0 {
            return Err(PyError::ValueError);
        }
        i += exp_digits;
    }
    if i != b.len() {
        return Err(PyError::ValueError);
    }
    t.parse::<f64>().map_err(|_| PyError::ValueError)
}

/// Python's `float(int)`: correctly rounded, OverflowError past the
/// largest float.
fn float_from_int(decimal: &str) -> Result<f64, PyError> {
    let f: f64 = decimal.parse().map_err(|_| PyError::ValueError)?;
    if f.is_infinite() {
        Err(PyError::OverflowError)
    } else {
        Ok(f)
    }
}

/// Python's `float(x)`.
pub fn py_float(value: &Value) -> Result<f64, PyError> {
    match value {
        Value::Bool(b) => Ok(if *b { 1.0 } else { 0.0 }),
        Value::Int(s) => float_from_int(s),
        Value::Float(f) => Ok(*f),
        Value::Str(s) => float_from_text(s),
        Value::Null | Value::List(_) | Value::Dict(_) => Err(PyError::TypeError),
    }
}

/// Python's `int(text)` in base 10. As in `float`, only ASCII digits.
fn int_from_text(text: &str) -> Result<String, PyError> {
    let t = text.trim_matches(py_isspace);
    if !t.is_ascii() {
        return Err(PyError::ValueError);
    }
    let (negative, body) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let digits = without_underscores(body).ok_or(PyError::ValueError)?;
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return Err(PyError::ValueError);
    }
    if digits.len() > MAX_INT_DIGITS {
        return Err(PyError::ValueError);
    }
    Ok(canonical_int(negative, &digits))
}

/// Python's `int(x)`, as the decimal text of the result.
pub fn py_int(value: &Value) -> Result<String, PyError> {
    match value {
        Value::Bool(b) => Ok(if *b { "1" } else { "0" }.into()),
        Value::Int(s) => Ok(s.clone()),
        Value::Float(f) if f.is_nan() => Err(PyError::ValueError),
        Value::Float(f) if f.is_infinite() => Err(PyError::OverflowError),
        // `{:.0}` of an integral float is its exact decimal expansion.
        Value::Float(f) => {
            let text = format!("{:.0}", f.trunc());
            Ok(canonical_int(
                text.starts_with('-'),
                text.trim_start_matches('-'),
            ))
        }
        Value::Str(s) => int_from_text(s),
        Value::Null | Value::List(_) | Value::Dict(_) => Err(PyError::TypeError),
    }
}

/// Python's `str(x)` of a scalar; `None` for a list or dict, whose
/// `repr` 1.x would write out (decisions.md: such a row is skipped).
pub fn py_str(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some("None".into()),
        Value::Bool(b) => Some(if *b { "True" } else { "False" }.into()),
        Value::Int(s) => Some(s.clone()),
        Value::Float(f) => Some(float_repr(*f)),
        Value::Str(s) => Some(s.clone()),
        Value::List(_) | Value::Dict(_) => None,
    }
}

/// The decimal text of an int, plus one.
pub fn int_plus_one(decimal: &str) -> String {
    fn add_one(digits: &str) -> String {
        let mut bytes = digits.as_bytes().to_vec();
        for b in bytes.iter_mut().rev() {
            if *b == b'9' {
                *b = b'0';
            } else {
                *b += 1;
                return String::from_utf8(bytes).unwrap_or_default();
            }
        }
        let mut out = String::from("1");
        out.push_str(&String::from_utf8(bytes).unwrap_or_default());
        out
    }
    fn sub_one(digits: &str) -> String {
        // digits > 0
        let mut bytes = digits.as_bytes().to_vec();
        for b in bytes.iter_mut().rev() {
            if *b == b'0' {
                *b = b'9';
            } else {
                *b -= 1;
                break;
            }
        }
        let text = String::from_utf8(bytes).unwrap_or_default();
        canonical_int(false, &text)
    }
    match decimal.strip_prefix('-') {
        Some(magnitude) => {
            let rest = sub_one(magnitude);
            if rest == "0" {
                rest
            } else {
                format!("-{rest}")
            }
        }
        None => add_one(decimal),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_repr_is_pythons() {
        for (f, want) in [
            (1.0, "1.0"),
            (0.1, "0.1"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (9999999999999998.0, "9999999999999998.0"),
            (1.5e-5, "1.5e-05"),
            (0.0001, "0.0001"),
            (-0.0, "-0.0"),
            (123456789012345678.0, "1.2345678901234568e+17"),
            (1e22, "1e+22"),
            (1700000000.0, "1700000000.0"),
            (f64::MAX, "1.7976931348623157e+308"),
            (5e-324, "5e-324"),
        ] {
            assert_eq!(float_repr(f), want, "{f}");
        }
    }

    #[test]
    fn loads_and_dumps_round_trip_pythons_dialect() {
        let text =
            br#"{"a": [1, 2.5, NaN, -Infinity, "\u00e9\ud83d\ude00\ud83d"], "a": 3, "b": -0}"#;
        let value = loads(text).unwrap();
        assert_eq!(
            dumps(&value),
            r#"{"a": 3, "b": 0}"#,
            "a repeated key keeps its first place and its last value"
        );
        let value = loads(br#"["\u00e9\ud83d\ude00\ud83d", 1E5, 01]"#);
        assert_eq!(value, Err(LoadError::Invalid));
        let value = loads(br#"["\u00e9\ud83d\ude00\ud83d", 1E5, -0.0]"#).unwrap();
        assert_eq!(
            dumps(&value),
            r#"["\u00e9\ud83d\ude00\ufffd", 100000.0, -0.0]"#
        );
    }

    #[test]
    fn nesting_is_capped() {
        let nested = |depth: usize| format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        assert!(loads(nested(MAX_DEPTH).as_bytes()).is_ok());
        assert_eq!(
            loads(nested(MAX_DEPTH + 1).as_bytes()),
            Err(LoadError::Crash("RecursionError"))
        );
        assert_eq!(
            loads(nested(1_000_000).as_bytes()),
            Err(LoadError::Crash("RecursionError"))
        );
    }

    #[test]
    fn conversions_follow_python() {
        let s = |t: &str| Value::Str(t.into());
        assert_eq!(py_int(&s(" 1_2 ")), Ok("12".into()));
        assert_eq!(py_int(&s("1__2")), Err(PyError::ValueError));
        assert_eq!(py_int(&Value::Float(-2.99)), Ok("-2".into()));
        assert_eq!(
            py_int(&Value::Float(1e19)),
            Ok("10000000000000000000".into())
        );
        assert_eq!(
            py_int(&Value::Float(f64::INFINITY)),
            Err(PyError::OverflowError)
        );
        assert_eq!(py_float(&s("\u{1c}8\u{1f}")), Err(PyError::ValueError));
        assert_eq!(py_float(&s("\u{a0}8\t")), Ok(8.0));
        assert_eq!(py_float(&s("1_0.5")), Ok(10.5));
        assert_eq!(py_float(&s("1._5")), Err(PyError::ValueError));
        assert_eq!(py_float(&s("-Infinity")), Ok(f64::NEG_INFINITY));
        assert_eq!(
            py_float(&Value::Int(format!("1{}", "0".repeat(400)))),
            Err(PyError::OverflowError)
        );
        assert_eq!(int_plus_one("-1"), "0");
        assert_eq!(int_plus_one("-10"), "-9");
        assert_eq!(int_plus_one("999"), "1000");
    }
}
