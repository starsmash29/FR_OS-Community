//! Python's `csv.reader` with the default (excel) dialect, over a file
//! opened with `newline=""`: the IEEE registry is read through it, and
//! which rows a damaged registry yields (a stray quote swallowing the
//! rest of the file, a field past the size limit stopping the read) is
//! part of what the differential test compares. A port of CPython
//! 3.13's `Modules/_csv.c` reader state machine, restricted to the
//! default dialect: delimiter `,`, quote `"`, doubled quotes, no escape
//! character, not strict.

use crate::Crash;

/// `csv.field_size_limit()`'s default, in characters. A longer field
/// raises `_csv.Error`, which 1.x does not catch.
pub const FIELD_LIMIT: usize = 131_072;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    StartRecord,
    StartField,
    InField,
    InQuotedField,
    QuoteInQuotedField,
    EatCrnl,
}

struct Reader {
    state: State,
    fields: Vec<String>,
    field: String,
    field_len: usize,
}

const ERROR: Crash = Crash("Error");

impl Reader {
    fn add_char(&mut self, c: char) -> Result<(), Crash> {
        if self.field_len >= FIELD_LIMIT {
            return Err(ERROR);
        }
        self.field.push(c);
        self.field_len += 1;
        Ok(())
    }

    fn save_field(&mut self) {
        self.fields.push(std::mem::take(&mut self.field));
        self.field_len = 0;
    }

    /// One character of a line, or `None` for the end of the line.
    fn process(&mut self, c: Option<char>) -> Result<(), Crash> {
        let newline = matches!(c, Some('\n' | '\r'));
        let end = |c: Option<char>| {
            if c.is_none() {
                State::StartRecord
            } else {
                State::EatCrnl
            }
        };
        match self.state {
            State::StartRecord => {
                if c.is_none() {
                    // An empty line: the row is [].
                } else if newline {
                    self.state = State::EatCrnl;
                } else {
                    self.state = State::StartField;
                    return self.process(c);
                }
            }
            State::StartField => match c {
                None | Some('\n' | '\r') => {
                    self.save_field();
                    self.state = end(c);
                }
                Some('"') => self.state = State::InQuotedField,
                Some(',') => self.save_field(),
                Some(ch) => {
                    self.add_char(ch)?;
                    self.state = State::InField;
                }
            },
            State::InField => match c {
                None | Some('\n' | '\r') => {
                    self.save_field();
                    self.state = end(c);
                }
                Some(',') => {
                    self.save_field();
                    self.state = State::StartField;
                }
                Some(ch) => self.add_char(ch)?,
            },
            State::InQuotedField => match c {
                None => {}
                Some('"') => self.state = State::QuoteInQuotedField,
                Some(ch) => self.add_char(ch)?,
            },
            State::QuoteInQuotedField => match c {
                Some('"') => {
                    self.add_char('"')?;
                    self.state = State::InQuotedField;
                }
                Some(',') => {
                    self.save_field();
                    self.state = State::StartField;
                }
                None | Some('\n' | '\r') => {
                    self.save_field();
                    self.state = end(c);
                }
                Some(ch) => {
                    self.add_char(ch)?;
                    self.state = State::InField;
                }
            },
            State::EatCrnl => match c {
                Some('\n' | '\r') => {}
                None => self.state = State::StartRecord,
                // "new-line character seen in unquoted field"; lines end
                // at every \r and \n, so this can't be reached.
                Some(_) => return Err(ERROR),
            },
        }
        Ok(())
    }
}

/// The lines a text file opened with `newline=""` yields: split after
/// each `\n`, `\r\n` or lone `\r`, the terminator kept.
fn lines(text: &str) -> impl Iterator<Item = &str> {
    let bytes = text.as_bytes();
    let mut start = 0;
    std::iter::from_fn(move || {
        if start >= bytes.len() {
            return None;
        }
        let mut i = start;
        while i < bytes.len() {
            match bytes[i] {
                b'\n' => {
                    i += 1;
                    break;
                }
                b'\r' => {
                    i += if bytes.get(i + 1) == Some(&b'\n') {
                        2
                    } else {
                        1
                    };
                    break;
                }
                _ => i += 1,
            }
        }
        let line = text.get(start..i);
        start = i;
        line
    })
}

/// Every row `csv.reader` yields for `text`, handed to `row` one at a
/// time, or the `_csv.Error` that ended the read (the rows before it
/// were already handed over).
pub fn read_rows(text: &str, mut row: impl FnMut(Vec<String>)) -> Result<(), Crash> {
    let mut reader = Reader {
        state: State::StartRecord,
        fields: Vec::new(),
        field: String::new(),
        field_len: 0,
    };
    for line in lines(text) {
        for c in line.chars() {
            reader.process(Some(c))?;
        }
        reader.process(None)?;
        if reader.state == State::StartRecord {
            row(std::mem::take(&mut reader.fields));
        }
    }
    // The end of the file inside a field: the not-strict reader keeps
    // what it has.
    if reader.field_len != 0 || reader.state == State::InQuotedField {
        reader.save_field();
        row(std::mem::take(&mut reader.fields));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(text: &str) -> Result<Vec<Vec<String>>, Crash> {
        let mut out = Vec::new();
        read_rows(text, |r| out.push(r))?;
        Ok(out)
    }

    #[test]
    fn reads_as_python_does() {
        // list(csv.reader(io.StringIO(text, newline="")))
        assert_eq!(
            rows("a,\"b,c\",\"d\"\"e\"\r\n\nx\"y\",\"q\"z\n\"open\nline").unwrap(),
            vec![
                vec!["a", "b,c", "d\"e"],
                vec![],
                vec!["x\"y\"", "qz"],
                vec!["open\nline"],
            ]
        );
        assert_eq!(rows("a\rb,c").unwrap(), vec![vec!["a"], vec!["b", "c"]]);
        assert_eq!(rows("").unwrap(), Vec::<Vec<String>>::new());
    }

    #[test]
    fn field_limit() {
        let at = "x".repeat(FIELD_LIMIT);
        assert_eq!(rows(&at).unwrap(), vec![vec![at.clone()]]);
        assert_eq!(rows(&format!("{at}x")), Err(ERROR));
    }
}
