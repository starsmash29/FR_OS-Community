package helper

import (
	"errors"
	"unicode/utf8"
)

// Python's csv.reader with the default (excel) dialect, and the text it
// reads, as 1.x reads Kea's lease file: Kea writes the client's own
// hostname into it, so a client chooses some of these bytes, and FR_OS 2
// must read the same fields from them as 1.x does.

// csvFieldLimit is csv.field_size_limit()'s default. A longer field is
// a csv.Error, which 1.x doesn't catch.
const csvFieldLimit = 131072

var errCSVFieldLimit = errors.New("field larger than field limit (131072)")

// decodeReplace is bytes.decode("utf-8", errors="replace"): each maximal
// invalid subpart (a lead byte and the continuation bytes that fit it)
// becomes one U+FFFD, as Python and the Unicode standard do, where Go's
// range loop would give one per byte.
func decodeReplace(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	out := make([]rune, 0, len(b))
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r != utf8.RuneError || size > 1 {
			out = append(out, r)
			i += size
			continue
		}
		out = append(out, utf8.RuneError)
		i += invalidSubpart(b[i:])
	}
	return string(out)
}

// invalidSubpart is how many bytes at the start of b, which don't begin
// a valid character, one U+FFFD stands for.
func invalidSubpart(b []byte) int {
	lo, hi := byte(0x80), byte(0xBF)
	var need int
	switch c := b[0]; {
	case c >= 0xC2 && c <= 0xDF:
		need = 1
	case c == 0xE0:
		need, lo = 2, 0xA0
	case c == 0xED:
		need, hi = 2, 0x9F
	case c >= 0xE1 && c <= 0xEF:
		need = 2
	case c == 0xF0:
		need, lo = 3, 0x90
	case c == 0xF4:
		need, hi = 3, 0x8F
	case c >= 0xF1 && c <= 0xF3:
		need = 3
	default:
		return 1
	}
	n := 1
	for k := 0; k < need && n < len(b); k++ {
		if b[n] < lo || b[n] > hi {
			break
		}
		lo, hi = 0x80, 0xBF
		n++
	}
	return n
}

// splitLines is iterating over a file opened with newline="": a line
// ends after "\n", "\r\n" or a lone "\r", and keeps its ending.
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\n':
			lines = append(lines, s[start:i+1])
			start = i + 1
		case '\r':
			if i+1 < len(s) && s[i+1] == '\n' {
				i++
			}
			lines = append(lines, s[start:i+1])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// The parser's states (CPython's Modules/_csv.c).
const (
	csvStartRecord = iota
	csvStartField
	csvInField
	csvInQuotedField
	csvQuoteInQuotedField
	csvEatCRNL
)

// csvEOL is the end of each line the reader is handed.
const csvEOL = -2

type csvReader struct {
	lines  []string
	state  int
	field  []rune
	fields []string
}

func (p *csvReader) save() {
	p.fields = append(p.fields, string(p.field))
	p.field = p.field[:0]
}

func (p *csvReader) add(c rune) error {
	if len(p.field) >= csvFieldLimit {
		return errCSVFieldLimit
	}
	p.field = append(p.field, c)
	return nil
}

// process is parse_process_char for the excel dialect: delimiter ",",
// quote '"' doubled to escape it, no escape character, not strict.
func (p *csvReader) process(c rune) error {
	nl := c == '\n' || c == '\r'
	switch p.state {
	case csvStartRecord:
		if c == csvEOL {
			return nil
		}
		if nl {
			p.state = csvEatCRNL
			return nil
		}
		p.state = csvStartField
		fallthrough
	case csvStartField:
		switch {
		case nl || c == csvEOL:
			p.save()
			p.state = afterLine(c)
		case c == '"':
			p.state = csvInQuotedField
		case c == ',':
			p.save()
		default:
			p.state = csvInField
			return p.add(c)
		}
	case csvInField:
		switch {
		case nl || c == csvEOL:
			p.save()
			p.state = afterLine(c)
		case c == ',':
			p.save()
			p.state = csvStartField
		default:
			return p.add(c)
		}
	case csvInQuotedField:
		switch {
		case c == csvEOL:
		case c == '"':
			p.state = csvQuoteInQuotedField
		default:
			return p.add(c)
		}
	case csvQuoteInQuotedField:
		switch {
		case c == '"':
			p.state = csvInQuotedField
			return p.add(c)
		case c == ',':
			p.save()
			p.state = csvStartField
		case nl || c == csvEOL:
			p.save()
			p.state = afterLine(c)
		default:
			p.state = csvInField
			return p.add(c)
		}
	case csvEatCRNL:
		switch {
		case nl:
		case c == csvEOL:
			p.state = csvStartRecord
		default:
			return errors.New("new-line character seen in unquoted field")
		}
	}
	return nil
}

// afterLine is the state after a field a line end closed: the record
// is done at the end of the line, and a "\r" or "\n" in it is eaten
// up to there.
func afterLine(c rune) int {
	if c == csvEOL {
		return csvStartRecord
	}
	return csvEatCRNL
}

// next is the next row, false at the end (Reader_iternext).
func (p *csvReader) next() ([]string, bool, error) {
	p.fields, p.field, p.state = nil, p.field[:0], csvStartRecord
	for {
		if len(p.lines) == 0 {
			if len(p.field) != 0 || p.state == csvInQuotedField {
				p.save()
				break
			}
			return nil, false, nil
		}
		line := p.lines[0]
		p.lines = p.lines[1:]
		for _, c := range line {
			if err := p.process(c); err != nil {
				return nil, false, err
			}
		}
		if err := p.process(csvEOL); err != nil {
			return nil, false, err
		}
		if p.state == csvStartRecord {
			break
		}
	}
	if p.fields == nil {
		p.fields = []string{}
	}
	return p.fields, true, nil
}

// csvDictRows is csv.DictReader over text: each row as {fieldname:
// value}, the first row giving the names (a later name of two equal ones
// wins), empty rows skipped, a missing value absent (DictReader's restval
// None, which 1.x reads as "") and extra values dropped (they go under
// the key None, which 1.x never reads).
func csvDictRows(text string) ([]map[string]string, error) {
	p := &csvReader{lines: splitLines(text)}
	names, ok, err := p.next()
	if err != nil || !ok {
		return nil, err
	}
	var rows []map[string]string
	for {
		row, ok, err := p.next()
		if err != nil {
			return nil, err
		}
		if !ok {
			return rows, nil
		}
		if len(row) == 0 {
			continue
		}
		d := map[string]string{}
		for i, name := range names {
			if i < len(row) {
				d[name] = row[i]
			} else {
				delete(d, name) // restval None, over an earlier value of the same name
			}
		}
		rows = append(rows, d)
	}
}
