// Package pyyaml reads YAML as 1.x does: a port of PyYAML 6.0.1's pure
// Python SafeLoader front end (reader, scanner, parser, composer and
// resolver), the version 1.x pins in requirements.lock. 1.x reads
// config.yaml with yaml.safe_load, so what PyYAML accepts, refuses and
// resolves (YAML 1.1: yes/no are booleans, 0755 is octal, 1:30 is 90) is
// the specification here; the error messages are PyYAML's, word for
// word. The constructor, which turns nodes into config values, is in
// package config.
//
// PyYAML is under the MIT licence (Copyright (c) 2017-2021 Ingy döt Net,
// Copyright (c) 2006-2016 Kirill Simonov), compatible with the AGPLv3.
package pyyaml

import (
	"fmt"
	"strconv"
	"strings"
)

// Mark is a position in the text, for messages (yaml.error.Mark).
// Index and Column count code points, as Python does.
type Mark struct {
	Name                string
	Index, Line, Column int
	buffer              []rune
	pointer             int
	valid               bool
}

// Valid is false for the zero Mark (PyYAML's None).
func (m Mark) Valid() bool { return m.valid }

func isBreakOrNul(r rune) bool {
	return r == 0 || r == '\r' || r == '\n' || r == 0x85 || r == 0x2028 || r == 0x2029
}

func (m Mark) snippet() string {
	const indent, maxLength = 4, 75
	head := ""
	start := m.pointer
	for start > 0 && !isBreakOrNul(m.buffer[start-1]) {
		start--
		if float64(m.pointer-start) > maxLength/2.0-1 {
			head = " ... "
			start += 5
			break
		}
	}
	tail := ""
	end := m.pointer
	for end < len(m.buffer) && !isBreakOrNul(m.buffer[end]) {
		end++
		if float64(end-m.pointer) > maxLength/2.0-1 {
			tail = " ... "
			end -= 5
			break
		}
	}
	snippet := string(m.buffer[start:end])
	return strings.Repeat(" ", indent) + head + snippet + tail + "\n" +
		strings.Repeat(" ", indent+m.pointer-start+len(head)) + "^"
}

func (m Mark) String() string {
	return fmt.Sprintf("  in \"%s\", line %d, column %d:\n%s", m.Name, m.Line+1, m.Column+1, m.snippet())
}

func (m Mark) same(o Mark) bool {
	return m.Name == o.Name && m.Line == o.Line && m.Column == o.Column
}

// MarkedError is PyYAML's MarkedYAMLError (ScannerError, ParserError,
// ComposerError, ConstructorError): Error() is its str().
type MarkedError struct {
	Context     string
	HasContext  bool
	ContextMark Mark
	Problem     string
	HasProblem  bool
	ProblemMark Mark
}

func (e *MarkedError) Error() string {
	var lines []string
	if e.HasContext {
		lines = append(lines, e.Context)
	}
	if e.ContextMark.valid && (!e.HasProblem || !e.ProblemMark.valid || !e.ContextMark.same(e.ProblemMark)) {
		lines = append(lines, e.ContextMark.String())
	}
	if e.HasProblem {
		lines = append(lines, e.Problem)
	}
	if e.ProblemMark.valid {
		lines = append(lines, e.ProblemMark.String())
	}
	return strings.Join(lines, "\n")
}

// Errorf is a MarkedError: context may be "" with an invalid mark for
// PyYAML's None.
func Errorf(context string, contextMark Mark, problemMark Mark, format string, args ...any) *MarkedError {
	return &MarkedError{
		Context: context, HasContext: context != "", ContextMark: contextMark,
		Problem: fmt.Sprintf(format, args...), HasProblem: true, ProblemMark: problemMark,
	}
}

// ReaderError is PyYAML's ReaderError for a str input: a character YAML
// doesn't allow.
type ReaderError struct {
	Name      string
	Position  int
	Character rune
}

func (e *ReaderError) Error() string {
	return fmt.Sprintf("unacceptable character #x%04x: special characters are not allowed\n  in \"%s\", position %d",
		e.Character, e.Name, e.Position)
}

// LimitError is a refusal FR_OS 2 adds where PyYAML has none (or where
// Python itself would fail, not PyYAML): testdata/reference/decisions.md.
type LimitError struct{ Msg string }

func (e *LimitError) Error() string { return e.Msg }

// pyRepr is Python's repr of a str, for messages ("found character %r").
func pyRepr(s string) string {
	quote := byte('\'')
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for _, r := range s {
		switch {
		case r == rune(quote) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x7f:
			b.WriteRune(r)
		case !strconv.IsPrint(r):
			switch {
			case r <= 0xff:
				fmt.Fprintf(&b, `\x%02x`, r)
			case r <= 0xffff:
				fmt.Fprintf(&b, `\u%04x`, r)
			default:
				fmt.Fprintf(&b, `\U%08x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}
